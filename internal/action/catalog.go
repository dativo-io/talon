package action

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/dativo-io/talon/internal/policy"
)

// Trusted action catalog (#427). Compiled once per agent generation from
// agent.talon.yaml plus the validated snapshots of its trusted MCP sources;
// immutable afterwards. It describes governed actions and never holds
// executable code. Compilation performs no I/O: discovery happens before,
// through the source discoverer, and hands the compiler credential-free
// snapshots.
//
// JSON Schema: draft 2020-12 via santhosh-tekuri/jsonschema/v6, compiled
// OFFLINE. Every external `$ref` (http, https, file, anything not inside
// the schema document) is refused at compile time; nothing is ever fetched
// or read during compilation or validation. Supported subset exercised by
// conformance tests: type, properties, required, additionalProperties,
// enum, const, minimum/maximum, minLength/maxLength, pattern, items,
// nested objects, in-document $ref/$defs.

const (
	// ExecutionProfileTalonForwarded: Talon claims the attempt and dispatches
	// through its trusted dispatcher; the result is observed by Talon.
	ExecutionProfileTalonForwarded = "talon_forwarded"
	// BindingProfileWholePayloadV1 binds the complete normalized argument
	// payload with no exclusions.
	BindingProfileWholePayloadV1 = "talon/whole-payload/v1"
	// ProjectionVersionV1 is the reviewer-projection contract version.
	ProjectionVersionV1 = "talon/review-projection/v1"
)

var actionNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// ErrExternalRef is returned when a schema tries to reference anything
// outside its own document.
var ErrExternalRef = errors.New("external $ref is not permitted: schemas compile offline and self-contained")

// ErrSourceNotDiscovered marks a catalog whose static configuration is
// valid but whose trusted MCP sources have not been discovered: the
// compiler was handed no snapshot for them. Offline tooling reports it
// truthfully; runtime composition treats it as fail-closed.
var ErrSourceNotDiscovered = errors.New("trusted action source not discovered")

// SourceNotDiscoveredError lists the undiscovered source ids.
type SourceNotDiscoveredError struct {
	IDs []string
}

func (e *SourceNotDiscoveredError) Error() string {
	return fmt.Sprintf("%v: %s", ErrSourceNotDiscovered, strings.Join(e.IDs, ", "))
}

// Is makes errors.Is(err, ErrSourceNotDiscovered) true.
func (e *SourceNotDiscoveredError) Is(target error) bool { return target == ErrSourceNotDiscovered }

// refusingLoader is the only URL loader the compiler gets: it refuses every
// URL, so no network or filesystem access can happen during compilation.
type refusingLoader struct{}

func (refusingLoader) Load(u string) (any, error) {
	return nil, fmt.Errorf("%w (%s)", ErrExternalRef, u)
}

// Review is the compiled reviewer-projection classification: every
// top-level argument field is material and appears in exactly one set.
type Review struct {
	Shown       []string
	NonMaterial []string
}

// Definition is one immutable governed action, transport-neutral: the same
// type whether it was declared explicitly or discovered from a trusted MCP
// source. It carries authority facts (source identity, canonical name,
// schema, projection, binding, destination) and protocol metadata
// (mirrored parameters) — never request DTOs, ids, credentials or code.
type Definition struct {
	Name        string
	Description string
	// Source is the trusted origin this definition was compiled from.
	Source Source
	// UpstreamName is the action's name at its source ("" for declared).
	// Only Name is callable; the mapping is one-to-one and evidenced.
	UpstreamName string
	Schema       json.RawMessage // canonical JSON Schema bytes (business contract)
	SchemaDigest string
	Properties   []string // declared top-level argument fields (sorted)
	Review       Review
	// ProjectionDigest covers the projection contract version and the
	// classification sets.
	ProjectionDigest string
	// MirroredParams are the source's validated x-mcp-header declarations:
	// protocol metadata preserved for the MCP adapter, never policy.
	MirroredParams []MirroredParam
	// Title, Hints and OutputSchema are the source's bounded presentation
	// metadata (declared definitions have none). Hints, never policy: they
	// enter MetadataDigest only.
	Title        string
	Hints        *ToolHints
	OutputSchema json.RawMessage
	Destination  Destination
	// DestinationID is the stable material-destination identity bound into
	// the operation digest: method + URL for http, source id + endpoint for
	// mcp; never credentials.
	DestinationID    string
	ExecutionProfile string
	BindingProfile   string
	// DefinitionDigest covers everything a reviewer or a claim relies on:
	// canonical name, source identity and configuration, upstream name,
	// schema, projection, destination incl. success contract, profiles. A
	// change to ANY of it makes prior authorization unusable.
	DefinitionDigest string
	// MetadataDigest covers the descriptive and protocol facts (description,
	// mirrored parameters). It is catalog-generation input, not
	// authorization identity: a changed description never invalidates an
	// approval, and never authorizes anything either.
	MetadataDigest string

	schema *jsonschema.Schema
}

// Destination is the trusted downstream of a talon_forwarded action and
// its outcome contract.
type Destination struct {
	Type   string // http | mcp
	URL    string
	Method string // http only
	// SuccessStatusCodes are the ONLY observed responses that mean the
	// business effect completed (http). Empty = every response is unknown.
	SuccessStatusCodes []int
}

// CatalogSource is the inspectable, credential-free summary of one trusted
// source as compiled into a catalog.
type CatalogSource struct {
	ID                 string             `json:"id"`
	Type               string             `json:"type"`
	URL                string             `json:"url"`
	ConfigDigest       string             `json:"config_digest"`
	Generation         string             `json:"generation"`
	ServerInfo         SourceServerInfo   `json:"server_info"`
	SupportedVersions  []string           `json:"supported_versions,omitempty"`
	Capabilities       SourceCapabilities `json:"capabilities"`
	CapabilitiesDigest string             `json:"capabilities_digest"`
	TTLMs              json.Number        `json:"ttl_ms"`
	CacheScope         string             `json:"cache_scope"`
	DiscoveredAt       time.Time          `json:"discovered_at"`
	RefreshAt          time.Time          `json:"refresh_at"`
	ToolCount          int                `json:"tool_count"`
	Excluded           []ExcludedTool     `json:"excluded,omitempty"`
}

// Catalog is the compiled, immutable action set of one agent.
type Catalog struct {
	defs    map[string]*Definition
	names   []string
	sources []CatalogSource // sorted by id
	// Digest names the catalog generation: every definition's identity and
	// metadata plus every source's discovered generation.
	Digest string
}

// CompileCatalog validates and compiles the agent's actions: explicit
// definitions from their declared schema and destination, discovered
// definitions from the matching source snapshot plus the Talon overlay.
// Every definition must end up with a closed object schema, a fully
// classified projection and a trusted destination; the build fails closed
// on any defect, duplicate or ambiguity. snapshots must hold one validated
// snapshot per configured source (nil is valid only when no source is
// configured; otherwise ErrSourceNotDiscovered is returned AFTER all static
// checks passed).
func CompileCatalog(cfg *policy.ActionsConfig, snapshots map[string]*SourceSnapshot) (*Catalog, error) {
	c := &Catalog{defs: map[string]*Definition{}}
	if cfg == nil {
		c.Digest = Digest([]byte("{}"))
		return c, nil
	}
	sourceIDs := sortedKeys(cfg.Sources)
	for _, id := range sourceIDs {
		if err := ValidateSourceConfig(id, cfg.Sources[id]); err != nil {
			return nil, fmt.Errorf("actions.sources.%s: %w", id, err)
		}
	}
	discovered, err := c.compileDeclaredAndPlanDiscovered(cfg)
	if err != nil {
		return nil, err
	}
	// Static configuration is valid. Discovered definitions now need their
	// source snapshots; every configured source must have been discovered.
	var missing []string
	for _, id := range sourceIDs {
		if snapshots == nil || snapshots[id] == nil {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		return nil, &SourceNotDiscoveredError{IDs: missing}
	}
	for _, id := range sourceIDs {
		cs, err := catalogSource(id, cfg.Sources[id], snapshots[id])
		if err != nil {
			return nil, fmt.Errorf("actions.sources.%s: %w", id, err)
		}
		c.sources = append(c.sources, cs)
	}
	for i := range discovered {
		p := &discovered[i]
		def, err := compileDiscoveredDefinition(p.name, p.cfg, p.upstream, cfg.Sources[p.cfg.Source], snapshots[p.cfg.Source])
		if err != nil {
			return nil, fmt.Errorf("actions.definitions.%s: %w", p.name, err)
		}
		c.add(def)
	}
	c.finish()
	return c, nil
}

// pendingDiscovered is a statically valid discovered definition awaiting
// its source snapshot.
type pendingDiscovered struct {
	name     string
	cfg      policy.ActionDefinitionConfig
	upstream string
}

// compileDeclaredAndPlanDiscovered runs the static pass over every
// definition: declared ones compile fully, discovered ones are shape-checked
// and their one-to-one upstream mapping is enforced.
func (c *Catalog) compileDeclaredAndPlanDiscovered(cfg *policy.ActionsConfig) ([]pendingDiscovered, error) {
	var discovered []pendingDiscovered
	mapped := map[string]string{} // source\x00upstream → canonical name
	for _, name := range sortedKeys(cfg.Definitions) {
		dc := cfg.Definitions[name]
		if !actionNameRe.MatchString(name) {
			return nil, fmt.Errorf("actions.definitions.%s: invalid action name (want ^[a-z][a-z0-9_]{0,63}$)", name)
		}
		if dc.Source == "" {
			if dc.UpstreamName != "" {
				return nil, fmt.Errorf("actions.definitions.%s: upstream_name requires source", name)
			}
			def, err := compileDefinition(name, dc)
			if err != nil {
				return nil, fmt.Errorf("actions.definitions.%s: %w", name, err)
			}
			c.add(def)
			continue
		}
		upstream, err := checkDiscoveredShape(cfg, name, dc)
		if err != nil {
			return nil, fmt.Errorf("actions.definitions.%s: %w", name, err)
		}
		key := dc.Source + "\x00" + upstream
		if prev, dup := mapped[key]; dup {
			return nil, fmt.Errorf("actions.definitions.%s: upstream tool %q of source %q is already mapped by %s — one upstream action maps to exactly one canonical action", name, upstream, dc.Source, prev)
		}
		mapped[key] = name
		discovered = append(discovered, pendingDiscovered{name: name, cfg: dc, upstream: upstream})
	}
	return discovered, nil
}

// checkDiscoveredShape enforces the discovered definition shape and
// returns the upstream tool name (the canonical name when none is given).
func checkDiscoveredShape(cfg *policy.ActionsConfig, name string, dc policy.ActionDefinitionConfig) (string, error) {
	if len(dc.InputSchema) > 0 {
		return "", fmt.Errorf("input_schema is not allowed with source (the schema comes from the trusted source's validated definition)")
	}
	if dc.Destination != (policy.ActionDestinationConfig{}) {
		return "", fmt.Errorf("destination is not allowed with source (the source is the destination)")
	}
	if _, ok := cfg.Sources[dc.Source]; !ok {
		return "", fmt.Errorf("references unknown source %q", dc.Source)
	}
	upstream := dc.UpstreamName
	if upstream == "" {
		upstream = name
	}
	if !ValidUpstreamName(upstream) {
		return "", fmt.Errorf("invalid upstream_name %q", dc.UpstreamName)
	}
	return upstream, nil
}

// finish orders the catalog and computes its generation digest.
func (c *Catalog) finish() {
	sort.Strings(c.names)
	var b strings.Builder
	for _, n := range c.names {
		d := c.defs[n]
		b.WriteString(n)
		b.WriteByte('=')
		b.WriteString(d.DefinitionDigest)
		b.WriteByte(':')
		b.WriteString(d.MetadataDigest)
		b.WriteByte('\n')
	}
	for i := range c.sources {
		s := &c.sources[i]
		fmt.Fprintf(&b, "source=%s:%s:%s\n", s.ID, s.ConfigDigest, s.Generation)
	}
	c.Digest = Digest([]byte(b.String()))
}

func (c *Catalog) add(def *Definition) {
	c.defs[def.Name] = def
	c.names = append(c.names, def.Name)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ValidUpstreamName bounds a source tool name: non-empty, printable, no
// whitespace or control characters, at most 128 bytes.
func ValidUpstreamName(s string) bool {
	if s == "" || len(s) > 128 || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if r < 0x21 || r == 0x7f {
			return false
		}
	}
	return true
}

// catalogSource checks that a snapshot belongs to the trusted configuration
// it is presented for and summarizes it.
func catalogSource(id string, cfg policy.ActionSourceConfig, snap *SourceSnapshot) (CatalogSource, error) {
	want := SourceConfigDigest(id, cfg)
	if snap.ID != id || !strings.EqualFold(snap.Type, SourceTypeMCP) || snap.ConfigDigest != want {
		return CatalogSource{}, fmt.Errorf("discovered snapshot does not belong to this trusted source configuration (id/type/config mismatch)")
	}
	if snap.Generation == "" {
		return CatalogSource{}, fmt.Errorf("discovered snapshot has no generation digest")
	}
	return CatalogSource{
		ID: id, Type: SourceTypeMCP, URL: cfg.URL, ConfigDigest: want, Generation: snap.Generation,
		ServerInfo: snap.ServerInfo, SupportedVersions: append([]string(nil), snap.SupportedVersions...),
		Capabilities: snap.Capabilities, CapabilitiesDigest: snap.Capabilities.Digest(),
		TTLMs: snap.TTLMs, CacheScope: snap.CacheScope, DiscoveredAt: snap.DiscoveredAt, RefreshAt: snap.RefreshAt(),
		ToolCount: len(snap.Tools), Excluded: append([]ExcludedTool(nil), snap.Excluded...),
	}, nil
}

func compileDefinition(name string, cfg policy.ActionDefinitionConfig) (*Definition, error) {
	canonSchema, compiled, err := compileInputSchema(name, cfg.InputSchema)
	if err != nil {
		return nil, err
	}
	props := topLevelProperties(cfg.InputSchema)
	review, err := compileReview(props, cfg.Review)
	if err != nil {
		return nil, err
	}
	destination, err := compileDestination(cfg.Destination)
	if err != nil {
		return nil, err
	}
	def := &Definition{
		Name:             name,
		Description:      cfg.Description,
		Source:           Source{Type: SourceTypeDeclared},
		Schema:           canonSchema,
		SchemaDigest:     Digest(canonSchema),
		Properties:       props,
		Review:           review,
		Destination:      destination,
		DestinationID:    "http:" + destination.Method + " " + destination.URL,
		ExecutionProfile: ExecutionProfileTalonForwarded,
		BindingProfile:   BindingProfileWholePayloadV1,
		schema:           compiled,
	}
	finishDefinition(def)
	return def, nil
}

// compileDiscoveredDefinition overlays Talon's trusted definition on the
// source's validated tool: the schema and mirrored parameters come from the
// snapshot, everything with authority from configuration.
func compileDiscoveredDefinition(name string, cfg policy.ActionDefinitionConfig, upstream string, src policy.ActionSourceConfig, snap *SourceSnapshot) (*Definition, error) {
	tool, ok := snap.lookup(upstream)
	if !ok {
		for _, ex := range snap.Excluded {
			if ex.Name == upstream {
				return nil, fmt.Errorf("upstream tool %q of source %q has an invalid definition and cannot be governed: %s", upstream, snap.ID, ex.Reason)
			}
		}
		return nil, fmt.Errorf("upstream tool %q was not discovered at source %q (%d valid tool(s) discovered)", upstream, snap.ID, len(snap.Tools))
	}
	schemaMap, err := closedSchemaMap(tool.Schema)
	if err != nil {
		return nil, err
	}
	canonSchema, compiled, err := compileInputSchema(name, schemaMap)
	if err != nil {
		return nil, err
	}
	props := topLevelProperties(schemaMap)
	review, err := compileReview(props, cfg.Review)
	if err != nil {
		return nil, err
	}
	description := cfg.Description
	if description == "" {
		description = tool.Description
	}
	def := &Definition{
		Name:        name,
		Description: description,
		Source: Source{
			Type: SourceTypeMCP, ID: snap.ID, URL: src.URL, ConfigDigest: snap.ConfigDigest,
			Generation: snap.Generation, ServerInfo: snap.ServerInfo,
		},
		UpstreamName:     upstream,
		Schema:           canonSchema,
		SchemaDigest:     Digest(canonSchema),
		Properties:       props,
		Review:           review,
		MirroredParams:   append([]MirroredParam(nil), tool.MirroredParams...),
		Title:            tool.Title,
		Hints:            cloneHints(tool.Hints),
		OutputSchema:     append(json.RawMessage(nil), tool.OutputSchema...),
		Destination:      Destination{Type: DestinationTypeMCP, URL: src.URL},
		DestinationID:    "mcp:" + snap.ID + " " + src.URL,
		ExecutionProfile: ExecutionProfileTalonForwarded,
		BindingProfile:   BindingProfileWholePayloadV1,
		schema:           compiled,
	}
	finishDefinition(def)
	return def, nil
}

// closedSchemaMap decodes a discovered tool's canonical schema with exact
// numbers and applies the catalog's closed-object normalization: an absent
// additionalProperties is closed (Talon validates and forwards exactly the
// declared, classified fields); any permissive value is unsupported, since
// an undeclared field could never be classified for a reviewer.
func closedSchemaMap(canonical json.RawMessage) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(canonical))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil {
		return nil, fmt.Errorf("upstream inputSchema is not a JSON object")
	}
	if t, _ := m["type"].(string); t != "object" {
		return nil, fmt.Errorf("upstream inputSchema.type must be \"object\"")
	}
	ap, has := m["additionalProperties"]
	if !has {
		m["additionalProperties"] = false
		return m, nil
	}
	if b, ok := ap.(bool); !ok || b {
		return nil, fmt.Errorf("upstream inputSchema.additionalProperties %v is unsupported: a governed action's arguments must be a closed set of declared, classified fields", ap)
	}
	return m, nil
}

func (s *SourceSnapshot) lookup(name string) (*DiscoveredTool, bool) {
	for i := range s.Tools {
		if s.Tools[i].Name == name {
			return &s.Tools[i], true
		}
	}
	return nil, false
}

// finishDefinition computes the digests every definition carries.
func finishDefinition(def *Definition) {
	def.ProjectionDigest = Digest([]byte(strings.Join([]string{
		ProjectionVersionV1,
		"shown=" + strings.Join(def.Review.Shown, ","), "non_material=" + strings.Join(def.Review.NonMaterial, ","),
	}, "\n")))
	def.MetadataDigest = Digest([]byte("mirrors=" + mirroredParamsKey(def.MirroredParams) + "\npresentation=" + presentationKey(def.Title, def.Description, def.Hints, def.OutputSchema)))
	def.DefinitionDigest = definitionIdentity(def)
}

func cloneHints(h *ToolHints) *ToolHints {
	if h == nil {
		return nil
	}
	c := *h
	if h.Destructive != nil {
		v := *h.Destructive
		c.Destructive = &v
	}
	if h.OpenWorld != nil {
		v := *h.OpenWorld
		c.OpenWorld = &v
	}
	return &c
}

// compileInputSchema enforces the closed-object contract and compiles the
// canonical schema offline.
func compileInputSchema(name string, schema map[string]any) ([]byte, *jsonschema.Schema, error) {
	if len(schema) == 0 {
		return nil, nil, fmt.Errorf("input_schema is required")
	}
	if t, _ := schema["type"].(string); t != "object" {
		return nil, nil, fmt.Errorf("input_schema.type must be \"object\"")
	}
	if ap, ok := schema["additionalProperties"].(bool); !ok || ap {
		return nil, nil, fmt.Errorf("input_schema.additionalProperties must be false: every argument field of a governed action is a declared, classified property")
	}
	rawSchema, err := json.Marshal(schema)
	if err != nil {
		return nil, nil, fmt.Errorf("input_schema: %w", err)
	}
	canonSchema, err := Canonicalize(rawSchema)
	if err != nil {
		return nil, nil, fmt.Errorf("input_schema: %w", err)
	}
	compiled, err := compileSchema(name, canonSchema)
	if err != nil {
		return nil, nil, err
	}
	return canonSchema, compiled, nil
}

// compileDestination validates the http destination and its trusted
// success contract.
func compileDestination(cfg policy.ActionDestinationConfig) (Destination, error) {
	if !strings.EqualFold(cfg.Type, "http") {
		return Destination{}, fmt.Errorf("destination.type must be http")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return Destination{}, fmt.Errorf("destination.url must be an absolute http(s) URL")
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return Destination{}, fmt.Errorf("destination.url: plaintext http is allowed only for loopback destinations")
	}
	if u.User != nil {
		return Destination{}, fmt.Errorf("destination.url must not embed credentials")
	}
	method := strings.ToUpper(strings.TrimSpace(cfg.Method))
	if method == "" {
		method = "POST"
	}
	var success []int
	if cfg.Success != nil {
		if len(cfg.Success.StatusCodes) == 0 {
			return Destination{}, fmt.Errorf("destination.success.status_codes must not be empty when declared")
		}
		for _, c := range cfg.Success.StatusCodes {
			if c < 200 || c > 299 {
				return Destination{}, fmt.Errorf("destination.success.status_codes: %d is not a 2xx status", c)
			}
			success = append(success, c)
		}
		sort.Ints(success)
	}
	return Destination{Type: DestinationTypeHTTP, URL: u.String(), Method: method, SuccessStatusCodes: success}, nil
}

// definitionIdentity digests everything a reviewer or a claim relies on:
// the authority facts. Description, mirrored parameters, serverInfo, cache
// hints and the discovered generation are deliberately absent — a schema
// change already enters through the schema digest, and nothing else the
// source says can alter what was authorized.
func definitionIdentity(def *Definition) string {
	successStr := make([]string, len(def.Destination.SuccessStatusCodes))
	for i, c := range def.Destination.SuccessStatusCodes {
		successStr[i] = fmt.Sprint(c)
	}
	return Digest([]byte(strings.Join([]string{
		"name=" + def.Name, "source=" + def.Source.Type + ":" + def.Source.ID, "source_config=" + def.Source.ConfigDigest,
		"upstream=" + def.UpstreamName, "schema=" + def.SchemaDigest, "projection=" + def.ProjectionDigest,
		"destination=" + def.DestinationID, "success=" + strings.Join(successStr, ","),
		"profile=" + def.ExecutionProfile, "binding=" + def.BindingProfile,
	}, "\n")))
}

// schemaDialect2020 is the only dialect a governed action may declare.
// The public contract is JSON Schema 2020-12; a document that names
// another dialect would otherwise be compiled under THAT dialect's
// semantics (DefaultDraft only covers an absent $schema), so the catalog
// pins the dialect before compilation. The empty-fragment form is the
// same canonical URI.
const schemaDialect2020 = "https://json-schema.org/draft/2020-12/schema"

// compileSchema compiles one schema document with draft 2020-12 semantics
// and no external resolution whatsoever.
func compileSchema(name string, canonical []byte) (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(canonical))
	if err != nil {
		return nil, fmt.Errorf("input_schema: %w", err)
	}
	if m, ok := doc.(map[string]any); ok {
		if id, has := m["$id"]; has {
			return nil, fmt.Errorf("input_schema: $id (%v) is not permitted; the catalog assigns schema identity", id)
		}
		if err := checkSchemaDialect(m); err != nil {
			return nil, err
		}
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(refusingLoader{})
	resURL := "talon://actions/" + name + "/input_schema.json"
	if err := c.AddResource(resURL, doc); err != nil {
		return nil, fmt.Errorf("input_schema: %w", err)
	}
	sch, err := c.Compile(resURL)
	if err != nil {
		if strings.Contains(err.Error(), ErrExternalRef.Error()) {
			return nil, fmt.Errorf("input_schema: %w", ErrExternalRef)
		}
		return nil, fmt.Errorf("input_schema does not compile: %w", err)
	}
	return sch, nil
}

// checkSchemaDialect accepts an absent $schema or the canonical 2020-12
// URI and rejects every other dialect (draft-07, 2019-09, custom URIs).
func checkSchemaDialect(m map[string]any) error {
	raw, has := m["$schema"]
	if !has {
		return nil
	}
	s, ok := raw.(string)
	if !ok {
		return fmt.Errorf("input_schema: $schema must be the string %q", schemaDialect2020)
	}
	if s == schemaDialect2020 || s == schemaDialect2020+"#" {
		return nil
	}
	return fmt.Errorf("input_schema: $schema %q is not supported; governed action schemas are JSON Schema 2020-12 (%s)", s, schemaDialect2020)
}

func topLevelProperties(schema map[string]any) []string {
	props, _ := schema["properties"].(map[string]any)
	out := make([]string, 0, len(props))
	for k := range props {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// compileReview enforces the projection contract: every declared field is
// material and must be classified exactly once; classifications must name
// existing fields. Absent review = every field shown.
//
// review.masked is refused outright: a reviewer approves the EXACT material
// effect, and a {masked,type,length} stand-in lets them approve a value
// they never saw. A field is either shown verbatim or explicitly declared
// non-material; there is no third representation in this slice.
func compileReview(props []string, cfg *policy.ActionReviewConfig) (Review, error) {
	if cfg != nil && len(cfg.Masked) > 0 {
		return Review{}, fmt.Errorf("review.masked %v is not supported: a reviewer must see the exact value of every material field — list each in review.fields, or in review.non_material only if it truly cannot change the effect", cfg.Masked)
	}
	if cfg == nil || (len(cfg.Fields) == 0 && len(cfg.NonMaterial) == 0) {
		return Review{Shown: append([]string(nil), props...)}, nil
	}
	known := map[string]struct{}{}
	for _, p := range props {
		known[p] = struct{}{}
	}
	seen := map[string]string{}
	classify := func(kind string, list []string) ([]string, error) {
		out := make([]string, 0, len(list))
		for _, f := range list {
			f = strings.TrimSpace(f)
			if _, ok := known[f]; !ok {
				return nil, fmt.Errorf("review.%s: %q is not a declared input_schema property", kind, f)
			}
			if prev, dup := seen[f]; dup {
				return nil, fmt.Errorf("review: %q classified as both %s and %s", f, prev, kind)
			}
			seen[f] = kind
			out = append(out, f)
		}
		sort.Strings(out)
		return out, nil
	}
	shown, err := classify("fields", cfg.Fields)
	if err != nil {
		return Review{}, err
	}
	nonMaterial, err := classify("non_material", cfg.NonMaterial)
	if err != nil {
		return Review{}, err
	}
	var missing []string
	for _, p := range props {
		if _, ok := seen[p]; !ok {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		return Review{}, fmt.Errorf("review: material field(s) %v are not classified — list each in review.fields or review.non_material (omission would let a reviewer approve without seeing it)", missing)
	}
	return Review{Shown: shown, NonMaterial: nonMaterial}, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Lookup returns the definition for an exact canonical name.
func (c *Catalog) Lookup(name string) (*Definition, bool) {
	if c == nil {
		return nil, false
	}
	d, ok := c.defs[name]
	return d, ok
}

// Names lists catalog entries deterministically.
func (c *Catalog) Names() []string {
	if c == nil {
		return nil
	}
	return append([]string(nil), c.names...)
}

// Sources lists the compiled trusted sources deterministically.
func (c *Catalog) Sources() []CatalogSource {
	if c == nil {
		return nil
	}
	return append([]CatalogSource(nil), c.sources...)
}

// RefreshAt reports when the earliest source freshness hint expires. ok is
// false when the catalog has no discovered source (nothing to refresh).
func (c *Catalog) RefreshAt() (at time.Time, ok bool) {
	if c == nil {
		return time.Time{}, false
	}
	for i := range c.sources {
		if t := c.sources[i].RefreshAt; !ok || t.Before(at) {
			at, ok = t, true
		}
	}
	return at, ok
}

// IsAuthoritativeSuccess reports whether an observed status is declared as
// business success by the trusted contract.
func (d *Definition) IsAuthoritativeSuccess(status int) bool {
	for _, c := range d.Destination.SuccessStatusCodes {
		if c == status {
			return true
		}
	}
	return false
}

// ValidateArguments checks canonical arguments against the definition's
// schema. Errors are bounded descriptions, never echoing values.
func (d *Definition) ValidateArguments(canonical []byte) error {
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(canonical))
	if err != nil {
		return fmt.Errorf("arguments: %w", err)
	}
	if err := d.schema.Validate(inst); err != nil {
		// Bounded, value-free description: the validator reports keyword
		// paths and instance locations, never argument values.
		lines := strings.Split(strings.TrimSpace(err.Error()), "\n")
		if len(lines) > 8 {
			lines = append(lines[:8], "…")
		}
		return fmt.Errorf("%s", strings.Join(lines, "; "))
	}
	return nil
}

// ReviewProjection renders the reviewer-safe view of canonical arguments:
// shown fields verbatim, non-material fields omitted. Every material field
// is therefore shown exactly as it will be dispatched.
func (d *Definition) ReviewProjection(canonical []byte) map[string]json.RawMessage {
	var all map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &all); err != nil {
		return nil
	}
	out := make(map[string]json.RawMessage, len(all))
	for _, f := range d.Review.Shown {
		if v, ok := all[f]; ok {
			out[f] = v
		}
	}
	return out
}
