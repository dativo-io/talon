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

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/dativo-io/talon/internal/policy"
)

// Trusted action catalog (#427). Compiled once per agent generation from
// agent.talon.yaml; immutable afterwards. It describes governed actions and
// never holds executable code.
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
	Masked      []string
	NonMaterial []string
}

// Definition is one immutable governed action.
type Definition struct {
	Name         string
	Description  string
	Schema       json.RawMessage // canonical JSON Schema bytes
	SchemaDigest string
	Properties   []string // declared top-level argument fields (sorted)
	Review       Review
	// ProjectionDigest covers the projection contract version and the
	// three classification sets.
	ProjectionDigest string
	Destination      Destination
	// DestinationID is the stable material-destination identity bound into
	// the operation digest: method + URL, never credentials.
	DestinationID    string
	ExecutionProfile string
	BindingProfile   string
	// DefinitionDigest covers everything above (schema, projection,
	// destination incl. success contract, profiles). A change to ANY of it
	// makes prior authorization unusable.
	DefinitionDigest string

	schema *jsonschema.Schema
}

// Destination is the trusted downstream of a talon_forwarded action and
// its outcome contract.
type Destination struct {
	Type   string
	URL    string
	Method string
	// SuccessStatusCodes are the ONLY observed responses that mean the
	// business effect completed. Empty = every response is unknown.
	SuccessStatusCodes []int
}

// Catalog is the compiled, immutable action set of one agent.
type Catalog struct {
	defs   map[string]*Definition
	names  []string
	Digest string
}

// CompileCatalog validates and compiles the agent's declared actions.
// Every definition must have a closed object schema, a fully classified
// projection and an http destination; the build fails closed on any defect.
func CompileCatalog(cfg *policy.ActionsConfig) (*Catalog, error) {
	c := &Catalog{defs: map[string]*Definition{}}
	if cfg == nil {
		c.Digest = Digest([]byte("{}"))
		return c, nil
	}
	names := make([]string, 0, len(cfg.Definitions))
	for n := range cfg.Definitions {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		def, err := compileDefinition(name, cfg.Definitions[name])
		if err != nil {
			return nil, fmt.Errorf("actions.definitions.%s: %w", name, err)
		}
		c.defs[name] = def
		c.names = append(c.names, name)
	}
	var b strings.Builder
	for _, n := range c.names {
		b.WriteString(n)
		b.WriteByte('=')
		b.WriteString(c.defs[n].DefinitionDigest)
		b.WriteByte('\n')
	}
	c.Digest = Digest([]byte(b.String()))
	return c, nil
}

func compileDefinition(name string, cfg policy.ActionDefinitionConfig) (*Definition, error) {
	if !actionNameRe.MatchString(name) {
		return nil, fmt.Errorf("invalid action name (want ^[a-z][a-z0-9_]{0,63}$)")
	}
	if len(cfg.InputSchema) == 0 {
		return nil, fmt.Errorf("input_schema is required")
	}
	if t, _ := cfg.InputSchema["type"].(string); t != "object" {
		return nil, fmt.Errorf("input_schema.type must be \"object\"")
	}
	if ap, ok := cfg.InputSchema["additionalProperties"].(bool); !ok || ap {
		return nil, fmt.Errorf("input_schema.additionalProperties must be false: every argument field of a governed action is a declared, classified property")
	}
	rawSchema, err := json.Marshal(cfg.InputSchema)
	if err != nil {
		return nil, fmt.Errorf("input_schema: %w", err)
	}
	canonSchema, err := Canonicalize(rawSchema)
	if err != nil {
		return nil, fmt.Errorf("input_schema: %w", err)
	}
	compiled, err := compileSchema(name, canonSchema)
	if err != nil {
		return nil, err
	}
	props := topLevelProperties(cfg.InputSchema)
	review, err := compileReview(props, cfg.Review)
	if err != nil {
		return nil, err
	}
	if strings.ToLower(cfg.Destination.Type) != "http" {
		return nil, fmt.Errorf("destination.type must be http")
	}
	u, err := url.Parse(cfg.Destination.URL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("destination.url must be an absolute http(s) URL")
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return nil, fmt.Errorf("destination.url: plaintext http is allowed only for loopback destinations")
	}
	if u.User != nil {
		return nil, fmt.Errorf("destination.url must not embed credentials")
	}
	method := strings.ToUpper(strings.TrimSpace(cfg.Destination.Method))
	if method == "" {
		method = "POST"
	}
	var success []int
	if cfg.Destination.Success != nil {
		if len(cfg.Destination.Success.StatusCodes) == 0 {
			return nil, fmt.Errorf("destination.success.status_codes must not be empty when declared")
		}
		for _, c := range cfg.Destination.Success.StatusCodes {
			if c < 200 || c > 299 {
				return nil, fmt.Errorf("destination.success.status_codes: %d is not a 2xx status", c)
			}
			success = append(success, c)
		}
		sort.Ints(success)
	}
	def := &Definition{
		Name:             name,
		Description:      cfg.Description,
		Schema:           canonSchema,
		SchemaDigest:     Digest(canonSchema),
		Properties:       props,
		Review:           review,
		Destination:      Destination{Type: "http", URL: u.String(), Method: method, SuccessStatusCodes: success},
		DestinationID:    "http:" + method + " " + u.String(),
		ExecutionProfile: ExecutionProfileTalonForwarded,
		BindingProfile:   BindingProfileWholePayloadV1,
		schema:           compiled,
	}
	def.ProjectionDigest = Digest([]byte(strings.Join([]string{
		ProjectionVersionV1,
		"shown=" + strings.Join(review.Shown, ","), "masked=" + strings.Join(review.Masked, ","), "non_material=" + strings.Join(review.NonMaterial, ","),
	}, "\n")))
	successStr := make([]string, len(success))
	for i, c := range success {
		successStr[i] = fmt.Sprint(c)
	}
	identity := strings.Join([]string{
		"name=" + name, "schema=" + def.SchemaDigest, "projection=" + def.ProjectionDigest,
		"destination=" + def.DestinationID, "success=" + strings.Join(successStr, ","),
		"profile=" + def.ExecutionProfile, "binding=" + def.BindingProfile,
	}, "\n")
	def.DefinitionDigest = Digest([]byte(identity))
	return def, nil
}

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
func compileReview(props []string, cfg *policy.ActionReviewConfig) (Review, error) {
	if cfg == nil || (len(cfg.Fields) == 0 && len(cfg.Masked) == 0 && len(cfg.NonMaterial) == 0) {
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
	masked, err := classify("masked", cfg.Masked)
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
		return Review{}, fmt.Errorf("review: material field(s) %v are not classified — list each in review.fields, review.masked or review.non_material (omission would let a reviewer approve without seeing it)", missing)
	}
	return Review{Shown: shown, Masked: masked, NonMaterial: nonMaterial}, nil
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

// MaskedValue is the safe representation of a masked material field.
type MaskedValue struct {
	Masked bool   `json:"masked"`
	Type   string `json:"type"`
	Length int    `json:"length"`
}

// ReviewProjection renders the reviewer-safe view of canonical arguments:
// shown fields verbatim, masked fields as {masked,type,length}, non-material
// fields omitted. Every material field is therefore represented.
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
	for _, f := range d.Review.Masked {
		if v, ok := all[f]; ok {
			mv := MaskedValue{Masked: true, Type: jsonType(v), Length: len(v)}
			if mv.Type == "string" {
				var sv string
				_ = json.Unmarshal(v, &sv)
				mv.Length = len(sv)
			}
			b, _ := json.Marshal(mv)
			out[f] = b
		}
	}
	return out
}

func jsonType(v json.RawMessage) string {
	if len(v) == 0 {
		return "null"
	}
	switch v[0] {
	case '"':
		return "string"
	case '{':
		return "object"
	case '[':
		return "array"
	case 't', 'f':
		return "boolean"
	case 'n':
		return "null"
	}
	return "number"
}
