package action

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/xeipuuv/gojsonschema"

	"github.com/dativo-io/talon/internal/policy"
)

// Trusted action catalog (#427). Compiled once per agent generation from
// agent.talon.yaml; immutable afterwards. It describes governed actions and
// never holds executable code.

const (
	// ExecutionProfileTalonForwarded: Talon claims the attempt and dispatches
	// through its trusted dispatcher; the result is observed by Talon.
	ExecutionProfileTalonForwarded = "talon_forwarded"
	// BindingProfileWholePayloadV1 binds the complete normalized argument
	// payload with no exclusions.
	BindingProfileWholePayloadV1 = "talon/whole-payload/v1"
)

var actionNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// Definition is one immutable governed action.
type Definition struct {
	Name         string
	Description  string
	Schema       json.RawMessage // canonical JSON Schema bytes
	SchemaDigest string
	ReviewFields []string
	Destination  Destination
	// DestinationID is the stable material-destination identity bound into
	// the operation digest: method + URL, never credentials.
	DestinationID    string
	ExecutionProfile string
	BindingProfile   string
	// DefinitionDigest covers everything above.
	DefinitionDigest string

	schema *gojsonschema.Schema
}

// Destination is the trusted downstream of a talon_forwarded action.
type Destination struct {
	Type   string
	URL    string
	Method string
}

// Catalog is the compiled, immutable action set of one agent.
type Catalog struct {
	defs   map[string]*Definition
	names  []string
	Digest string
}

// CompileCatalog validates and compiles the agent's declared actions.
// Every definition must have a usable object schema and an http
// destination; the build fails closed on any defect.
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
	rawSchema, err := json.Marshal(cfg.InputSchema)
	if err != nil {
		return nil, fmt.Errorf("input_schema: %w", err)
	}
	canonSchema, err := Canonicalize(rawSchema)
	if err != nil {
		return nil, fmt.Errorf("input_schema: %w", err)
	}
	compiled, err := gojsonschema.NewSchema(gojsonschema.NewBytesLoader(canonSchema))
	if err != nil {
		return nil, fmt.Errorf("input_schema does not compile: %w", err)
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
	def := &Definition{
		Name:             name,
		Description:      cfg.Description,
		Schema:           canonSchema,
		SchemaDigest:     Digest(canonSchema),
		Destination:      Destination{Type: "http", URL: u.String(), Method: method},
		DestinationID:    "http:" + method + " " + u.String(),
		ExecutionProfile: ExecutionProfileTalonForwarded,
		BindingProfile:   BindingProfileWholePayloadV1,
		schema:           compiled,
	}
	if cfg.Review != nil {
		def.ReviewFields = append([]string(nil), cfg.Review.Fields...)
	}
	sort.Strings(def.ReviewFields)
	identity := strings.Join([]string{name, def.SchemaDigest, def.DestinationID, def.ExecutionProfile, def.BindingProfile, strings.Join(def.ReviewFields, ",")}, "\x00")
	def.DefinitionDigest = Digest([]byte(identity))
	return def, nil
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

// ValidateArguments checks canonical arguments against the definition's
// schema. Errors are bounded descriptions, never echoing values.
func (d *Definition) ValidateArguments(canonical []byte) error {
	res, err := d.schema.Validate(gojsonschema.NewBytesLoader(canonical))
	if err != nil {
		return fmt.Errorf("schema validation failed: %w", err)
	}
	if res.Valid() {
		return nil
	}
	msgs := make([]string, 0, len(res.Errors()))
	for i, e := range res.Errors() {
		if i >= 8 {
			msgs = append(msgs, "…")
			break
		}
		msgs = append(msgs, e.Field()+": "+e.Description())
	}
	return fmt.Errorf("%s", strings.Join(msgs, "; "))
}

// ReviewProjection returns the reviewer-safe view of canonical arguments:
// only declared review fields (all material fields remain bound by the
// digest regardless). When no review fields are declared every top-level
// field is shown, since nothing in v1 is classified as protected.
func (d *Definition) ReviewProjection(canonical []byte) map[string]json.RawMessage {
	var all map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &all); err != nil {
		return nil
	}
	if len(d.ReviewFields) == 0 {
		return all
	}
	out := make(map[string]json.RawMessage, len(d.ReviewFields))
	for _, f := range d.ReviewFields {
		if v, ok := all[f]; ok {
			out[f] = v
		}
	}
	return out
}
