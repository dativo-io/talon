package action

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/dativo-io/talon/internal/policy"
)

// Trusted sources (#427). A governed definition carries the identity of the
// trusted origin it was compiled from, independently of the adapter that
// will one day execute it:
//
//	declared  the explicit agent.talon.yaml definition (input_schema +
//	          http destination)
//	mcp       a Talon-configured MCP source whose validated tools/list
//	          supplied the schema and protocol metadata, overlaid with
//	          Talon's own review classification
//
// The upstream server is authoritative for bounded source metadata only
// (tool name, description, inputSchema, x-mcp-header declarations, cache
// hints, informational serverInfo). It can never define Talon policy,
// materiality, approval, execution posture, tenant, agent, source identity,
// credentials or destination authority: those come from trusted
// configuration, and the compiler ignores anything else the upstream says.

// Source types.
const (
	SourceTypeDeclared = "declared"
	SourceTypeMCP      = "mcp"
)

// Destination types.
const (
	DestinationTypeHTTP = "http"
	DestinationTypeMCP  = "mcp"
)

// Source identifies the trusted origin of one definition.
type Source struct {
	Type string
	// ID is the Talon-configured source id ("" for declared definitions).
	ID string
	// URL is the trusted endpoint of an mcp source.
	URL string
	// ConfigDigest covers the trusted source configuration that is material
	// to where an authorized effect goes: type, id, endpoint and the
	// credential REFERENCE (header, scheme, secret name — never the secret
	// bytes, so a rotation under the same connector identity changes
	// nothing).
	ConfigDigest string
	// Generation is the digest of the discovered source metadata the
	// definition was compiled from ("" for declared). It names the facts,
	// not the authority: a description-only change updates it without
	// changing the definition identity.
	Generation string
	// ServerInfo is the upstream's self-declared identity. Informational
	// only; it is never a trusted identity and enters no digest.
	ServerInfo SourceServerInfo
}

// SourceServerInfo is the informational identity an MCP source reports.
type SourceServerInfo struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// MirroredParam is one validated x-mcp-header declaration of a discovered
// tool: the argument at Path is mirrored into the Mcp-Param-{Header}
// request header. Protocol metadata carried so the MCP adapter (#431) can
// generate outbound headers from the authorized body; it is never
// materiality, approval policy, destination authority or identity.
type MirroredParam struct {
	Header string   `json:"header"`
	Path   []string `json:"path"`
	Type   string   `json:"type,omitempty"`
}

// DiscoveredTool is one validated tool definition of a source, normalized
// to the catalog's neutral representation.
type DiscoveredTool struct {
	Name        string
	Description string
	// Schema is the canonical input schema with protocol annotations
	// (x-mcp-header) stripped: the business argument contract.
	Schema json.RawMessage
	// MirroredParams are the validated x-mcp-header declarations.
	MirroredParams []MirroredParam
}

// ExcludedTool is a source tool that did not validate and therefore cannot
// be mapped (a mapped exclusion is a compile error; an unmapped one is
// inspectable only).
type ExcludedTool struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// SourceSnapshot is the validated, credential-free outcome of discovering
// one trusted source at one instant. The compiler consumes snapshots; it
// performs no I/O.
type SourceSnapshot struct {
	ID                string
	Type              string
	URL               string
	ConfigDigest      string
	ServerInfo        SourceServerInfo
	SupportedVersions []string
	Tools             []DiscoveredTool // sorted by name, unique
	Excluded          []ExcludedTool   // sorted by name
	// TTLMs / CacheScope are the upstream's tools/list freshness hints.
	TTLMs        json.Number
	CacheScope   string
	DiscoveredAt time.Time
	// Generation digests every tool's name, business schema, mirrored
	// params and description, in sorted order.
	Generation string
}

var sourceIDRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

// Discovery bounds.
const (
	DefaultSourceTimeout = 15 * time.Second
	MaxSourceTimeout     = 2 * time.Minute
)

// SourceConfigDigest is the trusted connector identity of a source config
// (see Source.ConfigDigest).
func SourceConfigDigest(id string, cfg policy.ActionSourceConfig) string {
	authRef := ""
	if cfg.Auth != nil {
		scheme := "Bearer"
		if cfg.Auth.Scheme != nil {
			scheme = *cfg.Auth.Scheme
		}
		header := cfg.Auth.Header
		if header == "" {
			header = "Authorization"
		}
		authRef = header + "\x00" + scheme + "\x00" + cfg.Auth.SecretName
	}
	return Digest([]byte(strings.Join([]string{"type=" + strings.ToLower(cfg.Type), "id=" + id, "url=" + cfg.URL, "auth_ref=" + authRef}, "\n")))
}

// ValidateSourceConfig applies the static source rules shared by the
// compiler and the discoverer: id grammar, mcp type, an absolute https URL
// (plaintext http for loopback only, no embedded credentials), a complete
// auth block when present, and a bounded timeout.
func ValidateSourceConfig(id string, cfg policy.ActionSourceConfig) error {
	if !sourceIDRe.MatchString(id) {
		return fmt.Errorf("invalid source id (want ^[a-z][a-z0-9_-]{0,63}$)")
	}
	if !strings.EqualFold(cfg.Type, SourceTypeMCP) {
		return fmt.Errorf("type must be mcp")
	}
	u, err := url.Parse(strings.TrimSpace(cfg.URL))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("url must be an absolute http(s) URL")
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return fmt.Errorf("url: plaintext http is allowed only for loopback sources")
	}
	if u.User != nil {
		return fmt.Errorf("url must not embed credentials; use auth.secret_name")
	}
	if cfg.Auth != nil && strings.TrimSpace(cfg.Auth.SecretName) == "" {
		return fmt.Errorf("auth.secret_name is required when the auth block is present")
	}
	if _, err := SourceTimeout(cfg); err != nil {
		return err
	}
	return nil
}

// SourceTimeout resolves the discovery deadline of a source.
func SourceTimeout(cfg policy.ActionSourceConfig) (time.Duration, error) {
	if strings.TrimSpace(cfg.Timeout) == "" {
		return DefaultSourceTimeout, nil
	}
	d, err := time.ParseDuration(cfg.Timeout)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("timeout: invalid duration %q", cfg.Timeout)
	}
	if d > MaxSourceTimeout {
		return 0, fmt.Errorf("timeout: %s exceeds the maximum %s", cfg.Timeout, MaxSourceTimeout)
	}
	return d, nil
}

// NewSourceSnapshot finalizes a discovered source: tools are sorted,
// duplicate names are rejected (an ambiguous source is a malformed source),
// and the generation digest is computed over the business-relevant facts.
func NewSourceSnapshot(snap SourceSnapshot) (*SourceSnapshot, error) {
	sort.Slice(snap.Tools, func(i, j int) bool { return snap.Tools[i].Name < snap.Tools[j].Name })
	sort.Slice(snap.Excluded, func(i, j int) bool { return snap.Excluded[i].Name < snap.Excluded[j].Name })
	seen := map[string]bool{}
	for _, t := range snap.Tools {
		if seen[t.Name] {
			return nil, fmt.Errorf("source %q: duplicate upstream tool name %q", snap.ID, t.Name)
		}
		seen[t.Name] = true
	}
	for _, e := range snap.Excluded {
		if seen[e.Name] {
			return nil, fmt.Errorf("source %q: upstream tool name %q is both valid and excluded", snap.ID, e.Name)
		}
	}
	var b strings.Builder
	for _, t := range snap.Tools {
		fmt.Fprintf(&b, "tool=%s\nschema=%s\nmirrors=%s\ndescription=%s\n", t.Name, Digest(t.Schema), mirroredParamsKey(t.MirroredParams), Digest([]byte(t.Description)))
	}
	snap.Generation = Digest([]byte(b.String()))
	return &snap, nil
}

// mirroredParamsKey renders mirrored declarations deterministically.
func mirroredParamsKey(params []MirroredParam) string {
	parts := make([]string, 0, len(params))
	for _, p := range params {
		parts = append(parts, strings.ToLower(p.Header)+"<-"+strings.Join(p.Path, ".")+":"+p.Type)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// RefreshAt is when the snapshot's freshness hint expires (ttlMs 0 or an
// unusable hint = immediately).
func (s *SourceSnapshot) RefreshAt() time.Time {
	if s == nil {
		return time.Time{}
	}
	ms, err := s.TTLMs.Float64()
	if err != nil || ms <= 0 {
		return s.DiscoveredAt
	}
	return s.DiscoveredAt.Add(time.Duration(ms * float64(time.Millisecond)))
}
