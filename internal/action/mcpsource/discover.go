// Package mcpsource discovers trusted MCP action sources (#427): it is the
// ONE implementation that turns a Talon-configured source into a
// credential-free action.SourceSnapshot the catalog compiler consumes.
//
//	configured source
//	  → server/discover        (must speak 2026-07-28 and advertise tools)
//	  → every tools/list page  (shared wire fetch: strict, bounded, loop-safe)
//	  → per-tool validation    (name, inputSchema, x-mcp-header via the #447
//	                            declaration parser; protocol annotations
//	                            stripped from the business schema)
//	  → immutable snapshot     (sorted, duplicate-free, generation digest)
//
// The upstream decides nothing with authority: its name, description,
// schema, mirrored-parameter declarations and cache hints are recorded as
// facts; serverInfo is informational. Redirects are never followed, the
// credential is resolved from the vault per pass and appears in no output,
// and every pass is bounded by a deadline and size limits.
package mcpsource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/mcp/wire"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/secrets"
)

// ClientName is the identity Talon presents to a source.
const ClientName = "talon-action-catalog"

// SecretGetter resolves a vault-backed credential under the agent's ACL
// identity (*secrets.SecretStore satisfies it).
type SecretGetter interface {
	Get(ctx context.Context, name, tenantID, agentID string) (*secrets.Secret, error)
}

// Limits bounds one discovery pass beyond the wire's own body cap.
type Limits struct {
	MaxTools            int // valid + excluded definitions one source may present
	MaxToolBytes        int // raw bytes of one tool definition
	MaxExtensions       int // advertised extensions/experimental entries kept
	MaxExtensionBytes   int // canonical bytes of one extension settings object
	MaxInstructionBytes int // instructions kept (longer is truncated at a rune boundary)
}

// DefaultLimits are the production bounds.
func DefaultLimits() Limits {
	return Limits{MaxTools: 1024, MaxToolBytes: 64 << 10, MaxExtensions: 32, MaxExtensionBytes: 4 << 10, MaxInstructionBytes: 8 << 10}
}

// Discoverer discovers sources. It is safe for concurrent use.
type Discoverer struct {
	secrets SecretGetter
	client  *http.Client
	limits  Limits
	// Version is reported as Talon's clientInfo version.
	Version string
	now     func() time.Time
}

// New returns a discoverer whose HTTP client never follows a redirect.
// secretStore may be nil when no source declares auth; with an auth block
// and no store, discovery of that source fails closed.
func New(secretStore SecretGetter) *Discoverer {
	return &Discoverer{
		secrets: secretStore,
		client:  &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		limits:  DefaultLimits(),
		Version: "dev",
		now:     func() time.Time { return time.Now().UTC() },
	}
}

// WithLimits overrides the bounds (tests, operator tuning).
func (d *Discoverer) WithLimits(l Limits) *Discoverer {
	d.limits = l
	return d
}

// DiscoverSources discovers every configured source of one agent,
// all-or-nothing: one failing source fails the pass with every cause
// listed, so a candidate catalog is never compiled from a partial set.
func (d *Discoverer) DiscoverSources(ctx context.Context, tenantID, agentID string, cfg *policy.ActionsConfig) (map[string]*action.SourceSnapshot, error) {
	out := map[string]*action.SourceSnapshot{}
	if cfg == nil {
		return out, nil
	}
	ids := make([]string, 0, len(cfg.Sources))
	for id := range cfg.Sources {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var causes []string
	for _, id := range ids {
		snap, err := d.Discover(ctx, tenantID, agentID, id, cfg.Sources[id])
		if err != nil {
			causes = append(causes, fmt.Sprintf("actions.sources.%s: %v", id, err))
			continue
		}
		out[id] = snap
	}
	if len(causes) > 0 {
		return nil, errors.New(strings.Join(causes, "; "))
	}
	return out, nil
}

// Discover runs one bounded discovery pass against one source.
func (d *Discoverer) Discover(ctx context.Context, tenantID, agentID, id string, cfg policy.ActionSourceConfig) (*action.SourceSnapshot, error) {
	if err := action.ValidateSourceConfig(id, cfg); err != nil {
		return nil, err
	}
	timeout, _ := action.SourceTimeout(cfg)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	do, err := d.doer(ctx, tenantID, agentID, cfg)
	if err != nil {
		return nil, err
	}
	meta := wire.OutboundMeta(wire.Meta{ClientCapabilities: json.RawMessage("{}")}, wire.Implementation{Name: ClientName, Version: d.Version})

	// server/discover: the source must speak this protocol version and
	// advertise tools before any list is trusted.
	resp, err := wire.Exchange(ctx, do, cfg.URL, json.RawMessage("1"), wire.MethodDiscover, wire.EncodeListParams(meta, ""), "", nil)
	if err != nil {
		return nil, fmt.Errorf("server/discover: %w", err)
	}
	disc, err := wire.ParseDiscoverResult(resp.Result)
	if err != nil {
		return nil, fmt.Errorf("server/discover: %w", err)
	}
	if !contains(disc.SupportedVersions, wire.ProtocolVersion) {
		return nil, fmt.Errorf("server/discover: source supports %v, not MCP %s", disc.SupportedVersions, wire.ProtocolVersion)
	}
	capabilities, err := d.captureCapabilities(disc)
	if err != nil {
		return nil, fmt.Errorf("server/discover: %w", err)
	}
	if capabilities.Tools == nil {
		return nil, fmt.Errorf("server/discover: source does not advertise the tools capability")
	}

	list, err := wire.FetchToolList(ctx, do, cfg.URL, json.RawMessage("2"), meta)
	if err != nil {
		return nil, fmt.Errorf("tools/list: %w", err)
	}
	if len(list.Tools) > d.limits.MaxTools {
		return nil, fmt.Errorf("tools/list: %d tool definitions exceed the limit of %d", len(list.Tools), d.limits.MaxTools)
	}
	// One logical capture: the snapshot is as fresh as its least fresh
	// part (server/discover and the whole tools/list), and as restricted
	// as its most restricted part.
	ttl, scope := wire.MergeCacheHints(disc.TTLMs, disc.CacheScope, list.TTLMs, list.CacheScope)
	snap := action.SourceSnapshot{
		ID: id, Type: action.SourceTypeMCP, URL: cfg.URL, ConfigDigest: action.SourceConfigDigest(id, cfg),
		ServerInfo:        action.SourceServerInfo{Name: disc.ServerInfo.Name, Version: disc.ServerInfo.Version},
		SupportedVersions: append([]string(nil), disc.SupportedVersions...),
		Capabilities:      capabilities,
		TTLMs:             ttl, CacheScope: scope, DiscoveredAt: d.now(),
	}
	for i, raw := range list.Tools {
		tool, excluded, err := d.normalizeTool(raw)
		if err != nil {
			return nil, fmt.Errorf("tools/list: tool at index %d: %w", i, err)
		}
		if excluded != nil {
			snap.Excluded = append(snap.Excluded, *excluded)
			continue
		}
		snap.Tools = append(snap.Tools, *tool)
	}
	return action.NewSourceSnapshot(snap)
}

// doer wraps the client with the vault-backed credential of this source,
// resolved once per pass under the agent's ACL identity.
func (d *Discoverer) doer(ctx context.Context, tenantID, agentID string, cfg policy.ActionSourceConfig) (wire.Doer, error) {
	header, value := "", ""
	if auth := cfg.Auth; auth != nil {
		if d.secrets == nil {
			return nil, fmt.Errorf("auth.secret_name %q: no secrets store is wired", auth.SecretName)
		}
		sec, err := d.secrets.Get(ctx, auth.SecretName, tenantID, agentID)
		if err != nil {
			return nil, fmt.Errorf("auth.secret_name %q: secret retrieval failed: %w", auth.SecretName, err)
		}
		header = auth.Header
		if header == "" {
			header = "Authorization"
		}
		scheme := "Bearer"
		if auth.Scheme != nil {
			scheme = *auth.Scheme
		}
		value = string(sec.Value)
		if scheme != "" {
			value = scheme + " " + value
		}
	}
	return wire.DoerFunc(func(r *http.Request) (*http.Response, error) {
		if header != "" {
			r.Header.Set(header, value)
		}
		//nolint:gosec // G704: the endpoint is trusted operator configuration validated by action.ValidateSourceConfig
		return d.client.Do(r)
	}), nil
}

// captureCapabilities converts the validated server/discover capabilities
// object into the bounded neutral record under the 2026-07-28 shapes:
//
//	tools / prompts     object, optional boolean listChanged
//	resources           object, optional boolean listChanged / subscribe
//	logging / completions  JSON object
//	experimental        object of JSON objects (names kept, settings not)
//	extensions          object of JSON objects keyed by a prefixed
//	                    extension id ("{vendor-prefix}/{extension-name}")
//
// absent → absent; present and valid → captured; present and malformed →
// the source fails (nothing is repaired). A valid extension Talon does not
// implement is captured as a fact, never adopted.
func (d *Discoverer) captureCapabilities(disc *wire.DiscoverResult) (action.SourceCapabilities, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(disc.Capabilities, &members); err != nil || members == nil {
		return action.SourceCapabilities{}, fmt.Errorf("capabilities is not an object")
	}
	out := action.SourceCapabilities{}
	var err error
	if out.Tools, err = listCapability(members, "tools"); err != nil {
		return action.SourceCapabilities{}, err
	}
	if out.Prompts, err = listCapability(members, "prompts"); err != nil {
		return action.SourceCapabilities{}, err
	}
	if raw, has := members["resources"]; has {
		var rc struct {
			ListChanged *bool `json:"listChanged"`
			Subscribe   *bool `json:"subscribe"`
		}
		if !isObject(raw) || json.Unmarshal(raw, &rc) != nil {
			return action.SourceCapabilities{}, fmt.Errorf("capabilities.resources must be an object with boolean listChanged/subscribe")
		}
		out.Resources = &action.ResourceCapability{ListChanged: rc.ListChanged != nil && *rc.ListChanged, Subscribe: rc.Subscribe != nil && *rc.Subscribe}
	}
	if out.Logging, err = objectFlag(members, "logging"); err != nil {
		return action.SourceCapabilities{}, err
	}
	if out.Completions, err = objectFlag(members, "completions"); err != nil {
		return action.SourceCapabilities{}, err
	}
	if out.Experimental, err = d.experimentalNames(members); err != nil {
		return action.SourceCapabilities{}, err
	}
	if out.Extensions, err = d.extensions(members); err != nil {
		return action.SourceCapabilities{}, err
	}
	out.Instructions = truncateRunes(disc.Instructions, d.limits.MaxInstructionBytes)
	return out, nil
}

// objectFlag reports a member that must be a JSON object when present.
func objectFlag(members map[string]json.RawMessage, name string) (bool, error) {
	raw, has := members[name]
	if !has {
		return false, nil
	}
	if !isObject(raw) {
		return false, fmt.Errorf("capabilities.%s must be a JSON object", name)
	}
	return true, nil
}

// listCapability parses a {listChanged?: boolean} member.
func listCapability(members map[string]json.RawMessage, name string) (*action.ListCapability, error) {
	raw, has := members[name]
	if !has {
		return nil, nil
	}
	var lc struct {
		ListChanged *bool `json:"listChanged"`
	}
	if !isObject(raw) || json.Unmarshal(raw, &lc) != nil {
		return nil, fmt.Errorf("capabilities.%s must be an object with an optional boolean listChanged", name)
	}
	return &action.ListCapability{ListChanged: lc.ListChanged != nil && *lc.ListChanged}, nil
}

// experimentalNames keeps the names of advertised experimental
// capabilities: each value must be a JSON object; names are bounded
// printable strings (experimental keys have no prefixed-id grammar).
func (d *Discoverer) experimentalNames(members map[string]json.RawMessage) ([]string, error) {
	raw, has := members["experimental"]
	if !has {
		return nil, nil
	}
	var exp map[string]json.RawMessage
	if !isObject(raw) || json.Unmarshal(raw, &exp) != nil {
		return nil, fmt.Errorf("capabilities.experimental must be an object")
	}
	if len(exp) > d.limits.MaxExtensions {
		return nil, fmt.Errorf("capabilities.experimental advertises more than %d entries", d.limits.MaxExtensions)
	}
	names := make([]string, 0, len(exp))
	for name, settings := range exp {
		if !validExperimentalName(name) {
			return nil, fmt.Errorf("capabilities.experimental name %q is not a bounded printable identifier", name)
		}
		if !isObject(settings) {
			return nil, fmt.Errorf("capabilities.experimental[%q] must be a JSON object", name)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

// extensions keeps the advertised extensions with canonical, size-bounded
// settings; ids must follow the prefixed MCP extension-id grammar.
func (d *Discoverer) extensions(members map[string]json.RawMessage) ([]action.SourceExtension, error) {
	raw, has := members["extensions"]
	if !has {
		return nil, nil
	}
	var exts map[string]json.RawMessage
	if !isObject(raw) || json.Unmarshal(raw, &exts) != nil {
		return nil, fmt.Errorf("capabilities.extensions must be an object")
	}
	if len(exts) > d.limits.MaxExtensions {
		return nil, fmt.Errorf("capabilities.extensions advertises more than %d entries", d.limits.MaxExtensions)
	}
	out := make([]action.SourceExtension, 0, len(exts))
	for id, settings := range exts {
		if !wire.ValidExtensionID(id) {
			return nil, fmt.Errorf("capabilities.extensions id %q is not a prefixed extension identifier ({vendor-prefix}/{extension-name})", id)
		}
		if !isObject(settings) {
			return nil, fmt.Errorf("capabilities.extensions[%q] settings must be a JSON object", id)
		}
		canonical, err := action.Canonicalize(settings)
		if err != nil || len(canonical) > d.limits.MaxExtensionBytes {
			return nil, fmt.Errorf("capabilities.extensions[%q] settings are not a bounded canonical object (limit %d bytes)", id, d.limits.MaxExtensionBytes)
		}
		out = append(out, action.SourceExtension{ID: id, Settings: canonical})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func validExperimentalName(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if r <= 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func isObject(raw json.RawMessage) bool {
	var m map[string]json.RawMessage
	return len(raw) > 0 && json.Unmarshal(raw, &m) == nil && m != nil
}

func truncateRunes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && cut < len(s) && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut]
}

// normalizeTool validates one upstream definition. A definition without a
// usable name is a malformed source (error); one with an invalid schema or
// x-mcp-header declaration is excluded with its reason (a mapped exclusion
// becomes a compile error, an unmapped one stays inspectable).
func (d *Discoverer) normalizeTool(raw json.RawMessage) (*action.DiscoveredTool, *action.ExcludedTool, error) {
	var t struct {
		Name         string          `json:"name"`
		Title        string          `json:"title"`
		Description  string          `json:"description"`
		InputSchema  json.RawMessage `json:"inputSchema"`
		OutputSchema json.RawMessage `json:"outputSchema"`
		Annotations  *struct {
			Title           string `json:"title"`
			ReadOnlyHint    bool   `json:"readOnlyHint"`
			DestructiveHint *bool  `json:"destructiveHint"`
			IdempotentHint  bool   `json:"idempotentHint"`
			OpenWorldHint   *bool  `json:"openWorldHint"`
		} `json:"annotations"`
	}
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, nil, fmt.Errorf("not a tool object: %w", err)
	}
	if !action.ValidUpstreamName(t.Name) {
		return nil, nil, fmt.Errorf("invalid tool name %q", t.Name)
	}
	exclude := func(code, reason string) (*action.DiscoveredTool, *action.ExcludedTool, error) {
		return nil, &action.ExcludedTool{Name: t.Name, Code: code, Reason: reason}, nil
	}
	if len(raw) > d.limits.MaxToolBytes {
		return exclude(action.ExcludeDefinitionOversized, fmt.Sprintf("definition is %d bytes, over the %d-byte limit", len(raw), d.limits.MaxToolBytes))
	}
	if len(t.InputSchema) == 0 || string(t.InputSchema) == "null" {
		return exclude(action.ExcludeSchemaMissing, "inputSchema is missing")
	}
	decl, err := wire.HeaderParamsFromSchema(t.InputSchema)
	if err != nil {
		return exclude(action.ExcludeHeaderAnnotationInvalid, "invalid x-mcp-header declaration: "+err.Error())
	}
	canonical, err := action.Canonicalize(wire.StripHeaderAnnotations(t.InputSchema))
	if err != nil {
		return exclude(action.ExcludeSchemaUnbounded, "inputSchema is not a bounded canonical JSON document: "+err.Error())
	}
	tool := &action.DiscoveredTool{Name: t.Name, Title: t.Title, Description: t.Description, Schema: canonical}
	if len(t.OutputSchema) > 0 && string(t.OutputSchema) != "null" {
		if !isObject(t.OutputSchema) {
			return exclude(action.ExcludeOutputSchemaInvalid, "outputSchema is not a JSON object")
		}
		out, err := action.Canonicalize(t.OutputSchema)
		if err != nil {
			return exclude(action.ExcludeOutputSchemaInvalid, "outputSchema is not a bounded canonical JSON document: "+err.Error())
		}
		tool.OutputSchema = out
	}
	if a := t.Annotations; a != nil {
		tool.Hints = &action.ToolHints{Title: a.Title, ReadOnly: a.ReadOnlyHint, Destructive: a.DestructiveHint, Idempotent: a.IdempotentHint, OpenWorld: a.OpenWorldHint}
	}
	for _, p := range decl.Decls() {
		tool.MirroredParams = append(tool.MirroredParams, action.MirroredParam{Header: p.Header, Path: append([]string(nil), p.Path...), Type: p.Type})
	}
	return tool, nil, nil
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
