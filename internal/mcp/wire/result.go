package wire

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
)

// ServerInfoMeta renders the per-response identity field.
func ServerInfoMeta(server Implementation) map[string]any {
	return map[string]any{MetaServerInfo: server}
}

// Complete builds a resultType:"complete" result from fields and stamps the
// server identity.
func Complete(server Implementation, fields map[string]any) map[string]any {
	var out map[string]any
	if len(fields) > math.MaxInt-2 {
		// Defensive fallback: avoid capacity arithmetic overflow.
		out = make(map[string]any)
	} else {
		out = make(map[string]any, len(fields)+2)
	}
	for k, v := range fields {
		out[k] = v
	}
	out["resultType"] = ResultTypeComplete
	out["_meta"] = mergeMeta(out["_meta"], server)
	return out
}

// Cacheable adds the hints every cacheable result MUST carry. ttlMs < 0 is
// clamped to 0 (immediately stale).
func Cacheable(result map[string]any, ttlMs int, scope string) map[string]any {
	if ttlMs < 0 {
		ttlMs = 0
	}
	if scope != CacheScopePublic {
		scope = CacheScopePrivate
	}
	result["ttlMs"] = ttlMs
	result["cacheScope"] = scope
	return result
}

// Discover builds the server/discover result from what the route actually
// implements. caps is advertised verbatim; the caller passes only real
// capabilities.
func Discover(server Implementation, caps map[string]any, instructions string, ttlMs int) map[string]any {
	fields := map[string]any{
		"supportedVersions": SupportedVersions,
		"capabilities":      caps,
	}
	if instructions != "" {
		fields["instructions"] = instructions
	}
	return Cacheable(Complete(server, fields), ttlMs, CacheScopePublic)
}

// Upstream result validation errors.
var (
	ErrResultTypeMissing     = errors.New("upstream result has no resultType (required by MCP 2026-07-28)")
	ErrResultTypeUnsupported = errors.New("upstream resultType is not supported on this surface")
	ErrListResultInvalid     = errors.New("upstream tools/list result is not a 2026-07-28 ListToolsResult")
)

// ValidateUpstreamResult checks a result received from an upstream server
// and prepares it for the client. Truth table:
//
//	missing resultType → ErrResultTypeMissing (upstream protocol violation)
//	complete           → validated and continued
//	input_required     → preserved losslessly (MRTR continuation)
//	task               → ErrResultTypeUnsupported (Tasks extension is not advertised, #448)
//	anything else      → ErrResultTypeUnsupported
//
// The result is kept verbatim apart from the identity stamp: this server's
// serverInfo replaces the upstream's, which is kept under its own key so
// nothing is silently dropped.
func ValidateUpstreamResult(raw json.RawMessage, server Implementation) (map[string]any, error) {
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil || out == nil {
		return nil, fmt.Errorf("upstream result is not a JSON object")
	}
	rt, has := out["resultType"]
	if !has {
		return nil, ErrResultTypeMissing
	}
	switch rt {
	case ResultTypeComplete, ResultTypeInputRequired:
	default:
		return nil, fmt.Errorf("%w: %v", ErrResultTypeUnsupported, rt)
	}
	out["_meta"] = mergeMeta(out["_meta"], server)
	return out, nil
}

// ListResult is a validated upstream ListToolsResult.
type ListResult struct {
	Tools      []json.RawMessage
	NextCursor string
	TTLMs      int
	CacheScope string
	// Rest keeps any other members (additive extension fields) verbatim.
	Rest map[string]any
}

// ParseListResult accepts only the current ListToolsResult shape:
// resultType complete, a tools array, optional string nextCursor, and
// well-typed cache hints when present (absent hints read as 0 / private).
func ParseListResult(raw json.RawMessage) (*ListResult, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return nil, fmt.Errorf("%w: not an object", ErrListResultInvalid)
	}
	rt, has := obj["resultType"]
	if !has {
		return nil, ErrResultTypeMissing
	}
	var rtS string
	if json.Unmarshal(rt, &rtS) != nil || rtS != ResultTypeComplete {
		return nil, fmt.Errorf("%w: %s", ErrResultTypeUnsupported, string(rt))
	}
	toolsRaw, has := obj["tools"]
	if !has {
		return nil, fmt.Errorf("%w: tools array missing", ErrListResultInvalid)
	}
	lr := &ListResult{CacheScope: CacheScopePrivate, Rest: map[string]any{}}
	if err := json.Unmarshal(toolsRaw, &lr.Tools); err != nil {
		return nil, fmt.Errorf("%w: tools is not an array", ErrListResultInvalid)
	}
	if err := parseListHints(obj, lr); err != nil {
		return nil, err
	}
	for k, v := range obj {
		switch k {
		case "resultType", "tools", "nextCursor", "ttlMs", "cacheScope", "_meta":
			continue
		}
		var any_ any
		_ = json.Unmarshal(v, &any_)
		lr.Rest[k] = any_
	}
	return lr, nil
}

// parseListHints validates the optional pagination and cache members.
func parseListHints(obj map[string]json.RawMessage, lr *ListResult) error {
	if c, has := obj["nextCursor"]; has {
		if err := json.Unmarshal(c, &lr.NextCursor); err != nil {
			return fmt.Errorf("%w: nextCursor must be a string", ErrListResultInvalid)
		}
	}
	if t, has := obj["ttlMs"]; has {
		var f float64
		if err := json.Unmarshal(t, &f); err != nil || f != float64(int(f)) {
			return fmt.Errorf("%w: ttlMs must be an integer", ErrListResultInvalid)
		}
		if f > 0 {
			lr.TTLMs = int(f)
		}
	}
	if sc, has := obj["cacheScope"]; has {
		var s string
		if err := json.Unmarshal(sc, &s); err != nil || (s != CacheScopePublic && s != CacheScopePrivate) {
			return fmt.Errorf("%w: cacheScope must be public or private", ErrListResultInvalid)
		}
	}
	return nil
}

// StripHeaderAnnotations removes every x-mcp-header annotation from a tool
// inputSchema so a definition presented by a route that declares no
// mirrored parameters never invites a client to send Mcp-Param-* headers
// the route cannot validate from that same definition.
func StripHeaderAnnotations(schema json.RawMessage) json.RawMessage {
	var node any
	if err := json.Unmarshal(schema, &node); err != nil {
		return schema
	}
	stripAnnotations(node)
	out, err := json.Marshal(node)
	if err != nil {
		return schema
	}
	return out
}

func stripAnnotations(node any) {
	switch v := node.(type) {
	case map[string]any:
		delete(v, "x-mcp-header")
		for _, child := range v {
			stripAnnotations(child)
		}
	case []any:
		for _, child := range v {
			stripAnnotations(child)
		}
	}
}

func mergeMeta(existing any, server Implementation) map[string]any {
	meta := map[string]any{}
	if m, ok := existing.(map[string]any); ok {
		for k, v := range m {
			meta[k] = v
		}
	}
	if prev, has := meta[MetaServerInfo]; has {
		meta["io.dativo.talon/upstreamServerInfo"] = prev
	}
	meta[MetaServerInfo] = server
	return meta
}
