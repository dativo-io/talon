package wire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
)

// ServerInfoMeta renders the per-response identity field.
func ServerInfoMeta(server Implementation) map[string]any {
	return map[string]any{MetaServerInfo: server}
}

// Complete builds a resultType:"complete" result from fields and stamps the
// server identity.
func Complete(server Implementation, fields map[string]any) map[string]any {
	// Capacity is only a hint; no arithmetic on an input-derived length
	// (CodeQL go/allocation-size-overflow).
	out := make(map[string]any, len(fields))
	for k, v := range fields {
		out[k] = v
	}
	out["resultType"] = ResultTypeComplete
	out["_meta"] = mergeMeta(out["_meta"], server)
	return out
}

// Cacheable adds the hints every cacheable result MUST carry. ttlMs is the
// exact JSON number to emit (a non-negative value; callers pass either
// Talon's own hint or a validated upstream value unchanged).
func Cacheable(result map[string]any, ttlMs json.Number, scope string) map[string]any {
	if !validTTL(ttlMs) {
		ttlMs = "0"
	}
	if scope != CacheScopePublic {
		scope = CacheScopePrivate
	}
	result["ttlMs"] = ttlMs
	result["cacheScope"] = scope
	return result
}

// TTL renders an integer millisecond hint as the JSON number Cacheable emits.
func TTL(ms int) json.Number {
	if ms < 0 {
		ms = 0
	}
	return json.Number(strconv.Itoa(ms))
}

// validTTL reports whether n is a non-negative JSON number.
func validTTL(n json.Number) bool {
	r, ok := new(big.Rat).SetString(string(n))
	return ok && r.Sign() >= 0
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
	return Cacheable(Complete(server, fields), TTL(ttlMs), CacheScopePublic)
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
	// TTLMs is the upstream's exact ttlMs number (non-negative; fractions
	// are legal JSON numbers and are preserved, never narrowed).
	TTLMs      json.Number
	CacheScope string
	// Rest keeps any other members (additive extension fields) verbatim.
	Rest map[string]any
}

// ParseListResult accepts only the current ListToolsResult shape:
// resultType complete, a tools array, optional string nextCursor, and the
// REQUIRED CacheableResult hints ttlMs (non-negative JSON number) and
// cacheScope (public | private). Nothing missing or malformed is repaired.
func ParseListResult(raw json.RawMessage) (*ListResult, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var obj map[string]json.RawMessage
	if err := dec.Decode(&obj); err != nil || obj == nil {
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
	lr := &ListResult{Rest: map[string]any{}}
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

// parseListHints validates the optional cursor and the REQUIRED cache hints.
func parseListHints(obj map[string]json.RawMessage, lr *ListResult) error {
	if c, has := obj["nextCursor"]; has {
		if err := json.Unmarshal(c, &lr.NextCursor); err != nil {
			return fmt.Errorf("%w: nextCursor must be a string", ErrListResultInvalid)
		}
	}
	ttl, scope, err := parseCacheHints(obj, ErrListResultInvalid)
	if err != nil {
		return err
	}
	lr.TTLMs, lr.CacheScope = ttl, scope
	return nil
}

// parseCacheHints validates the REQUIRED CacheableResult hints: ttlMs a
// non-negative JSON number token (kept verbatim), cacheScope exactly public
// or private. Nothing missing or malformed is repaired.
func parseCacheHints(obj map[string]json.RawMessage, invalid error) (json.Number, string, error) {
	t, has := obj["ttlMs"]
	if !has {
		return "", "", fmt.Errorf("%w: ttlMs is required on a cacheable result", invalid)
	}
	tt := bytes.TrimSpace(t)
	if len(tt) == 0 || (tt[0] != '-' && (tt[0] < '0' || tt[0] > '9')) || !validTTL(json.Number(tt)) {
		return "", "", fmt.Errorf("%w: ttlMs must be a non-negative JSON number", invalid)
	}
	sc, has := obj["cacheScope"]
	if !has {
		return "", "", fmt.Errorf("%w: cacheScope is required on a cacheable result", invalid)
	}
	var s string
	if err := json.Unmarshal(sc, &s); err != nil || (s != CacheScopePublic && s != CacheScopePrivate) {
		return "", "", fmt.Errorf("%w: cacheScope must be public or private", invalid)
	}
	return json.Number(tt), s, nil
}

// StripHeaderAnnotations removes every x-mcp-header annotation from a tool
// inputSchema so a definition presented by a route that declares no
// mirrored parameters never invites a client to send Mcp-Param-* headers
// the route cannot validate from that same definition.
func StripHeaderAnnotations(schema json.RawMessage) json.RawMessage {
	var node any
	dec := json.NewDecoder(bytes.NewReader(schema))
	dec.UseNumber() // numbers in the schema survive the round trip verbatim
	if err := dec.Decode(&node); err != nil {
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
