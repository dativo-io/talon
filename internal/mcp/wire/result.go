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

// ErrCallResultInvalid is a tools/call result whose structure is not the
// current CallToolResult: after the request was written it proves nothing,
// so the caller treats it as an unknown outcome, never a success.
var ErrCallResultInvalid = errors.New("upstream tools/call result is not a valid 2026-07-28 CallToolResult")

// MetaUpstreamServerInfo is where the upstream's own serverInfo is kept
// when Talon stamps its identity on a relayed result.
const MetaUpstreamServerInfo = "io.dativo.talon/upstreamServerInfo"

// ValidateCallToolResult checks the result of a tools/call Talon sent to an
// upstream and returns the normalized result the client may receive.
// Truth table:
//
//	not an object                → ErrCallResultInvalid
//	missing resultType           → ErrResultTypeMissing
//	task / any other value       → ErrResultTypeUnsupported (Tasks are #448)
//	input_required               → returned unchanged (the caller decides; a
//	                               governed action cannot continue through it)
//	complete with a bad structure→ ErrCallResultInvalid: content must be an
//	                               array of valid content blocks, isError a
//	                               JSON boolean when present, structuredContent
//	                               an object when present, _meta an object
//	complete                     → normalized
//
// Normalization keeps only the CallToolResult members (resultType, content,
// structuredContent, isError) and a strict allowlist of metadata: Talon's
// serverInfo, and the upstream's serverInfo under MetaUpstreamServerInfo.
// Every other upstream _meta key — vendor keys and anything in Talon's own
// namespace — is dropped, so upstream-controlled metadata cannot carry
// unscanned data to a client or spoof a governance verdict.
func ValidateCallToolResult(raw json.RawMessage, server Implementation) (map[string]any, error) {
	var in map[string]json.RawMessage
	if err := json.Unmarshal(raw, &in); err != nil || in == nil {
		return nil, fmt.Errorf("%w: not a JSON object", ErrCallResultInvalid)
	}
	rtRaw, has := in["resultType"]
	if !has {
		return nil, ErrResultTypeMissing
	}
	var rt string
	if json.Unmarshal(rtRaw, &rt) != nil {
		return nil, fmt.Errorf("%w: %s", ErrResultTypeUnsupported, string(rtRaw))
	}
	switch rt {
	case ResultTypeInputRequired:
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		return out, nil
	case ResultTypeComplete:
		return completeCallResult(in, server)
	default:
		return nil, fmt.Errorf("%w: %q", ErrResultTypeUnsupported, rt)
	}
}

// completeCallResult validates and normalizes a resultType:"complete"
// CallToolResult (see ValidateCallToolResult).
func completeCallResult(in map[string]json.RawMessage, server Implementation) (map[string]any, error) {
	content, err := callResultContent(in["content"])
	if err != nil {
		return nil, err
	}
	out := map[string]any{"resultType": ResultTypeComplete, "content": content}
	if v, has := in["isError"]; has {
		var isErr bool
		if !isJSONBool(v) || json.Unmarshal(v, &isErr) != nil {
			return nil, fmt.Errorf("%w: isError is not a boolean", ErrCallResultInvalid)
		}
		out["isError"] = isErr
	}
	if v, has := in["structuredContent"]; has {
		var sc map[string]any
		if err := json.Unmarshal(v, &sc); err != nil || sc == nil {
			return nil, fmt.Errorf("%w: structuredContent is not an object", ErrCallResultInvalid)
		}
		out["structuredContent"] = sc
	}
	meta, err := callResultMeta(in["_meta"], server)
	if err != nil {
		return nil, err
	}
	out["_meta"] = meta
	return out, nil
}

// callResultContent validates the required content array block by block.
func callResultContent(raw json.RawMessage) ([]any, error) {
	if raw == nil {
		return nil, fmt.Errorf("%w: content is required", ErrCallResultInvalid)
	}
	var blocks []json.RawMessage
	if err := json.Unmarshal(raw, &blocks); err != nil || blocks == nil {
		return nil, fmt.Errorf("%w: content is not an array", ErrCallResultInvalid)
	}
	content := make([]any, 0, len(blocks))
	for i, b := range blocks {
		block, err := contentBlock(b)
		if err != nil {
			return nil, fmt.Errorf("%w: content[%d]: %v", ErrCallResultInvalid, i, err)
		}
		content = append(content, block)
	}
	return content, nil
}

// callResultMeta applies the metadata allowlist: Talon's serverInfo, and
// the upstream's (an object) under MetaUpstreamServerInfo. Nothing else
// from the upstream survives.
func callResultMeta(raw json.RawMessage, server Implementation) (map[string]any, error) {
	meta := map[string]any{MetaServerInfo: server}
	if raw == nil {
		return meta, nil
	}
	var um map[string]json.RawMessage
	if err := json.Unmarshal(raw, &um); err != nil || um == nil {
		return nil, fmt.Errorf("%w: _meta is not an object", ErrCallResultInvalid)
	}
	var info map[string]any
	if si, ok := um[MetaServerInfo]; ok && json.Unmarshal(si, &info) == nil && info != nil {
		meta[MetaUpstreamServerInfo] = info
	}
	return meta, nil
}

// contentBlockFields are the string members each simple content block type
// requires.
var contentBlockFields = map[string][]string{
	"text":          {"text"},
	"image":         {"data", "mimeType"},
	"audio":         {"data", "mimeType"},
	"resource_link": {"uri", "name"},
}

// contentBlock validates one CallToolResult content block by its type.
func contentBlock(raw json.RawMessage) (map[string]any, error) {
	var b map[string]any
	if err := json.Unmarshal(raw, &b); err != nil || b == nil {
		return nil, errors.New("not an object")
	}
	typ, _ := b["type"].(string)
	if fields, ok := contentBlockFields[typ]; ok {
		for _, k := range fields {
			if s, ok := b[k].(string); !ok || (k == "uri" && s == "") {
				return nil, fmt.Errorf("%s block needs a string %s", typ, k)
			}
		}
	} else if typ == "resource" {
		if err := embeddedResource(b["resource"]); err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("unsupported content type %q", typ)
	}
	for _, k := range []string{"annotations", "_meta"} {
		if v, has := b[k]; has {
			if _, ok := v.(map[string]any); !ok {
				return nil, fmt.Errorf("%s is not an object", k)
			}
		}
	}
	return b, nil
}

// embeddedResource validates a resource block's resource: a uri and
// exactly one of text or blob.
func embeddedResource(v any) error {
	r, ok := v.(map[string]any)
	if !ok {
		return errors.New("resource block without a resource object")
	}
	uri, _ := r["uri"].(string)
	_, isText := r["text"].(string)
	_, isBlob := r["blob"].(string)
	if uri == "" || isText == isBlob {
		return errors.New("embedded resource needs a uri and exactly one of text or blob")
	}
	return nil
}

// isJSONBool reports whether raw is literally true or false (json.Unmarshal
// into a bool already refuses strings and numbers; this keeps the check
// explicit and independent of decoder leniency).
func isJSONBool(raw json.RawMessage) bool {
	t := string(bytes.TrimSpace(raw))
	return t == "true" || t == "false"
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
		meta[MetaUpstreamServerInfo] = prev
	}
	meta[MetaServerInfo] = server
	return meta
}
