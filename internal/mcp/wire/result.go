package wire

import (
	"encoding/json"
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

// NormalizeUpstreamResult prepares a result received from an upstream server
// for return to the client: it is kept verbatim (lossless, including
// input_required / requestState / inputRequests), an absent resultType is
// made explicit as "complete" (clients MUST treat absence as complete), and
// the identity stamp names this server. The upstream serverInfo, if any, is
// kept under its own key so nothing is silently dropped.
func NormalizeUpstreamResult(raw json.RawMessage, server Implementation) (map[string]any, error) {
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = map[string]any{}
	}
	if _, has := out["resultType"]; !has {
		out["resultType"] = ResultTypeComplete
	}
	out["_meta"] = mergeMeta(out["_meta"], server)
	return out, nil
}

// ResultType reports the resultType of a raw result ("complete" when absent).
func ResultType(raw json.RawMessage) string {
	var probe struct {
		ResultType string `json:"resultType"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil || probe.ResultType == "" {
		return ResultTypeComplete
	}
	return probe.ResultType
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
