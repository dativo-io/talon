package wire

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	sentinelPrefix = "=?base64?"
	sentinelSuffix = "?="
	maxSafeInteger = 1<<53 - 1
)

// isPlainHeaderValue reports whether v can travel as-is in an HTTP field
// value: visible ASCII, space or tab, no leading/trailing whitespace, and
// not shaped like the Base64 sentinel.
func isPlainHeaderValue(v string) bool {
	if v == "" {
		return true
	}
	if v[0] == ' ' || v[0] == '\t' || v[len(v)-1] == ' ' || v[len(v)-1] == '\t' {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c != ' ' && c != '\t' && (c < 0x21 || c > 0x7e) {
			return false
		}
	}
	return !isSentinel(v)
}

func isSentinel(v string) bool {
	return strings.HasPrefix(v, sentinelPrefix) && strings.HasSuffix(v, sentinelSuffix) && len(v) >= len(sentinelPrefix)+len(sentinelSuffix)
}

// EncodeHeaderValue applies the Value Encoding rules: plain ASCII as-is,
// everything else (non-ASCII, control characters, surrounding whitespace, a
// literal that looks like the sentinel) as =?base64?…?=.
func EncodeHeaderValue(v string) string {
	if isPlainHeaderValue(v) {
		return v
	}
	return sentinelPrefix + base64.StdEncoding.EncodeToString([]byte(v)) + sentinelSuffix
}

// DecodeHeaderValue reverses EncodeHeaderValue and rejects values that are
// neither plain header values nor well-formed sentinels.
func DecodeHeaderValue(v string) (string, error) {
	if isSentinel(v) {
		inner := v[len(sentinelPrefix) : len(v)-len(sentinelSuffix)]
		raw, err := base64.StdEncoding.DecodeString(inner)
		if err != nil {
			return "", fmt.Errorf("invalid base64 sentinel")
		}
		if !utf8.Valid(raw) {
			return "", fmt.Errorf("sentinel does not decode to UTF-8")
		}
		return string(raw), nil
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c != ' ' && c != '\t' && (c < 0x21 || c > 0x7e) {
			return "", fmt.Errorf("header value contains characters outside visible ASCII")
		}
	}
	return v, nil
}

// singleHeader returns the one value of a header, distinguishing absent from
// duplicated.
func singleHeader(h http.Header, name string) (value string, present, dup bool) {
	vals := h.Values(name)
	switch len(vals) {
	case 0:
		return "", false, false
	case 1:
		return vals[0], true, false
	default:
		return vals[0], true, true
	}
}

// captureHeaderParams collects every Mcp-Param-* header present. Nothing is
// validated against a schema here; the route does that once the trusted
// declaration for the named tool is known.
func captureHeaderParams(h http.Header) map[string]HeaderParam {
	out := map[string]HeaderParam{}
	for name, vals := range h {
		if len(name) <= len(HeaderParamPrefix) || !strings.EqualFold(name[:len(HeaderParamPrefix)], HeaderParamPrefix) {
			continue
		}
		part := name[len(HeaderParamPrefix):]
		hp := HeaderParam{Name: part, Raw: vals[0], Dup: len(vals) > 1}
		dec, err := DecodeHeaderValue(vals[0])
		if err != nil {
			hp.Invalid = true
		} else {
			hp.Decoded = dec
		}
		out[strings.ToLower(part)] = hp
	}
	return out
}

// ---------------------------------------------------------------------------
// x-mcp-header declarations
// ---------------------------------------------------------------------------

// ParamDecl is one trusted declaration: the argument at Path (a chain of
// `properties` keys) is mirrored into the Mcp-Param-{Header} header.
type ParamDecl struct {
	Header string   // name part as declared (original case)
	Path   []string // property path from the arguments root
	Type   string   // "string" | "integer" | "boolean" | "" (infer from the value)
}

// HeaderParams is the set of trusted mirrored-parameter declarations for one
// tool. It is built from a trusted schema (HeaderParamsFromSchema) or from
// operator configuration (HeaderParamsFromConfig) — never from the request.
type HeaderParams struct {
	decls []ParamDecl
}

// Empty reports whether no parameter is declared.
func (hp *HeaderParams) Empty() bool { return hp == nil || len(hp.decls) == 0 }

// Decls returns the declarations in a deterministic order.
func (hp *HeaderParams) Decls() []ParamDecl {
	if hp == nil {
		return nil
	}
	out := append([]ParamDecl(nil), hp.decls...)
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Header) < strings.ToLower(out[j].Header) })
	return out
}

// isToken reports RFC 9110 field-name token syntax (1*tchar).
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

func addDecl(hp *HeaderParams, seen map[string]bool, d ParamDecl) error {
	if !isToken(d.Header) {
		return fmt.Errorf("x-mcp-header %q at %s: not a valid HTTP field-name token", d.Header, strings.Join(d.Path, "."))
	}
	key := strings.ToLower(d.Header)
	if seen[key] {
		return fmt.Errorf("x-mcp-header %q at %s: duplicate header name (case-insensitive)", d.Header, strings.Join(d.Path, "."))
	}
	switch d.Type {
	case "string", "integer", "boolean", "":
	default:
		return fmt.Errorf("x-mcp-header %q at %s: type %q is not a mirrorable primitive (string, integer, boolean)", d.Header, strings.Join(d.Path, "."), d.Type)
	}
	seen[key] = true
	hp.decls = append(hp.decls, d)
	return nil
}

// HeaderParamsFromSchema walks a tool inputSchema and returns its
// x-mcp-header declarations, enforcing the spec constraints: token name,
// case-insensitive uniqueness, primitive type (integer/string/boolean, not
// number), and static reachability through `properties` only. Any violation
// makes the tool definition invalid (the caller excludes the tool).
func HeaderParamsFromSchema(schema json.RawMessage) (*HeaderParams, error) {
	hp := &HeaderParams{}
	if len(schema) == 0 {
		return hp, nil
	}
	var root map[string]any
	if err := json.Unmarshal(schema, &root); err != nil {
		return nil, fmt.Errorf("inputSchema: %w", err)
	}
	seen := map[string]bool{}
	if err := walkSchema(root, nil, true, hp, seen); err != nil {
		return nil, err
	}
	return hp, nil
}

// walkSchema visits every subschema. reachable is true only while the chain
// from the root consists solely of `properties` keys.
func walkSchema(node map[string]any, path []string, reachable bool, hp *HeaderParams, seen map[string]bool) error {
	if err := declareAnnotation(node, path, reachable, hp, seen); err != nil {
		return err
	}
	for key, child := range node {
		switch key {
		case "properties":
			props, ok := child.(map[string]any)
			if !ok {
				continue
			}
			for pname, sub := range props {
				if subm, ok := sub.(map[string]any); ok {
					if err := walkSchema(subm, append(append([]string(nil), path...), pname), reachable, hp, seen); err != nil {
						return err
					}
				}
			}
		case "$defs", "definitions", "patternProperties", "dependentSchemas":
			// maps of subschemas: every value is a schema, none reachable
			if m, ok := child.(map[string]any); ok {
				for _, sub := range m {
					if err := walkUnreachable(sub, path, hp, seen); err != nil {
						return err
					}
				}
			}
		case "items", "prefixItems", "additionalProperties", "oneOf", "anyOf", "allOf", "not", "if", "then", "else", "contains", "propertyNames":
			if err := walkUnreachable(child, path, hp, seen); err != nil {
				return err
			}
		}
	}
	return nil
}

// declareAnnotation records an x-mcp-header annotation on node, enforcing
// reachability, non-root placement and the primitive-type rule.
func declareAnnotation(node map[string]any, path []string, reachable bool, hp *HeaderParams, seen map[string]bool) error {
	raw, has := node["x-mcp-header"]
	if !has {
		return nil
	}
	name, _ := raw.(string)
	if !reachable {
		return fmt.Errorf("x-mcp-header %q at %s: not statically reachable through `properties` only", name, strings.Join(path, "."))
	}
	if len(path) == 0 {
		return fmt.Errorf("x-mcp-header %q: annotation on the schema root is not permitted", name)
	}
	typ, _ := node["type"].(string)
	if typ == "number" || typ == "" {
		return fmt.Errorf("x-mcp-header %q at %s: type must be one of string, integer, boolean", name, strings.Join(path, "."))
	}
	return addDecl(hp, seen, ParamDecl{Header: name, Path: append([]string(nil), path...), Type: typ})
}

func walkUnreachable(child any, path []string, hp *HeaderParams, seen map[string]bool) error {
	switch v := child.(type) {
	case map[string]any:
		return walkSchema(v, path, false, hp, seen)
	case []any:
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				if err := walkSchema(m, path, false, hp, seen); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// lookupPath returns the JSON value at a properties path, and whether it is
// present (a present null counts as absent for header purposes).
func lookupPath(args map[string]any, path []string) (any, bool) {
	var cur any = args
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[p]
		if !ok {
			return nil, false
		}
	}
	if cur == nil {
		return nil, false
	}
	return cur, true
}

// primitiveString renders a mirrorable primitive per the type-conversion
// rules; ok is false for non-primitive or out-of-range values.
func primitiveString(v any, declaredType string) (s string, ok bool) {
	typeOK := func(want string) bool { return declaredType == "" || declaredType == want }
	switch x := v.(type) {
	case string:
		return x, typeOK("string")
	case bool:
		return strconv.FormatBool(x), typeOK("boolean")
	case json.Number:
		if !typeOK("integer") {
			return "", false
		}
		return safeIntegerString(x)
	case float64:
		if !typeOK("integer") {
			return "", false
		}
		return safeIntegerString(json.Number(strconv.FormatFloat(x, 'f', -1, 64)))
	}
	return "", false
}

// safeIntegerString renders a JSON number that is an integer within the
// IEEE-754 safe range; anything else is not mirrorable.
func safeIntegerString(n json.Number) (string, bool) {
	i, err := n.Int64()
	if err != nil {
		f, ferr := n.Float64()
		if ferr != nil || f != math.Trunc(f) {
			return "", false
		}
		i = int64(f)
	}
	if i > maxSafeInteger || i < -maxSafeInteger {
		return "", false
	}
	return strconv.FormatInt(i, 10), true
}

func decodeArgs(args json.RawMessage) (map[string]any, error) {
	out := map[string]any{}
	if len(args) == 0 || string(args) == "null" {
		return out, nil
	}
	dec := json.NewDecoder(strings.NewReader(string(args)))
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// ValidateHeaderParams checks every captured Mcp-Param-* header the trusted
// declaration recognizes against the parsed argument at its path (streamable-
// http §Server Validation). The body remains the value; the header is only
// an integrity duplicate. Unrecognized Mcp-Param-* headers are ignored (and
// never forwarded by callers).
func ValidateHeaderParams(decl *HeaderParams, args json.RawMessage, captured map[string]HeaderParam) *Error {
	if decl.Empty() {
		return nil
	}
	argMap, err := decodeArgs(args)
	if err != nil {
		return newErr(http.StatusBadRequest, CodeInvalidParams, ReasonInvalidRequest, "params.arguments: "+err.Error())
	}
	for _, d := range decl.Decls() {
		hdr, has := captured[strings.ToLower(d.Header)]
		headerName := HeaderParamPrefix + d.Header
		val, present := lookupPath(argMap, d.Path)
		if !present {
			if has {
				return headerMismatch(ReasonParamHeaderMismatch, fmt.Sprintf("Header mismatch: %s is present but the body carries no value for %s", headerName, strings.Join(d.Path, ".")))
			}
			continue
		}
		if !has {
			return headerMismatch(ReasonParamHeaderMissing, fmt.Sprintf("Header mismatch: required header %s is missing for argument %s", headerName, strings.Join(d.Path, ".")))
		}
		if hdr.Dup {
			return headerMismatch(ReasonParamHeaderDuplicate, fmt.Sprintf("Header mismatch: %s was sent more than once", headerName))
		}
		if hdr.Invalid {
			return headerMismatch(ReasonParamHeaderInvalid, fmt.Sprintf("Header mismatch: %s contains invalid characters or an undecodable sentinel", headerName))
		}
		want, ok := primitiveString(val, d.Type)
		if !ok {
			return headerMismatch(ReasonParamHeaderInvalid, fmt.Sprintf("Header mismatch: argument %s is not a mirrorable primitive of the declared type", strings.Join(d.Path, ".")))
		}
		if !valuesEqual(want, hdr.Decoded, val) {
			return headerMismatch(ReasonParamHeaderMismatch, fmt.Sprintf("Header mismatch: %s header value does not match body value for %s", headerName, strings.Join(d.Path, ".")))
		}
	}
	return nil
}

// valuesEqual compares a rendered body primitive with a decoded header
// value; integers compare numerically (42 == 42.0).
func valuesEqual(want, got string, bodyVal any) bool {
	if want == got {
		return true
	}
	switch bodyVal.(type) {
	case json.Number, float64:
		a, okA := new(big.Rat).SetString(want)
		b, okB := new(big.Rat).SetString(got)
		return okA && okB && a.Cmp(b) == 0
	}
	return false
}

// OutboundHeaderParams generates the Mcp-Param-* headers for an AUTHORIZED,
// normalized outbound argument payload from a trusted declaration. Inbound
// header values are never consulted. A value that cannot be mirrored (not a
// primitive of the declared type) is an error: nothing is sent.
func OutboundHeaderParams(decl *HeaderParams, args json.RawMessage) (http.Header, error) {
	out := http.Header{}
	if decl.Empty() {
		return out, nil
	}
	argMap, err := decodeArgs(args)
	if err != nil {
		return nil, err
	}
	for _, d := range decl.Decls() {
		val, present := lookupPath(argMap, d.Path)
		if !present {
			continue
		}
		s, ok := primitiveString(val, d.Type)
		if !ok {
			return nil, fmt.Errorf("argument %s is not a mirrorable primitive for header %s", strings.Join(d.Path, "."), HeaderParamPrefix+d.Header)
		}
		out.Set(HeaderParamPrefix+d.Header, EncodeHeaderValue(s))
	}
	return out, nil
}
