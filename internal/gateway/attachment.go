package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/attachment"
	"github.com/dativo-io/talon/internal/classifier"
)

// FileBlock represents a single base64-encoded file found inside an LLM API request.
type FileBlock struct {
	Index     int    // position in the content array
	MsgIndex  int    // index of the parent message
	Type      string // e.g. "file", "image_url", "document", "image"
	MIMEType  string // e.g. "application/pdf", "image/png"
	Extension string // derived from MIME or filename, e.g. "pdf"
	Filename  string // if available
	RawSize   int    // decoded byte count
	Data      []byte // decoded content
}

// AttachmentScanResult holds per-file scan results.
type AttachmentScanResult struct {
	Filename        string   `json:"filename"`
	Extension       string   `json:"extension"`
	MIMEType        string   `json:"mime_type"`
	SizeBytes       int      `json:"size_bytes"`
	TextExtracted   bool     `json:"text_extracted"`
	PIIFound        bool     `json:"pii_found"`
	PIITypes        []string `json:"pii_types,omitempty"`
	InjectionsFound int      `json:"injections_found"`
	ActionTaken     string   `json:"action_taken"`
}

// AttachmentsScanSummary aggregates results for all file blocks in a request.
type AttachmentsScanSummary struct {
	FilesScanned    int                    `json:"files_scanned"`
	FilesBlocked    int                    `json:"files_blocked"`
	PIITypes        []string               `json:"pii_types,omitempty"`
	InjectionsFound int                    `json:"injections_found"`
	ActionTaken     string                 `json:"action_taken"`
	Results         []AttachmentScanResult `json:"results,omitempty"`
	// BlockRequest is true when the entire request should be rejected.
	BlockRequest bool `json:"-"`
	// ModifiedBody is non-nil when file blocks were stripped from the request.
	ModifiedBody []byte `json:"-"`
}

// ScanRequestAttachments finds base64-encoded file blocks in an LLM API request,
// decodes them, extracts text, scans for PII and prompt injection, and applies
// the configured policy. Returns nil when no file blocks are present.
func ScanRequestAttachments(
	ctx context.Context,
	body []byte,
	provider string,
	extractor *attachment.Extractor,
	piiScanner *classifier.Scanner,
	injScanner *attachment.Scanner,
	policy *AttachmentPolicyConfig,
) *AttachmentsScanSummary {
	if policy == nil || policy.Action == "allow" {
		return nil
	}

	blocks := extractFileBlocks(body, provider)
	if len(blocks) == 0 {
		return nil
	}

	summary := &AttachmentsScanSummary{
		ActionTaken: policy.Action,
	}
	piiTypeSet := map[string]bool{}
	needsStrip := false

	for i := range blocks {
		fb := &blocks[i]
		result := scanSingleFileBlock(ctx, fb, extractor, piiScanner, injScanner, policy)
		summary.Results = append(summary.Results, result)
		summary.FilesScanned++

		if result.PIIFound {
			for _, t := range result.PIITypes {
				piiTypeSet[t] = true
			}
		}
		summary.InjectionsFound += result.InjectionsFound

		switch result.ActionTaken {
		case "blocked":
			summary.FilesBlocked++
			if policy.Action == "block" || policy.InjectionAction == "block" {
				summary.BlockRequest = true
			}
			needsStrip = true
		case "stripped":
			summary.FilesBlocked++
			needsStrip = true
		}
	}

	for t := range piiTypeSet {
		summary.PIITypes = append(summary.PIITypes, t)
	}

	if needsStrip && !summary.BlockRequest {
		stripped, err := stripFileBlocks(body, provider)
		if err == nil {
			summary.ModifiedBody = stripped
		}
	}

	return summary
}

func scanSingleFileBlock(
	ctx context.Context,
	fb *FileBlock,
	extractor *attachment.Extractor,
	piiScanner *classifier.Scanner,
	injScanner *attachment.Scanner,
	policy *AttachmentPolicyConfig,
) AttachmentScanResult {
	result := AttachmentScanResult{
		Filename:  fb.Filename,
		Extension: fb.Extension,
		MIMEType:  fb.MIMEType,
		SizeBytes: fb.RawSize,
	}

	// Type enforcement
	if !isTypeAllowed(fb.Extension, policy) {
		result.ActionTaken = enforcementAction(policy)
		log.Warn().Str("extension", fb.Extension).Str("filename", fb.Filename).
			Str("action", result.ActionTaken).Msg("attachment_type_not_allowed")
		return result
	}

	// Size enforcement
	maxBytes := int64(policy.MaxFileSizeMB) * 1024 * 1024
	if maxBytes > 0 && int64(fb.RawSize) > maxBytes {
		result.ActionTaken = enforcementAction(policy)
		log.Warn().Int("size_bytes", fb.RawSize).Int64("max_bytes", maxBytes).
			Str("filename", fb.Filename).Str("action", result.ActionTaken).
			Msg("attachment_size_exceeded")
		return result
	}

	// Text extraction (skip for images — nothing to extract)
	if isImageExtension(fb.Extension) {
		result.ActionTaken = "allowed"
		return result
	}

	if extractor == nil {
		result.ActionTaken = "allowed"
		return result
	}

	text, err := extractor.ExtractBytes(ctx, fb.Filename, fb.Data)
	if err != nil {
		log.Warn().Err(err).Str("filename", fb.Filename).Msg("attachment_extract_failed")
		result.ActionTaken = decideOnExtractFailure(policy)
		return result
	}
	if text == "" {
		result.ActionTaken = "allowed"
		return result
	}
	result.TextExtracted = true

	// PII scan
	if piiScanner != nil {
		cls := piiScanner.Scan(ctx, text)
		if cls != nil && cls.HasPII {
			result.PIIFound = true
			types := map[string]bool{}
			for _, e := range cls.Entities {
				types[e.Type] = true
			}
			for t := range types {
				result.PIITypes = append(result.PIITypes, t)
			}
		}
	}

	// Injection scan
	if injScanner != nil {
		scanRes := injScanner.Scan(ctx, text)
		if scanRes != nil {
			result.InjectionsFound = len(scanRes.InjectionsFound)
		}
	}

	// Determine action
	result.ActionTaken = resolveFileAction(result, policy)
	return result
}

func resolveFileAction(result AttachmentScanResult, policy *AttachmentPolicyConfig) string {
	action := "allowed"

	if result.InjectionsFound > 0 {
		switch policy.InjectionAction {
		case "block":
			return "blocked"
		case "strip":
			action = "stripped"
		}
	}
	if result.PIIFound {
		switch policy.Action {
		case "block":
			return "blocked"
		case "strip":
			if action == "allowed" {
				action = "stripped"
			}
		}
	}
	return action
}

func decideOnExtractFailure(policy *AttachmentPolicyConfig) string {
	if policy.Action == "block" {
		return "blocked"
	}
	return "allowed"
}

// enforcementAction maps the policy-level action to a per-file action for
// hard enforcement checks (type/size). In "warn" mode this returns "warned"
// so the violation is recorded without triggering body modification.
func enforcementAction(policy *AttachmentPolicyConfig) string {
	switch policy.Action {
	case "block":
		return "blocked"
	case "strip":
		return "stripped"
	default:
		return "warned"
	}
}

func isTypeAllowed(ext string, policy *AttachmentPolicyConfig) bool {
	ext = strings.TrimPrefix(strings.ToLower(ext), ".")
	for _, blocked := range policy.BlockedTypes {
		if strings.TrimPrefix(strings.ToLower(blocked), ".") == ext {
			return false
		}
	}
	if len(policy.AllowedTypes) == 0 {
		return true
	}
	for _, allowed := range policy.AllowedTypes {
		if strings.TrimPrefix(strings.ToLower(allowed), ".") == ext {
			return true
		}
	}
	return false
}

func isImageExtension(ext string) bool {
	switch strings.TrimPrefix(strings.ToLower(ext), ".") {
	case "png", "jpg", "jpeg", "gif", "webp", "bmp", "tiff", "svg":
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Provider-specific file block extraction
// ---------------------------------------------------------------------------

func extractFileBlocks(body []byte, provider string) []FileBlock {
	switch provider {
	case "anthropic":
		return extractAnthropicFileBlocks(body)
	default:
		return extractOpenAIFileBlocks(body)
	}
}

// extractOpenAIFileBlocks finds base64-encoded files in OpenAI Chat Completions
// and Responses API requests. Handles:
//   - content[].image_url.url  with data: URI
//   - content[].file.file_data with data: URI
//   - input[].content blocks   (Responses API)
func extractOpenAIFileBlocks(body []byte) []FileBlock {
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}

	var blocks []FileBlock

	// Chat Completions: messages[].content
	if msgs, ok := raw["messages"].([]interface{}); ok {
		for mi, m := range msgs {
			msg, ok := m.(map[string]interface{})
			if !ok {
				continue
			}
			content, ok := msg["content"].([]interface{})
			if !ok {
				continue
			}
			blocks = append(blocks, extractOpenAIContentBlocks(content, mi)...)
		}
	}

	// Responses API: input[].content
	if items, ok := raw["input"].([]interface{}); ok {
		for mi, item := range items {
			it, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			content, ok := it["content"].([]interface{})
			if !ok {
				continue
			}
			blocks = append(blocks, extractOpenAIContentBlocks(content, mi)...)
		}
	}

	return blocks
}

func extractOpenAIContentBlocks(content []interface{}, msgIdx int) []FileBlock {
	var blocks []FileBlock
	for ci, part := range content {
		p, ok := part.(map[string]interface{})
		if !ok {
			continue
		}
		typ, _ := p["type"].(string)

		var fb *FileBlock
		switch typ {
		case "image_url":
			fb = extractImageURLBlock(p, msgIdx, ci)
		case "file":
			fb = extractFileDataBlock(p, msgIdx, ci)
		case "input_file":
			fb = extractInputFileBlock(p, msgIdx, ci)
		}
		if fb != nil {
			blocks = append(blocks, *fb)
		}
	}
	return blocks
}

func extractImageURLBlock(p map[string]interface{}, msgIdx, ci int) *FileBlock {
	iu, ok := p["image_url"].(map[string]interface{})
	if !ok {
		return nil
	}
	url, _ := iu["url"].(string)
	if !strings.HasPrefix(url, "data:") {
		return nil
	}
	mime, data, err := decodeDataURI(url)
	if err != nil {
		return nil
	}
	ext := extensionFromMIME(mime)
	return &FileBlock{
		Index: ci, MsgIndex: msgIdx, Type: "image_url",
		MIMEType: mime, Extension: ext,
		Filename: fmt.Sprintf("image_%d_%d.%s", msgIdx, ci, ext),
		RawSize:  len(data), Data: data,
	}
}

func extractFileDataBlock(p map[string]interface{}, msgIdx, ci int) *FileBlock {
	f, ok := p["file"].(map[string]interface{})
	if !ok {
		return nil
	}
	fileData, _ := f["file_data"].(string)
	if !strings.HasPrefix(fileData, "data:") {
		return nil
	}
	mime, data, err := decodeDataURI(fileData)
	if err != nil {
		return nil
	}
	ext := extensionFromMIME(mime)
	fname, _ := f["filename"].(string)
	if fname != "" {
		if fext := extensionFromFilename(fname); fext != "" {
			ext = fext
		}
	} else {
		fname = fmt.Sprintf("file_%d_%d.%s", msgIdx, ci, ext)
	}
	return &FileBlock{
		Index: ci, MsgIndex: msgIdx, Type: "file",
		MIMEType: mime, Extension: ext,
		Filename: fname, RawSize: len(data), Data: data,
	}
}

func extractInputFileBlock(p map[string]interface{}, msgIdx, ci int) *FileBlock {
	fileData, _ := p["file_data"].(string)
	if fileData == "" {
		if nested, ok := p["file"].(map[string]interface{}); ok {
			fileData, _ = nested["file_data"].(string)
		}
	}
	if !strings.HasPrefix(fileData, "data:") {
		return nil
	}
	mime, data, err := decodeDataURI(fileData)
	if err != nil {
		return nil
	}
	ext := extensionFromMIME(mime)
	fname, _ := p["filename"].(string)
	if fname != "" {
		if fext := extensionFromFilename(fname); fext != "" {
			ext = fext
		}
	} else {
		fname = fmt.Sprintf("input_file_%d_%d.%s", msgIdx, ci, ext)
	}
	return &FileBlock{
		Index: ci, MsgIndex: msgIdx, Type: "input_file",
		MIMEType: mime, Extension: ext,
		Filename: fname, RawSize: len(data), Data: data,
	}
}

// extractAnthropicFileBlocks finds base64-encoded content in Anthropic messages.
// Handles: content[].source.type=="base64" for type "document" and "image".
func extractAnthropicFileBlocks(body []byte) []FileBlock {
	var raw struct {
		Messages []struct {
			Content []map[string]interface{} `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}

	var blocks []FileBlock
	for mi, msg := range raw.Messages {
		for ci, block := range msg.Content {
			typ, _ := block["type"].(string)
			if typ != "document" && typ != "image" {
				continue
			}
			src, ok := block["source"].(map[string]interface{})
			if !ok {
				continue
			}
			srcType, _ := src["type"].(string)
			if srcType != "base64" {
				continue
			}
			dataStr, _ := src["data"].(string)
			if dataStr == "" {
				continue
			}
			data, err := base64.StdEncoding.DecodeString(dataStr)
			if err != nil {
				data, err = base64.RawStdEncoding.DecodeString(dataStr)
				if err != nil {
					continue
				}
			}
			mime, _ := src["media_type"].(string)
			ext := extensionFromMIME(mime)
			fname := fmt.Sprintf("%s_%d_%d.%s", typ, mi, ci, ext)

			blocks = append(blocks, FileBlock{
				Index: ci, MsgIndex: mi, Type: typ,
				MIMEType: mime, Extension: ext,
				Filename: fname, RawSize: len(data), Data: data,
			})
		}
	}
	return blocks
}

// ---------------------------------------------------------------------------
// stripFileBlocks removes base64 file content blocks from the request body.
// Text blocks and other non-file content are preserved.
// ---------------------------------------------------------------------------

func stripFileBlocks(body []byte, provider string) ([]byte, error) {
	switch provider {
	case "anthropic":
		return stripAnthropicFileBlocks(body)
	default:
		return stripOpenAIFileBlocks(body)
	}
}

func stripOpenAIFileBlocks(body []byte) ([]byte, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	if msgs, ok := raw["messages"].([]interface{}); ok {
		for _, m := range msgs {
			msg, ok := m.(map[string]interface{})
			if !ok {
				continue
			}
			content, ok := msg["content"].([]interface{})
			if !ok {
				continue
			}
			msg["content"] = filterOpenAIContent(content)
		}
	}

	if items, ok := raw["input"].([]interface{}); ok {
		for _, item := range items {
			it, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			content, ok := it["content"].([]interface{})
			if !ok {
				continue
			}
			it["content"] = filterOpenAIContent(content)
		}
	}

	return json.Marshal(raw)
}

func filterOpenAIContent(content []interface{}) []interface{} {
	var out []interface{}
	for _, part := range content {
		p, ok := part.(map[string]interface{})
		if !ok {
			out = append(out, part)
			continue
		}
		typ, _ := p["type"].(string)
		switch typ {
		case "image_url":
			iu, ok := p["image_url"].(map[string]interface{})
			if ok {
				url, _ := iu["url"].(string)
				if strings.HasPrefix(url, "data:") {
					continue
				}
			}
		case "file":
			f, ok := p["file"].(map[string]interface{})
			if ok {
				fd, _ := f["file_data"].(string)
				if strings.HasPrefix(fd, "data:") {
					continue
				}
			}
		case "input_file":
			fd, _ := p["file_data"].(string)
			if fd == "" {
				if nested, ok := p["file"].(map[string]interface{}); ok {
					fd, _ = nested["file_data"].(string)
				}
			}
			if strings.HasPrefix(fd, "data:") {
				continue
			}
		}
		out = append(out, part)
	}
	if out == nil {
		out = []interface{}{}
	}
	return out
}

func stripAnthropicFileBlocks(body []byte) ([]byte, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	if msgs, ok := raw["messages"].([]interface{}); ok {
		for _, m := range msgs {
			msg, ok := m.(map[string]interface{})
			if !ok {
				continue
			}
			content, ok := msg["content"].([]interface{})
			if !ok {
				continue
			}
			var filtered []interface{}
			for _, block := range content {
				b, ok := block.(map[string]interface{})
				if !ok {
					filtered = append(filtered, block)
					continue
				}
				typ, _ := b["type"].(string)
				if typ == "document" || typ == "image" {
					if src, ok := b["source"].(map[string]interface{}); ok {
						if srcType, _ := src["type"].(string); srcType == "base64" {
							continue
						}
					}
				}
				filtered = append(filtered, block)
			}
			if filtered == nil {
				filtered = []interface{}{}
			}
			msg["content"] = filtered
		}
	}

	return json.Marshal(raw)
}

// ---------------------------------------------------------------------------
// Data URI / MIME helpers
// ---------------------------------------------------------------------------

// decodeDataURI parses "data:<mime>;base64,<encoded>" and returns MIME + decoded bytes.
func decodeDataURI(uri string) (mime string, data []byte, err error) {
	if !strings.HasPrefix(uri, "data:") {
		return "", nil, fmt.Errorf("not a data URI")
	}
	rest := uri[5:]
	idx := strings.Index(rest, ",")
	if idx < 0 {
		return "", nil, fmt.Errorf("malformed data URI: no comma")
	}
	meta := rest[:idx]
	encoded := rest[idx+1:]

	parts := strings.SplitN(meta, ";", 2)
	mime = parts[0]

	data, err = base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		data, err = base64.RawStdEncoding.DecodeString(encoded)
		if err != nil {
			return mime, nil, fmt.Errorf("base64 decode: %w", err)
		}
	}
	return mime, data, nil
}

func extensionFromFilename(name string) string {
	idx := strings.LastIndex(name, ".")
	if idx < 0 || idx == len(name)-1 {
		return ""
	}
	return strings.ToLower(name[idx+1:])
}

func extensionFromMIME(mime string) string {
	m := map[string]string{
		"application/pdf":    "pdf",
		"text/plain":         "txt",
		"text/csv":           "csv",
		"text/html":          "html",
		"text/markdown":      "md",
		"image/png":          "png",
		"image/jpeg":         "jpg",
		"image/gif":          "gif",
		"image/webp":         "webp",
		"image/svg+xml":      "svg",
		"application/msword": "doc",
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
		"application/vnd.ms-excel": "xls",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
	}
	if ext, ok := m[strings.ToLower(mime)]; ok {
		return ext
	}
	// Fallback: last part of MIME subtype
	parts := strings.SplitN(mime, "/", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return "bin"
}
