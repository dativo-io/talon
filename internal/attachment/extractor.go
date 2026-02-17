package attachment

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Extractor extracts text content from various file formats.
type Extractor struct {
	maxSize int64 // Max file size in bytes
}

// NewExtractor creates a file content extractor with a size limit.
func NewExtractor(maxSizeMB int) *Extractor {
	return &Extractor{
		maxSize: int64(maxSizeMB) * 1024 * 1024,
	}
}

// Extract reads and extracts text from a file.
// Supported formats: .txt, .md, .csv, .html/.htm (MVP).
// PDF and DOCX return placeholders for future implementation.
func (e *Extractor) Extract(ctx context.Context, path string) (string, error) {
	_, span := tracer.Start(ctx, "attachment.extract")
	defer span.End()

	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("stat file %s: %w", path, err)
	}

	if info.Size() > e.maxSize {
		return "", fmt.Errorf("file size %d exceeds limit %d bytes", info.Size(), e.maxSize)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading file %s: %w", path, err)
	}

	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ".txt", ".md", ".csv":
		return string(content), nil

	case ".html", ".htm":
		text := stripScriptAndStyleBlocks(string(content))
		return text, nil

	case ".pdf":
		return "[PDF content extraction - not yet implemented]", nil

	case ".docx":
		return "[DOCX content extraction - not yet implemented]", nil

	default:
		return "", fmt.Errorf("unsupported file type: %s", ext)
	}
}

// stripScriptAndStyleBlocks removes entire <script>...</script> and
// <style>...</style> blocks from HTML so that untrusted script/style
// content (including embedded instructions) is not passed to scanning/sandboxing.
// The opening tag, payload, and closing tag are fully removed (not replaced with
// markers). Tag matching is case-insensitive. Any remaining unclosed <script or
// <style (e.g. malformed tags without '>') are truncated so no payload can leak.
func stripScriptAndStyleBlocks(html string) string {
	text := stripTagBlocks(html, "script")
	text = stripTagBlocks(text, "style")
	// Defense in depth: ensure no unclosed tag suffix remains (e.g. <script without '>')
	text = truncateAtUnclosedTag(text)
	return text
}

// truncateAtUnclosedTag returns the prefix of s up to (but not including) the
// first "<script" or "<style" that has no closing '>' before the next tag or
// end of string, so injection text in malformed tags never reaches the scanner.
func truncateAtUnclosedTag(s string) string {
	lower := strings.ToLower(s)
	earliest := -1
	for _, tag := range []string{"<script", "<style"} {
		i := strings.Index(lower, tag)
		if i < 0 {
			continue
		}
		rest := s[i:]
		if strings.IndexByte(rest, '>') < 0 {
			if earliest < 0 || i < earliest {
				earliest = i
			}
		}
	}
	if earliest >= 0 {
		return s[:earliest]
	}
	return s
}

// stripTagBlocks removes all <tagName>...</tagName> blocks (case-insensitive).
// Returns the string with those blocks removed. If an opening tag has no
// closing '>' or no matching closing tag, the entire suffix from that tag
// is removed so no untrusted payload can leak.
func stripTagBlocks(text, tagName string) string {
	lower := strings.ToLower(text)
	openTag := "<" + tagName
	closeTag := "</" + tagName + ">"
	for {
		i := strings.Index(lower, openTag)
		if i < 0 {
			break
		}
		j := strings.IndexByte(text[i:], '>')
		if j < 0 {
			// Malformed tag: no '>' — remove from opening tag to end of string
			text = text[:i]
			break
		}
		startContent := i + j + 1
		if startContent >= len(lower) {
			text = text[:i]
			break
		}
		k := strings.Index(lower[startContent:], closeTag)
		if k < 0 {
			// No closing tag — remove from opening tag to end of string
			text = text[:i]
			break
		}
		endBlock := startContent + k + len(closeTag)
		text = text[:i] + text[endBlock:]
		lower = strings.ToLower(text)
	}
	return text
}
