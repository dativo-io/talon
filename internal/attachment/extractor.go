package attachment

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ledongthuc/pdf"
	"github.com/microcosm-cc/bluemonday"
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
// Supported formats: .txt, .md, .csv, .html/.htm, .pdf (MVP).
// DOCX returns a placeholder for future implementation.
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
	return e.extractFromContent(content, ext)
}

// ExtractBytes extracts text from in-memory content using the given filename to determine format.
// Use this when attachments are already loaded (e.g. from --attach); avoids writing temp files.
// Same supported formats and size limit as Extract.
func (e *Extractor) ExtractBytes(ctx context.Context, filename string, content []byte) (string, error) {
	_, span := tracer.Start(ctx, "attachment.extract_bytes")
	defer span.End()

	if int64(len(content)) > e.maxSize {
		return "", fmt.Errorf("content size %d exceeds limit %d bytes", len(content), e.maxSize)
	}

	ext := strings.ToLower(filepath.Ext(filename))
	return e.extractFromContent(content, ext)
}

// extractFromContent performs format-specific extraction (shared by Extract and ExtractBytes).
func (e *Extractor) extractFromContent(content []byte, ext string) (string, error) {
	switch ext {
	case ".txt", ".md", ".csv":
		return string(content), nil

	case ".html", ".htm":
		p := bluemonday.StrictPolicy()
		return p.Sanitize(string(content)), nil

	case ".pdf":
		return e.extractPDF(content)

	case ".docx":
		return "[DOCX content extraction - not yet implemented]", nil

	default:
		return "", fmt.Errorf("unsupported file type: %s", ext)
	}
}

// extractPDF extracts plain text from PDF content using ledongthuc/pdf.
// Encrypted or malformed PDFs may return an error or partial/empty text.
func (e *Extractor) extractPDF(content []byte) (string, error) {
	ra := bytes.NewReader(content)
	r, err := pdf.NewReader(ra, int64(len(content)))
	if err != nil {
		return "", fmt.Errorf("reading PDF: %w", err)
	}
	plain, err := r.GetPlainText()
	if err != nil {
		return "", fmt.Errorf("extracting PDF text: %w", err)
	}
	b, err := io.ReadAll(plain)
	if err != nil {
		return "", fmt.Errorf("reading PDF text: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}
