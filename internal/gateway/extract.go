package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dativo-io/talon/internal/classifier"
)

// ExtractedRequest holds text and model extracted from a provider request body for governance.
type ExtractedRequest struct {
	Text  string // Concatenated message text for PII scanning
	Model string
}

// ExtractOpenAI extracts message text and model from an OpenAI chat completions request body.
// Handles content as string or array of content blocks (multi-modal); only text is concatenated.
func ExtractOpenAI(body []byte) (ExtractedRequest, error) {
	var req struct {
		Model    string      `json:"model"`
		Messages []openAIMsg `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return ExtractedRequest{}, fmt.Errorf("openai request body: %w", err)
	}
	var sb strings.Builder
	for _, m := range req.Messages {
		sb.WriteString(openAIContentToText(m.Content))
		sb.WriteString("\n")
	}
	return ExtractedRequest{
		Text:  strings.TrimSpace(sb.String()),
		Model: strings.TrimSpace(req.Model),
	}, nil
}

type openAIMsg struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"` // string or []ContentPart
}

func openAIContentToText(c interface{}) string {
	if c == nil {
		return ""
	}
	switch v := c.(type) {
	case string:
		return v
	case []interface{}:
		var sb strings.Builder
		for _, part := range v {
			if m, ok := part.(map[string]interface{}); ok {
				if typ, _ := m["type"].(string); typ == "text" {
					if text, _ := m["text"].(string); text != "" {
						sb.WriteString(text)
					}
				}
			}
		}
		return sb.String()
	default:
		return ""
	}
}

// ExtractAnthropic extracts message text and model from an Anthropic messages request body.
// Includes system (string or array of blocks) and messages[].content text.
func ExtractAnthropic(body []byte) (ExtractedRequest, error) {
	var req struct {
		Model    string         `json:"model"`
		System   interface{}    `json:"system"` // string or []ContentBlock
		Messages []anthropicMsg `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return ExtractedRequest{}, fmt.Errorf("anthropic request body: %w", err)
	}
	var sb strings.Builder
	sb.WriteString(anthropicContentToText(req.System))
	sb.WriteString("\n")
	for _, m := range req.Messages {
		sb.WriteString(anthropicContentToText(m.Content))
		sb.WriteString("\n")
	}
	return ExtractedRequest{
		Text:  strings.TrimSpace(sb.String()),
		Model: strings.TrimSpace(req.Model),
	}, nil
}

type anthropicMsg struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"` // array of {type: "text", text: "..."}
}

func anthropicContentToText(c interface{}) string {
	if c == nil {
		return ""
	}
	switch v := c.(type) {
	case string:
		return v
	case []interface{}:
		var sb strings.Builder
		for _, part := range v {
			if m, ok := part.(map[string]interface{}); ok {
				if typ, _ := m["type"].(string); typ == "text" {
					if text, _ := m["text"].(string); text != "" {
						sb.WriteString(text)
					}
				}
			}
		}
		return sb.String()
	default:
		return ""
	}
}

// ExtractModel extracts only the model field from a JSON body (provider-agnostic).
func ExtractModel(body []byte) (string, error) {
	var m struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return "", fmt.Errorf("extract model: %w", err)
	}
	return strings.TrimSpace(m.Model), nil
}

// ExtractForProvider returns extracted text and model for the given provider.
func ExtractForProvider(provider string, body []byte) (ExtractedRequest, error) {
	switch provider {
	case "openai", "ollama":
		return ExtractOpenAI(body)
	case "anthropic":
		return ExtractAnthropic(body)
	default:
		return ExtractOpenAI(body)
	}
}

// RedactRequestBody redacts PII in the request body using the classifier.
// Returns the modified JSON body for the given provider format.
func RedactRequestBody(ctx context.Context, provider string, body []byte, scanner *classifier.Scanner) ([]byte, error) {
	if scanner == nil {
		return body, nil
	}
	switch provider {
	case "openai", "ollama":
		return redactOpenAIBody(ctx, body, scanner)
	case "anthropic":
		return redactAnthropicBody(ctx, body, scanner)
	default:
		return redactOpenAIBody(ctx, body, scanner)
	}
}

func redactOpenAIBody(ctx context.Context, body []byte, scanner *classifier.Scanner) ([]byte, error) {
	var req struct {
		Model    string      `json:"model"`
		Messages []openAIMsg `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	for i := range req.Messages {
		req.Messages[i].Content = redactOpenAIContent(ctx, req.Messages[i].Content, scanner)
	}
	return json.Marshal(req)
}

func redactOpenAIContent(ctx context.Context, c interface{}, scanner *classifier.Scanner) interface{} {
	if c == nil {
		return nil
	}
	switch v := c.(type) {
	case string:
		return scanner.Redact(ctx, v)
	case []interface{}:
		out := make([]interface{}, len(v))
		for i, part := range v {
			if m, ok := part.(map[string]interface{}); ok {
				if typ, _ := m["type"].(string); typ == "text" {
					if text, _ := m["text"].(string); text != "" {
						m["text"] = scanner.Redact(ctx, text)
					}
				}
				out[i] = m
			} else {
				out[i] = part
			}
		}
		return out
	default:
		return c
	}
}

func redactAnthropicBody(ctx context.Context, body []byte, scanner *classifier.Scanner) ([]byte, error) {
	var req map[string]interface{}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	if s, ok := req["system"].(string); ok && s != "" {
		req["system"] = scanner.Redact(ctx, s)
	}
	if raw, ok := req["messages"].([]interface{}); ok {
		for _, m := range raw {
			if msg, ok := m.(map[string]interface{}); ok {
				msg["content"] = redactAnthropicContent(ctx, msg["content"], scanner)
			}
		}
	}
	return json.Marshal(req)
}

func redactAnthropicContent(ctx context.Context, c interface{}, scanner *classifier.Scanner) interface{} {
	if c == nil {
		return nil
	}
	if arr, ok := c.([]interface{}); ok {
		out := make([]interface{}, len(arr))
		for i, part := range arr {
			if m, ok := part.(map[string]interface{}); ok {
				if typ, _ := m["type"].(string); typ == "text" {
					if text, _ := m["text"].(string); text != "" {
						m["text"] = scanner.Redact(ctx, text)
					}
				}
				out[i] = m
			} else {
				out[i] = part
			}
		}
		return out
	}
	return c
}
