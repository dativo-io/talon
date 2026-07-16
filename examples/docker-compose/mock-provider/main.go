// Standalone mock OpenAI-compatible server for demos.
// Returns canned responses with realistic token counts so evidence trails look real.
// Supports both streaming (SSE) and non-streaming modes.
//
// Usage: go run main.go [-port 9090]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

type chatRequest struct {
	Model    string    `json:"model"`
	Messages []message `json:"messages"`
	Stream   bool      `json:"stream"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []choice `json:"choices"`
	Usage   usage    `json:"usage"`
}

type choice struct {
	Index        int     `json:"index"`
	Message      message `json:"message"`
	FinishReason string  `json:"finish_reason"`
}

type usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

var cannedResponses = map[string]string{
	"reset":   "I can help you reset your password. For security, I'll send a reset link to your registered email address. Please check your inbox in the next few minutes.",
	"summary": "Here's a summary of the key trends in European AI regulation: The EU AI Act establishes a risk-based framework classifying AI systems into four categories. High-risk systems face strict requirements including conformity assessments and human oversight.",
	"default": "I'd be happy to help with that. Based on the information provided, here are my recommendations. Please note that this is a mock response for demonstration purposes — no real LLM was called.",
}

func pickResponse(messages []message) string {
	if len(messages) == 0 {
		return cannedResponses["default"]
	}
	last := strings.ToLower(messages[len(messages)-1].Content)
	for keyword, resp := range cannedResponses {
		if strings.Contains(last, keyword) {
			return resp
		}
	}
	return cannedResponses["default"]
}

func estimateTokens(text string) int {
	words := len(strings.Fields(text))
	return int(float64(words) * 1.3)
}

func handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":{"message":"Method not allowed","type":"invalid_request_error"}}`, http.StatusMethodNotAllowed)
		return
	}

	var req chatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":{"message":"Invalid JSON: %s","type":"invalid_request_error"}}`, err), http.StatusBadRequest)
		return
	}

	content := pickResponse(req.Messages)
	model := req.Model
	if model == "" {
		model = "gpt-4o-mini"
	}

	promptTokens := 0
	for _, m := range req.Messages {
		promptTokens += estimateTokens(m.Content)
	}
	completionTokens := estimateTokens(content)

	id := fmt.Sprintf("chatcmpl-mock-%d", time.Now().UnixNano()%100000)

	if req.Stream {
		handleStreaming(w, id, model, content, promptTokens, completionTokens)
		return
	}

	resp := chatResponse{
		ID:      id,
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   model,
		Choices: []choice{{
			Index:        0,
			Message:      message{Role: "assistant", Content: content},
			FinishReason: "stop",
		}},
		Usage: usage{
			PromptTokens:     promptTokens,
			CompletionTokens: completionTokens,
			TotalTokens:      promptTokens + completionTokens,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleStreaming(w http.ResponseWriter, id, model, content string, promptTokens, completionTokens int) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	words := strings.Fields(content)
	for i, word := range words {
		delta := word
		if i < len(words)-1 {
			delta += " "
		}
		chunk := map[string]interface{}{
			"id":      id,
			"object":  "chat.completion.chunk",
			"created": time.Now().Unix(),
			"model":   model,
			"choices": []map[string]interface{}{
				{
					"index": 0,
					"delta": map[string]string{
						"content": delta,
					},
					"finish_reason": nil,
				},
			},
		}
		data, _ := json.Marshal(chunk)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
		time.Sleep(30 * time.Millisecond)
	}

	// Final chunk with finish_reason and usage
	finalChunk := map[string]interface{}{
		"id":      id,
		"object":  "chat.completion.chunk",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": []map[string]interface{}{
			{
				"index":         0,
				"delta":         map[string]string{},
				"finish_reason": "stop",
			},
		},
		"usage": map[string]int{
			"prompt_tokens":     promptTokens,
			"completion_tokens": completionTokens,
			"total_tokens":      promptTokens + completionTokens,
		},
	}
	data, _ := json.Marshal(finalChunk)
	fmt.Fprintf(w, "data: %s\n\n", data)
	fmt.Fprintf(w, "data: [DONE]\n\n")
	flusher.Flush()
}

func handleModels(w http.ResponseWriter, r *http.Request) {
	models := map[string]interface{}{
		"object": "list",
		"data": []map[string]interface{}{
			{"id": "gpt-4o", "object": "model", "owned_by": "mock-provider"},
			{"id": "gpt-4o-mini", "object": "model", "owned_by": "mock-provider"},
			{"id": "gpt-4-turbo", "object": "model", "owned_by": "mock-provider"},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","provider":"mock-openai"}`)
}

// reqCounter makes mock IDs deterministic per process run (msg_mock_000001,
// resp_mock_000001, ...) so demo transcripts are reproducible.
var reqCounter atomic.Int64

func nextID(prefix string) string {
	return fmt.Sprintf("%s_mock_%06d", prefix, reqCounter.Add(1))
}

// ---- Anthropic Messages API (wire family: anthropic) ----------------------
//
// Shapes mirror internal/gateway/testdata/conformance/anthropic fixtures:
// non-streaming usage carries input/cache_creation/cache_read/output tokens;
// streaming emits message_start (usage incl. cache counts) ->
// content_block_delta* -> message_delta (output_tokens) -> message_stop.

type anthropicRequest struct {
	Model    string    `json:"model"`
	Messages []message `json:"messages"`
	Stream   bool      `json:"stream"`
}

func anthropicUsage(promptTokens int) map[string]int {
	// Fixed cache counts keep the demo deterministic: every request "writes"
	// 120 cache tokens and "reads" 2048 — enough to show cache-aware pricing
	// (cache_read_tokens > 0, pricing_basis table) in signed evidence.
	return map[string]int{
		"input_tokens":                promptTokens,
		"cache_creation_input_tokens": 120,
		"cache_read_input_tokens":     2048,
	}
}

func handleAnthropicMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"type":"error","error":{"type":"invalid_request_error","message":"Method not allowed"}}`, http.StatusMethodNotAllowed)
		return
	}
	// Fault injection (-fail-first N): the first N requests to this endpoint fail
	// with -fail-status, mimicking a transient provider outage (Anthropic's real
	// overloaded_error shape). Lets tests prove the demo's recorder-level retry
	// absorbs exactly the failure seen in the field (HTTP 529 "Overloaded").
	if n := failCount.Add(1); *failFirst > 0 && n <= int64(*failFirst) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(*failStatus)
		fmt.Fprintf(w, `{"type":"error","error":{"type":"overloaded_error","message":"Overloaded (mock fault %d of %d)"}}`, n, *failFirst)
		return
	}
	var req anthropicRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"type":"error","error":{"type":"invalid_request_error","message":"Invalid JSON: %s"}}`, err), http.StatusBadRequest)
		return
	}
	content := pickResponse(req.Messages)
	model := req.Model
	if model == "" {
		model = "claude-sonnet-5"
	}
	promptTokens := 0
	for _, m := range req.Messages {
		promptTokens += estimateTokens(m.Content)
	}
	outputTokens := estimateTokens(content)
	id := nextID("msg")

	if req.Stream {
		handleAnthropicStreaming(w, id, model, content, promptTokens, outputTokens)
		return
	}

	usage := anthropicUsage(promptTokens)
	usage["output_tokens"] = outputTokens
	resp := map[string]interface{}{
		"id":            id,
		"type":          "message",
		"role":          "assistant",
		"model":         model,
		"content":       []map[string]string{{"type": "text", "text": content}},
		"stop_reason":   "end_turn",
		"stop_sequence": nil,
		"usage":         usage,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func sseEvent(w http.ResponseWriter, flusher http.Flusher, event string, payload interface{}) {
	data, _ := json.Marshal(payload)
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
	flusher.Flush()
}

func handleAnthropicStreaming(w http.ResponseWriter, id, model, content string, promptTokens, outputTokens int) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")

	startUsage := anthropicUsage(promptTokens)
	startUsage["output_tokens"] = 1
	sseEvent(w, flusher, "message_start", map[string]interface{}{
		"type": "message_start",
		"message": map[string]interface{}{
			"id": id, "type": "message", "role": "assistant", "model": model,
			"content": []interface{}{}, "stop_reason": nil, "usage": startUsage,
		},
	})
	sseEvent(w, flusher, "content_block_start", map[string]interface{}{
		"type": "content_block_start", "index": 0,
		"content_block": map[string]string{"type": "text", "text": ""},
	})
	words := strings.Fields(content)
	for i, word := range words {
		delta := word
		if i < len(words)-1 {
			delta += " "
		}
		sseEvent(w, flusher, "content_block_delta", map[string]interface{}{
			"type": "content_block_delta", "index": 0,
			"delta": map[string]string{"type": "text_delta", "text": delta},
		})
		time.Sleep(5 * time.Millisecond)
	}
	sseEvent(w, flusher, "content_block_stop", map[string]interface{}{"type": "content_block_stop", "index": 0})
	sseEvent(w, flusher, "message_delta", map[string]interface{}{
		"type":  "message_delta",
		"delta": map[string]interface{}{"stop_reason": "end_turn", "stop_sequence": nil},
		"usage": map[string]int{"output_tokens": outputTokens},
	})
	sseEvent(w, flusher, "message_stop", map[string]interface{}{"type": "message_stop"})
}

// ---- OpenAI Responses API (wire family: openai, Codex-style) ---------------
//
// Shapes mirror internal/gateway/testdata/conformance/responses fixtures:
// usage rides the terminal response.completed event (nested under response),
// with cached tokens as a SUBSET in input_tokens_details.cached_tokens.

type responsesRequest struct {
	Model  string      `json:"model"`
	Input  interface{} `json:"input"`
	Stream bool        `json:"stream"`
	Store  *bool       `json:"store"`
}

func responsesInputText(in interface{}) string {
	switch v := in.(type) {
	case string:
		return v
	case []interface{}:
		var b strings.Builder
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok {
				if c, ok := m["content"].(string); ok {
					b.WriteString(c + " ")
				}
			}
		}
		return b.String()
	default:
		return ""
	}
}

func handleResponses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":{"message":"Method not allowed","type":"invalid_request_error"}}`, http.StatusMethodNotAllowed)
		return
	}
	var req responsesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":{"message":"Invalid JSON: %s","type":"invalid_request_error"}}`, err), http.StatusBadRequest)
		return
	}
	inputText := responsesInputText(req.Input)
	content := pickResponse([]message{{Role: "user", Content: inputText}})
	model := req.Model
	if model == "" {
		model = "gpt-5.3-codex"
	}
	inputTokens := estimateTokens(inputText)
	if inputTokens < 16 {
		inputTokens = 16
	}
	outputTokens := estimateTokens(content)
	id := nextID("resp")
	store := false
	if req.Store != nil {
		store = *req.Store
	}

	usage := map[string]interface{}{
		"input_tokens":         inputTokens,
		"input_tokens_details": map[string]int{"cached_tokens": 16}, // subset of input
		"output_tokens":        outputTokens,
		"total_tokens":         inputTokens + outputTokens,
	}
	response := map[string]interface{}{
		"id": id, "object": "response", "status": "completed", "model": model,
		"store": store,
		"output": []map[string]interface{}{{
			"type": "message", "role": "assistant", "status": "completed",
			"content": []map[string]interface{}{{"type": "output_text", "text": content, "annotations": []interface{}{}}},
		}},
		"usage": usage,
	}

	if req.Stream {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		sseEvent(w, flusher, "response.created", map[string]interface{}{
			"type": "response.created", "response": map[string]interface{}{"id": id, "status": "in_progress"},
		})
		words := strings.Fields(content)
		for i, word := range words {
			delta := word
			if i < len(words)-1 {
				delta += " "
			}
			sseEvent(w, flusher, "response.output_text.delta", map[string]interface{}{
				"type": "response.output_text.delta", "delta": delta,
			})
			time.Sleep(5 * time.Millisecond)
		}
		sseEvent(w, flusher, "response.completed", map[string]interface{}{
			"type": "response.completed", "response": response,
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

var (
	failFirst  *int
	failStatus *int
	failCount  atomic.Int64
)

func main() {
	port := flag.Int("port", 9090, "listen port")
	failFirst = flag.Int("fail-first", 0, "fail the first N /v1/messages requests (transient-outage fault injection)")
	failStatus = flag.Int("fail-status", 529, "HTTP status for injected /v1/messages failures")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", handleChatCompletions)
	mux.HandleFunc("/v1/messages", handleAnthropicMessages)
	mux.HandleFunc("/v1/responses", handleResponses)
	mux.HandleFunc("/v1/models", handleModels)
	mux.HandleFunc("/health", handleHealth)

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Mock multi-wire provider listening on %s", addr)
	log.Printf("  POST /v1/chat/completions  (OpenAI Chat, streaming + non-streaming)")
	log.Printf("  POST /v1/messages          (Anthropic Messages, streaming + non-streaming, cache usage)")
	log.Printf("  POST /v1/responses         (OpenAI Responses, streaming + non-streaming, cached_tokens)")
	log.Printf("  GET  /v1/models")
	log.Printf("  GET  /health")
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
