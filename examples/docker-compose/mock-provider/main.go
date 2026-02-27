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

func main() {
	port := flag.Int("port", 9090, "listen port")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", handleChatCompletions)
	mux.HandleFunc("/v1/models", handleModels)
	mux.HandleFunc("/health", handleHealth)

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Mock OpenAI provider listening on %s", addr)
	log.Printf("  POST /v1/chat/completions  (streaming + non-streaming)")
	log.Printf("  GET  /v1/models")
	log.Printf("  GET  /health")
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
