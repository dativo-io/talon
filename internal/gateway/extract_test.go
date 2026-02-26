package gateway

import (
	"context"
	"testing"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/stretchr/testify/require"
)

func TestExtractOpenAI(t *testing.T) {
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"Hello world"}]}`)
	got, err := ExtractOpenAI(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.Model != "gpt-4o" {
		t.Errorf("model = %q, want gpt-4o", got.Model)
	}
	if got.Text != "Hello world" {
		t.Errorf("text = %q, want Hello world", got.Text)
	}
}

func TestExtractOpenAI_ArrayContent(t *testing.T) {
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":[{"type":"text","text":"Hi"}]}]}`)
	got, err := ExtractOpenAI(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.Model != "gpt-4o" {
		t.Errorf("model = %q", got.Model)
	}
	if got.Text != "Hi" {
		t.Errorf("text = %q, want Hi", got.Text)
	}
}

func TestExtractAnthropic(t *testing.T) {
	body := []byte(`{"model":"claude-3-5-sonnet","system":"You are helpful.","messages":[{"role":"user","content":[{"type":"text","text":"Hello"}]}]}`)
	got, err := ExtractAnthropic(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.Model != "claude-3-5-sonnet" {
		t.Errorf("model = %q", got.Model)
	}
	if got.Text != "You are helpful.\nHello" && got.Text != "You are helpful.\n\nHello" {
		t.Errorf("text = %q", got.Text)
	}
}

func TestExtractModel(t *testing.T) {
	body := []byte(`{"model":"gpt-4o-mini","messages":[]}`)
	model, err := ExtractModel(body)
	if err != nil {
		t.Fatal(err)
	}
	if model != "gpt-4o-mini" {
		t.Errorf("model = %q", model)
	}
}

func TestExtractForProvider(t *testing.T) {
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"x"}]}`)
	got, err := ExtractForProvider("openai", body)
	if err != nil {
		t.Fatal(err)
	}
	if got.Model != "gpt-4o" || got.Text != "x" {
		t.Errorf("got %+v", got)
	}
	got, err = ExtractForProvider("anthropic", body)
	if err != nil {
		t.Fatal(err)
	}
	if got.Model != "gpt-4o" {
		t.Errorf("model = %q", got.Model)
	}
}

func TestRedactRequestBody(t *testing.T) {
	scanner := classifier.MustNewScanner()
	ctx := context.Background()

	t.Run("openai_no_pii", func(t *testing.T) {
		body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}`)
		redacted, err := RedactRequestBody(ctx, "openai", body, scanner)
		require.NoError(t, err)
		require.NotNil(t, redacted)
		got, _ := ExtractOpenAI(redacted)
		require.Equal(t, "Hello", got.Text)
	})

	t.Run("openai_string_content", func(t *testing.T) {
		body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"My email is test@example.com"}]}`)
		redacted, err := RedactRequestBody(ctx, "openai", body, scanner)
		require.NoError(t, err)
		require.NotNil(t, redacted)
		got, _ := ExtractOpenAI(redacted)
		require.Contains(t, got.Text, "[EMAIL]")
	})

	t.Run("anthropic", func(t *testing.T) {
		body := []byte(`{"model":"claude-3","system":"Help","messages":[{"role":"user","content":[{"type":"text","text":"Hi"}]}]}`)
		redacted, err := RedactRequestBody(ctx, "anthropic", body, scanner)
		require.NoError(t, err)
		require.NotNil(t, redacted)
	})

	t.Run("nil_scanner", func(t *testing.T) {
		body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"x"}]}`)
		redacted, err := RedactRequestBody(ctx, "openai", body, nil)
		require.NoError(t, err)
		require.Equal(t, body, redacted)
	})

	t.Run("responses_api_string_input", func(t *testing.T) {
		body := []byte(`{"model":"gpt-4o","input":"Send report to alice@example.com"}`)
		redacted, err := RedactRequestBody(ctx, "openai", body, scanner)
		require.NoError(t, err)
		got, _ := ExtractOpenAI(redacted)
		require.Contains(t, got.Text, "[EMAIL]")
		require.NotContains(t, got.Text, "alice@example.com")
	})

	t.Run("responses_api_array_input", func(t *testing.T) {
		body := []byte(`{"model":"gpt-4o","input":[{"role":"user","content":"Contact bob@test.eu"}]}`)
		redacted, err := RedactRequestBody(ctx, "openai", body, scanner)
		require.NoError(t, err)
		got, _ := ExtractOpenAI(redacted)
		require.Contains(t, got.Text, "[EMAIL]")
		require.NotContains(t, got.Text, "bob@test.eu")
	})

	t.Run("responses_api_preserves_other_fields", func(t *testing.T) {
		body := []byte(`{"model":"gpt-4o","input":"Email alice@test.com","store":true,"previous_response_id":"rs_abc"}`)
		redacted, err := RedactRequestBody(ctx, "openai", body, scanner)
		require.NoError(t, err)
		require.Contains(t, string(redacted), `"store":true`)
		require.Contains(t, string(redacted), `"previous_response_id":"rs_abc"`)
		require.NotContains(t, string(redacted), "alice@test.com")
	})

	t.Run("responses_api_input_text_blocks", func(t *testing.T) {
		body := []byte(`{"model":"gpt-4o","input":[{"role":"user","content":[{"type":"input_text","text":"Email bob@test.eu now"}]}]}`)
		redacted, err := RedactRequestBody(ctx, "openai", body, scanner)
		require.NoError(t, err)
		require.NotContains(t, string(redacted), "bob@test.eu")
		require.Contains(t, string(redacted), "[EMAIL]")
	})

	t.Run("responses_api_no_content_on_reference_items", func(t *testing.T) {
		body := []byte(`{"model":"gpt-4o","input":[{"type":"item_reference","id":"rs_abc123"},{"role":"user","content":"Email alice@test.com"}],"previous_response_id":"rs_prev"}`)
		redacted, err := RedactRequestBody(ctx, "openai", body, scanner)
		require.NoError(t, err)
		require.NotContains(t, string(redacted), "alice@test.com")
		require.Contains(t, string(redacted), "item_reference")
		require.Contains(t, string(redacted), "rs_abc123")
		require.NotContains(t, string(redacted), `"content":null`, "must not add content:null to items that had no content field")
	})
}

func TestExtractOpenAI_ResponsesAPI(t *testing.T) {
	t.Run("string_input", func(t *testing.T) {
		body := []byte(`{"model":"gpt-4o","input":"What is 2+2?"}`)
		got, err := ExtractOpenAI(body)
		require.NoError(t, err)
		require.Equal(t, "gpt-4o", got.Model)
		require.Equal(t, "What is 2+2?", got.Text)
	})

	t.Run("array_input_with_content_string", func(t *testing.T) {
		body := []byte(`{"model":"gpt-4o","input":[{"role":"user","content":"Hello there"}]}`)
		got, err := ExtractOpenAI(body)
		require.NoError(t, err)
		require.Contains(t, got.Text, "Hello there")
	})

	t.Run("array_input_with_content_blocks", func(t *testing.T) {
		body := []byte(`{"model":"gpt-4o","input":[{"role":"user","content":[{"type":"input_text","text":"Hi from blocks"}]}]}`)
		got, err := ExtractOpenAI(body)
		require.NoError(t, err)
		require.Contains(t, got.Text, "Hi from blocks")
	})

	t.Run("preserves_chat_completions", func(t *testing.T) {
		body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"Still works"}]}`)
		got, err := ExtractOpenAI(body)
		require.NoError(t, err)
		require.Equal(t, "Still works", got.Text)
	})
}
