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
}
