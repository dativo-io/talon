package adapter_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/classifier/adapter"
	"github.com/dativo-io/talon/internal/classifier/presidio"
	"github.com/dativo-io/talon/internal/testutil"
)

// emailResults returns one EMAIL_ADDRESS result covering the first occurrence
// of needle in text, using the given offset encoding ("" mimics stock
// Presidio, which reports codepoint offsets and no encoding field).
func emailResults(text, needle, encoding string, score float64) []presidio.RecognizerResult {
	byteStart := strings.Index(text, needle)
	if byteStart < 0 {
		return nil
	}
	start, end := byteStart, byteStart+len(needle)
	if encoding == "" || encoding == presidio.OffsetEncodingRune {
		start = utf8.RuneCountInString(text[:byteStart])
		end = start + utf8.RuneCountInString(needle)
	}
	return []presidio.RecognizerResult{{
		EntityType:     "EMAIL_ADDRESS",
		Start:          start,
		End:            end,
		Score:          score,
		OffsetEncoding: encoding,
	}}
}

func newAdapter(t *testing.T, cfg adapter.Config) *adapter.HTTPAdapter {
	t.Helper()
	a, err := adapter.New(cfg)
	require.NoError(t, err)
	return a
}

func TestAnalyze_StockPresidioRuneOffsetsOverUnicode(t *testing.T) {
	// Emoji (4 UTF-8 bytes), CJK, and combining sequences before the entity
	// make rune and byte offsets diverge substantially.
	texts := []string{
		"Contact 😀 test@example.com please",
		"名前は久保です。メール test@example.com まで",
		"Hélló test@example.com bye",
	}
	for _, text := range texts {
		srv := testutil.NewPresidioMockServer(t, func(got string) []presidio.RecognizerResult {
			// Stock Presidio: rune offsets, no offset_encoding field.
			return emailResults(got, "test@example.com", "", 1.0)
		})
		a := newAdapter(t, adapter.Config{Type: adapter.TypePresidio, Endpoint: srv.URL})

		cls, err := a.Analyze(context.Background(), text)
		require.NoError(t, err, "text %q", text)
		require.True(t, cls.HasPII)
		require.Len(t, cls.Entities, 1)
		e := cls.Entities[0]
		assert.Equal(t, "email", e.Type)
		assert.Equal(t, "test@example.com", e.Value, "byte-exact relocation for %q", text)
		assert.Equal(t, strings.Index(text, "test@example.com"), e.Position)
	}
}

func TestAnalyze_ByteOffsetsForHTTPType(t *testing.T) {
	text := "Reach 😀 me at test@example.com"
	srv := testutil.NewPresidioMockServer(t, func(got string) []presidio.RecognizerResult {
		return emailResults(got, "test@example.com", presidio.OffsetEncodingByte, 0.9)
	})
	a := newAdapter(t, adapter.Config{Type: adapter.TypeHTTP, Endpoint: srv.URL})

	cls, err := a.Analyze(context.Background(), text)
	require.NoError(t, err)
	require.Len(t, cls.Entities, 1)
	assert.Equal(t, "test@example.com", cls.Entities[0].Value)
}

func TestAnalyze_ExplicitEncodingOverridesTypeDefault(t *testing.T) {
	// An http-type engine that declares rune encoding per result is honored.
	text := "😀 test@example.com"
	srv := testutil.NewPresidioMockServer(t, func(got string) []presidio.RecognizerResult {
		return emailResults(got, "test@example.com", presidio.OffsetEncodingRune, 0.9)
	})
	a := newAdapter(t, adapter.Config{Type: adapter.TypeHTTP, Endpoint: srv.URL})

	cls, err := a.Analyze(context.Background(), text)
	require.NoError(t, err)
	require.Len(t, cls.Entities, 1)
	assert.Equal(t, "test@example.com", cls.Entities[0].Value)
}

func TestAnalyze_ScoreFilterDropsWeakEntities(t *testing.T) {
	text := "mail test@example.com now"
	srv := testutil.NewPresidioMockServer(t, func(got string) []presidio.RecognizerResult {
		return emailResults(got, "test@example.com", presidio.OffsetEncodingByte, 0.3)
	})
	a := newAdapter(t, adapter.Config{Type: adapter.TypeHTTP, Endpoint: srv.URL, MinScore: 0.5})

	cls, err := a.Analyze(context.Background(), text)
	require.NoError(t, err)
	assert.False(t, cls.HasPII)
	assert.Empty(t, cls.Entities)
	assert.Equal(t, 0, cls.Tier)
}

func TestAnalyze_UnknownEntityTypePassthrough(t *testing.T) {
	text := "code PRJ-9931 is internal"
	srv := testutil.NewPresidioMockServer(t, func(string) []presidio.RecognizerResult {
		return []presidio.RecognizerResult{{
			EntityType:     "INTERNAL_PROJECT_CODE",
			Start:          5,
			End:            13,
			Score:          0.95,
			OffsetEncoding: presidio.OffsetEncodingByte,
		}}
	})
	a := newAdapter(t, adapter.Config{Type: adapter.TypeHTTP, Endpoint: srv.URL, Name: "custom-ner"})

	cls, err := a.Analyze(context.Background(), text)
	require.NoError(t, err)
	require.Len(t, cls.Entities, 1)
	assert.Equal(t, "internal_project_code", cls.Entities[0].Type,
		"unknown types pass through lower_snake so policies can match them")
	assert.Equal(t, "PRJ-9931", cls.Entities[0].Value)
	assert.Equal(t, "custom-ner", a.Detector())
}

func TestAnalyze_NoEntities(t *testing.T) {
	srv := testutil.NewPresidioMockServer(t, func(string) []presidio.RecognizerResult { return nil })
	a := newAdapter(t, adapter.Config{Type: adapter.TypePresidio, Endpoint: srv.URL})

	cls, err := a.Analyze(context.Background(), "nothing sensitive here")
	require.NoError(t, err)
	assert.False(t, cls.HasPII)
	assert.NotNil(t, cls.Entities)
}

func TestAnalyze_FailureKinds(t *testing.T) {
	tests := []struct {
		mode string
		kind adapter.Kind
	}{
		{testutil.ScannerFailStatus, adapter.KindStatus},
		{testutil.ScannerFailMalformed, adapter.KindDecode},
		{testutil.ScannerFailBadOffset, adapter.KindValidation},
		{testutil.ScannerFailOversized, adapter.KindValidation},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			srv := testutil.NewFailingScannerServer(t, tt.mode)
			a := newAdapter(t, adapter.Config{Type: adapter.TypePresidio, Endpoint: srv.URL})

			cls, err := a.Analyze(context.Background(), "probe test@example.com")
			require.Error(t, err)
			assert.Nil(t, cls)
			assert.True(t, errors.Is(err, adapter.ErrScannerUnavailable))
			assert.Equal(t, string(tt.kind), adapter.FailureKind(err))
		})
	}
}

func TestAnalyze_Timeout(t *testing.T) {
	srv := testutil.NewFailingScannerServer(t, testutil.ScannerFailTimeout)
	a := newAdapter(t, adapter.Config{
		Type:     adapter.TypePresidio,
		Endpoint: srv.URL,
		Timeout:  50 * time.Millisecond,
	})

	_, err := a.Analyze(context.Background(), "slow scan")
	require.Error(t, err)
	assert.True(t, errors.Is(err, adapter.ErrScannerUnavailable))
	assert.Equal(t, string(adapter.KindTimeout), adapter.FailureKind(err))
}

func TestAnalyze_ContextCancellation(t *testing.T) {
	srv := testutil.NewFailingScannerServer(t, testutil.ScannerFailTimeout)
	a := newAdapter(t, adapter.Config{Type: adapter.TypePresidio, Endpoint: srv.URL})

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	_, err := a.Analyze(ctx, "cancelled scan")
	require.Error(t, err)
	assert.True(t, errors.Is(err, adapter.ErrScannerUnavailable))
}

func TestAnalyze_OneInvalidEntityRejectsWholeResponse(t *testing.T) {
	text := "mail test@example.com now"
	srv := testutil.NewPresidioMockServer(t, func(got string) []presidio.RecognizerResult {
		valid := emailResults(got, "test@example.com", presidio.OffsetEncodingByte, 0.9)
		return append(valid, presidio.RecognizerResult{
			EntityType:     "PHONE_NUMBER",
			Start:          10,
			End:            5, // start > end
			Score:          0.9,
			OffsetEncoding: presidio.OffsetEncodingByte,
		})
	})
	a := newAdapter(t, adapter.Config{Type: adapter.TypeHTTP, Endpoint: srv.URL})

	cls, err := a.Analyze(context.Background(), text)
	require.Error(t, err, "a single invalid entity must reject the entire scan")
	assert.Nil(t, cls)
	assert.Equal(t, string(adapter.KindValidation), adapter.FailureKind(err))
}

func TestAnalyze_UnixDomainSocket(t *testing.T) {
	text := "uds test@example.com scan"
	endpoint := testutil.NewUDSScannerServer(t, func(got string) []presidio.RecognizerResult {
		return emailResults(got, "test@example.com", "", 1.0)
	})
	a := newAdapter(t, adapter.Config{Type: adapter.TypePresidio, Endpoint: endpoint})

	require.NoError(t, a.HealthCheck(context.Background()))

	cls, err := a.Analyze(context.Background(), text)
	require.NoError(t, err)
	require.Len(t, cls.Entities, 1)
	assert.Equal(t, "test@example.com", cls.Entities[0].Value)
}

func TestRedactText_PlaceholderParityWithBuiltin(t *testing.T) {
	text := "Contact 😀 test@example.com please"
	srv := testutil.NewPresidioMockServer(t, func(got string) []presidio.RecognizerResult {
		return emailResults(got, "test@example.com", "", 1.0)
	})
	a := newAdapter(t, adapter.Config{Type: adapter.TypePresidio, Endpoint: srv.URL})

	redacted, err := a.RedactText(context.Background(), text)
	require.NoError(t, err)
	assert.Equal(t, "Contact 😀 [EMAIL] please", redacted)
}

func TestRedactText_EngineFailureReturnsError(t *testing.T) {
	srv := testutil.NewFailingScannerServer(t, testutil.ScannerFailStatus)
	a := newAdapter(t, adapter.Config{Type: adapter.TypePresidio, Endpoint: srv.URL})

	out, err := a.RedactText(context.Background(), "mail test@example.com")
	require.Error(t, err)
	assert.Empty(t, out, "failed redaction must not return the original text")
}

func TestVerifyEgress_ResidualAndFailure(t *testing.T) {
	text := "still has test@example.com inside"
	srv := testutil.NewPresidioMockServer(t, func(got string) []presidio.RecognizerResult {
		return emailResults(got, "test@example.com", "", 1.0)
	})
	a := newAdapter(t, adapter.Config{Type: adapter.TypePresidio, Endpoint: srv.URL})

	err := a.VerifyEgress(context.Background(), text)
	require.Error(t, err)
	assert.True(t, errors.Is(err, classifier.ErrPIIDetected))
	assert.Equal(t, []string{"email"}, classifier.ResidualTypes(err))

	require.NoError(t, a.VerifyEgress(context.Background(), "clean text"))

	failing := testutil.NewFailingScannerServer(t, testutil.ScannerFailStatus)
	b := newAdapter(t, adapter.Config{Type: adapter.TypePresidio, Endpoint: failing.URL})
	err = b.VerifyEgress(context.Background(), "anything")
	require.Error(t, err, "unverifiable egress must fail closed")
	assert.True(t, errors.Is(err, adapter.ErrScannerUnavailable))
}

func TestHealthCheck_FallsBackToAnalyzeProbe(t *testing.T) {
	// An engine with /analyze but no /health endpoint still passes the probe.
	srv := testutil.NewPresidioMockServer(t, func(string) []presidio.RecognizerResult { return nil })
	a := newAdapter(t, adapter.Config{Type: adapter.TypeHTTP, Endpoint: srv.URL + "/missing"})
	require.Error(t, a.HealthCheck(context.Background()), "404 on both endpoints fails")

	analyzeOnly := testutil.NewPresidioMockServer(t, func(string) []presidio.RecognizerResult { return nil })
	b := newAdapter(t, adapter.Config{Type: adapter.TypeHTTP, Endpoint: analyzeOnly.URL})
	assert.NoError(t, b.HealthCheck(context.Background()))
}

func TestNew_RejectsBadEndpoints(t *testing.T) {
	for _, endpoint := range []string{"grpc://x", "unix://", "http://"} {
		_, err := adapter.New(adapter.Config{Type: adapter.TypePresidio, Endpoint: endpoint})
		assert.Error(t, err, endpoint)
	}
}
