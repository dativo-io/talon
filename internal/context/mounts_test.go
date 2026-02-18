package context

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/policy"
)

func TestLoadSharedContext_ReadsDirectory(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "info.md"), []byte("# Company Info\nWe are Acme Corp."), 0o644))

	pol := &policy.Policy{
		Context: &policy.ContextConfig{
			SharedMounts: []policy.SharedMount{
				{Name: "company", Path: dir, Classification: "tier_0"},
			},
		},
	}
	sc, err := LoadSharedContext(pol)
	require.NoError(t, err)
	require.Len(t, sc.Mounts, 1)
	assert.Contains(t, sc.Mounts[0].Content, "Acme Corp")
}

func TestLoadSharedContext_StripsPrivateTags(t *testing.T) {
	dir := t.TempDir()
	content := "Public: hello\n<private>secret salary data</private>\nMore public"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "data.md"), []byte(content), 0o644))

	pol := &policy.Policy{
		Context: &policy.ContextConfig{
			SharedMounts: []policy.SharedMount{
				{Name: "hr", Path: dir, Classification: "tier_0"},
			},
		},
	}
	sc, err := LoadSharedContext(pol)
	require.NoError(t, err)
	require.Len(t, sc.Mounts, 1)
	assert.NotContains(t, sc.Mounts[0].Content, "secret salary data")
	assert.Contains(t, sc.Mounts[0].RawContent, "secret salary data")
	assert.Equal(t, 1, sc.Mounts[0].PrivateStripped)
}

func TestLoadSharedContext_ExtractsClassifiedTier(t *testing.T) {
	dir := t.TempDir()
	content := "Data: <classified:tier_1>sensitive info</classified>"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "data.md"), []byte(content), 0o644))

	pol := &policy.Policy{
		Context: &policy.ContextConfig{
			SharedMounts: []policy.SharedMount{
				{Name: "data", Path: dir, Classification: "tier_0"},
			},
		},
	}
	sc, err := LoadSharedContext(pol)
	require.NoError(t, err)
	require.Len(t, sc.Mounts, 1)
	assert.Equal(t, 1, sc.Mounts[0].Classification)
}

func TestLoadSharedContext_TierPropagation(t *testing.T) {
	dir := t.TempDir()
	content := "Data: <classified:tier_2>highly classified</classified>"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "data.md"), []byte(content), 0o644))

	pol := &policy.Policy{
		Context: &policy.ContextConfig{
			SharedMounts: []policy.SharedMount{
				{Name: "data", Path: dir, Classification: "tier_0"},
			},
		},
	}
	sc, err := LoadSharedContext(pol)
	require.NoError(t, err)
	assert.Equal(t, 2, sc.Mounts[0].Classification)
}

func TestLoadSharedContext_SkipsNonTextFiles(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "image.png"), []byte("fake png"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "doc.md"), []byte("# Document"), 0o644))

	pol := &policy.Policy{
		Context: &policy.ContextConfig{
			SharedMounts: []policy.SharedMount{
				{Name: "docs", Path: dir, Classification: "tier_0"},
			},
		},
	}
	sc, err := LoadSharedContext(pol)
	require.NoError(t, err)
	require.Len(t, sc.Mounts, 1)
	assert.Contains(t, sc.Mounts[0].Content, "Document")
	assert.NotContains(t, sc.Mounts[0].Content, "fake png")
}

func TestLoadSharedContext_MissingPath(t *testing.T) {
	pol := &policy.Policy{
		Context: &policy.ContextConfig{
			SharedMounts: []policy.SharedMount{
				{Name: "missing", Path: "/nonexistent/path/abc", Classification: "tier_0"},
			},
		},
	}
	_, err := LoadSharedContext(pol)
	assert.Error(t, err)
}

func TestFormatForPrompt_IncludesAllMounts(t *testing.T) {
	sc := &SharedContext{
		Mounts: []Mount{
			{Name: "company", RawContent: "Company info here", Description: "About us"},
			{Name: "procedures", RawContent: "Step 1: do this"},
		},
	}
	prompt := sc.FormatForPrompt()
	assert.Contains(t, prompt, "[SHARED ENTERPRISE CONTEXT]")
	assert.Contains(t, prompt, "--- company ---")
	assert.Contains(t, prompt, "(About us)")
	assert.Contains(t, prompt, "Company info here")
	assert.Contains(t, prompt, "--- procedures ---")
	assert.Contains(t, prompt, "Step 1: do this")
}

func TestGetMaxTier(t *testing.T) {
	sc := &SharedContext{
		Mounts: []Mount{
			{Name: "a", Classification: 0},
			{Name: "b", Classification: 2},
			{Name: "c", Classification: 1},
		},
	}
	assert.Equal(t, 2, sc.GetMaxTier())
}
