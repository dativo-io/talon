package pack

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListForWizard_ExcludesHidden(t *testing.T) {
	packs := ListForWizard()
	for _, p := range packs {
		assert.False(t, p.Hidden, "hidden pack %q should not appear in wizard list", p.ID)
	}
}

func TestListForWizard_SortedByOrder(t *testing.T) {
	packs := ListForWizard()
	require.NotEmpty(t, packs)
	for i := 1; i < len(packs); i++ {
		assert.LessOrEqual(t, packs[i-1].Order, packs[i].Order,
			"pack %q (order %d) should come before %q (order %d)",
			packs[i-1].ID, packs[i-1].Order, packs[i].ID, packs[i].Order)
	}
}

func TestListForWizard_ContainsExpectedPacks(t *testing.T) {
	packs := ListForWizard()
	ids := make(map[string]bool)
	for _, p := range packs {
		ids[p.ID] = true
	}
	assert.True(t, ids["openclaw"], "openclaw should be visible")
	assert.True(t, ids["copaw"], "copaw should be visible")
	assert.True(t, ids["langchain"], "langchain should be visible")
	assert.True(t, ids["crewai"], "crewai should be visible")
	assert.True(t, ids["generic"], "generic should be visible")
	assert.True(t, ids["fintech-eu"], "fintech-eu should be visible")
	assert.True(t, ids["ecommerce-eu"], "ecommerce-eu should be visible")
	assert.True(t, ids["saas-eu"], "saas-eu should be visible")
	assert.True(t, ids["telecom-eu"], "telecom-eu should be visible")
	assert.False(t, ids["n8n"], "n8n should be hidden")
	assert.False(t, ids["flowise"], "flowise should be hidden")
}

func TestFindByID_CrewAIHasFilesAndPostMessage(t *testing.T) {
	p, ok := FindByID("crewai")
	require.True(t, ok)
	assert.Equal(t, "CrewAI", p.DisplayName)
	assert.Equal(t, "CrewAI", p.Framework)
	assert.NotEmpty(t, p.Files, "crewai pack should have template files")
	assert.NotEmpty(t, p.PostMessage, "crewai pack should have post-init message")
	assert.Len(t, p.Files, 2, "crewai should have agent and config templates")
}

func TestReadComplianceOverlay(t *testing.T) {
	for _, name := range []string{"gdpr", "nis2", "dora", "eu-ai-act"} {
		content, err := ReadComplianceOverlay(name)
		require.NoError(t, err, "overlay %q", name)
		assert.NotEmpty(t, content)
		assert.Contains(t, string(content), "compliance:")
	}
	t.Run("invalid", func(t *testing.T) {
		_, err := ReadComplianceOverlay("invalid")
		assert.Error(t, err)
	})
}

func TestComplianceOverlayNames(t *testing.T) {
	names := ComplianceOverlayNames()
	assert.Equal(t, []string{"gdpr", "nis2", "dora", "eu-ai-act"}, names)
}

func TestRegisterPack(t *testing.T) {
	t.Cleanup(resetForTest)

	RegisterPack(PackDescriptor{
		ID:          "custom-pack",
		DisplayName: "Custom Pack",
		Description: "Custom multi-agent orchestration governance",
		Order:       35,
	})

	packs := ListForWizard()
	found := false
	for _, p := range packs {
		if p.ID == "custom-pack" {
			found = true
			break
		}
	}
	assert.True(t, found, "registered pack custom-pack should appear in list")
}

func TestValidPackIDs(t *testing.T) {
	ids := ValidPackIDs()
	assert.Contains(t, ids, "openclaw")
	assert.Contains(t, ids, "generic")
	assert.NotContains(t, ids, "n8n")
}

func TestFindByID(t *testing.T) {
	t.Run("found builtin", func(t *testing.T) {
		p, ok := FindByID("openclaw")
		assert.True(t, ok)
		assert.Equal(t, "OpenClaw", p.DisplayName)
	})

	t.Run("found hidden", func(t *testing.T) {
		p, ok := FindByID("n8n")
		assert.True(t, ok)
		assert.True(t, p.Hidden)
	})

	t.Run("not found", func(t *testing.T) {
		_, ok := FindByID("nonexistent")
		assert.False(t, ok)
	})

	t.Run("found custom", func(t *testing.T) {
		t.Cleanup(resetForTest)
		RegisterPack(PackDescriptor{ID: "custom-test", DisplayName: "Custom", Order: 99})
		p, ok := FindByID("custom-test")
		assert.True(t, ok)
		assert.Equal(t, "Custom", p.DisplayName)
	})
}
