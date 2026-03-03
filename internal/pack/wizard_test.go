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
	assert.True(t, ids["langchain"], "langchain should be visible")
	assert.True(t, ids["generic"], "generic should be visible")
	assert.False(t, ids["n8n"], "n8n should be hidden")
	assert.False(t, ids["flowise"], "flowise should be hidden")
}

func TestRegisterPack(t *testing.T) {
	t.Cleanup(resetForTest)

	RegisterPack(PackDescriptor{
		ID:          "crewai",
		DisplayName: "CrewAI",
		Description: "Multi-agent orchestration governance",
		Order:       35,
	})

	packs := ListForWizard()
	found := false
	for _, p := range packs {
		if p.ID == "crewai" {
			found = true
			break
		}
	}
	assert.True(t, found, "registered pack crewai should appear in list")
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
