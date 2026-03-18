package enrich

import (
	"context"
	"testing"

	"github.com/dativo-io/talon/internal/classifier/entity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuiltInEnricher_Person(t *testing.T) {
	e := NewBuiltInEnricher()
	ctx := context.Background()
	opts := &EnrichOptions{ConfidenceMin: 0.5, EmitUnknownAttr: false}

	tests := []struct {
		name       string
		raw        string
		wantGender string
		wantSet    bool
	}{
		{"Mrs title", "Mrs Smith", GenderFemale, true},
		{"Mr title", "Mr Jones", GenderMale, true},
		{"Herr title", "Herr Müller", GenderMale, true},
		{"Frau title", "Frau Schmidt", GenderFemale, true},
		{"Mme title", "Mme Dupont", GenderFemale, true},
		{"no title", "Jane Doe", GenderUnknown, false},
		{"empty", "", GenderUnknown, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ent := &entity.CanonicalEntity{Id: 1, Type: "person", Raw: tt.raw, Attributes: make(map[string]string)}
			out, err := e.Enrich(ctx, []*entity.CanonicalEntity{ent}, opts)
			require.NoError(t, err)
			require.Len(t, out, 1)
			if tt.wantSet {
				assert.Equal(t, tt.wantGender, out[0].Attributes["gender"], "gender")
			} else {
				_, has := out[0].Attributes["gender"]
				assert.False(t, has, "should not set gender")
			}
		})
	}
}

func TestBuiltInEnricher_Location(t *testing.T) {
	e := NewBuiltInEnricher()
	ctx := context.Background()
	opts := &EnrichOptions{ConfidenceMin: 0.5}

	tests := []struct {
		name      string
		raw       string
		wantScope string
		wantSet   bool
	}{
		{"city Berlin", "Berlin", ScopeCity, true},
		{"city Paris", "Paris", ScopeCity, true},
		{"region Bavaria", "Bavaria", ScopeRegion, true},
		{"country Germany", "Germany", ScopeCountry, true},
		{"unknown place", "Nowhereville", ScopeUnknown, false},
		{"empty", "", ScopeUnknown, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ent := &entity.CanonicalEntity{Id: 1, Type: "location", Raw: tt.raw, Attributes: make(map[string]string)}
			out, err := e.Enrich(ctx, []*entity.CanonicalEntity{ent}, opts)
			require.NoError(t, err)
			require.Len(t, out, 1)
			if tt.wantSet {
				assert.Equal(t, tt.wantScope, out[0].Attributes["scope"], "scope")
			} else {
				_, has := out[0].Attributes["scope"]
				assert.False(t, has, "should not set scope")
			}
		})
	}
}

func TestBuiltInEnricher_OtherTypeIgnored(t *testing.T) {
	e := NewBuiltInEnricher()
	ctx := context.Background()
	ent := &entity.CanonicalEntity{Id: 1, Type: "email", Raw: "a@b.com", Attributes: make(map[string]string)}
	out, err := e.Enrich(ctx, []*entity.CanonicalEntity{ent}, nil)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Empty(t, out[0].Attributes)
}

func TestBuiltInEnricher_EmptyInput(t *testing.T) {
	e := NewBuiltInEnricher()
	ctx := context.Background()
	out, err := e.Enrich(ctx, nil, nil)
	require.NoError(t, err)
	assert.Nil(t, out)
	out, err = e.Enrich(ctx, []*entity.CanonicalEntity{}, nil)
	require.NoError(t, err)
	assert.Empty(t, out)
}
