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
		{"Mrs. title with period", "Mrs. Smith", GenderFemale, true},
		{"Mr title", "Mr Jones", GenderMale, true},
		{"Mr. title with period", "Mr. Jones", GenderMale, true},
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

func TestBuiltInEnricher_IBAN(t *testing.T) {
	e := NewBuiltInEnricher()
	ctx := context.Background()

	tests := []struct {
		name    string
		raw     string
		wantCC  string
		wantSet bool
	}{
		{"DE IBAN", "DE89370400440532013000", "DE", true},
		{"FR IBAN", "FR7630006000011234567890189", "FR", true},
		{"PL IBAN with spaces", "PL 61 1090 1014 0000 0712 1981 2874", "PL", true},
		{"GB IBAN", "GB29NWBK60161331926819", "GB", true},
		{"numeric only", "1234567890", "", false},
		{"empty", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ent := &entity.CanonicalEntity{Id: 1, Type: "iban", Raw: tt.raw, Attributes: make(map[string]string)}
			out, err := e.Enrich(ctx, []*entity.CanonicalEntity{ent}, nil)
			require.NoError(t, err)
			require.Len(t, out, 1)
			if tt.wantSet {
				assert.Equal(t, tt.wantCC, out[0].Attributes["country_code"])
			} else {
				_, has := out[0].Attributes["country_code"]
				assert.False(t, has, "should not set country_code")
			}
		})
	}
}

func TestBuiltInEnricher_Phone(t *testing.T) {
	e := NewBuiltInEnricher()
	ctx := context.Background()

	tests := []struct {
		name    string
		raw     string
		wantCC  string
		wantSet bool
	}{
		{"DE +49", "+49 30 123456", "DE", true},
		{"FR +33", "+33 1 23 45 67 89", "FR", true},
		{"PL +48", "+48-22-123-45-67", "PL", true},
		{"GB +44", "+44 20 7946 0958", "GB", true},
		{"IT +39", "+39 06 1234567", "IT", true},
		{"PT +351", "+351 21 123 4567", "PT", true},
		{"00-prefix DE", "0049 30 123456", "DE", true},
		{"local number", "030 123456", "", false},
		{"empty", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ent := &entity.CanonicalEntity{Id: 1, Type: "phone", Raw: tt.raw, Attributes: make(map[string]string)}
			out, err := e.Enrich(ctx, []*entity.CanonicalEntity{ent}, nil)
			require.NoError(t, err)
			require.Len(t, out, 1)
			if tt.wantSet {
				assert.Equal(t, tt.wantCC, out[0].Attributes["country_code"])
			} else {
				_, has := out[0].Attributes["country_code"]
				assert.False(t, has, "should not set country_code")
			}
		})
	}
}

func TestBuiltInEnricher_Email(t *testing.T) {
	e := NewBuiltInEnricher()
	ctx := context.Background()

	tests := []struct {
		name     string
		raw      string
		wantType string
		wantSet  bool
	}{
		{"gmail free", "user@gmail.com", "free", true},
		{"hotmail free", "someone@hotmail.com", "free", true},
		{"gmx free", "person@gmx.de", "free", true},
		{"protonmail free", "user@protonmail.com", "free", true},
		{"corporate", "j.smith@acme-corp.eu", "corporate", true},
		{"corporate de", "anna@dativo.de", "corporate", true},
		{"no @ sign", "not-an-email", "", false},
		{"empty", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ent := &entity.CanonicalEntity{Id: 1, Type: "email", Raw: tt.raw, Attributes: make(map[string]string)}
			out, err := e.Enrich(ctx, []*entity.CanonicalEntity{ent}, nil)
			require.NoError(t, err)
			require.Len(t, out, 1)
			if tt.wantSet {
				assert.Equal(t, tt.wantType, out[0].Attributes["domain_type"])
			} else {
				_, has := out[0].Attributes["domain_type"]
				assert.False(t, has, "should not set domain_type")
			}
		})
	}
}

func TestBuiltInEnricher_UnknownTypeIgnored(t *testing.T) {
	e := NewBuiltInEnricher()
	ctx := context.Background()
	ent := &entity.CanonicalEntity{Id: 1, Type: "credit_card", Raw: "4111111111111111", Attributes: make(map[string]string)}
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
