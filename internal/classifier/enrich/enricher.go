package enrich

import (
	"context"
	"regexp"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/dativo-io/talon/internal/classifier/entity"
	talonotel "github.com/dativo-io/talon/internal/otel"
)

var tracer = talonotel.Tracer("github.com/dativo-io/talon/internal/classifier/enrich")

// Gender values for PERSON entities.
const (
	GenderMale    = "male"
	GenderFemale  = "female"
	GenderNeutral = "neutral"
	GenderUnknown = "unknown"
)

// Scope values for LOCATION entities.
const (
	ScopeCity    = "city"
	ScopeRegion  = "region"
	ScopeCountry = "country"
	ScopeUnknown = "unknown"
)

// Enricher adds semantic attributes (e.g. gender for PERSON, scope for LOCATION)
// to canonical entities. Pluggable so a different provider can be used later.
type Enricher interface {
	Enrich(ctx context.Context, entities []*entity.CanonicalEntity, opts *EnrichOptions) ([]*entity.CanonicalEntity, error)
}

// EnrichOptions configures enrichment behavior.
//
//nolint:revive // EnrichOptions is the public API name; renaming to Options would break callers
type EnrichOptions struct {
	LocaleHint      string
	PreserveTitles  bool
	DefaultGender   string
	DefaultScope    string
	ConfidenceMin   float64
	EmitUnknownAttr bool
}

// BuiltInEnricher implements Enricher with title/honorific and dictionary heuristics.
type BuiltInEnricher struct {
	personTitles  map[string]string // prefix -> gender
	locationDict  map[string]string // normalized name -> scope
	personTitleRe *regexp.Regexp
}

// NewBuiltInEnricher returns an enricher with default PERSON titles and LOCATION dictionary.
func NewBuiltInEnricher() *BuiltInEnricher {
	personTitles := map[string]string{
		"mr": GenderMale, "mister": GenderMale, "herr": GenderMale, "monsieur": GenderMale, "signor": GenderMale, "sr": GenderMale,
		"mrs": GenderFemale, "ms": GenderFemale, "miss": GenderFemale, "frau": GenderFemale, "madame": GenderFemale, "madam": GenderFemale, "mme": GenderFemale, "sra": GenderFemale, "srta": GenderFemale,
	}
	locationDict := map[string]string{}
	for _, c := range knownCities {
		locationDict[strings.ToLower(c)] = ScopeCity
	}
	for _, r := range knownRegions {
		locationDict[strings.ToLower(r)] = ScopeRegion
	}
	for _, c := range knownCountries {
		locationDict[strings.ToLower(c)] = ScopeCountry
	}
	// Title/honorific at start of text or after space: optional period, then space.
	personTitleRe := regexp.MustCompile(`(?i)\b(mr|mrs|ms|miss|mister|herr|frau|madame|madam|monsieur|mme|signor|sra|srta)\.?\s+`)
	return &BuiltInEnricher{
		personTitles:  personTitles,
		locationDict:  locationDict,
		personTitleRe: personTitleRe,
	}
}

// Enrich adds Attributes to entities that support them (person -> gender, location -> scope).
// Does not modify the slice order; may mutate each entity's Attributes map.
//
//nolint:gocyclo // switch on entity type and opts fields; splitting would not reduce complexity meaningfully
func (e *BuiltInEnricher) Enrich(ctx context.Context, entities []*entity.CanonicalEntity, opts *EnrichOptions) ([]*entity.CanonicalEntity, error) {
	if len(entities) == 0 {
		return entities, nil
	}
	_, span := tracer.Start(ctx, "enrich.enrich", trace.WithAttributes(attribute.Int("entity_count", len(entities))))
	defer span.End()

	defaultGender := GenderUnknown
	defaultScope := ScopeUnknown
	confMin := 0.5
	emitUnknown := false
	if opts != nil {
		if opts.DefaultGender != "" {
			defaultGender = opts.DefaultGender
		}
		if opts.DefaultScope != "" {
			defaultScope = opts.DefaultScope
		}
		if opts.ConfidenceMin > 0 {
			confMin = opts.ConfidenceMin
		}
		emitUnknown = opts.EmitUnknownAttr
	}

	for _, ent := range entities {
		if ent == nil {
			continue
		}
		if ent.Attributes == nil {
			ent.Attributes = make(map[string]string)
		}
		switch ent.Type {
		case "person":
			gender, conf, _ := e.enrichPerson(ent.Raw, opts)
			if conf >= confMin {
				if gender != GenderUnknown || emitUnknown {
					ent.Attributes["gender"] = gender
				}
			} else if emitUnknown {
				ent.Attributes["gender"] = defaultGender
			}
		case "location":
			scope, conf := e.enrichLocation(ent.Raw)
			if conf >= confMin {
				if scope != ScopeUnknown || emitUnknown {
					ent.Attributes["scope"] = scope
				}
			} else if emitUnknown {
				ent.Attributes["scope"] = defaultScope
			}
		case "iban":
			if cc := extractIBANCountry(ent.Raw); cc != "" {
				ent.Attributes["country_code"] = cc
			}
		case "phone":
			if cc := extractPhoneCountry(ent.Raw); cc != "" {
				ent.Attributes["country_code"] = cc
			}
		case "email":
			if dt := classifyEmailDomain(ent.Raw); dt != "" {
				ent.Attributes["domain_type"] = dt
			}
		}
	}

	span.SetStatus(codes.Ok, "")
	return entities, nil
}

func (e *BuiltInEnricher) enrichPerson(raw string, opts *EnrichOptions) (gender string, confidence float64, source string) {
	preserveTitles := opts != nil && opts.PreserveTitles
	trimmed := strings.TrimSpace(raw)
	_ = preserveTitles
	// 1) Explicit title / honorific (FindStringIndex returns [start, end], len >= 2 when not nil)
	if idx := e.personTitleRe.FindStringIndex(trimmed); len(idx) >= 2 && idx[0] == 0 {
		// Trim space first (regex captures trailing space), then optional period, so "Mrs. " -> "mrs".
		honorific := strings.TrimSuffix(strings.TrimRight(strings.ToLower(trimmed[idx[0]:idx[1]]), " "), ".")
		if g, ok := e.personTitles[honorific]; ok {
			return g, 0.95, "title"
		}
	}
	// 2) Locale-aware first-name lookup could go here (optional)
	// 3) Otherwise unknown or neutral
	if preserveTitles {
		// Leave as unknown so downstream can still show placeholder
		return GenderUnknown, 0.3, "none"
	}
	return GenderUnknown, 0.3, "none"
}

func (e *BuiltInEnricher) enrichLocation(raw string) (scope string, confidence float64) {
	key := strings.ToLower(strings.TrimSpace(raw))
	if s, ok := e.locationDict[key]; ok {
		return s, 0.9
	}
	return ScopeUnknown, 0.3
}

// extractIBANCountry returns the ISO 3166-1 alpha-2 country code from the first
// two characters of an IBAN (e.g. "DE89370400440532013000" → "DE").
func extractIBANCountry(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.ReplaceAll(s, " ", "")
	if len(s) >= 2 {
		cc := strings.ToUpper(s[:2])
		if cc[0] >= 'A' && cc[0] <= 'Z' && cc[1] >= 'A' && cc[1] <= 'Z' {
			return cc
		}
	}
	return ""
}

// phoneCountryPrefixes maps E.164 dialing prefixes to ISO country codes (EU-focused).
var phoneCountryPrefixes = []struct {
	prefix string
	cc     string
}{
	{"+49", "DE"},
	{"+490", "DE"},
	{"+33", "FR"},
	{"+34", "ES"},
	{"+39", "IT"},
	{"+31", "NL"},
	{"+32", "BE"},
	{"+43", "AT"},
	{"+48", "PL"},
	{"+351", "PT"},
	{"+353", "IE"},
	{"+30", "GR"},
	{"+420", "CZ"},
	{"+40", "RO"},
	{"+36", "HU"},
	{"+46", "SE"},
	{"+45", "DK"},
	{"+358", "FI"},
	{"+47", "NO"},
	{"+44", "GB"},
	{"+41", "CH"},
	{"+352", "LU"},
	{"+372", "EE"},
	{"+371", "LV"},
	{"+370", "LT"},
	{"+385", "HR"},
	{"+386", "SI"},
	{"+421", "SK"},
	{"+359", "BG"},
}

// extractPhoneCountry derives the country code from an E.164-style phone number prefix.
func extractPhoneCountry(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "-", "")
	if !strings.HasPrefix(s, "+") {
		// Try 00-prefixed international format
		if strings.HasPrefix(s, "00") {
			s = "+" + s[2:]
		} else {
			return ""
		}
	}
	// Match longest prefix first (entries with 4-char prefix before 3-char)
	for _, p := range phoneCountryPrefixes {
		if strings.HasPrefix(s, p.prefix) {
			return p.cc
		}
	}
	return ""
}

// freeEmailDomains is a set of well-known free/consumer email providers.
var freeEmailDomains = map[string]bool{
	"gmail.com": true, "googlemail.com": true,
	"yahoo.com": true, "yahoo.de": true, "yahoo.fr": true, "yahoo.co.uk": true,
	"outlook.com": true, "hotmail.com": true, "hotmail.de": true, "hotmail.fr": true,
	"live.com": true, "msn.com": true,
	"aol.com": true, "mail.com": true, "gmx.de": true, "gmx.net": true,
	"web.de": true, "t-online.de": true, "freenet.de": true,
	"protonmail.com": true, "proton.me": true,
	"icloud.com": true, "me.com": true, "mac.com": true,
	"yandex.com": true, "yandex.ru": true,
	"zoho.com": true, "tutanota.com": true, "tuta.io": true,
}

// classifyEmailDomain returns "free" for consumer providers, "corporate" for company domains.
func classifyEmailDomain(raw string) string {
	s := strings.TrimSpace(raw)
	at := strings.LastIndex(s, "@")
	if at < 0 || at >= len(s)-1 {
		return ""
	}
	domain := strings.ToLower(s[at+1:])
	if freeEmailDomains[domain] {
		return "free"
	}
	return "corporate"
}

// Known cities, regions, countries for scope classification (EU-focused subset).
var (
	knownCities = []string{
		"Berlin", "Munich", "Hamburg", "Frankfurt", "Cologne", "Paris", "Lyon", "Marseille", "Madrid", "Barcelona", "Rome", "Milan", "Amsterdam", "Brussels", "Vienna", "Warsaw", "Lisbon", "Dublin", "Athens", "Prague", "Bucharest", "Budapest", "Stockholm", "Copenhagen", "Helsinki", "Oslo", "London", "Manchester", "Birmingham", "Edinburgh", "Zurich", "Geneva",
	}
	knownRegions = []string{
		"Bavaria", "Baden-Württemberg", "Île-de-France", "Catalonia", "Andalusia", "Lombardy", "Tuscany", "Scotland", "Wales", "England", "Flanders", "Wallonia", "Transylvania", "Saxony",
	}
	knownCountries = []string{
		"Germany", "France", "Spain", "Italy", "Netherlands", "Belgium", "Austria", "Poland", "Portugal", "Ireland", "Greece", "Czech Republic", "Romania", "Hungary", "Sweden", "Denmark", "Finland", "Norway", "UK", "United Kingdom", "Switzerland", "EU", "Europe",
	}
)
