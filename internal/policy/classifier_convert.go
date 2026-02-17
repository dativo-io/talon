package policy

import (
	"github.com/dativo-io/talon/internal/classifier"
)

// ToClassifierRecognizers converts policy custom recognizers (e.g. from
// .talon.yaml data_classification.custom_recognizers) into classifier.RecognizerConfig.
// When a pattern's score is omitted (0), Score is set to nil so the classifier
// uses DefaultMinScore and the pattern is not filtered out by the scanner.
func ToClassifierRecognizers(custom []CustomRecognizerConfig) []classifier.RecognizerConfig {
	if len(custom) == 0 {
		return nil
	}
	out := make([]classifier.RecognizerConfig, 0, len(custom))
	for i := range custom {
		c := &custom[i]
		patterns := make([]classifier.PatternConfig, 0, len(c.Patterns))
		for j := range c.Patterns {
			p := &c.Patterns[j]
			pc := classifier.PatternConfig{
				Name:  p.Name,
				Regex: p.Regex,
			}
			if p.Score > 0 {
				s := p.Score
				pc.Score = &s
			}
			// else Score stays nil → classifier uses DefaultMinScore at compile time
			patterns = append(patterns, pc)
		}
		out = append(out, classifier.RecognizerConfig{
			Name:            c.Name,
			SupportedEntity: c.SupportedEntity,
			Patterns:        patterns,
			Sensitivity:     c.Sensitivity,
		})
	}
	return out
}
