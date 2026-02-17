package policy

import (
	"fmt"

	"github.com/dativo-io/talon/internal/classifier"
)

// PIIScannerOptions builds classifier.ScannerOption slice from policy data_classification
// so that enabled_entities, disabled_entities, and custom_recognizers are applied at runtime.
// globalPatternFile is optional (e.g. ~/.talon/patterns.yaml); use "" to skip.
// Call classifier.NewScanner(opts...) to obtain a policy-aware PII scanner.
func PIIScannerOptions(cfg *DataClassificationConfig, globalPatternFile string) ([]classifier.ScannerOption, error) {
	var opts []classifier.ScannerOption
	if cfg == nil {
		if globalPatternFile != "" {
			opts = append(opts, classifier.WithPatternFile(globalPatternFile))
		}
		return opts, nil
	}
	if globalPatternFile != "" {
		opts = append(opts, classifier.WithPatternFile(globalPatternFile))
	}
	if len(cfg.EnabledEntities) > 0 {
		opts = append(opts, classifier.WithEnabledEntities(cfg.EnabledEntities))
	}
	if len(cfg.DisabledEntities) > 0 {
		opts = append(opts, classifier.WithDisabledEntities(cfg.DisabledEntities))
	}
	if len(cfg.CustomRecognizers) > 0 {
		recs := ToClassifierRecognizers(cfg.CustomRecognizers)
		opts = append(opts, classifier.WithCustomRecognizers(recs))
	}
	return opts, nil
}

// NewPIIScannerForPolicy returns a PII scanner configured from the policy's
// data_classification (enabled_entities, disabled_entities, custom_recognizers).
// Use this whenever a Policy is available so per-agent settings are not ignored.
// globalPatternFile is optional (e.g. ~/.talon/patterns.yaml); use "" to skip.
func NewPIIScannerForPolicy(pol *Policy, globalPatternFile string) (*classifier.Scanner, error) {
	var opts []classifier.ScannerOption
	if pol != nil && pol.Policies.DataClassification != nil {
		var err error
		opts, err = PIIScannerOptions(pol.Policies.DataClassification, globalPatternFile)
		if err != nil {
			return nil, fmt.Errorf("policy data_classification: %w", err)
		}
	} else if globalPatternFile != "" {
		opts = []classifier.ScannerOption{classifier.WithPatternFile(globalPatternFile)}
	}
	return classifier.NewScanner(opts...)
}

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
