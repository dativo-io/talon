package evidence

import "github.com/dativo-io/talon/internal/classifier"

// ScannerInfo identifies the scan engine behind a Classification so evidence
// records which engine produced (or failed to produce) the PII verdict.
// Entity types only, never raw PII text or raw engine errors.
type ScannerInfo struct {
	// Engine is the detector identity (e.g. "talon-regex", "presidio-prod").
	Engine string `json:"engine"`
	// Type is the engine type: regex | presidio | http | llm.
	Type string `json:"type"`
	// Version is the operator-declared engine version (or the adapter's
	// prompt version for llm engines).
	Version string `json:"version,omitempty"`
	// ScanDurationMS is the request scan duration, when measured.
	ScanDurationMS int64 `json:"scan_duration_ms,omitempty"`
	// Failure is the adapter failure kind (timeout|transport|status|decode|
	// validation) when a scan failure drove a fail-closed block.
	Failure string `json:"failure,omitempty"`
}

// engineDescriptor is implemented by external scanner adapters.
type engineDescriptor interface {
	Detector() string
	EngineType() string
	EngineVersion() string
}

// NewScannerInfo describes the given scan engine for evidence. Returns nil
// for a nil engine.
func NewScannerInfo(engine classifier.Analyzer) *ScannerInfo {
	if engine == nil {
		return nil
	}
	if d, ok := engine.(engineDescriptor); ok {
		return &ScannerInfo{Engine: d.Detector(), Type: d.EngineType(), Version: d.EngineVersion()}
	}
	return &ScannerInfo{Engine: engine.Detector(), Type: "regex"}
}
