package evidence

// Response-scan enforcement kinds (#476). They state whether Talon could
// still have changed what the client received when the scan ran.
const (
	// ResponseScanEnforcementPostDelivery: the response was streamed to the
	// client as it arrived and scanned afterwards. Observation only — the
	// bytes were already delivered when the result was known.
	ResponseScanEnforcementPostDelivery = "post_delivery_observation"
	// ResponseScanEnforcementObservation: the (non-streaming) response was
	// scanned before the write, but the configured action never alters or
	// withholds it (warn).
	ResponseScanEnforcementObservation = "observation"
	// ResponseScanEnforcementPreventive: the response was held until the
	// scan verdict and could be redacted or withheld (redact/block).
	ResponseScanEnforcementPreventive = "preventive"
)

// Response-scan status values.
const (
	ResponseScanStatusComplete   = "complete"
	ResponseScanStatusIncomplete = "incomplete"
)

// Response-scan incomplete reasons: why the scan does not cover the whole
// model response. An incomplete scan with no PII found is not a clean scan.
const (
	ResponseScanIncompleteScannerUnavailable   = "scanner_unavailable"
	ResponseScanIncompleteClientCancelled      = "client_cancelled"
	ResponseScanIncompleteUpstreamError        = "upstream_error"
	ResponseScanIncompleteCaptureLimitExceeded = "capture_limit_exceeded"
	ResponseScanIncompleteNoTextContent        = "no_text_content"
)

// ResponseScan records how the response-side PII control was applied to
// this request (#476, spec 1.10). It exists so a post-delivery observation
// can never be read as preventive protection: `enforcement` says whether
// Talon could still change what the client received, `status` says whether
// the scan covered the whole model output. `output_pii_detected` /
// `output_pii_types` keep describing what was actually found; when `status`
// is `incomplete` their absence means "not fully observed", never "clean".
// Omitted on records that predate spec 1.10 and when the response action is
// allow (no response scan runs).
type ResponseScan struct {
	// Action is the configured response_pii_action: warn | redact | block.
	Action string `json:"action"`
	// Enforcement is one of the ResponseScanEnforcement* values.
	Enforcement string `json:"enforcement"`
	// Streamed is true when the upstream answered with an SSE stream.
	Streamed bool `json:"streamed,omitempty"`
	// Status is complete or incomplete.
	Status string `json:"status"`
	// IncompleteReason is set when Status is incomplete.
	IncompleteReason string `json:"incomplete_reason,omitempty"`
	// BytesObserved is the number of streamed response bytes the bounded
	// observation captured (post-delivery observation only).
	BytesObserved int64 `json:"bytes_observed,omitempty"`
	// CaptureLimit is the observation capture bound in bytes (post-delivery
	// observation only).
	CaptureLimit int64 `json:"capture_limit,omitempty"`
}

// ResponsePIIRedacted reports whether the response content of this record was
// redacted before release. Records carrying response_scan (spec 1.10) answer
// from it; older records answer from the signed data-flow disposition of the
// response item, and records without either fall back to the pre-1.10
// reading of output_pii_detected (which could not tell warn from redact).
func (c *Classification) ResponsePIIRedacted(df *DataFlow) bool {
	if c == nil || !c.OutputPIIDetected {
		return false
	}
	if rs := c.ResponseScan; rs != nil {
		return rs.Enforcement == ResponseScanEnforcementPreventive && rs.Action == "redact"
	}
	if df != nil {
		for i := range df.Items {
			if df.Items[i].Source == FlowSourceResponse {
				return df.Items[i].Disposition == FlowDispositionRedacted
			}
		}
	}
	return true
}

// ResponsePIIObserved reports whether response PII was detected but the
// response was delivered unchanged (warn): observation, not enforcement.
func (c *Classification) ResponsePIIObserved(df *DataFlow) bool {
	if c == nil || !c.OutputPIIDetected {
		return false
	}
	if rs := c.ResponseScan; rs != nil {
		return rs.Enforcement != ResponseScanEnforcementPreventive
	}
	if df != nil {
		for i := range df.Items {
			if df.Items[i].Source == FlowSourceResponse {
				return df.Items[i].Disposition == FlowDispositionSurfaced
			}
		}
	}
	return false
}
