package evidence

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	// SignedExportAlgorithm is the algorithm label emitted by signed exports.
	SignedExportAlgorithm = "HMAC-SHA256"

	// Verify statuses for exported evidence records.
	VerifyStatusValid            = "valid"
	VerifyStatusInvalidSignature = "invalid_signature"
	VerifyStatusMissingSignature = "missing_signature"
	VerifyStatusMalformed        = "malformed_record"
	VerifyStatusUnsupported      = "unsupported_record"
)

// SignedExportEnvelope wraps full signed evidence records with export metadata.
type SignedExportEnvelope struct {
	ExportMetadata ExportMetadata `json:"export_metadata"`
	Records        []Evidence     `json:"records"`
}

// RecordVerifyResult is the verification outcome for one exported record.
type RecordVerifyResult struct {
	ID     string `json:"id,omitempty"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// FileVerifyReport summarizes verification outcomes for an exported evidence file.
type FileVerifyReport struct {
	Total            int                  `json:"total_records"`
	Valid            int                  `json:"valid_records"`
	Invalid          int                  `json:"invalid_records"`
	MissingSignature int                  `json:"missing_signature_records"`
	Unparseable      int                  `json:"unparseable_records"`
	Unsupported      int                  `json:"unsupported_records"`
	Records          []RecordVerifyResult `json:"records,omitempty"`
	Hint             string               `json:"hint,omitempty"`
}

// HasFailures returns true when any record is invalid, malformed, missing signature, or unsupported.
func (r FileVerifyReport) HasFailures() bool {
	return r.Invalid > 0 || r.MissingSignature > 0 || r.Unparseable > 0 || r.Unsupported > 0
}

// VerifyExport verifies signed evidence files in signed-json and signed-ndjson formats.
// It can also process a bare JSON array of Evidence records.
func (s *Store) VerifyExport(data []byte) (FileVerifyReport, error) {
	var report FileVerifyReport
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		report.Unsupported = 1
		report.Records = append(report.Records, RecordVerifyResult{
			Status: VerifyStatusUnsupported,
			Detail: "empty file",
		})
		return report, fmt.Errorf("unsupported export format: empty file")
	}

	switch trimmed[0] {
	case '{':
		report, err := s.verifySignedJSON(trimmed)
		if report.Total == 0 && bytes.Contains(trimmed, []byte("\n")) {
			ndReport, ndErr := s.verifyNDJSON(trimmed)
			if ndReport.Total > 0 || ndErr == nil {
				return ndReport, ndErr
			}
		}
		return report, err
	case '[':
		return s.verifyJSONArray(trimmed)
	default:
		return s.verifyNDJSON(trimmed)
	}
}

func (s *Store) verifySignedJSON(data []byte) (FileVerifyReport, error) {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(data, &payload); err != nil {
		return FileVerifyReport{
			Unparseable: 1,
			Records: []RecordVerifyResult{{
				Status: VerifyStatusMalformed,
				Detail: "malformed JSON envelope",
			}},
		}, nil
	}

	recordsRaw, hasRecords := payload["records"]
	if !hasRecords {
		return FileVerifyReport{
			Unsupported: 1,
			Records: []RecordVerifyResult{{
				Status: VerifyStatusUnsupported,
				Detail: "missing records field",
			}},
		}, fmt.Errorf("unsupported export format: missing records field")
	}

	var meta ExportMetadata
	if metaRaw, ok := payload["export_metadata"]; ok {
		_ = json.Unmarshal(metaRaw, &meta)
	}
	if !meta.Signed {
		return FileVerifyReport{
			Unsupported: 1,
			Records: []RecordVerifyResult{{
				Status: VerifyStatusUnsupported,
				Detail: "export_metadata.signed is false or missing",
			}},
		}, fmt.Errorf("unsupported export format: signed metadata missing")
	}

	var rawRecords []json.RawMessage
	if err := json.Unmarshal(recordsRaw, &rawRecords); err != nil {
		return FileVerifyReport{
			Unparseable: 1,
			Records: []RecordVerifyResult{{
				Status: VerifyStatusMalformed,
				Detail: "records field is not a JSON array",
			}},
		}, nil
	}
	report := s.verifyRawRecords(rawRecords)
	report.Total = len(rawRecords)
	report.Hint = verificationHint(report)
	return report, nil
}

func (s *Store) verifyJSONArray(data []byte) (FileVerifyReport, error) {
	var rawRecords []json.RawMessage
	if err := json.Unmarshal(data, &rawRecords); err != nil {
		return FileVerifyReport{
			Unparseable: 1,
			Records: []RecordVerifyResult{{
				Status: VerifyStatusMalformed,
				Detail: "malformed JSON array",
			}},
		}, nil
	}
	report := s.verifyRawRecords(rawRecords)
	report.Total = len(rawRecords)
	report.Hint = verificationHint(report)
	return report, nil
}

func (s *Store) verifyNDJSON(data []byte) (FileVerifyReport, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var rawRecords []json.RawMessage
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		rawRecords = append(rawRecords, json.RawMessage(line))
	}
	if err := scanner.Err(); err != nil {
		return FileVerifyReport{}, fmt.Errorf("reading file: %w", err)
	}
	if len(rawRecords) == 0 {
		return FileVerifyReport{
			Unsupported: 1,
			Records: []RecordVerifyResult{{
				Status: VerifyStatusUnsupported,
				Detail: "no parseable NDJSON lines",
			}},
		}, fmt.Errorf("unsupported export format: empty ndjson")
	}
	report := s.verifyRawRecords(rawRecords)
	report.Total = len(rawRecords)
	report.Hint = verificationHint(report)
	return report, nil
}

func (s *Store) verifyRawRecords(rawRecords []json.RawMessage) FileVerifyReport {
	report := FileVerifyReport{
		Records: make([]RecordVerifyResult, 0, len(rawRecords)),
	}
	for i := range rawRecords {
		ev, status, detail := parseEvidenceRecord(rawRecords[i])
		result := RecordVerifyResult{
			Status: status,
			Detail: detail,
		}

		if ev != nil {
			result.ID = ev.ID
			switch {
			case ev.Signature == "":
				result.Status = VerifyStatusMissingSignature
				result.Detail = "missing signature field"
				report.MissingSignature++
			case s.VerifyRecord(ev):
				result.Status = VerifyStatusValid
				result.Detail = "signature valid"
				report.Valid++
			default:
				result.Status = VerifyStatusInvalidSignature
				result.Detail = "signature does not match record contents"
				report.Invalid++
			}
			report.Records = append(report.Records, result)
			continue
		}

		switch status {
		case VerifyStatusMalformed:
			report.Unparseable++
		case VerifyStatusUnsupported:
			report.Unsupported++
		}
		report.Records = append(report.Records, result)
	}
	return report
}

func parseEvidenceRecord(raw json.RawMessage) (*Evidence, string, string) {
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(raw, &shape); err != nil {
		return nil, VerifyStatusMalformed, "malformed evidence record JSON"
	}

	if !looksLikeEvidence(shape) {
		return nil, VerifyStatusUnsupported, "record does not match signed evidence schema"
	}

	var ev Evidence
	if err := json.Unmarshal(raw, &ev); err != nil {
		return nil, VerifyStatusMalformed, "could not parse evidence record"
	}
	return &ev, VerifyStatusValid, ""
}

func looksLikeEvidence(shape map[string]json.RawMessage) bool {
	_, hasPolicy := shape["policy_decision"]
	_, hasExecution := shape["execution"]
	_, hasTimestamp := shape["timestamp"]
	return hasPolicy && hasExecution && hasTimestamp
}

func verificationHint(report FileVerifyReport) string {
	if report.Total > 0 && report.Valid == 0 && report.Invalid > 0 && report.MissingSignature == 0 && report.Unparseable == 0 && report.Unsupported == 0 {
		return "all signatures failed; check TALON_SIGNING_KEY"
	}
	return ""
}
