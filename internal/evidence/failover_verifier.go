package evidence

import (
	"context"
	"fmt"
	"strings"
)

// Failover verifier verdicts (semantic rules layered on top of per-record
// HMAC verification):
//
//   - valid_fallback: failed attempt(s) + fallback decision share the
//     correlation ID, the dispatched provider passed the sovereignty check.
//   - valid_fail_closed: failed attempt(s) and/or policy-skipped candidates
//     with no successful provider dispatch — the governance layer refusing to
//     route (e.g. out of Europe under eu_strict) is a successful outcome.
//   - invalid: fallback was dispatched to a provider the sovereignty policy
//     rejected, or an involved record fails signature verification.
//   - insufficient: evidence records the final provider without the failed
//     attempt and decision context (proves where the answer came from but not
//     why traffic moved there), or attempts exist with no decision record.
const (
	FailoverVerdictValidFallback   = "valid_fallback"
	FailoverVerdictValidFailClosed = "valid_fail_closed"
	FailoverVerdictInvalid         = "invalid"
	FailoverVerdictInsufficient    = "insufficient"
)

// FailoverFinding is the verifier outcome for one correlation ID.
type FailoverFinding struct {
	CorrelationID string   `json:"correlation_id"`
	Verdict       string   `json:"verdict"`
	Details       []string `json:"details,omitempty"`
	EvidenceIDs   []string `json:"evidence_ids,omitempty"`
}

// OK reports whether the finding is a passing verdict.
func (f *FailoverFinding) OK() bool {
	return f.Verdict == FailoverVerdictValidFallback || f.Verdict == FailoverVerdictValidFailClosed
}

// VerifyFailoverChain loads all records sharing a correlation ID and applies
// the failover verifier rules. Returns nil when the correlation ID has no
// failover-related evidence.
func (s *Store) VerifyFailoverChain(ctx context.Context, correlationID string) (*FailoverFinding, error) {
	records, err := s.ListByCorrelationID(ctx, correlationID)
	if err != nil {
		return nil, err
	}
	return VerifyFailoverRecords(correlationID, records, s.VerifyRecord), nil
}

// ListFailoverCorrelationIDs returns correlation IDs that have failover
// evidence, newest first, up to limit.
func (s *Store) ListFailoverCorrelationIDs(ctx context.Context, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT correlation_id FROM evidence
		 WHERE invocation_type IN ('gateway_failover_attempt', 'llm_failover_attempt')
		    OR evidence_json LIKE '%"failover":%'
		 GROUP BY correlation_id
		 ORDER BY MAX(timestamp) DESC
		 LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("querying failover correlation ids: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scanning correlation id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// VerifyFailoverRecords applies the failover verifier rules to the records of
// one correlation ID. verifySig verifies a record's HMAC signature (pass
// Store.VerifyRecord; a nil func skips signature checks — tests only).
// Returns nil when no record carries failover context.
//
//nolint:gocyclo // rule evaluation is a flat sequence of independent checks
func VerifyFailoverRecords(correlationID string, records []*Evidence, verifySig func(*Evidence) bool) *FailoverFinding {
	attempts := map[string]*Evidence{}
	var decisions, failClosed []*Evidence
	var involved []*Evidence
	for _, ev := range records {
		if ev.Failover == nil {
			continue
		}
		involved = append(involved, ev)
		switch ev.Failover.Role {
		case FailoverRoleFailedAttempt:
			attempts[ev.ID] = ev
		case FailoverRoleFallbackDecision:
			decisions = append(decisions, ev)
		case FailoverRoleFailClosed:
			failClosed = append(failClosed, ev)
		}
	}
	if len(involved) == 0 {
		return nil
	}

	finding := &FailoverFinding{CorrelationID: correlationID}
	for _, ev := range involved {
		finding.EvidenceIDs = append(finding.EvidenceIDs, ev.ID)
	}
	worst := ""
	addDetail := func(verdict, detail string) {
		finding.Details = append(finding.Details, detail)
		if verdict == FailoverVerdictInvalid || worst == FailoverVerdictInvalid {
			worst = FailoverVerdictInvalid
			return
		}
		worst = FailoverVerdictInsufficient
	}

	// Rule 0: every involved record must carry a valid signature.
	if verifySig != nil {
		for _, ev := range involved {
			if !verifySig(ev) {
				addDetail(FailoverVerdictInvalid, fmt.Sprintf("record %s fails signature verification", ev.ID))
			}
		}
	}

	checkAttemptRefs := func(ev *Evidence) {
		if len(ev.Failover.FailedAttemptIDs) == 0 {
			addDetail(FailoverVerdictInsufficient,
				fmt.Sprintf("record %s (%s) has no linked failed-attempt records: evidence proves the final provider but not why traffic moved", ev.ID, ev.Failover.Role))
			return
		}
		for _, id := range ev.Failover.FailedAttemptIDs {
			if _, ok := attempts[id]; !ok {
				addDetail(FailoverVerdictInsufficient,
					fmt.Sprintf("record %s references failed attempt %s which is missing from the correlation trail", ev.ID, id))
			}
		}
	}

	// Rule 1+3: fallback decisions must link failed attempts and must not have
	// dispatched to a sovereignty-rejected provider.
	for _, ev := range decisions {
		fc := ev.Failover
		checkAttemptRefs(ev)
		if strings.EqualFold(strings.TrimSpace(fc.SovereigntyMode), "eu_strict") {
			region := strings.ToUpper(strings.TrimSpace(fc.Region))
			if fc.SovereigntyCheck != "allowed" || (region != "EU" && region != "LOCAL") {
				addDetail(FailoverVerdictInvalid,
					fmt.Sprintf("record %s dispatched fallback to provider %s (region %q, sovereignty_check %q) under eu_strict", ev.ID, fc.Provider, fc.Region, fc.SovereigntyCheck))
			}
		}
	}

	// Rule 2: fail-closed outcomes must show why nothing was dispatched
	// (failed attempts and/or policy-skipped candidates).
	for _, ev := range failClosed {
		if len(ev.Failover.FailedAttemptIDs) == 0 && len(ev.Failover.SkippedCandidates) == 0 {
			addDetail(FailoverVerdictInsufficient,
				fmt.Sprintf("fail-closed record %s has neither failed attempts nor skipped candidates", ev.ID))
			continue
		}
		for _, id := range ev.Failover.FailedAttemptIDs {
			if _, ok := attempts[id]; !ok {
				addDetail(FailoverVerdictInsufficient,
					fmt.Sprintf("fail-closed record %s references failed attempt %s which is missing from the correlation trail", ev.ID, id))
			}
		}
	}

	// Rule 4: failed attempts with no decision context are insufficient —
	// the trail shows an error but not the governance outcome.
	if len(decisions) == 0 && len(failClosed) == 0 {
		addDetail(FailoverVerdictInsufficient,
			"failed provider attempt(s) recorded without a fallback decision or fail-closed record")
	}

	if worst != "" {
		finding.Verdict = worst
		return finding
	}
	if len(decisions) > 0 {
		finding.Verdict = FailoverVerdictValidFallback
		return finding
	}
	finding.Verdict = FailoverVerdictValidFailClosed
	return finding
}
