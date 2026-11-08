package session

import (
	"sort"

	"github.com/dativo-io/talon/internal/evidence"
)

// Timeline is the `talon audit list --session --json` contract and the
// console's session timeline: the shared summary plus every record of the
// session as an Index row, in source-time order (timestamp ascending, id as
// the tie-break). Records are not interpreted: a denied tool action, a
// provider sub-attempt and an allowed request each keep their own
// invocation_type, decision and error flag.
type Timeline struct {
	Summary evidence.SessionSummary `json:"summary"`
	Records []evidence.Index        `json:"records"`
}

// BuildTimeline projects records (all sharing sessionID, already scoped to
// what the reader may see) into a Timeline. Nil records are skipped; the
// output is deterministic for any input order.
func BuildTimeline(sessionID string, records []*evidence.Evidence) Timeline {
	rows := make([]evidence.Index, 0, len(records))
	for _, r := range records {
		if r == nil {
			continue
		}
		rows = append(rows, evidence.IndexOf(r))
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if !rows[i].Timestamp.Equal(rows[j].Timestamp) {
			return rows[i].Timestamp.Before(rows[j].Timestamp)
		}
		return rows[i].ID < rows[j].ID
	})
	return Timeline{Summary: evidence.BuildSessionSummary(sessionID, records), Records: rows}
}
