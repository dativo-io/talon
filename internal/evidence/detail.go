package evidence

import (
	"context"
	"time"
)

// IndexOf projects one full record to its Index row, the same projection
// ListIndex applies in SQL-backed listings. Timeline views built from
// ListBySessionID use it so a session's rows and the global list never
// disagree about a record.
func IndexOf(ev *Evidence) Index { return toIndex(ev) }

// Verification is the outcome of checking one record's HMAC signature at
// read time. Signed and verified are different facts: every stored record is
// signed; State says whether that signature still matches the record.
type Verification struct {
	State     string    `json:"state"` // valid | invalid
	CheckedAt time.Time `json:"checked_at"`
}

// RecordDetail is the `talon audit show` contract and the console's evidence
// detail: the full record plus the verification performed for this read.
type RecordDetail struct {
	Record       *Evidence    `json:"record"`
	Verification Verification `json:"verification"`
}

// Valid reports whether the signature verified.
func (d *RecordDetail) Valid() bool { return d.Verification.State == "valid" }

// Detail fetches one record and verifies its signature.
func (s *Store) Detail(ctx context.Context, id string) (*RecordDetail, error) {
	ev, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	state := "invalid"
	if s.VerifyRecord(ev) {
		state = "valid"
	}
	return &RecordDetail{Record: ev, Verification: Verification{State: state, CheckedAt: time.Now().UTC()}}, nil
}
