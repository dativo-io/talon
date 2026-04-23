package health

import (
	"sync"
	"time"
)

// EvidenceWriteStatus is a process-level health snapshot for evidence writes.
type EvidenceWriteStatus struct {
	OK            bool      `json:"ok"`
	LastGoodWrite time.Time `json:"last_good_write,omitempty"`
	LastErrorAt   time.Time `json:"last_error_at,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
}

var (
	evidenceWriteMu     sync.RWMutex
	evidenceWriteStatus = EvidenceWriteStatus{OK: true}
)

// MarkEvidenceWriteSuccess marks the evidence subsystem as healthy.
func MarkEvidenceWriteSuccess(at time.Time) {
	evidenceWriteMu.Lock()
	defer evidenceWriteMu.Unlock()
	evidenceWriteStatus.OK = true
	evidenceWriteStatus.LastGoodWrite = at.UTC()
}

// MarkEvidenceWriteFailure marks the evidence subsystem as degraded.
func MarkEvidenceWriteFailure(at time.Time, err error) {
	evidenceWriteMu.Lock()
	defer evidenceWriteMu.Unlock()
	evidenceWriteStatus.OK = false
	evidenceWriteStatus.LastErrorAt = at.UTC()
	if err != nil {
		evidenceWriteStatus.LastError = err.Error()
	}
}

// GetEvidenceWriteStatus returns a copy of current evidence write status.
func GetEvidenceWriteStatus() EvidenceWriteStatus {
	evidenceWriteMu.RLock()
	defer evidenceWriteMu.RUnlock()
	return evidenceWriteStatus
}

// ResetEvidenceWriteStatusForTest resets global status for deterministic tests.
func ResetEvidenceWriteStatusForTest() {
	evidenceWriteMu.Lock()
	defer evidenceWriteMu.Unlock()
	evidenceWriteStatus = EvidenceWriteStatus{OK: true}
}
