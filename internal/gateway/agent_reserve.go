package gateway

import (
	"sync"
	"time"
)

// agentInflight is the in-memory half of agent daily/monthly cap admission.
// Agent spend is read from signed evidence, and the evidence record of a
// request is written AFTER the provider answered — so without this ledger a
// burst of concurrent requests (different sessions, or no session at all)
// all read the same pre-burst spend and all pass a cap that had headroom for
// one of them. Each admitted request reserves its pre-request estimate here
// until its record (settled cost, or a deny with zero cost) has committed;
// every admission reads settled spend + the OTHER requests' reservations.
//
// Process-local by design: Talon runs as one process over one evidence
// database, and a crash loses the in-flight estimates together with the
// requests they belonged to — an unrecorded request charges nothing, so
// there is nothing to recover. Delegated requests awaiting their response
// settlement are covered durably by the settlement ledger instead
// (settlementRepo.pendingEstimate); the two overlap only for the instant
// between the ledger commit and the release below, conservatively.
type agentInflight struct {
	mu sync.Mutex
	m  map[string]float64
	// unrecorded holds settled charges whose record failed to commit after
	// dispatch (see noteUnrecorded).
	unrecorded map[string][]unrecordedCharge
}

// agentReservation is one request's claim on an agent's cap headroom.
// release is idempotent; the owning request path defers it.
type agentReservation struct {
	key      string
	estimate float64
	done     bool
}

func agentInflightKey(agent *ResolvedIdentity) string {
	return agent.TenantID + "\x00" + agent.Name
}

// reserve adds estimate to the agent's in-flight total and returns the sum
// of every OTHER in-flight reservation. Callers reserve FIRST and read the
// settled spend AFTER: a request that commits between the two is counted
// once in the reservation snapshot and once in the store for that single
// read — conservative for one admission, never zero times.
func (a *agentInflight) reserve(key string, estimate float64) (res *agentReservation, others float64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.m == nil {
		a.m = map[string]float64{}
	}
	others = a.m[key]
	a.m[key] = others + estimate
	return &agentReservation{key: key, estimate: estimate}, others
}

func (a *agentInflight) release(r *agentReservation) {
	if r == nil || r.done {
		return
	}
	r.done = true
	a.mu.Lock()
	defer a.mu.Unlock()
	v := a.m[r.key] - r.estimate
	if v <= 1e-12 {
		delete(a.m, r.key)
		return
	}
	a.m[r.key] = v
}

// pending reports the agent's current in-flight total (tests).
func (a *agentInflight) pending(key string) float64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.m[key]
}

// adjust re-prices an existing claim (a fallback candidate's estimate
// replaces the primary's) and returns the sum of every OTHER in-flight
// reservation at that moment; a nil claim is created. The caller re-reads
// settled spend AFTER adjusting, exactly as reserve requires.
func (a *agentInflight) adjust(r *agentReservation, key string, estimate float64) (res *agentReservation, others float64) {
	if r == nil || r.done {
		return a.reserve(key, estimate)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	total := a.m[r.key] - r.estimate + estimate
	a.m[r.key] = total
	r.estimate = estimate
	return r, total - estimate
}

// unrecordedCharge is a settled cost whose evidence record failed to commit
// AFTER the provider answered: it never reaches CostByAgent, so without this
// the next admission would read the agent's spend short by that amount.
type unrecordedCharge struct {
	at     time.Time
	amount float64
}

// noteUnrecorded remembers a charge the evidence store refused. Process-
// local and bounded to the current month: a restart forgets it (the durable
// fix is a follow-up; see LIMITATIONS §7).
func (a *agentInflight) noteUnrecorded(key string, amount float64, at time.Time) {
	if amount <= 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.unrecorded == nil {
		a.unrecorded = map[string][]unrecordedCharge{}
	}
	a.unrecorded[key] = append(a.unrecorded[key], unrecordedCharge{at: at, amount: amount})
}

// unrecordedSince sums the remembered charges at or after since, pruning
// everything older than keep (the month window) as it goes.
func (a *agentInflight) unrecordedSince(key string, since, keep time.Time) float64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	kept := a.unrecorded[key][:0]
	var sum float64
	for _, c := range a.unrecorded[key] {
		if c.at.Before(keep) {
			continue
		}
		kept = append(kept, c)
		if !c.at.Before(since) {
			sum += c.amount
		}
	}
	if len(kept) == 0 {
		delete(a.unrecorded, key)
	} else {
		a.unrecorded[key] = kept
	}
	return sum
}
