package runtimestatus

import "time"

// ReloadFacts is what the running processes that serve a role report about
// re-reading agent files (#575): how often they re-scan, whether a process
// does not re-scan at all, and what their newest re-scan rejected. It tells
// an operator when a changed or new agent file can become active; that it
// did is proved only by the policy digests a process reports (ProveLoaded).
type ReloadFacts struct {
	// Known: at least one such process reports its catalog.
	Known bool
	// Disabled: such a process reports reload disabled
	// (agents_reload_interval "0"); it loads agent files only when it starts.
	Disabled bool
	// Every is the longest interval such a process reports (zero when none
	// reports one).
	Every time.Duration
	// Varies: the processes report different intervals.
	Varies bool
	// Unreported: a process with reload enabled does not report its interval
	// (its record was written by an earlier release).
	Unreported bool
	// RejectedCauses are the causes a process gives for rejecting its newest
	// re-scan (invalid or duplicate files by path, or a build failure). It
	// keeps serving its previous generation until a re-scan validates.
	RejectedCauses []string
}

// ReloadFactsOf reads the facts of the running processes in v that serve
// role ("" = any).
func ReloadFactsOf(v View, role string) ReloadFacts {
	var f ReloadFacts
	for i := range v.Processes {
		p := &v.Processes[i]
		if p.Assessed != Running || !p.Serves(role) || p.Catalog == nil {
			continue
		}
		f.Known = true
		c := p.Catalog
		if c.ReloadRejected {
			f.RejectedCauses = append(f.RejectedCauses, c.RejectedCauses...)
		}
		every := time.Duration(c.ReloadIntervalMs) * time.Millisecond
		switch {
		case !c.ReloadEnabled:
			f.Disabled = true
		case every <= 0:
			f.Unreported = true
		default:
			if f.Every != 0 && every != f.Every {
				f.Varies = true
			}
			if every > f.Every {
				f.Every = every
			}
		}
	}
	return f
}

// Setting names agents_reload_interval with the interval the processes
// report: "every 2s, agents_reload_interval"; "within 30s, ..." when they
// report different intervals (the longest bounds the next re-scan of every
// one); the bare setting when a process does not report its interval.
func (f ReloadFacts) Setting() string {
	switch {
	case f.Every <= 0 || f.Unreported:
		return "agents_reload_interval"
	case f.Varies:
		return "within " + f.Every.String() + ", agents_reload_interval"
	}
	return "every " + f.Every.String() + ", agents_reload_interval"
}
