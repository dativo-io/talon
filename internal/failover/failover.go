// Package failover provides upstream error classification and fallback
// candidate filtering for provider fallback chains (error-driven,
// sovereignty-respecting). It is a leaf package shared by the gateway proxy
// path (internal/gateway) and the LLM router path (internal/llm): only
// transient upstream failures may trigger failover, and every candidate must
// pass the filter pipeline (sovereignty today; model policy facts from #189
// plug in as additional CandidateFilter implementations without rework).
package failover

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/dativo-io/talon/internal/config"
)

// Error classes recorded in evidence for failed provider attempts.
// Transient classes may trigger failover to the next chain candidate;
// permanent classes never do (retrying a 401 on a second provider would
// only widen the blast radius of a misconfiguration).
const (
	ClassTimeout     = "timeout"
	ClassConnection  = "connection_error"
	ClassRateLimited = "rate_limited"
	ClassUpstream5xx = "upstream_5xx"
	ClassAuth        = "auth_error"
	ClassClient      = "client_error"
	ClassCanceled    = "canceled"
	ClassNone        = ""
)

// Classification is the failover-relevant classification of an upstream outcome.
type Classification struct {
	Class     string
	Transient bool
}

// ClassifyHTTP classifies the outcome of an upstream HTTP attempt from the
// transport error and/or response status code. Caller-context cancellation is
// never transient: the client went away, so dispatching the request to another
// provider would be a policy-relevant action nobody is waiting for.
func ClassifyHTTP(err error, statusCode int) Classification {
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return Classification{Class: ClassCanceled, Transient: false}
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return Classification{Class: ClassTimeout, Transient: true}
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return Classification{Class: ClassTimeout, Transient: true}
		}
		// Any other transport-level failure (connection refused/reset, DNS,
		// EOF mid-body) means the provider was unreachable or dropped us.
		return Classification{Class: ClassConnection, Transient: true}
	}
	switch {
	case statusCode == 429:
		return Classification{Class: ClassRateLimited, Transient: true}
	case statusCode >= 500:
		return Classification{Class: ClassUpstream5xx, Transient: true}
	case statusCode == 401 || statusCode == 403:
		return Classification{Class: ClassAuth, Transient: false}
	case statusCode >= 400:
		return Classification{Class: ClassClient, Transient: false}
	}
	return Classification{Class: ClassNone, Transient: false}
}

// ClassifyProviderCode maps a typed llm.ProviderError code to a failover
// classification. Unknown codes are permanent (fail closed: no failover on
// outcomes we cannot classify).
func ClassifyProviderCode(code string) Classification {
	switch code {
	case "rate_limit":
		return Classification{Class: ClassRateLimited, Transient: true}
	case "server_error":
		return Classification{Class: ClassUpstream5xx, Transient: true}
	case "timeout":
		return Classification{Class: ClassTimeout, Transient: true}
	case "auth_failed":
		return Classification{Class: ClassAuth, Transient: false}
	case "model_not_found":
		return Classification{Class: ClassClient, Transient: false}
	default:
		return Classification{Class: ClassNone, Transient: false}
	}
}

// Candidate is one entry of an ordered fallback chain, resolved with the
// metadata filters need. ChainPosition 0 is the primary; fallback entries
// start at 1. RuleID names the config rule that produced the candidate
// (e.g. "gateway.providers.openai.fallback[1]" or
// "policies.model_routing.tier_2.fallback_chain[0]") so evidence can cite it.
type Candidate struct {
	Provider      string
	Model         string
	Region        string // jurisdiction of the endpoint: "EU", "US", "LOCAL", "unknown"
	ChainPosition int
	RuleID        string
}

// FilterResult reports whether a candidate may be dispatched to, and if not,
// which filter refused it and why. Skipped candidates are evidenced distinctly
// from failed runtime attempts (a refusal is a governance outcome, not an error).
type FilterResult struct {
	Allowed bool
	Filter  string // name of the filter that refused (empty when allowed)
	Reason  string // machine-readable reason (empty when allowed)
}

// CandidateFilter decides whether a fallback candidate is policy-valid.
// Implementations must be side-effect free; the caller records the outcome.
// Issue #189 (model policy facts: availability, ZDR, retention, access scope)
// adds filters behind this same interface.
type CandidateFilter interface {
	Name() string
	Allows(ctx context.Context, c Candidate) FilterResult
}

// Pipeline evaluates filters in order; the first refusal wins.
type Pipeline []CandidateFilter

// Evaluate runs the pipeline for a candidate.
func (p Pipeline) Evaluate(ctx context.Context, c Candidate) FilterResult {
	for _, f := range p {
		if res := f.Allows(ctx, c); !res.Allowed {
			return res
		}
	}
	return FilterResult{Allowed: true}
}

// sovereigntyFilter refuses non-EU/LOCAL candidates under eu_strict.
// Fail-closed: an empty or unknown region is refused under eu_strict.
type sovereigntyFilter struct {
	mode string
}

// NewSovereigntyFilter returns the sovereignty candidate filter for the given
// data-sovereignty mode. Under any mode other than eu_strict it allows all
// candidates (routing preference is handled elsewhere).
func NewSovereigntyFilter(mode string) CandidateFilter {
	return sovereigntyFilter{mode: mode}
}

func (f sovereigntyFilter) Name() string { return "sovereignty" }

func (f sovereigntyFilter) Allows(_ context.Context, c Candidate) FilterResult {
	if f.mode != config.DataSovereigntyEUStrict {
		return FilterResult{Allowed: true}
	}
	region := strings.ToUpper(strings.TrimSpace(c.Region))
	if region == "EU" || region == "LOCAL" {
		return FilterResult{Allowed: true}
	}
	return FilterResult{
		Allowed: false,
		Filter:  f.Name(),
		Reason:  fmt.Sprintf("sovereignty: provider %s region %q not EU/LOCAL under %s", c.Provider, c.Region, f.mode),
	}
}
