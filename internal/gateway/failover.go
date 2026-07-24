package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/failover"
)

// failoverWriter defers committing the response to the destination writer
// until the upstream outcome is known. Headers and status are buffered; a
// success status (<400) commits on the FIRST BODY WRITE — not on the header
// write — so an upstream that returns 200 headers and then dies before any
// body byte is read can still fail over. SSE streams pass through unbuffered
// from their first event; error responses stay fully buffered so the gateway
// can retry against a fallback candidate and only flush the buffered upstream
// error when no candidate remains. Once committed (first body byte of a
// success response), failover is no longer possible for this request.
type failoverWriter struct {
	dst       http.ResponseWriter
	header    http.Header
	status    int
	committed bool
	buf       bytes.Buffer
	// pendingTerminal holds a terminal SSE error event produced before any
	// upstream body byte was delivered (#217): written directly it would
	// count as the first body byte, commit the response, and permanently
	// disable failover. flushTo delivers it on every give-up path; a fallback
	// attempt that replaces this writer discards it.
	pendingTerminal []byte
}

func newFailoverWriter(dst http.ResponseWriter) *failoverWriter {
	return &failoverWriter{dst: dst, header: make(http.Header)}
}

func (f *failoverWriter) Header() http.Header {
	if f.committed {
		return f.dst.Header()
	}
	return f.header
}

func (f *failoverWriter) WriteHeader(code int) {
	if f.committed {
		return
	}
	f.status = code
}

func (f *failoverWriter) Write(b []byte) (int, error) {
	if !f.committed && f.status != 0 && f.status < 400 {
		f.commit()
	}
	if f.committed {
		return f.dst.Write(b)
	}
	return f.buf.Write(b)
}

func (f *failoverWriter) Flush() {
	if !f.committed {
		return
	}
	if fl, ok := f.dst.(http.Flusher); ok {
		fl.Flush()
	}
}

// deferTerminalEvent buffers a terminal SSE error event instead of letting it
// commit an uncommitted response (#217). Returns false once committed —
// mid-stream terminal events after real upstream bytes go straight to the
// client (#195).
func (f *failoverWriter) deferTerminalEvent(event []byte) bool {
	if f.committed {
		return false
	}
	f.pendingTerminal = append(f.pendingTerminal, event...)
	return true
}

func (f *failoverWriter) commit() {
	for k, vs := range f.header {
		for _, v := range vs {
			f.dst.Header().Set(k, v)
		}
	}
	if f.status != 0 {
		f.dst.WriteHeader(f.status)
	}
	f.committed = true
}

// flushTo commits the buffered response (headers, status, body, and any
// deferred terminal event) to the destination. No-op for the
// already-committed portion.
func (f *failoverWriter) flushTo() {
	if !f.committed {
		f.commit()
	}
	if f.buf.Len() > 0 {
		//nolint:gosec // G705: buffered upstream API response (JSON), gateway passthrough
		_, _ = f.dst.Write(f.buf.Bytes())
	}
	if len(f.pendingTerminal) > 0 {
		//nolint:gosec // G705: gateway-authored constant terminal SSE event (#195/#217)
		_, _ = f.dst.Write(f.pendingTerminal)
		if fl, ok := f.dst.(http.Flusher); ok {
			fl.Flush()
		}
	}
}

// failoverAttemptRecord describes one failed runtime attempt against a provider.
type failoverAttemptRecord struct {
	Provider       string
	Model          string
	Class          failover.Classification
	UpstreamStatus int
	ErrMsg         string
	ChainPosition  int
	RuleID         string
	GroupID        string
	DurationMS     int64
	EvidenceID     string
}

// failoverOutcome summarizes the fallback chain execution for evidence,
// metrics, and OTel span attributes.
type failoverOutcome struct {
	SelectedProvider string
	SelectedModel    string
	ChainPosition    int
	RuleID           string
	// GroupID identifies this failover engagement in evidence (one gateway
	// request = one group).
	GroupID        string
	FailedAttempts []failoverAttemptRecord
	Skipped        []evidence.SkippedCandidate
	// FailClosed is true when the failover machinery was engaged and the
	// agent received an error: either no policy-valid candidate existed
	// (no fallback dispatch at all) or every valid candidate failed. Under
	// eu_strict, refusing to route outside EU/LOCAL is a successful
	// governance outcome even though the request failed.
	FailClosed bool
	// Engaged is true when the primary attempt failed transiently and a
	// fallback chain was configured (i.e. failover logic actually ran).
	Engaged bool
}

// failedAttemptIDs returns the evidence IDs of all recorded failed attempts.
func (o *failoverOutcome) failedAttemptIDs() []string {
	if len(o.FailedAttempts) == 0 {
		return nil
	}
	ids := make([]string, 0, len(o.FailedAttempts))
	for i := range o.FailedAttempts {
		if id := o.FailedAttempts[i].EvidenceID; id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

// recordAttemptFn persists a signed failed-attempt evidence record and
// returns its evidence ID ("" when persistence failed; the request continues
// — evidence write failures are logged, never silently drop traffic).
type recordAttemptFn func(ctx context.Context, rec failoverAttemptRecord) string

// checkCandidateFn re-runs agent/provider authorization and gateway policy
// for a fallback candidate (provider, model). Failover dispatch is a
// Talon-initiated action: it must pass the same gates the agent's own
// request passed for the primary (allowed_providers, agent model lists,
// egress rules, budgets) or the chain becomes a policy bypass.
// checkCandidateFn gates a fallback candidate. The optional bodyOverride is a
// re-filtered request body for THIS candidate: when the target provider's tool
// policy is `filter` (not block), forbidden tools are stripped from the body
// and the candidate proceeds, instead of being skipped — matching the primary
// path's filter semantics (#266 review round 4). nil = forward the body as-is.
type checkCandidateFn func(ctx context.Context, provider, model string) (failover.FilterResult, []byte)

// classifyAttempt classifies a Forward outcome from its transport error
// and/or buffered upstream status.
func classifyAttempt(err error, status int) failover.Classification {
	if err != nil {
		return failover.ClassifyHTTP(err, 0)
	}
	return failover.ClassifyHTTP(nil, status)
}

// rewriteModelInBody replaces the top-level "model" field of a JSON request
// body. On any parse error the original body is returned unchanged (the
// upstream will reject it with a provider-native error).
func rewriteModelInBody(body []byte, model string) []byte {
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		return body
	}
	m["model"] = model
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return out
}

// fallbackAuthHeaders clones the primary attempt's upstream headers and
// replaces credentials with the fallback target's own. Secret-mode targets
// read from the tenant-scoped secret store; client_bearer targets keep the
// agent's bearer token.
func (g *Gateway) fallbackAuthHeaders(ctx context.Context, agent *ResolvedIdentity, providerName string, prov ProviderConfig, originalAuthorization string, base map[string]string) (map[string]string, error) {
	headers := make(map[string]string, len(base))
	for k, v := range base {
		switch strings.ToLower(k) {
		case "authorization", "x-api-key":
			continue
		}
		headers[k] = v
	}
	authMode := strings.TrimSpace(prov.UpstreamAuthMode)
	if authMode == "" {
		authMode = DefaultUpstreamAuthMode
	}
	if authMode == "client_bearer" {
		clientKey := strings.TrimSpace(strings.TrimPrefix(originalAuthorization, "Bearer "))
		if clientKey == "" {
			return nil, fmt.Errorf("fallback provider %s: no client bearer credential", providerName)
		}
		headers["Authorization"] = "Bearer " + clientKey
		return headers, nil
	}
	anthropicFamily := g.config.providerAPIFamily(providerName) == "anthropic"
	if prov.SecretName != "" {
		secret, err := g.secretsStore.Get(ctx, prov.SecretName, agent.TenantID, agent.Name)
		if err != nil {
			return nil, fmt.Errorf("fallback provider %s: secret retrieval: %w", providerName, err)
		}
		if anthropicFamily {
			headers["x-api-key"] = string(secret.Value)
		} else {
			headers["Authorization"] = "Bearer " + string(secret.Value)
		}
	}
	if anthropicFamily && !headerPresent(headers, "anthropic-version") {
		headers["anthropic-version"] = "2023-06-01"
	}
	return headers, nil
}

// headerPresent reports whether a header key exists in the map, ignoring case.
func headerPresent(headers map[string]string, key string) bool {
	for k := range headers {
		if strings.EqualFold(k, key) {
			return true
		}
	}
	return false
}

// modelAllowedForProvider checks a fallback target's model against the target
// provider's allow/block lists (prevents a fallback rewrite from bypassing a
// per-provider model policy).
func modelAllowedForProvider(prov ProviderConfig, model string) bool {
	for _, m := range prov.BlockedModels {
		if m == model {
			return false
		}
	}
	if len(prov.AllowedModels) == 0 {
		return true
	}
	for _, m := range prov.AllowedModels {
		if m == model {
			return true
		}
	}
	return false
}

// forwardWithFailover forwards the request to the routed provider and, on a
// transient upstream failure (timeout / connection error / 429 / 5xx), walks
// the provider's ordered fallback chain. Every candidate passes the filter
// pipeline first (sovereignty under eu_strict; issue #189 model policy facts
// plug in here) — refused candidates are recorded as skipped, never
// dispatched. Failed runtime attempts are persisted as separate signed
// evidence records via recordAttempt. When no candidate succeeds the request
// fails closed: the buffered upstream error (or a gateway 502 when nothing
// was dispatched) is returned to the agent and the outcome marks the
// governance result for the final evidence record.
//
//nolint:gocyclo // sequential chain walk with per-candidate filtering and error classification
func (g *Gateway) forwardWithFailover(
	ctx context.Context,
	dst http.ResponseWriter,
	p ForwardParams,
	route RouteResult,
	agent *ResolvedIdentity,
	clientModel string,
	originalAuthorization string,
	recordAttempt recordAttemptFn,
	checkCandidate checkCandidateFn,
) (*failoverOutcome, error) {
	out := &failoverOutcome{SelectedProvider: route.Provider, SelectedModel: clientModel}

	prov, _ := g.config.Provider(route.Provider)
	chain := prov.Fallback

	fw := newFailoverWriter(dst)
	primaryStart := time.Now()
	err := Forward(fw, p)
	class := classifyAttempt(err, fw.status)

	if !class.Transient || fw.committed || len(chain) == 0 {
		// Success, permanent upstream error, mid-stream failure after first
		// byte, or no chain configured: identical behavior to a chainless
		// gateway.
		fw.flushTo()
		return out, err
	}

	out.Engaged = true
	out.GroupID = newFailoverGroupID()
	primaryRec := failoverAttemptRecord{
		Provider:       route.Provider,
		Model:          clientModel,
		Class:          class,
		UpstreamStatus: fw.status,
		ChainPosition:  0,
		RuleID:         fmt.Sprintf("gateway.providers.%s", route.Provider),
		GroupID:        out.GroupID,
		DurationMS:     time.Since(primaryStart).Milliseconds(),
	}
	if err != nil {
		primaryRec.ErrMsg = err.Error()
	}
	primaryRec.EvidenceID = recordAttempt(ctx, primaryRec)
	out.FailedAttempts = append(out.FailedAttempts, primaryRec)

	mode := g.config.EffectiveSovereigntyMode
	filters := failover.Pipeline{failover.NewSovereigntyFilter(mode)}
	lastBuffered := fw

	for i, target := range chain {
		if ctx.Err() != nil {
			break
		}
		ruleID := fmt.Sprintf("gateway.providers.%s.fallback[%d]", route.Provider, i)
		model := target.Model
		if model == "" {
			model = clientModel
		}
		cand := failover.Candidate{
			Provider:      target.Provider,
			Model:         model,
			Region:        g.providerRegion(target.Provider),
			ChainPosition: i + 1,
			RuleID:        ruleID,
		}
		if res := filters.Evaluate(ctx, cand); !res.Allowed {
			out.Skipped = append(out.Skipped, evidence.SkippedCandidate{
				Provider: target.Provider, Model: model, ChainPosition: i + 1,
				Filter: res.Filter, Reason: res.Reason,
			})
			if res.Filter == "sovereignty" {
				RecordSovereigntyProviderDenied(ctx, target.Provider)
			}
			log.Warn().Str("provider", target.Provider).Str("filter", res.Filter).Str("reason", res.Reason).Msg("gateway_failover_candidate_skipped")
			continue
		}
		tprov, ok := g.config.Provider(target.Provider)
		if !ok || !tprov.Enabled {
			out.Skipped = append(out.Skipped, evidence.SkippedCandidate{
				Provider: target.Provider, Model: model, ChainPosition: i + 1,
				Filter: "config", Reason: "provider not enabled",
			})
			continue
		}
		if !modelAllowedForProvider(tprov, model) {
			out.Skipped = append(out.Skipped, evidence.SkippedCandidate{
				Provider: target.Provider, Model: model, ChainPosition: i + 1,
				Filter: "model_allowlist", Reason: fmt.Sprintf("model %q not allowed for provider %s", model, target.Provider),
			})
			continue
		}
		var candBodyOverride []byte
		if checkCandidate != nil {
			res, bodyOverride := checkCandidate(ctx, target.Provider, model)
			if !res.Allowed {
				out.Skipped = append(out.Skipped, evidence.SkippedCandidate{
					Provider: target.Provider, Model: model, ChainPosition: i + 1,
					Filter: res.Filter, Reason: res.Reason,
				})
				log.Warn().Str("provider", target.Provider).Str("filter", res.Filter).Str("reason", res.Reason).Msg("gateway_failover_candidate_skipped")
				continue
			}
			candBodyOverride = bodyOverride
		}

		headers, hdrErr := g.fallbackAuthHeaders(ctx, agent, target.Provider, tprov, originalAuthorization, p.Headers)
		if hdrErr != nil {
			out.Skipped = append(out.Skipped, evidence.SkippedCandidate{
				Provider: target.Provider, Model: model, ChainPosition: i + 1,
				Filter: "credentials", Reason: "upstream credential unavailable",
			})
			log.Warn().Err(hdrErr).Str("provider", target.Provider).Msg("gateway_failover_credentials_unavailable")
			continue
		}

		ap := p
		ap.UpstreamURL = strings.TrimSuffix(tprov.BaseURL, "/") + route.Path
		ap.Headers = headers
		// A candidate whose tool policy is `filter` gets a body with the
		// target-forbidden tools stripped (#266 review round 4); otherwise the
		// primary-filtered body is forwarded unchanged.
		if candBodyOverride != nil {
			ap.Body = candBodyOverride
		}
		if target.Model != "" {
			ap.Body = rewriteModelInBody(ap.Body, target.Model)
		}

		log.Info().
			Str("from_provider", route.Provider).
			Str("to_provider", target.Provider).
			Str("error_class", class.Class).
			Int("chain_position", i+1).
			Msg("gateway_failover_attempt")

		fw = newFailoverWriter(dst)
		attemptStart := time.Now()
		err = Forward(fw, ap)
		class = classifyAttempt(err, fw.status)

		success := err == nil && class.Class == failover.ClassNone
		if success || fw.committed {
			// Success — or a mid-stream failure after bytes already reached
			// the client, which makes this candidate the provider actually
			// used whether we like it or not. Only these outcomes may become
			// the fallback decision: once failover is engaged, a fallback
			// candidate that fails for ANY reason (transient or permanent,
			// e.g. a misconfigured secret returning 401) is a failed attempt,
			// never "the provider actually used".
			out.SelectedProvider = target.Provider
			out.SelectedModel = model
			out.ChainPosition = i + 1
			out.RuleID = ruleID
			fw.flushTo()
			return out, err
		}

		rec := failoverAttemptRecord{
			Provider:       target.Provider,
			Model:          model,
			Class:          class,
			UpstreamStatus: fw.status,
			ChainPosition:  i + 1,
			RuleID:         ruleID,
			GroupID:        out.GroupID,
			DurationMS:     time.Since(attemptStart).Milliseconds(),
		}
		if err != nil {
			rec.ErrMsg = err.Error()
		}
		rec.EvidenceID = recordAttempt(ctx, rec)
		out.FailedAttempts = append(out.FailedAttempts, rec)
		lastBuffered = fw
	}

	// Chain exhausted: fail closed. Return the last buffered upstream error
	// when a dispatch happened; otherwise (every candidate refused before
	// dispatch) a gateway error naming the governance outcome.
	out.FailClosed = true
	out.SelectedProvider = ""
	out.SelectedModel = ""
	if lastBuffered.status != 0 || lastBuffered.buf.Len() > 0 {
		lastBuffered.flushTo()
	} else {
		WriteProviderError(dst, g.config.providerAPIFamily(route.Provider), http.StatusBadGateway,
			"upstream provider failed and no policy-valid fallback candidate exists (fail-closed)")
	}
	if err == nil {
		err = fmt.Errorf("provider %s failed (%s) and no fallback candidate succeeded: %w", route.Provider, primaryRec.Class.Class, ErrNoFallbackCandidate)
	}
	return out, err
}

// ErrNoFallbackCandidate is returned when a transient upstream failure could
// not be recovered because no policy-valid fallback candidate succeeded.
var ErrNoFallbackCandidate = errors.New("no policy-valid fallback candidate available")

// newFailoverGroupID mints the identifier tying one failover engagement's
// evidence records together.
func newFailoverGroupID() string {
	return "fog_" + uuid.New().String()[:12]
}

// recordFailoverAttemptEvidence persists a signed evidence record for one
// failed provider attempt (evidence-by-default: the failed attempt is a fact
// of its own, linked to the request by correlation ID). Returns the evidence
// ID, or "" when the write failed.
func (g *Gateway) recordFailoverAttemptEvidence(ctx context.Context, correlationID string, agent *ResolvedIdentity, mode string, tier int, rec failoverAttemptRecord, dataFlow *evidence.DataFlow) string {
	errMsg := rec.ErrMsg
	if errMsg == "" && rec.UpstreamStatus != 0 {
		errMsg = fmt.Sprintf("upstream status %d", rec.UpstreamStatus)
	}
	failureReason := evidence.FailureReasonProviderTransient
	if !rec.Class.Transient {
		failureReason = evidence.FailureReasonProviderPermanent
	}
	ev, err := RecordGatewayEvidence(ctx, g.evidenceStore, RecordGatewayEvidenceParams{
		CorrelationID: correlationID,
		SessionID:     sessionIDFromContext(ctx),
		TenantID:      agent.TenantID,
		AgentName:     agent.Name,
		Team:          agent.Team,
		Provider:      rec.Provider,
		Model:         rec.Model,
		PolicyAllowed: true,
		// A failed attempt is a first-class evidence record and must carry the
		// same signed policy-digest matrix as any other decision, keyed to the
		// attempt's own provider so its effective policy is verifiable (#266 r5).
		PolicyVersion:  agent.PolicyDigest,
		PolicyDigests:  g.policyDigests(agent, rec.Provider),
		Currency:       g.pricingCurrency,
		InputTier:      tier,
		DurationMS:     rec.DurationMS,
		Error:          errMsg,
		InvocationType: "gateway_failover_attempt",
		Status:         "failed",
		FailureReason:  failureReason,
		DataFlow:       dataFlow,
		Failover: &evidence.FailoverContext{
			Role:            evidence.FailoverRoleFailedAttempt,
			FailoverGroupID: rec.GroupID,
			Provider:        rec.Provider,
			Region:          g.providerRegion(rec.Provider),
			Model:           rec.Model,
			ErrorClass:      rec.Class.Class,
			UpstreamStatus:  rec.UpstreamStatus,
			ChainPosition:   rec.ChainPosition,
			FallbackRuleID:  rec.RuleID,
			SovereigntyMode: mode,
		},
	})
	if err != nil {
		g.handleEvidenceWriteFailure(ctx, err)
		return ""
	}
	return ev.ID
}

// buildFailoverDecisionContext assembles the FailoverContext for the
// request's final evidence record after the failover machinery was engaged.
func (g *Gateway) buildFailoverDecisionContext(out *failoverOutcome, mode string) *evidence.FailoverContext {
	if out == nil || !out.Engaged {
		return nil
	}
	fc := &evidence.FailoverContext{
		Role:              evidence.FailoverRoleFallbackDecision,
		FailoverGroupID:   out.GroupID,
		Provider:          out.SelectedProvider,
		Model:             out.SelectedModel,
		ChainPosition:     out.ChainPosition,
		FallbackRuleID:    out.RuleID,
		SovereigntyMode:   mode,
		FailedAttemptIDs:  out.failedAttemptIDs(),
		SkippedCandidates: out.Skipped,
	}
	if out.FailClosed {
		fc.Role = evidence.FailoverRoleFailClosed
		if n := len(out.FailedAttempts); n > 0 {
			fc.ErrorClass = out.FailedAttempts[n-1].Class.Class
		}
		return fc
	}
	fc.Region = g.providerRegion(out.SelectedProvider)
	if mode == config.DataSovereigntyEUStrict {
		fc.SovereigntyCheck = "allowed"
	} else {
		fc.SovereigntyCheck = "not_evaluated"
	}
	return fc
}
