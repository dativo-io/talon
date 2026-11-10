import type { ProofLists } from "../lib/proof";

// ProofBoundary separates three kinds of information (#533 PR 2):
//  - Talon-verified: facts Talon recorded at its own enforcement boundary
//    in signed evidence (identity it resolved, its decision, dispatch as far
//    as recorded, route, cost, the signature check);
//  - Application-reported: values the calling application supplied that
//    Talon recorded as attribution (asserted session or correlation ids,
//    request source). Shown only when such a value exists;
//  - Not independently verified: what happens beyond Talon's interception
//    boundaries.
// A valid signature proves the integrity of the signed record, not every
// claim about the surrounding business workflow.
export function ProofBoundary({ facts, title = "What Talon can prove" }: { facts: ProofLists; title?: string }) {
  return (
    <section className="card section proof" aria-labelledby="proof-title" data-testid="proof-boundary">
      <div className="card-head">
        <h2 id="proof-title">{title}</h2>
      </div>
      <div className="card-body stack">
        {facts.signatureInvalid ? (
          <div className="notice error" role="alert">
            <div><strong>The signature does not verify.</strong> The record changed after signing, so none of its facts below can be relied on.</div>
          </div>
        ) : null}
        <div className="proof-columns">
          <div className="proof-col proof-verified">
            <h3>Talon-verified</h3>
            <p className="small muted">Recorded by Talon at its own boundary, in signed evidence.</p>
            <ul>{facts.verified.map((f, i) => <li key={i}>{f}</li>)}</ul>
          </div>
          <div className="proof-col proof-reported">
            <h3>Application-reported</h3>
            <p className="small muted">Supplied by the calling application and recorded as attribution, not authentication.</p>
            {facts.reported.length > 0 ? <ul>{facts.reported.map((f, i) => <li key={i}>{f}</li>)}</ul> : <p className="small">Nothing on this record was supplied by the application.</p>}
            <p className="small muted">Application results (workflow outputs, generated reports, approval receipts) are not supplied to this console.</p>
          </div>
          <div className="proof-col proof-unverified">
            <h3>Not independently verified</h3>
            <p className="small muted">Outside Talon's interception boundaries.</p>
            <ul>{facts.notVerified.map((f, i) => <li key={i}>{f}</li>)}</ul>
          </div>
        </div>
        <p className="small muted">A valid Talon signature proves the integrity of the signed record, not every claim about the surrounding business workflow, and not that every related event was recorded.</p>
      </div>
    </section>
  );
}

