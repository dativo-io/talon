import type { ProofLists } from "../lib/proof";

// ProofBoundary separates three kinds of information (#533 PR 2):
//  - Talon's facts: what Talon recorded at its own enforcement boundary
//    (identity it resolved, its decision, dispatch as far as recorded, route,
//    cost). Headed "signature verified" only for one record whose HMAC this
//    console checked, "Talon-recorded" otherwise, and "not reliable" when the
//    signature fails (#558 review): a tampered record is never presented as
//    Talon's facts;
//  - Application-reported: values the calling application supplied that
//    Talon recorded as attribution (asserted session or correlation ids,
//    request source). Shown only when such a value exists;
//  - Not independently verified: what happens beyond Talon's interception
//    boundaries.
// A valid signature proves the integrity of the signed record, not every
// claim about the surrounding business workflow.
const HEAD: Record<ProofLists["trust"], { title: string; lede: string }> = {
  signature_verified: { title: "Talon-recorded, signature verified", lede: "Recorded by Talon at its own boundary; this console checked the record's signature and it is unchanged." },
  recorded: { title: "Talon-recorded", lede: "Recorded by Talon at its own boundary. Signatures are not checked in this summary; each evidence record's page checks its own." },
  signature_invalid: { title: "Recorded claims — not reliable", lede: "The signature check failed: these statements come from an altered record." },
};

export function ProofBoundary({ facts, title = "What Talon can prove" }: { facts: ProofLists; title?: string }) {
  return (
    <section className="card section proof" aria-labelledby="proof-title" data-testid="proof-boundary">
      <div className="card-head">
        <h2 id="proof-title">{title}</h2>
      </div>
      <div className="card-body stack">
        {facts.trust === "signature_invalid" ? (
          <div className="notice error" role="alert">
            <div><strong>The signature does not verify.</strong> The record changed after signing, so nothing it says can be relied on: what follows is the record's content as claims, not facts Talon vouches for.</div>
          </div>
        ) : null}
        <div className="proof-columns">
          <div className={`proof-col ${facts.trust === "signature_invalid" ? "proof-invalid" : "proof-verified"}`}>
            <h3>{HEAD[facts.trust].title}</h3>
            <p className="small muted">{HEAD[facts.trust].lede}</p>
            <ul>{facts.recorded.map((f, i) => <li key={i}>{f}</li>)}</ul>
          </div>
          <div className="proof-col proof-reported">
            <h3>Application-reported</h3>
            <p className="small muted">Supplied by the calling application and recorded as attribution, not authentication.</p>
            {facts.trust === "signature_invalid" && facts.reported.length > 0 ? <p className="small">Also part of the altered record: not reliable.</p> : null}
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

