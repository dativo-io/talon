import type { Outcome } from "../api/types";

// Plain-language reading of evidence.OutcomeOf. The three facts (Talon's
// decision, dispatch, what the destination did) are Go's; this file only
// words them, and it never claims more than all three facts support: a
// destination answer is stated only when dispatch is recorded as dispatched
// and the downstream fact says so.

export interface OutcomeStory {
  // headline: one short sentence an operator reads first.
  headline: string;
  // detail: what the evidence does and does not establish.
  detail: string;
  tone: "ok" | "warn" | "error" | "info";
}

export function outcomeStory(o: Outcome | undefined | null): OutcomeStory {
  if (!o) return { headline: "Outcome not recorded", detail: "This record carries no decision or dispatch facts.", tone: "info" };
  const what = o.tool ? `the call to ${o.tool}` : "the request";
  if (o.downstream === "cache") {
    return { headline: "Served from Talon's cache", detail: `Talon answered ${what} from its semantic cache; no destination was called.`, tone: "ok" };
  }
  if (o.dispatch === "not_dispatched") {
    if (o.decision === "denied") {
      return { headline: "Talon denied it — not dispatched", detail: `Talon blocked ${what} before its dispatch boundary: the destination never received it.`, tone: "error" };
    }
    return { headline: "Talon allowed it — not dispatched", detail: `Talon allowed ${what}, but it was not handed to the destination: the destination never received it.${recorded(o)}`, tone: "warn" };
  }
  if (o.dispatch === "unknown") {
    return {
      headline: "Outcome unknown",
      detail: `Talon ${o.decision} ${what}, but the evidence does not establish whether the destination received it or what it did.${recorded(o)}`,
      tone: "warn",
    };
  }
  if (o.dispatch === "not_recorded") {
    return { headline: `Talon ${o.decision} it`, detail: "This record type does not record whether anything was dispatched; no destination outcome is claimed.", tone: o.decision === "denied" ? "error" : "info" };
  }
  // dispatched
  if (o.response_withheld) {
    return { headline: "Dispatched — answer withheld by Talon", detail: `The destination received ${what} and answered; Talon then withheld the answer (output checks).`, tone: "warn" };
  }
  switch (o.downstream) {
    case "completed":
      return { headline: "Talon allowed it — dispatched — destination responded", detail: `The destination received ${what} and returned an answer. What the destination did beyond that answer is not observed by Talon.`, tone: "ok" };
    case "rejected":
      return {
        headline: "Talon allowed it — dispatched — destination rejected it",
        detail: `Talon's policy permitted ${what}; the destination received it and refused it with its own error (for example its own validation). This is not a Talon denial.`,
        tone: "warn",
      };
    case "failed":
      return { headline: "Talon allowed it — dispatched — attempt failed", detail: `The evidence records that ${what} was dispatched and that the attempt failed.${recorded(o)}`, tone: "warn" };
    case "unknown":
      return { headline: "Dispatched — destination outcome unknown", detail: `${capitalize(what)} was dispatched; the evidence does not establish what the destination did.`, tone: "warn" };
  }
  return { headline: `Talon ${o.decision} it — dispatched`, detail: "No destination outcome is recorded for this record type.", tone: "info" };
}

// recorded appends the canonical outcome's basis (the recorded fact each axis
// was read from), so a cautious sentence can still be traced to its source.
function recorded(o: Outcome): string {
  return o.basis ? ` Recorded basis: ${o.basis}.` : "";
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
