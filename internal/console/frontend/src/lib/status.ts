import type { UseCaseStatus, UseCaseStatusCode, UseCaseStatuses } from "../api/types";
import type { Tone } from "./availability";

// Presentation of the use-case status (#575). The status itself is computed
// in Go (effective.StatusOf, the function `talon agents show` prints its
// Status with); this file only decides how it looks. Only "working" is
// green: a use case that nothing serves, that waits for its first request, or
// whose state is not known never reads as fine.
const TONES: Record<UseCaseStatusCode, Tone | "ok" | "accent"> = {
  working: "ok",
  waiting_for_first_request: "accent",
  not_active: "warn",
  needs_attention: "warn",
  blocked: "error",
  disabled: "neutral",
  runtime_not_confirmed: "info",
  not_determined: "info",
};

export function statusTone(code: string | undefined): Tone | "ok" | "accent" {
  return (code && TONES[code as UseCaseStatusCode]) || "info";
}

// statusFor finds one use case's status in a statuses section.
export function statusFor(s: UseCaseStatuses | undefined | null, tenant: string, name: string): UseCaseStatus | undefined {
  return (s?.items ?? []).find((i) => i.name === name && i.tenant_id === tenant);
}

// claimsNoFinding: "no finding" may be said of a use case only when its
// status is working. Readiness and fleet health find nothing wrong with a
// use case that nothing serves or that no request has reached; its status
// says what is going on instead.
export function claimsNoFinding(s: UseCaseStatus | undefined): boolean {
  return s?.code === "working";
}
