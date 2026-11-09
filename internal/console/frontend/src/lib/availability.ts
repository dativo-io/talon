import type { Availability, AvailabilityState } from "../api/types";

// One interpretation of the backend's availability states for every page.
// The rules are presentation only: the backend decides the state; this file
// decides how it reads and whether a number may be shown.

export type Tone = "neutral" | "info" | "warn" | "error";

export interface AvailabilityView {
  label: string;
  tone: Tone;
  // measured: the section was read and its values (minus Availability.unavailable)
  // are measurements, including real zeros.
  measured: boolean;
}

const VIEWS: Record<AvailabilityState, AvailabilityView> = {
  ok: { label: "Read from source", tone: "neutral", measured: true },
  empty: { label: "Source read: nothing in scope", tone: "neutral", measured: true },
  partial: { label: "Partially available", tone: "warn", measured: true },
  unavailable: { label: "Unavailable", tone: "error", measured: false },
  unknown: { label: "Unknown", tone: "info", measured: false },
};

export function viewOf(a: Availability | undefined | null): AvailabilityView {
  if (!a) return VIEWS.unknown;
  return VIEWS[a.state] ?? VIEWS.unknown;
}

// isMeasurement reports whether field (a JSON field name, or a dotted path
// for nested sections) may be shown as a value: the section must be measured
// and the field must not be listed as unavailable — by the section's
// availability or by a report's own unavailable_fields list.
export function isMeasurement(a: Availability | undefined | null, field?: string, unavailableFields?: string[] | null): boolean {
  if (!viewOf(a).measured) return false;
  if (!field) return true;
  if (a?.unavailable?.includes(field)) return false;
  if (unavailableFields?.includes(field)) return false;
  return true;
}

const SOURCE_LABELS: Record<string, string> = {
  evidence_store: "evidence store",
  session_store: "session store",
  config_files: "configuration files",
  runtime_probe: "runtime probe",
  none: "no source",
};

export function sourceLabel(source: string | undefined): string {
  if (!source) return "unknown source";
  return SOURCE_LABELS[source] ?? source;
}
