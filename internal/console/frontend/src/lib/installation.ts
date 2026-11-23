// Words one installation-level operational event (#593): a record Talon
// writes about the installation itself under the reserved namespace
// `system` — never a tenant's AI use case activity. The server decides
// which records these are (evidence.IsInstallationEvent); this only names
// them from the record's own type and Talon's recorded decision, and adds
// no fact.
export type InstallationTone = "ok" | "warn" | "info";

export interface InstallationEventView {
  label: string;
  outcome: string;
  tone: InstallationTone;
  detail: string;
}

export function installationEventView(type: string | undefined, allowed: boolean): InstallationEventView {
  switch (type) {
    case "config_reload":
      return allowed
        ? { label: "Configuration reload", outcome: "Activated", tone: "ok", detail: "talon serve activated a new generation of the agent files." }
        : { label: "Configuration reload", outcome: "Rejected", tone: "warn", detail: "talon serve rejected the changed agent files and kept serving its active generation." };
    case "recovery_resumed":
      return { label: "Recovery resumed", outcome: "Hold ended", tone: "info", detail: "talon backup resume ended the recovery hold after a restore; what the operator reconciled is in the reasons." };
    case "mode_change":
      return { label: "Enforcement mode change", outcome: "Recorded", tone: "info", detail: "Recorded by talon enforce, which was removed in v1.15.0." };
    default:
      return { label: type || "Installation event", outcome: allowed ? "Recorded" : "Recorded as denied", tone: allowed ? "info" : "warn", detail: "" };
  }
}
