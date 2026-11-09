// The time range applies to activity series only: the API accepts a custom
// window there. Cost and today's figures use fixed UTC accounting windows
// and say so where they are shown; no global control pretends to move them.
export type Range = "24h" | "7d" | "30d";

export function rangeQuery(r: Range, now: Date = new Date()): { from: string; to: string; bucket: string } {
  const to = new Date(Math.ceil(now.getTime() / 3_600_000) * 3_600_000);
  const hours = r === "24h" ? 24 : r === "7d" ? 168 : 720;
  const from = new Date(to.getTime() - hours * 3_600_000);
  return { from: from.toISOString(), to: to.toISOString(), bucket: r === "30d" ? "24h" : "1h" };
}

export function TimeRangeSelector({ value, onChange }: { value: Range; onChange: (r: Range) => void }) {
  const opts: { v: Range; label: string }[] = [
    { v: "24h", label: "24 hours" },
    { v: "7d", label: "7 days" },
    { v: "30d", label: "30 days" },
  ];
  return (
    <div className="segmented" role="group" aria-label="Activity time range (UTC)">
      {opts.map((o) => (
        <button key={o.v} type="button" aria-pressed={value === o.v} onClick={() => onChange(o.v)}>
          {o.label}
        </button>
      ))}
    </div>
  );
}
