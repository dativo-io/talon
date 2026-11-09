// Formatting only: no conversion, no aggregation across currencies, no
// rounding that changes a status. Times are shown in UTC because every
// accounting window in the API is a UTC window.

export function money(amount: number, currency: string | undefined): string {
  const code = (currency ?? "").trim().toUpperCase();
  if (/^[A-Z]{3}$/.test(code)) {
    try {
      return new Intl.NumberFormat("en-US", {
        style: "currency",
        currency: code,
        minimumFractionDigits: 2,
        // Sub-unit amounts keep four decimals: a $0.0123 model call must not read as $0.01.
        maximumFractionDigits: amount !== 0 && Math.abs(amount) < 1 ? 4 : 2,
      }).format(amount);
    } catch {
      // unknown ISO code: fall through and show the code literally
    }
  }
  return `${amount.toFixed(4)} ${code || "(no currency)"}`;
}

export function integer(n: number): string {
  return new Intl.NumberFormat("en-US").format(n);
}

export function percent(p: number): string {
  return `${p.toFixed(p >= 10 ? 0 : 1)}%`;
}

export function utc(ts: string | undefined | null): string {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime()) || d.getUTCFullYear() <= 1) return "—";
  return d.toISOString().replace("T", " ").replace(/\.\d{3}Z$/, " UTC").replace(/Z$/, " UTC");
}

export function utcShort(ts: string | undefined | null): string {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime()) || d.getUTCFullYear() <= 1) return "—";
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}`;
}

// isZeroTime: Go encodes an unset time.Time as 0001-01-01.
export function isZeroTime(ts: string | undefined | null): boolean {
  if (!ts) return true;
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) || d.getUTCFullYear() <= 1;
}

export function relative(ts: string | undefined | null, now: Date = new Date()): string {
  if (isZeroTime(ts)) return "never";
  const d = new Date(ts as string);
  const s = Math.round((now.getTime() - d.getTime()) / 1000);
  if (s < 0) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function duration(ms: number | undefined): string {
  if (ms === undefined || ms === null) return "—";
  if (ms < 1000) return `${ms} ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)} s`;
  const m = Math.floor(s / 60);
  return `${m}m ${Math.round(s - m * 60)}s`;
}

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KiB", "MiB", "GiB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}

export function humanize(token: string | undefined): string {
  if (!token) return "";
  return token.replace(/[_-]+/g, " ");
}

// goDuration renders a Go duration string ("1h0m0s", "24h0m0s", "30m0s") compactly.
export function goDuration(d: string | undefined): string {
  if (!d) return "?";
  const m = /^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+(?:\.\d+)?)s)?$/.exec(d);
  if (!m) return d;
  const h = Number(m[1] ?? 0), min = Number(m[2] ?? 0), s = Number(m[3] ?? 0);
  if (h && !min && !s) return `${h}h`;
  if (!h && min && !s) return `${min}m`;
  return [h ? `${h}h` : "", min ? `${min}m` : "", s ? `${s}s` : ""].join("") || "0s";
}
