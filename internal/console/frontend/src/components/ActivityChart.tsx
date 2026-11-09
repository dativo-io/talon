import type { ActivityBucket } from "../api/types";
import { utcShort } from "../lib/format";

// Requests and denials per backend bucket, drawn as plain SVG. Every bar is
// one bucket the API returned; nothing is interpolated or smoothed.
export function ActivityChart({ buckets, label }: { buckets: ActivityBucket[]; label: string }) {
  const w = 720;
  const h = 160;
  const pad = { l: 34, r: 6, t: 8, b: 20 };
  const max = Math.max(1, ...buckets.map((b) => b.requests));
  const bw = buckets.length > 0 ? (w - pad.l - pad.r) / buckets.length : 0;
  const y = (v: number) => pad.t + (h - pad.t - pad.b) * (1 - v / max);
  const totalReq = buckets.reduce((s, b) => s + b.requests, 0);
  const totalDeny = buckets.reduce((s, b) => s + b.denied, 0);
  const ticks = buckets.length > 0 ? [0, Math.floor(buckets.length / 2), buckets.length - 1] : [];
  return (
    <figure className="stack" aria-label={label}>
      <svg className="chart" viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" role="img" aria-label={`${label}: ${totalReq} requests, ${totalDeny} denied`}>
        <line className="axis" x1={pad.l} x2={w - pad.r} y1={h - pad.b} y2={h - pad.b} />
        <text x={pad.l - 4} y={pad.t + 8} textAnchor="end">{max}</text>
        <text x={pad.l - 4} y={h - pad.b} textAnchor="end">0</text>
        {buckets.map((b, i) => {
          const x = pad.l + i * bw + bw * 0.12;
          const bwi = Math.max(1, bw * 0.76);
          return (
            <g key={b.start}>
              <title>{`${utcShort(b.start)} UTC — ${b.requests} requests, ${b.denied} denied, ${b.errors} errors`}</title>
              <rect className="bar" x={x} width={bwi} y={y(b.requests)} height={Math.max(0, h - pad.b - y(b.requests))} />
              {b.denied > 0 ? <rect className="bar-deny" x={x} width={bwi} y={y(b.denied)} height={Math.max(0, h - pad.b - y(b.denied))} /> : null}
            </g>
          );
        })}
        {ticks.map((i) => {
          const b = buckets[i];
          return b ? (
            <text key={`t${i}`} x={i === 0 ? pad.l : i === buckets.length - 1 ? w - pad.r : pad.l + i * bw + bw / 2} y={h - 6} textAnchor={i === 0 ? "start" : i === buckets.length - 1 ? "end" : "middle"}>
              {utcShort(b.start)}
            </text>
          ) : null;
        })}
      </svg>
      <figcaption className="legend">
        <span><i className="l-req" />Requests ({totalReq})</span>
        <span><i className="l-deny" />Denied ({totalDeny})</span>
      </figcaption>
    </figure>
  );
}
