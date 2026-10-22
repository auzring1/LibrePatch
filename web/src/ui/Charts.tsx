import type { ReactNode } from "react";

/** One slice of a chart. `token` is a semantic color name: a status family ("success", "danger"...) or "chart-1".."chart-6". */
export interface Slice {
  label: string;
  value: number;
  token: string;
}

const fill = (token: string) => (token.startsWith("chart-") ? `var(--lp-${token})` : `var(--lp-${token}-solid)`);

/** A single stacked bar with a legend that carries the numbers, so the chart never depends on color alone. */
export function StackedBar({ slices, label }: { slices: Slice[]; label: string }) {
  const total = slices.reduce((s, x) => s + x.value, 0);
  return (
    <div>
      <div className="lp-stack" role="img" aria-label={`${label}: ${slices.map((s) => `${s.label} ${s.value}`).join(", ")}`}>
        {total > 0 && slices.filter((s) => s.value > 0).map((s) => <span key={s.label} style={{ width: `${(100 * s.value) / total}%`, background: fill(s.token) }} />)}
      </div>
      <ul className="lp-legend">
        {slices.map((s) => (
          <li key={s.label}>
            <span className="lp-dot" style={{ background: fill(s.token) }} aria-hidden="true" />
            {s.label} <b>{s.value}</b>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** A donut with the total in the middle and a legend (`legend={false}` when the page lists the numbers itself). */
export function Donut({ slices, label, center, sub, size = 132, legend = true }: { slices: Slice[]; label: string; center?: ReactNode; sub?: string; size?: number; legend?: boolean }) {
  const total = slices.reduce((s, x) => s + x.value, 0);
  const r = 46;
  const c = 2 * Math.PI * r;
  let offset = 0;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "var(--lp-space-5)", flexWrap: "wrap" }}>
      <svg className="lp-donut" width={size} height={size} viewBox="0 0 120 120" role="img" aria-label={`${label}: ${slices.map((s) => `${s.label} ${s.value}`).join(", ")}`}>
        <circle cx="60" cy="60" r={r} fill="none" stroke="var(--lp-surface-sunken)" strokeWidth="14" />
        {total > 0 &&
          slices
            .filter((s) => s.value > 0)
            .map((s) => {
              const len = (s.value / total) * c;
              const el = <circle key={s.label} cx="60" cy="60" r={r} fill="none" stroke={fill(s.token)} strokeWidth="14" strokeDasharray={`${Math.max(len - 1.5, 0)} ${c}`} strokeDashoffset={-offset} transform="rotate(-90 60 60)" />;
              offset += len;
              return el;
            })}
        <text x="60" y={sub ? 58 : 66} textAnchor="middle" fontSize="22" fontWeight="600">
          {center ?? total}
        </text>
        {sub && (
          <text className="lp-donut__sub" x="60" y="76" textAnchor="middle" fontSize="10">
            {sub}
          </text>
        )}
      </svg>
      {legend && (
        <ul className="lp-legend" style={{ flexDirection: "column", margin: 0 }}>
          {slices.map((s) => (
            <li key={s.label}>
              <span className="lp-dot" style={{ background: fill(s.token) }} aria-hidden="true" />
              {s.label} <b>{s.value}</b>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
