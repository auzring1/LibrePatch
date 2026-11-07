import { type Day, historySummary, niceMax } from "./format";

const W = 640;
const H = 190;
const M = { top: 10, right: 8, bottom: 24, left: 36 };

const shortDate = (iso: string) => {
  const [y, m, d] = iso.split("-").map(Number);
  if (!y || !m || !d) return iso;
  return new Date(y, m - 1, d).toLocaleDateString(undefined, { month: "short", day: "numeric" });
};

/**
 * Daily patch compliance as stacked columns (compliant at the bottom, then not compliant, then not scanned), drawn
 * as plain SVG with theme tokens. The SVG has a text summary as its name, and the same numbers are available as a
 * table behind a disclosure, so nothing depends on seeing the colors.
 */
export function ComplianceChart({ days }: { days: Day[] }) {
  const max = niceMax(Math.max(0, ...days.map((d) => d.total)));
  const pw = W - M.left - M.right;
  const ph = H - M.top - M.bottom;
  const band = pw / Math.max(days.length, 1);
  const bw = Math.min(band * 0.72, 22);
  const y = (v: number) => M.top + ph - (v / max) * ph;
  const ticks = [0, max / 2, max].filter((t, i, a) => a.indexOf(t) === i);
  const label = (n: number) => String(Math.round(n * 10) / 10);

  return (
    <div className="lp-dash-data">
      <svg className="lp-dash-chart" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={historySummary(days)} focusable="false">
        {ticks.map((t) => (
          <g key={t}>
            <line className="lp-dash-chart__grid" x1={M.left} x2={W - M.right} y1={y(t)} y2={y(t)} />
            <text className="lp-dash-chart__axis" x={M.left - 6} y={y(t) + 4} textAnchor="end">
              {label(t)}
            </text>
          </g>
        ))}
        {days.map((d, i) => {
          const x = M.left + band * i + (band - bw) / 2;
          const parts = [
            { v: d.compliant, cls: "lp-dash-seg--ok" },
            { v: d.nonCompliant, cls: "lp-dash-seg--bad" },
            { v: d.unknown, cls: "lp-dash-seg--unk" },
          ];
          let acc = 0;
          return (
            <g key={d.date}>
              <title>{`${shortDate(d.date)}: ${d.compliant} compliant, ${d.nonCompliant} not compliant, ${d.unknown} not scanned`}</title>
              {parts.map((p, k) => {
                if (p.v <= 0) return null;
                const top = y(acc + p.v);
                const h = y(acc) - top;
                acc += p.v;
                return <rect key={k} className={p.cls} x={x} y={top} width={bw} height={Math.max(h, 0.5)} />;
              })}
            </g>
          );
        })}
        {days.length > 0 && (
          <>
            <text className="lp-dash-chart__axis" x={M.left} y={H - 6} textAnchor="start">
              {shortDate(days[0]!.date)}
            </text>
            {days.length > 1 && (
              <text className="lp-dash-chart__axis" x={W - M.right} y={H - 6} textAnchor="end">
                {shortDate(days[days.length - 1]!.date)}
              </text>
            )}
          </>
        )}
      </svg>
      <ul className="lp-legend" aria-label="Chart legend">
        <li>
          <span className="lp-dot" style={{ background: "var(--lp-success-solid)" }} aria-hidden="true" />
          Compliant
        </li>
        <li>
          <span className="lp-dot" style={{ background: "var(--lp-danger-solid)" }} aria-hidden="true" />
          Not compliant
        </li>
        <li>
          <span className="lp-dot" style={{ background: "var(--lp-neutral-solid)" }} aria-hidden="true" />
          Not scanned
        </li>
      </ul>
      <details>
        <summary>View chart data as a table</summary>
        <div className="lp-dash-data__scroll" role="region" aria-label="Compliance history table" tabIndex={0} /* NOSONAR: a scrollable region must be reachable by keyboard (WCAG 2.1.1) */>
          <table>
            <caption className="lp-visually-hidden">Devices per compliance state, by day</caption>
            <thead>
              <tr>
                <th scope="col">Day</th>
                <th scope="col">Compliant</th>
                <th scope="col">Not compliant</th>
                <th scope="col">Not scanned</th>
              </tr>
            </thead>
            <tbody>
              {[...days].reverse().map((d) => (
                <tr key={d.date}>
                  <th scope="row">{shortDate(d.date)}</th>
                  <td>{d.compliant}</td>
                  <td>{d.nonCompliant}</td>
                  <td>{d.unknown}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </div>
  );
}
