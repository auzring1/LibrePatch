/** A deployment's progress: a stacked bar (succeeded, failed) with the numbers in text, so color is never the only signal. */
export function DeploymentProgress({ total, succeeded, failed }: { total: number; succeeded: number; failed: number }) {
  const pct = (n: number) => (total ? `${(100 * n) / total}%` : "0%");
  const done = succeeded + failed;
  return (
    <div style={{ minWidth: 160 }}>
      <div className="lp-stack" role="img" aria-label={`${succeeded} succeeded, ${failed} failed, ${Math.max(total - done, 0)} not finished`}>
        <span style={{ width: pct(succeeded), background: "var(--lp-success-solid)" }} />
        <span style={{ width: pct(failed), background: "var(--lp-danger-solid)" }} />
      </div>
      <span className="lp-dt__cell-sub">
        {done} of {total} finished{failed ? `, ${failed} failed` : ""}
      </span>
    </div>
  );
}
