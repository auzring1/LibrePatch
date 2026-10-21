import { Text } from "@mantine/core";
import type { Device } from "../api/client";
import { Card, Icons, StatusPill } from "../ui";
import { restartSummary } from "./restartInfo";

/** Whether the device needs a restart, and why. Files queued for deletion are shown but are not a restart request. */
export function RestartCard({ device: d }: { device: Device }) {
  const hw = d.hardware;
  const count = hw?.queued_file_delete_count ?? 0;
  const s = restartSummary(!!d.pending_reboot, hw?.pending_reboot_reasons, count);
  const samples = hw?.queued_file_deletes ?? [];
  return (
    <Card title="Restart" description="What Windows says it needs a restart for. Housekeeping that installers leave for the next restart is listed separately.">
      <div style={{ display: "grid", gap: "var(--lp-space-2)" }}>
        <div>
          {s.pending ? <StatusPill kind="warning" icon={Icons.Restart}>{s.headline}</StatusPill> : <StatusPill kind="success">{s.headline}</StatusPill>}
        </div>
        {s.reasons.length > 0 && (
          <ul style={{ margin: 0, paddingLeft: "var(--lp-space-4)" }}>
            {s.reasons.map((r) => (
              <li key={r}>{r}</li>
            ))}
          </ul>
        )}
        {s.note && (
          <Text size="sm" c="dimmed">
            {s.note}
          </Text>
        )}
        {samples.length > 0 && (
          <details>
            <summary>Files queued for deletion</summary>
            <ul className="lp-mono" style={{ margin: "var(--lp-space-2) 0 0", paddingLeft: "var(--lp-space-4)", fontSize: "var(--lp-text-xs)", overflowWrap: "anywhere" }}>
              {samples.map((p) => (
                <li key={p}>{p}</li>
              ))}
              {count > samples.length && <li>and {count - samples.length} more</li>}
            </ul>
          </details>
        )}
      </div>
    </Card>
  );
}
