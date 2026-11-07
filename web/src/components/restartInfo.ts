/** Why a device is, or is not, asked to restart. The agent sends the reasons; this turns them into words. */
export const RESTART_REASONS: Record<string, string> = {
  component_based_servicing: "Windows servicing finished installing an update and needs a restart",
  windows_update: "Windows Update needs a restart to finish",
  pending_file_rename: "Files are waiting to be renamed or replaced at the next restart",
  computer_rename: "The computer was renamed and needs a restart",
  reboot_required_file: "The system asked for a restart",
};

export interface RestartSummary {
  pending: boolean;
  headline: string;
  reasons: string[];
  /** An explanation to show under the reasons, if any. */
  note?: string;
}

const files = (n: number) => `${n} file${n === 1 ? " is" : "s are"}`;

/**
 * Queued file deletions (installers and updaters such as Edge and Firefox leave them behind and queue new ones within
 * hours) are listed on their own: they only count as a pending restart when the organization turned that on.
 */
export function restartSummary(pending: boolean, reasons: string[] = [], queuedDeletes = 0): RestartSummary {
  const words = reasons.map((r) => RESTART_REASONS[r] ?? r);
  if (pending && words.length === 0 && queuedDeletes > 0) {
    return {
      pending,
      headline: "A restart is needed",
      reasons: [`${files(queuedDeletes)} queued for deletion at the next restart`],
      note: "Counted because Settings > Device defaults treats queued file deletions as a pending restart.",
    };
  }
  if (pending) return { pending, headline: "A restart is needed", reasons: words };
  if (queuedDeletes > 0) {
    return {
      pending,
      headline: "No restart needed",
      reasons: [],
      note: `${files(queuedDeletes)} queued for deletion at the next restart. Installers and updaters leave these behind; they do not mean Windows needs a restart.`,
    };
  }
  return { pending, headline: "No restart needed", reasons: [] };
}
