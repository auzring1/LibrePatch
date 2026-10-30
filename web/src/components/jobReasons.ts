/** What a job's status reason means, in plain words. Unknown reasons are shown as they are. */
const REASONS: Record<string, string> = {
  waiting_other_job: "Waiting for another job on this PC to finish",
  waiting_not_before: "Waiting for its start time",
  waiting_window: "Waiting for the maintenance window",
  waiting_user_logon: "Waiting for someone to sign in",
  waiting_install_finish: "Waiting for a running install to finish",
  cancelled_by_administrator: "Cancelled by an administrator",
  deployment_cancelled: "The deployment was cancelled",
  dependency_failed: "A job it depended on failed",
  expired: "Expired before the PC could run it",
  failed: "Failed; Details says why",
  profile_in_use: "The profile is in use (the person is signed in)",
  profile_protected: "Protected: the account this computer signs in to automatically",
  no_silent_uninstall: "Cannot be removed without a window; Details says why",
  uninstaller_failed: "The uninstaller failed",
  installer_failed: "The installer failed",
  failed_detection: "Finished, but the program was not found afterwards",
};

export function jobReason(reason: string | null | undefined): string {
  if (!reason) return "";
  return REASONS[reason] ?? reason;
}

/** A job that has not finished and can be stopped. */
export const jobCanBeCancelled = (status: string) => ["queued", "sent", "accepted", "waiting", "running"].includes(status);
