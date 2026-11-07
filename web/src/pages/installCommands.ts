/** The commands the server returns for a new token (see POST /enrollment-tokens, "install"). */
export interface InstallCommand {
  /** One line that downloads the installer from this server, installs it and cleans up; empty while the server does not have it. */
  one_liner: string;
  /** curl.exe line that downloads the installer into the current folder; empty while the server does not have it. */
  download: string;
  /** The plain install command for a file that is already in the current folder. */
  command: string;
}

export interface InstallCommands {
  msi: InstallCommand;
  exe: InstallCommand;
}

/**
 * The text to copy. It is ONE line that works pasted into Command Prompt and PowerShell: the one-liner when the server has
 * the installer, otherwise the plain install command for a file the person already has in the current folder.
 */
export function commandText(c: InstallCommand): string {
  return c.one_liner.trim() !== "" ? c.one_liner : c.command;
}

/** The size of a download the way people read it: 14.2 MB. */
export function fileSize(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "";
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
