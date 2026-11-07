import type { InstallPrompts } from "../api/client";

/** The choices of "Messages to the user" as the form holds them. Everything at its default means: fully silent. */
export interface PromptsForm {
  inUse: InstallPrompts["in_use"];
  askTimeoutS: number | string;
  deferMinutes: number | string;
  restart: InstallPrompts["restart"];
  restartMinutes: number | string;
}

export const SILENT: PromptsForm = { inUse: "ignore", askTimeoutS: 300, deferMinutes: 60, restart: "none", restartMinutes: 5 };

export const IN_USE_OPTIONS: { value: InstallPrompts["in_use"]; label: string }[] = [
  { value: "ignore", label: "Install silently anyway (default)" },
  { value: "skip", label: "Wait until the program is closed" },
  { value: "ask", label: "Ask the user to close it" },
  { value: "close", label: "Warn the user, then close it" },
];

export const RESTART_OPTIONS: { value: InstallPrompts["restart"]; label: string }[] = [
  { value: "none", label: "Only report it (default)" },
  { value: "ask", label: "Ask the user" },
  { value: "countdown", label: "Restart after a countdown" },
];

/** True when the in-use choice needs the names of the package's programs. */
export const needsPrograms = (f: PromptsForm) => f.inUse !== "ignore";

/** The request body part: null when nothing was chosen, so the deployment stays silent and the server stores nothing. */
export function toPrompts(f: PromptsForm): InstallPrompts | null {
  if (f.inUse === "ignore" && f.restart === "none") return null;
  const p: InstallPrompts = { in_use: f.inUse, restart: f.restart };
  if (f.inUse === "ask" || f.inUse === "close") p.ask_timeout_s = Number(f.askTimeoutS) || 0;
  if (f.inUse === "skip" || f.inUse === "ask") p.defer_minutes = Number(f.deferMinutes) || 0;
  if (f.restart !== "none") p.restart_notify_minutes = Number(f.restartMinutes) || 0;
  return p;
}

/** The form for a stored choice (null = silent). */
export function fromPrompts(p: InstallPrompts | null | undefined): PromptsForm {
  if (!p) return { ...SILENT };
  return {
    inUse: p.in_use ?? "ignore",
    askTimeoutS: p.ask_timeout_s || 300,
    deferMinutes: p.defer_minutes || 60,
    restart: p.restart ?? "none",
    restartMinutes: p.restart_notify_minutes || 5,
  };
}

const minutes = (s: number) => `${Math.round(s / 60) || 1} min`;

/** One plain sentence for lists and summaries; "" when silent. */
export function describePrompts(p: InstallPrompts | null | undefined): string {
  if (!p) return "";
  const parts: string[] = [];
  switch (p.in_use) {
    case "skip":
      parts.push("waits until the program is closed");
      break;
    case "ask":
      parts.push(`asks the user to close the program (question stays up ${minutes(p.ask_timeout_s || 300)})`);
      break;
    case "close":
      parts.push(`warns the user, then closes the program after ${minutes(p.ask_timeout_s || 300)}`);
      break;
  }
  switch (p.restart) {
    case "ask":
      parts.push("asks before a restart the installer needs");
      break;
    case "countdown":
      parts.push(`restarts after a ${p.restart_notify_minutes || 5} min countdown when the installer needs it`);
      break;
  }
  return parts.join("; ");
}

/** Program names typed as "a.exe, b.exe" or one per line. */
export function parsePrograms(text: string): string[] {
  return text
    .split(/[\s,;]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}
