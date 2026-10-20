/** The read-only views of a device (D125): what the agent returns, and how it is shown. */

export interface ProcessRow {
  pid: number;
  parent_pid: number;
  name: string;
  session: number;
  threads: number;
  working_set_kb: number;
  path?: string;
}

export interface ServiceRow {
  name: string;
  display: string;
  state: string;
  start: string;
  account: string;
  path: string;
}

export interface EventRow {
  time: number;
  level: number;
  provider: string;
  id: number;
  message: string;
  /** Position in the list, added by the console so rows have unique keys. */
  _i?: number;
}

export type ViewKind = "processes" | "services" | "events";

export interface ViewData<T> {
  kind: ViewKind;
  taken_at: number;
  truncated: boolean;
  total: number;
  items: T[];
}

export const EVENT_LEVEL: Record<number, string> = { 1: "Critical", 2: "Error", 3: "Warning", 4: "Information", 5: "Verbose" };

export const eventLevel = (n: number) => EVENT_LEVEL[n] ?? String(n);

export const EVENT_LOGS = [
  { value: "System", label: "System" },
  { value: "Application", label: "Application" },
  { value: "Setup", label: "Setup" },
];

export const EVENT_LEVELS = [
  { value: "2", label: "Critical and errors" },
  { value: "3", label: "Warnings and worse" },
  { value: "4", label: "Information and worse" },
];

export const EVENT_SINCE = [
  { value: "60", label: "Last hour" },
  { value: "1440", label: "Last day" },
  { value: "4320", label: "Last 3 days" },
  { value: "10080", label: "Last week" },
];

/** "1.5 GB" from kilobytes. */
export function kb(n: number): string {
  if (n < 1024) return `${n} KB`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(n < 10 * 1024 ? 1 : 0)} MB`;
  return `${(n / 1024 / 1024).toFixed(1)} GB`;
}

export const START_LABEL: Record<string, string> = {
  automatic: "Automatic",
  automatic_delayed: "Automatic (delayed)",
  manual: "Manual",
  disabled: "Disabled",
};

/** Why the view is not there yet, in plain words. */
export function waitingText(status: string, reason: string): string {
  switch (status) {
    case "queued":
    case "sent":
      return "Waiting for the device to pick up the request…";
    case "accepted":
    case "waiting":
    case "running":
      return "The device is reading it…";
    case "failed":
      return reason ? `The device could not do it (${reason}).` : "The device could not do it.";
    case "rejected":
      return "The device refused: its local policy does not allow this view.";
    case "expired":
      return "The device did not answer in time.";
    default:
      return "";
  }
}

export const isFinalStatus = (s: string) => ["succeeded", "succeeded_reboot", "failed", "expired", "cancelled", "rejected"].includes(s);
