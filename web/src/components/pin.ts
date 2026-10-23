/** How a package's version pin reads in the console: the server stores "", "latest", "= 24.08" or "< 25". */
export type PinMode = "newest" | "exact" | "below" | "custom";

export interface PinForm {
  mode: PinMode;
  /** The version for "exact" and "below"; the whole text for "custom". */
  version: string;
}

/** The form for a stored pin. Anything the server accepts that is not one of the plain shapes is kept as it is ("custom"). */
export function parsePin(pin: string | null | undefined): PinForm {
  const p = (pin ?? "").trim();
  if (p === "" || p === "latest") return { mode: "newest", version: "" };
  const m = /^(=|<)\s+(\S+)$/.exec(p);
  if (m) return { mode: m[1] === "=" ? "exact" : "below", version: m[2]! };
  return { mode: "custom", version: p };
}

/** The stored pin for the form ("" = always the newest). */
export function formatPin(f: PinForm): string {
  const v = f.version.trim();
  switch (f.mode) {
    case "newest":
      return "";
    case "exact":
      return v ? `= ${v}` : "";
    case "below":
      return v ? `< ${v}` : "";
    default:
      return v;
  }
}

/** One sentence for what the pin does, for under the field. */
export function describePin(f: PinForm): string {
  const v = f.version.trim();
  switch (f.mode) {
    case "newest":
      return "New versions are installed as soon as they are in the catalog.";
    case "exact":
      return v ? `Always installs version ${v}, even when newer versions exist ; devices that already have a newer one are left alone.` : "Choose the version to stay on.";
    case "below":
      return v ? `Installs the newest version older than ${v}.` : "Enter the version it must stay below.";
    default:
      return "A pin written by hand.";
  }
}
