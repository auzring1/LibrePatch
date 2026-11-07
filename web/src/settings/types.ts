export interface SettingsOption {
  value: string;
  label: string;
}

/** One setting as the server declares it (see internal/server/settings). */
export interface SettingsField {
  key: string;
  label: string;
  help: string;
  kind: "bool" | "int" | "string" | "text" | "enum" | "multi" | "time" | "timezone" | "emails" | "cidrs" | "url" | "secret" | "list" | "regex" | "tags";
  default?: unknown;
  min?: number;
  max?: number;
  unit?: string;
  placeholder?: string;
  required?: boolean;
  fixed?: boolean;
  item_key?: string;
  show_if?: string;
  /** live | prefill | planned: what the setting does today. */
  effect: string;
  options?: SettingsOption[];
  fields?: SettingsField[];
}

export interface SettingsSection {
  id: string;
  label: string;
  description: string;
  perm: string;
  editable: boolean;
  fields: SettingsField[];
}

export interface SettingsDoc {
  section: string;
  revision: number;
  values: Record<string, unknown>;
  secrets_set: Record<string, boolean>;
  updated_at: string;
}

export interface SettingsSchema {
  schema_version: number;
  sections: SettingsSection[];
  events: SettingsOption[];
}
export type Values = Record<string, unknown>;

export const asArray = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
export const asObject = (v: unknown): Values => (v && typeof v === "object" && !Array.isArray(v) ? (v as Values) : {});

/** A copy of a field's default that is safe to edit. */
export const cloneDefault = (v: unknown): unknown => (v === undefined ? "" : JSON.parse(JSON.stringify(v)));

/** The starting value of a new list item. */
export function newItem(f: SettingsField): Values {
  const out: Values = {};
  for (const sub of f.fields ?? []) {
    if (sub.kind === "secret") continue;
    out[sub.key] = cloneDefault(sub.default);
  }
  return out;
}

/** Client-side checks that need no round trip; the server repeats every one of them and has the last word. */
export function localErrors(fields: SettingsField[], values: Values, path = ""): Record<string, string> {
  const errs: Record<string, string> = {};
  for (const f of fields) {
    const p = path ? `${path}.${f.key}` : f.key;
    const v = values[f.key];
    if (f.kind === "int") {
      if (typeof v !== "number" || !Number.isInteger(v)) errs[p] = "Enter a whole number.";
      else if (v < (f.min ?? 0) || v > (f.max ?? 0)) errs[p] = `Enter a number from ${f.min} to ${f.max}.`;
    } else if (f.required && f.kind !== "bool" && (v === undefined || v === null || v === "")) {
      errs[p] = "This is required.";
    } else if (f.kind === "list") {
      asArray(v).forEach((item, i) => Object.assign(errs, localErrors(f.fields ?? [], asObject(item), `${f.key}[${i}]`)));
    }
  }
  return errs;
}
