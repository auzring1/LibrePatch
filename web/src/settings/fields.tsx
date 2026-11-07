import { useMemo } from "react";
import { Button, Checkbox, NumberInput, PasswordInput, Select, Switch, TagsInput, Text, TextInput, Textarea, Autocomplete } from "@mantine/core";
import { Icons } from "../ui";
import { asArray, asObject, newItem, type SettingsField, type Values } from "./types";

export const EFFECT_NOTE: Record<string, string> = {
  prefill: "Used as the starting value when someone creates one; it does not change what already exists.",
  planned: "Saved and checked, but nothing uses it yet.",
};

const zones = (() => {
  try {
    return (Intl as unknown as { supportedValuesOf: (k: string) => string[] }).supportedValuesOf("timeZone");
  } catch {
    return ["UTC"];
  }
})();

interface Common {
  field: SettingsField;
  /** Where the field lives, for error messages and DOM ids: "smtp_host" or "rules[0].threshold". */
  path: string;
  errors: Record<string, string>;
  disabled?: boolean;
  /** Which secret paths are saved on the server (top-level only). */
  secretsSet?: Record<string, boolean>;
}

interface InputProps extends Common {
  value: unknown;
  onChange: (v: unknown) => void;
  /** The whole object this field belongs to (for show_if and secret flags). */
  siblings: Values;
  setSibling: (key: string, v: unknown) => void;
  itemActions?: (item: Values, index: number) => React.ReactNode;
}

const idOf = (path: string) => `set-${path.replace(/[^a-zA-Z0-9]+/g, "-")}`;

export function Help({ field }: { field: SettingsField }) {
  const note = field.effect ? EFFECT_NOTE[field.effect] : undefined;
  return (
    <>
      {field.help}
      {note && <span className="lp-set-note"> {note}</span>}
    </>
  );
}

/** One setting, rendered according to its kind. Everything it needs to say (label, help, limits) comes from the server's declaration. */
export function FieldInput(p: InputProps) {
  const { field: f, path, value, onChange, errors, disabled } = p;
  const id = idOf(path);
  const error = errors[path];
  const common = { id, label: f.label, description: <Help field={f} />, error, disabled, "data-setting": f.key } as const;
  switch (f.kind) {
    case "bool":
      return (
        <div className="lp-set-field" data-setting={f.key}>
          <Switch id={id} label={f.label} description={<Help field={f} />} checked={value === true} onChange={(e) => onChange(e.currentTarget.checked)} disabled={disabled} error={error} />
        </div>
      );
    case "int":
      return (
        <NumberInput
          {...common}
          value={typeof value === "number" ? value : ""}
          onChange={(v) => onChange(typeof v === "number" ? v : v === "" ? "" : Number(v))}
          min={f.min}
          max={f.max}
          allowDecimal={false}
          clampBehavior="none"
          rightSection={f.unit ? <span className="lp-set-unit">{f.unit}</span> : undefined}
          rightSectionWidth={f.unit ? 84 : undefined}
          rightSectionPointerEvents="none"
        />
      );
    case "text":
      return <Textarea {...common} autosize minRows={2} maxRows={8} value={String(value ?? "")} onChange={(e) => onChange(e.currentTarget.value)} maxLength={f.max} placeholder={f.placeholder} />;
    case "string":
    case "regex":
    case "url":
      return <TextInput {...common} value={String(value ?? "")} onChange={(e) => onChange(e.currentTarget.value)} maxLength={f.max} placeholder={f.placeholder} autoComplete="off" />;
    case "time":
      return <TextInput {...common} type="time" value={String(value ?? "")} onChange={(e) => onChange(e.currentTarget.value)} />;
    case "timezone":
      return <Autocomplete {...common} data={zones} value={String(value ?? "")} onChange={(v) => onChange(v)} placeholder={f.placeholder ?? "Leave empty for each person's own"} limit={30} />;
    case "enum":
      return <Select {...common} data={(f.options ?? []).map((o) => ({ value: o.value, label: o.label }))} value={String(value ?? "")} onChange={(v) => onChange(v ?? "")} allowDeselect={false} comboboxProps={{ withinPortal: true }} />;
    case "multi": {
      const cur = asArray(value).map(String);
      return (
        <Checkbox.Group id={id} label={f.label} description={<Help field={f} />} error={error} value={cur} onChange={(v) => onChange(v)} data-setting={f.key}>
          <div className="lp-set-checks">
            {(f.options ?? []).map((o) => (
              <Checkbox key={o.value} value={o.value} label={o.label} disabled={disabled} />
            ))}
          </div>
        </Checkbox.Group>
      );
    }
    case "emails":
    case "cidrs":
    case "tags":
      return <TagsInput {...common} value={asArray(value).map(String)} onChange={(v) => onChange(v)} splitChars={[",", " ", ";"]} placeholder={f.placeholder} clearable />;
    case "secret": {
      const set = !!p.secretsSet?.[path];
      const clearKey = "__clear_" + f.key;
      return (
        <div className="lp-set-field" data-setting={f.key}>
          <PasswordInput {...common} value={String(value ?? "")} onChange={(e) => onChange(e.currentTarget.value)} placeholder={set ? "Saved. Type to replace it." : ""} autoComplete="new-password" maxLength={f.max} />
          {set && !path.includes("[") && (
            <Checkbox mt={6} size="xs" label="Remove the saved value" checked={p.siblings[clearKey] === true} onChange={(e) => p.setSibling(clearKey, e.currentTarget.checked)} disabled={disabled} />
          )}
        </div>
      );
    }
    case "list":
      return <ListEditor {...p} />;
  }
  return null;
}

/** Whether a field should show, given its show_if sibling. */
export const visible = (f: SettingsField, siblings: Values) => !f.show_if || siblings[f.show_if] === true;

function itemTitle(f: SettingsField, item: Values, i: number): string {
  const key = f.item_key ? String(item[f.item_key] ?? "") : "";
  if (f.fixed && f.item_key) {
    const sub = (f.fields ?? []).find((x) => x.key === f.item_key);
    return sub?.options?.find((o) => o.value === key)?.label ?? key;
  }
  return String(item["name"] ?? item["label"] ?? key ?? "") || `Item ${i + 1}`;
}

export function ListEditor(p: InputProps) {
  const { field: f, path, errors, disabled } = p;
  const items = asArray(p.value).map(asObject);
  const set = (next: Values[]) => p.onChange(next);
  const subs = f.fields ?? [];
  const hidden = useMemo(() => new Set(["id", ...(f.fixed && f.item_key ? [f.item_key] : [])]), [f.fixed, f.item_key]);
  return (
    <div className="lp-set-list" role="group" aria-labelledby={idOf(path) + "-label"} data-setting={f.key}>
      <div className="lp-set-list__head">
        <div>
          <div className="lp-set-list__label" id={idOf(path) + "-label"}>
            {f.label}
          </div>
          <Text size="sm" c="dimmed">
            <Help field={f} />
          </Text>
        </div>
        {!f.fixed && (
          <Button size="compact-sm" variant="default" leftSection={<Icons.Plus size={14} aria-hidden />} disabled={disabled || (f.max !== undefined && f.max > 0 && items.length >= f.max)} onClick={() => set([...items, newItem(f)])}>
            Add
          </Button>
        )}
      </div>
      {errors[path] && (
        <Text size="sm" c="red" role="alert">
          {errors[path]}
        </Text>
      )}
      {items.length === 0 && !f.fixed && <div className="lp-set-list__empty">Nothing added yet.</div>}
      {items.map((item, i) => {
        const ip = `${path}[${i}]`;
        return (
          <fieldset className="lp-set-item" key={String(item["id"] || item[f.item_key ?? ""] || i) + ":" + i} aria-label={itemTitle(f, item, i)}>
            <legend>{itemTitle(f, item, i)}</legend>
            <div className="lp-set-grid">
              {subs
                .filter((s) => !hidden.has(s.key) && visible(s, item))
                .map((s) => (
                  <FieldInput
                    key={s.key}
                    field={s}
                    path={`${ip}.${s.key}`}
                    value={item[s.key]}
                    onChange={(v) => set(items.map((x, j) => (j === i ? { ...x, [s.key]: v } : x)))}
                    siblings={item}
                    setSibling={(k, v) => set(items.map((x, j) => (j === i ? { ...x, [k]: v } : x)))}
                    errors={errors}
                    disabled={disabled}
                    secretsSet={{ [`${ip}.${s.key}`]: !!p.secretsSet?.[`${f.key}.${String(item["id"] ?? "")}.${s.key}`] }}
                  />
                ))}
            </div>
            <div className="lp-set-item__actions">
              {p.itemActions?.(item, i)}
              {!f.fixed && (
                <Button size="compact-sm" variant="subtle" color="red" leftSection={<Icons.Trash size={14} aria-hidden />} disabled={disabled} onClick={() => set(items.filter((_, j) => j !== i))} aria-label={`Remove ${itemTitle(f, item, i)}`}>
                  Remove
                </Button>
              )}
            </div>
          </fieldset>
        );
      })}
    </div>
  );
}
