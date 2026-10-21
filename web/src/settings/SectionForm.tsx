import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Alert, Button } from "@mantine/core";
import { api, ApiError, errorMessage } from "../api/client";
import { Card, Icons, Skel, toast } from "../ui";
import { FieldInput, visible } from "./fields";
import { asObject, localErrors, type SettingsDoc, type SettingsField, type SettingsSection, type Values } from "./types";
import { useUnsaved } from "./useUnsaved";

/** The form sends secrets typed into the form and the explicit "remove" flags; everything else is plain values. */
export function toRequest(section: SettingsSection, values: Values): Values {
  const out: Values = {};
  for (const f of section.fields) {
    if (f.kind === "secret") {
      const clear = values["__clear_" + f.key] === true;
      const typed = String(values[f.key] ?? "");
      if (clear) out[f.key] = "";
      else if (typed !== "") out[f.key] = typed;
      continue;
    }
    out[f.key] = values[f.key];
  }
  // Secrets of list items travel inside the item as "secret"; empty ones must not be sent (they would be read as "keep", which is fine, but there is nothing to say).
  for (const f of section.fields) {
    if (f.kind !== "list") continue;
    out[f.key] = (Array.isArray(values[f.key]) ? (values[f.key] as Values[]) : []).map((item) => {
      const copy: Values = { ...item };
      for (const sub of f.fields ?? []) if (sub.kind === "secret" && String(copy[sub.key] ?? "") === "") delete copy[sub.key];
      return copy;
    });
  }
  return out;
}

const dirtyOf = (a: Values, b: Values) => JSON.stringify(a) !== JSON.stringify(b);

export function sectionQueryKey(id: string) {
  return ["settings", "section", id] as const;
}

interface Props {
  section: SettingsSection;
  /** Fields the form should highlight (from the search box). */
  focus?: string | null;
  /** Content shown after the form (test buttons, logs, references). */
  after?: ReactNode;
  /** Per-item actions inside list fields. */
  itemActions?: (field: SettingsField, item: Values) => ReactNode;
}

export function SectionForm({ section, focus, after, itemActions }: Props) {
  const qc = useQueryClient();
  const { setDirty } = useUnsaved();
  const q = useQuery({ queryKey: sectionQueryKey(section.id), queryFn: () => api<SettingsDoc>("GET", `/settings/sections/${section.id}`) });
  const [values, setValues] = useState<Values>({});
  const [baseline, setBaseline] = useState<Values>({});
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [conflict, setConflict] = useState(false);
  const revision = useRef(0);

  const load = (d: SettingsDoc) => {
    revision.current = d.revision ?? 0;
    const v = JSON.parse(JSON.stringify(d.values ?? {})) as Values;
    setValues(v);
    setBaseline(JSON.parse(JSON.stringify(v)) as Values);
    setErrors({});
    setConflict(false);
  };
  useEffect(() => {
    if (q.data) load(q.data);
  }, [q.data]);

  const dirty = useMemo(() => dirtyOf(values, baseline), [values, baseline]);
  useEffect(() => {
    setDirty(dirty);
    return () => setDirty(false);
  }, [dirty, setDirty]);

  // Scroll to and flash the field the search box pointed at.
  useEffect(() => {
    if (!focus || !q.data) return;
    const el = document.querySelector<HTMLElement>(`[data-setting="${CSS.escape(focus)}"]`);
    if (!el) return;
    el.scrollIntoView({ block: "center", behavior: "smooth" });
    el.classList.add("lp-set-flash");
    const t = window.setTimeout(() => el.classList.remove("lp-set-flash"), 2200);
    return () => window.clearTimeout(t);
  }, [focus, q.data]);

  const save = useMutation({
    mutationFn: () => api<SettingsDoc>("PUT", `/settings/sections/${section.id}`, { revision: revision.current, values: toRequest(section, values) }),
    onSuccess: (d) => {
      qc.setQueryData(sectionQueryKey(section.id), d);
      void qc.invalidateQueries({ queryKey: ["settings", "effective"] });
      load(d);
      toast.success(`${section.label} settings saved.`);
    },
    onError: (e) => {
      if (e instanceof ApiError && e.status === 409) {
        setConflict(true);
        return;
      }
      if (e instanceof ApiError && e.status === 422 && Object.keys(e.fields).length > 0) {
        setErrors(e.fields);
        toast.error("Some settings are not valid. See the messages on the page.");
        return;
      }
      toast.error(errorMessage(e));
    },
  });

  const local = useMemo(() => localErrors(section.fields.filter((f) => f.kind !== "secret"), values), [section.fields, values]);
  const allErrors = { ...local, ...errors };
  const blocked = Object.keys(local).length > 0;

  if (q.isLoading) {
    return (
      <Card>
        <div role="status" aria-label="Loading" style={{ display: "grid", gap: "var(--lp-space-3)" }}>
          <Skel w="35%" h={16} />
          <Skel h={36} />
          <Skel h={36} />
        </div>
      </Card>
    );
  }
  if (q.error || !q.data) {
    return (
      <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
        {errorMessage(q.error)}
      </Alert>
    );
  }
  const set = (key: string, v: unknown) => {
    setValues((cur) => ({ ...cur, [key]: v }));
    setErrors((e) => {
      if (!Object.keys(e).some((k) => k === key || k.startsWith(key + ".") || k.startsWith(key + "["))) return e;
      return Object.fromEntries(Object.entries(e).filter(([k]) => !(k === key || k.startsWith(key + ".") || k.startsWith(key + "["))));
    });
  };
  const defaults = Object.fromEntries(section.fields.filter((f) => f.kind !== "secret").map((f) => [f.key, f.default]));
  return (
    <div className="lp-set-form">
      {conflict && (
        <Alert color="yellow" icon={<Icons.Warning size={18} aria-hidden />} title="Someone else changed these settings">
          <p style={{ margin: 0 }}>Your changes were not saved, because another administrator saved this section after you opened it.</p>
          <Button mt="xs" size="compact-sm" variant="default" onClick={() => void q.refetch()}>
            Reload the latest settings
          </Button>
        </Alert>
      )}
      <Card title={section.label} description={section.description}>
        <div className="lp-set-fields">
          {section.fields
            .filter((f) => visible(f, values))
            .map((f) => (
              <div key={f.key} className="lp-set-row">
                <FieldInput
                  field={f}
                  path={f.key}
                  value={values[f.key]}
                  onChange={(v) => set(f.key, v)}
                  siblings={values}
                  setSibling={set}
                  errors={allErrors}
                  secretsSet={q.data.secrets_set ?? {}}
                  itemActions={itemActions ? (item) => itemActions(f, asObject(item)) : undefined}
                />
                {f.kind !== "secret" && f.kind !== "list" && JSON.stringify(values[f.key]) !== JSON.stringify(defaults[f.key]) && (
                  <button type="button" className="lp-set-reset" onClick={() => set(f.key, JSON.parse(JSON.stringify(defaults[f.key] ?? "")))} aria-label={`Reset to default: ${f.label}`}>
                    Reset to default
                  </button>
                )}
              </div>
            ))}
        </div>
      </Card>
      {after}
      <div className={`lp-unsaved${dirty ? " lp-unsaved--on" : ""}`} role="region" aria-label="Unsaved changes" hidden={!dirty}>
        <span>
          <Icons.Warning size={16} aria-hidden /> You have unsaved changes.
        </span>
        <span className="lp-unsaved__actions">
          <Button variant="default" onClick={() => (setValues(JSON.parse(JSON.stringify(baseline)) as Values), setErrors({}))} disabled={save.isPending}>
            Discard
          </Button>
          <Button onClick={() => save.mutate()} loading={save.isPending} disabled={blocked} leftSection={<Icons.Save size={16} aria-hidden />}>
            Save changes
          </Button>
        </span>
      </div>
    </div>
  );
}
