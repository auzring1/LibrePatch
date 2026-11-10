import { useEffect, useState } from "react";
import { Button, Drawer, Group, Modal, NumberInput, Select, Stack, Text, Textarea, TextInput } from "@mantine/core";
import type { Site } from "../../api/client";
import { Icons } from "../../ui";
import type { WidgetSettings } from "./boards";
import { destinationsFor, availableMetrics, RANGE_CHOICES, widgetDef, WIDGETS, type WidgetCtx, type WidgetDef } from "./registry";

/** The "Add widget" panel: the library, grouped, with a short line on each. */
export function AddWidgetDrawer({ opened, onClose, kinds, onAdd }: { opened: boolean; onClose: () => void; kinds: string[]; onAdd: (def: WidgetDef) => void }) {
  const groups = ["Numbers", "Lists", "Charts", "Other"] as const;
  return (
    <Drawer opened={opened} onClose={onClose} title="Add a widget" position="right" size="md">
      <Text size="sm" c="dimmed" mb="md">
        Pick a widget; it is added at the bottom of the dashboard, where you can drag it into place and resize it. Widgets you are not allowed to see are not listed.
      </Text>
      <Stack gap="lg">
        {groups.map((g) => {
          const defs = WIDGETS.filter((w) => w.group === g && kinds.includes(w.kind));
          if (defs.length === 0) return null;
          return (
            <section key={g} aria-label={g}>
              <Text fw={600} mb="xs">
                {g}
              </Text>
              <ul className="lp-dash-custom">
                {defs.map((def) => (
                  <li key={def.kind}>
                    <span style={{ minWidth: 0 }}>
                      <Text fw={500}>{def.title}</Text>
                      <Text size="sm" c="dimmed">
                        {def.description}
                      </Text>
                    </span>
                    <Button variant="default" size="compact-md" leftSection={<Icons.Plus size={14} aria-hidden="true" />} onClick={() => onAdd(def)} aria-label={`Add ${def.title}`}>
                      Add
                    </Button>
                  </li>
                ))}
              </ul>
            </section>
          );
        })}
      </Stack>
    </Drawer>
  );
}

/** One widget's settings: its title, the site, the time range, how many rows, which number, where it leads, its text. */
export function WidgetSettingsDialog({
  opened,
  onClose,
  type,
  settings,
  sites,
  ctx,
  onApply,
}: {
  opened: boolean;
  onClose: () => void;
  type: string;
  settings: WidgetSettings;
  sites: Site[];
  ctx: WidgetCtx | null;
  onApply: (s: WidgetSettings) => void;
}) {
  const def = widgetDef(type);
  const [v, setV] = useState<WidgetSettings>(settings);
  useEffect(() => {
    if (opened) setV(settings);
  }, [opened, settings]);
  if (!def) return null;
  const has = (f: string) => (def.fields as string[]).includes(f);
  const metrics = ctx ? availableMetrics(ctx.d) : [];
  const dests = ctx ? destinationsFor(ctx) : [];
  const set = (patch: WidgetSettings) => setV((cur) => ({ ...cur, ...patch }));
  return (
    <Modal opened={opened} onClose={onClose} title={`${def.title} settings`} centered>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          onApply(v);
        }}
      >
        <Stack>
          <TextInput label="Title" description="Leave empty for the default title" maxLength={60} value={v.title ?? ""} onChange={(e) => set({ title: e.currentTarget.value })} />
          {has("metric") && <Select label="Number" allowDeselect={false} data={metrics} value={v.metric ?? metrics[0]?.value ?? null} onChange={(m) => set({ metric: m ?? undefined })} />}
          {has("dest") && <Select label="Opens" allowDeselect={false} data={dests.map((x) => ({ value: x.id, label: x.label }))} value={v.dest ?? null} onChange={(m) => set({ dest: m ?? undefined })} description={dests.find((x) => x.id === v.dest)?.hint} />}
          {has("site") && (
            <Select
              label="Site"
              description="Show one site on this widget, whatever the site switcher says"
              clearable={false}
              allowDeselect={false}
              data={[{ value: "", label: "Follow the site switcher" }, ...sites.map((s) => ({ value: s.id, label: s.name }))]}
              value={v.site ?? ""}
              onChange={(m) => set({ site: m || undefined })}
            />
          )}
          {has("range") && <Select label="Time range" allowDeselect={false} data={RANGE_CHOICES} value={v.range ?? "30d"} onChange={(m) => set({ range: m ?? undefined })} />}
          {has("count") && <NumberInput label="Rows to show" description="Up to 8; the dashboard keeps the top entries" min={1} max={8} allowDecimal={false} value={v.count ?? 8} onChange={(n) => set({ count: typeof n === "number" ? n : undefined })} />}
          {has("text") && <Textarea label="Text" maxLength={500} autosize minRows={3} maxRows={8} value={v.text ?? ""} onChange={(e) => set({ text: e.currentTarget.value })} description="Plain text. Web addresses become links." />}
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit">Apply</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

/** Asks for a name (new dashboard). */
export function NameDialog({ opened, onClose, title, initial, confirm, onSubmit }: { opened: boolean; onClose: () => void; title: string; initial: string; confirm: string; onSubmit: (name: string) => void }) {
  const [name, setName] = useState(initial);
  useEffect(() => {
    if (opened) setName(initial);
  }, [opened, initial]);
  return (
    <Modal opened={opened} onClose={onClose} title={title} centered>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (name.trim()) onSubmit(name.trim());
        }}
      >
        <Stack>
          <TextInput label="Name" data-autofocus maxLength={40} value={name} onChange={(e) => setName(e.currentTarget.value)} required />
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={!name.trim()}>
              {confirm}
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}
