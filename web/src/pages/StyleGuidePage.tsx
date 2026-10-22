import { useMemo, useState } from "react";
import { Alert, Button, Checkbox, Drawer, Group, Menu, Modal, NumberInput, PasswordInput, Radio, SegmentedControl, Select, Stack, Switch, Tabs, Text, TextInput, Textarea, Tooltip } from "@mantine/core";
import { useSession } from "../api/session";
import { useAppearance } from "../design/AppearanceProvider";
import { SURFACE_KEYS } from "../design/accent";
import { THEMES } from "../design/themes";
import {
  Card,
  DataTable,
  Donut,
  EmptyState,
  Icons,
  IconButton,
  Page,
  PageHeader,
  SeverityBadge,
  Skel,
  StackedBar,
  StatGrid,
  StatTile,
  Status,
  StatusPill,
  TableSkeleton,
  TileSkeleton,
  toast,
  useConfirm,
  type Column,
  type PillKind,
} from "../ui";
import { useDocumentTitle } from "../branding/BrandingProvider";
import { PRODUCT_NAME } from "../brand.generated";

interface Demo {
  id: string;
  host: string;
  os: string;
  status: string;
  online: boolean;
  severity: string;
  missing: number;
  seen: number;
  site: string;
}

const SITES = ["Main campus", "North clinic", "Lab annex"];
const SEV = ["critical", "important", "moderate", "low", ""];
const DEMO: Demo[] = Array.from({ length: 64 }, (_, i) => ({
  id: `d${i}`,
  host: `${["WS", "LT", "KIOSK", "SRV"][i % 4]}-${String(100 + i)}`,
  os: i % 5 === 0 ? "Windows 10 Pro 22H2" : "Windows 11 Pro 24H2",
  status: i % 11 === 0 ? "pending" : i % 13 === 0 ? "revoked" : "active",
  online: i % 3 !== 0,
  severity: SEV[i % SEV.length]!,
  missing: (i * 7) % 9,
  seen: Date.now() - ((i * 37) % 600) * 60_000,
  site: SITES[i % SITES.length]!,
}));

const KINDS: PillKind[] = ["success", "warning", "danger", "info", "neutral"];
const TOKEN_GROUPS: { title: string; names: string[] }[] = [
  { title: "Surfaces", names: [...SURFACE_KEYS] },
  { title: "Text and borders", names: ["text", "text-muted", "border", "border-strong", "focus"] },
  { title: "Accent (branding layered on the theme)", names: ["accent", "on-accent", "accent-text", "accent-subtle", "accent-subtle-text", "accent-border"] },
  { title: "Status", names: KINDS.flatMap((k) => [`${k}-fg`, `${k}-bg`, `${k}-solid`]) },
  { title: "Severity", names: ["critical", "important", "moderate", "low"].flatMap((k) => [`${k}-fg`, `${k}-bg`, `${k}-solid`]) },
  { title: "Charts", names: [1, 2, 3, 4, 5, 6].map((i) => `chart-${i}`) },
];

function Section({ id, title, children }: { id: string; title: string; children: React.ReactNode }) {
  return (
    <Card title={title} id={id}>
      <Stack gap="md">{children}</Stack>
    </Card>
  );
}

/** Every component of the design system, in the active theme. Administrators only. */
export function StyleGuidePage() {
  const { canOrg } = useSession();
  const { theme, offered, choice, setChoice, density } = useAppearance();
  const confirm = useConfirm();
  const [modal, setModal] = useState(false);
  const [drawer, setDrawer] = useState(false);
  const [seg, setSeg] = useState("a");
  useDocumentTitle("Style guide");
  const cols = useMemo<Column<Demo>[]>(
    () => [
      { id: "host", header: "Device", value: (r) => r.host, primary: true, required: true, width: 170, cell: (r) => <strong>{r.host}</strong> },
      { id: "status", header: "Status", value: (r) => r.status, width: 120, cell: (r) => <Status value={r.status} size="sm" />, filter: { type: "select", options: ["active", "pending", "revoked"].map((v) => ({ value: v, label: v })) } },
      { id: "conn", header: "Connection", value: (r) => (r.online ? "online" : "offline"), width: 130, cell: (r) => <Status value={r.online ? "online" : "offline"} size="sm" />, filter: { type: "select", options: [{ value: "online", label: "Online" }, { value: "offline", label: "Offline" }] } },
      { id: "sev", header: "Worst missing update", value: (r) => r.severity, width: 170, cell: (r) => <SeverityBadge severity={r.severity} size="sm" /> },
      { id: "missing", header: "Missing", value: (r) => r.missing, width: 100, align: "right", cell: (r) => <span className="lp-num">{r.missing}</span> },
      { id: "os", header: "Operating system", value: (r) => r.os, width: 190 },
      { id: "site", header: "Site", value: (r) => r.site, width: 140, filter: { type: "select", options: SITES.map((s) => ({ value: s, label: s })) } },
      { id: "seen", header: "Last seen", value: (r) => r.seen, defaultHidden: true, width: 150, cell: (r) => new Date(r.seen).toLocaleString() },
    ],
    [],
  );

  if (!canOrg("branding:write")) return <Alert color="yellow">The style guide is for administrators.</Alert>;

  return (
    <Page>
      <PageHeader
        title="Style guide"
        description="Every component of the console's design system in the theme you are using. Switch themes from your account menu (top right) to see each one."
        
        actions={<StatusPill kind="info">Theme: {theme.name}</StatusPill>}
      />

      <Section id="themes" title="Themes">
        <Text size="sm" c="dimmed">
          Each theme is one small file in <code>src/design/themes</code>. A test checks every text, border, focus, status, severity and chart color of every theme against WCAG AA, and layers sample brand accents on each.
        </Text>
        <Group>
          {THEMES.map((t) => (
            <Button key={t.id} variant={choice === t.id || (!choice && theme.id === t.id) ? "filled" : "default"} disabled={!offered.some((o) => o.id === t.id)} onClick={() => setChoice(t.id)} aria-pressed={theme.id === t.id}>
              {t.name}
            </Button>
          ))}
        </Group>
        {TOKEN_GROUPS.map((g) => (
          <div key={g.title}>
            <Text fw={600} size="sm" mb={6}>
              {g.title}
            </Text>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(150px, 1fr))", gap: 8 }}>
              {g.names.map((n) => (
                <div key={n} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: "var(--lp-text-xs)" }}>
                  <span style={{ width: 28, height: 28, borderRadius: 6, background: `var(--lp-${n})`, border: "1px solid var(--lp-border-strong)", flex: "none" }} aria-hidden="true" />
                  <code>--lp-{n}</code>
                </div>
              ))}
            </div>
          </div>
        ))}
      </Section>

      <Section id="type" title="Typography">
        <div style={{ display: "grid", gap: 6 }}>
          {[
            ["3xl", "Page title style 28"],
            ["2xl", "Page heading 22"],
            ["xl", "Section heading 18"],
            ["lg", "Card title 16"],
            ["md", "Body text 14: the quick brown fox jumps over the lazy dog 0123456789"],
            ["sm", "Table text 13: the quick brown fox jumps over the lazy dog 0123456789"],
            ["xs", "Captions 12: the quick brown fox jumps over the lazy dog"],
          ].map(([k, s]) => (
            <div key={k} style={{ fontSize: `var(--lp-text-${k})`, fontWeight: k === "md" || k === "sm" || k === "xs" ? 400 : 600 }}>
              {s}
            </div>
          ))}
          <div className="lp-mono">Monospace: 3f9c1a — C:\Program Files\{PRODUCT_NAME}</div>
        </div>
      </Section>

      <Section id="buttons" title="Buttons">
        <Group>
          <Button>Primary</Button>
          <Button variant="default">Secondary</Button>
          <Button variant="light">Subtle accent</Button>
          <Button variant="subtle">Ghost</Button>
          <Button color="red">Delete</Button>
          <Button color="red" variant="light">
            Remove
          </Button>
          <Button disabled>Disabled</Button>
          <Button loading>Loading</Button>
          <Button leftSection={<Icons.Plus size={16} aria-hidden />}>With icon</Button>
          <Button size="xs">Small</Button>
          <Button size="lg">Large</Button>
          <IconButton label="Refresh" icon={<Icons.NavAgentUpdates size={18} aria-hidden />} variant="default" />
          <IconButton label="More actions" icon={<Icons.More size={18} aria-hidden />} />
        </Group>
        <Group>
          <Menu>
            <Menu.Target>
              <Button variant="default" rightSection={<Icons.ChevronDown size={14} aria-hidden />}>
                Menu
              </Button>
            </Menu.Target>
            <Menu.Dropdown>
              <Menu.Label>Actions</Menu.Label>
              <Menu.Item leftSection={<Icons.Edit size={15} aria-hidden />}>Edit</Menu.Item>
              <Menu.Item leftSection={<Icons.Copy size={15} aria-hidden />}>Duplicate</Menu.Item>
              <Menu.Divider />
              <Menu.Item color="red" leftSection={<Icons.Trash size={15} aria-hidden />}>
                Delete
              </Menu.Item>
            </Menu.Dropdown>
          </Menu>
          <Tooltip label="Tooltips explain icon-only controls" withArrow>
            <Button variant="default">Hover or focus me</Button>
          </Tooltip>
        </Group>
      </Section>

      <Section id="forms" title="Inputs">
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 16 }}>
          <TextInput label="Text input" description="Helper text" placeholder="Placeholder" />
          <TextInput label="With an error" defaultValue="not-an-email" error="Enter an address like name@example.org" />
          <PasswordInput label="Password" defaultValue="secret-value" />
          <Select label="Select" data={["Main campus", "North clinic", "Lab annex"]} defaultValue="North clinic" allowDeselect={false} />
          <NumberInput label="Number" defaultValue={25} min={0} />
          <TextInput label="Disabled" defaultValue="Read only" disabled />
        </div>
        <Textarea label="Textarea" autosize minRows={2} placeholder="Longer text" />
        <Group align="flex-start" gap="xl">
          <Stack gap="xs">
            <Checkbox label="Checkbox" defaultChecked />
            <Checkbox label="Indeterminate" indeterminate />
            <Checkbox label="Disabled" disabled />
          </Stack>
          <Radio.Group defaultValue="a" label="Radio group">
            <Stack gap="xs" mt={4}>
              <Radio value="a" label="First choice" />
              <Radio value="b" label="Second choice" />
            </Stack>
          </Radio.Group>
          <Stack gap="xs">
            <Switch label="Toggle (on)" defaultChecked />
            <Switch label="Toggle (off)" />
            <Switch label="Disabled" disabled />
          </Stack>
          <SegmentedControl value={seg} onChange={setSeg} data={[{ value: "a", label: "All" }, { value: "b", label: "Active" }, { value: "c", label: "Revoked" }]} aria-label="Segmented control" />
        </Group>
      </Section>

      <Section id="tabs" title="Tabs">
        <Tabs defaultValue="one">
          <Tabs.List>
            <Tabs.Tab value="one">Overview</Tabs.Tab>
            <Tabs.Tab value="two">Hardware</Tabs.Tab>
            <Tabs.Tab value="three">Software</Tabs.Tab>
          </Tabs.List>
          <Tabs.Panel value="one" pt="sm">
            <Text size="sm">Tab panels keep their content visible and focus reachable by keyboard (arrow keys move between tabs).</Text>
          </Tabs.Panel>
          <Tabs.Panel value="two" pt="sm">
            Hardware
          </Tabs.Panel>
          <Tabs.Panel value="three" pt="sm">
            Software
          </Tabs.Panel>
        </Tabs>
      </Section>

      <Section id="status" title="Status pills and severity (icon + color + text)">
        <Group>
          {KINDS.map((k) => (
            <StatusPill key={k} kind={k}>
              {k[0]!.toUpperCase() + k.slice(1)}
            </StatusPill>
          ))}
        </Group>
        <Group>
          {["critical", "important", "moderate", "low", ""].map((s) => (
            <SeverityBadge key={s || "none"} severity={s} />
          ))}
        </Group>
        <Group>
          {["active", "pending", "revoked", "online", "offline", "queued", "running", "succeeded", "failed", "canceled", "reboot_pending", "compliant", "non_compliant"].map((s) => (
            <Status key={s} value={s} size="sm" />
          ))}
        </Group>
        <Group>
          <Alert color="green" icon={<Icons.Success size={18} aria-hidden />} title="Success">
            The deployment finished on every device.
          </Alert>
          <Alert color="yellow" icon={<Icons.Warning size={18} aria-hidden />} title="Warning">
            Three devices have not reported for a week.
          </Alert>
          <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />} title="Error">
            The installer's checksum did not match.
          </Alert>
          <Alert color="blue" icon={<Icons.Info size={18} aria-hidden />} title="Information">
            Updates install in the maintenance window.
          </Alert>
        </Group>
      </Section>

      <Section id="tiles" title="Stat tiles, charts">
        <StatGrid label="Example tiles">
          <StatTile label="Devices" value={248} kind="accent" icon={<Icons.NavDevices size={16} aria-hidden />} hint="12 added this week" />
          <StatTile label="Online now" value={211} kind="success" icon={<Icons.Online size={16} aria-hidden />} hint="85% of devices" />
          <StatTile label="Critical updates missing" value={37} kind="critical" icon={<Icons.Critical size={16} aria-hidden />} hint="on 21 devices" />
          <StatTile label="Waiting for a restart" value={9} kind="warning" icon={<Icons.Restart size={16} aria-hidden />} to="#tiles" />
          <StatTile label="Filter by this" value={4} kind="info" onClick={() => toast.info("Tiles can act as filters")} />
        </StatGrid>
        <Text size="sm" c="dimmed">
          Pages whose main content is a table use compact tiles, one short line each, so the table stays on the screen.
        </Text>
        <StatGrid compact label="Example compact tiles">
          <StatTile label="Devices" value={248} kind="accent" icon={<Icons.NavDevices size={16} aria-hidden />} hint="12 added this week" />
          <StatTile label="Online now" value={211} kind="success" icon={<Icons.Online size={16} aria-hidden />} hint="85% of devices" />
          <StatTile label="Critical updates missing" value={37} kind="critical" icon={<Icons.Critical size={16} aria-hidden />} hint="on 21 devices" />
          <StatTile label="Waiting for a restart" value={9} kind="warning" icon={<Icons.Restart size={16} aria-hidden />} />
        </StatGrid>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: 24 }}>
          <div>
            <Text fw={600} size="sm" mb={8}>
              Patch compliance
            </Text>
            <StackedBar
              label="Patch compliance"
              slices={[
                { label: "Compliant", value: 171, token: "success" },
                { label: "Not compliant", value: 54, token: "danger" },
                { label: "Unknown", value: 23, token: "neutral" },
              ]}
            />
          </div>
          <Donut
            label="Missing updates by severity"
            sub="missing"
            slices={[
              { label: "Critical", value: 12, token: "critical" },
              { label: "Important", value: 31, token: "important" },
              { label: "Moderate", value: 18, token: "moderate" },
              { label: "Low", value: 7, token: "low" },
            ]}
          />
          <Donut label="Series colors" slices={[1, 2, 3, 4, 5, 6].map((i) => ({ label: `Series ${i}`, value: 7 - i, token: `chart-${i}` }))} />
        </div>
      </Section>

      <Section id="table" title="Data table">
        <Text size="sm" c="dimmed">
          Sticky header, sortable and resizable columns (drag the edge or focus it and use the arrow keys), column picker, row selection with a bulk bar, filter chips, saved views (kept on your account), pagination, density ({density}) and CSV export. Hover or focus a row for its actions.
        </Text>
        <DataTable<Demo>
          id="styleguide"
          label="Example devices"
          data={DEMO}
          columns={cols}
          rowId={(r) => r.id}
          selectable
          rowLabel={(r) => r.host}
          exportName="example-devices"
          initialSort={{ id: "host" }}
          pageSize={10}
          searchPlaceholder="Search devices"
          rowHref={(r) => `#${r.id}`}
          rowActions={(r) => (
            <>
              <IconButton label={`Refresh ${r.host}`} icon={<Icons.NavAgentUpdates size={16} aria-hidden />} size="sm" />
              <IconButton label={`More actions for ${r.host}`} icon={<Icons.More size={16} aria-hidden />} size="sm" />
            </>
          )}
          bulkActions={(rows, clear) => (
            <>
              <Button size="compact-sm" variant="default" onClick={() => (toast.success(`Refresh queued for ${rows.length} devices`), clear())}>
                Refresh
              </Button>
              <Button size="compact-sm" color="red" variant="light" onClick={() => void confirm({ title: `Delete ${rows.length} devices?`, message: "This cannot be undone.", confirmLabel: "Delete permanently", danger: true }).then((ok) => ok && (toast.success("Deleted"), clear()))}>
                Delete…
              </Button>
            </>
          )}
        />
        <Text fw={600} size="sm">
          Loading and empty states
        </Text>
        <div className="lp-card" style={{ overflow: "hidden" }}>
          <TableSkeleton rows={3} cols={4} />
        </div>
        <TileSkeleton count={3} />
        <div className="lp-card">
          <EmptyState title="No deployments yet" description="Deployments install or update software on the devices you choose." actions={<Button leftSection={<Icons.Plus size={16} aria-hidden />}>New deployment</Button>} />
        </div>
        <Group>
          <Skel w={200} h={16} />
          <Skel w={120} h={16} />
        </Group>
      </Section>

      <Section id="overlays" title="Modal, drawer, confirm dialog, toasts">
        <Group>
          <Button variant="default" onClick={() => setModal(true)}>
            Open modal
          </Button>
          <Button variant="default" onClick={() => setDrawer(true)}>
            Open drawer
          </Button>
          <Button variant="default" color="red" onClick={() => void confirm({ title: "Revoke this device?", message: "The device loses its certificate and can no longer connect.", confirmLabel: "Revoke device", danger: true })}>
            Confirm dialog
          </Button>
          <Button variant="default" onClick={() => toast.success("Deployment queued", "Success")}>
            Success toast
          </Button>
          <Button variant="default" onClick={() => toast.error("The installer could not be verified", "Error")}>
            Error toast
          </Button>
          <Button variant="default" onClick={() => toast.warning("The agent is out of date", "Warning")}>
            Warning toast
          </Button>
          <Button variant="default" onClick={() => toast.info("Updates install in the maintenance window")}>
            Info toast
          </Button>
        </Group>
        <Modal opened={modal} onClose={() => setModal(false)} title="Modal title" centered>
          <Stack>
            <Text size="sm">Modals trap focus, close with Escape and return focus to the button that opened them.</Text>
            <TextInput label="Name" data-autofocus />
            <Group justify="flex-end">
              <Button variant="default" onClick={() => setModal(false)}>
                Cancel
              </Button>
              <Button onClick={() => setModal(false)}>Save</Button>
            </Group>
          </Stack>
        </Modal>
        <Drawer opened={drawer} onClose={() => setDrawer(false)} title="Side panel" position="right" size="md">
          <Stack>
            <Text size="sm">Drawers show details next to a table without leaving it.</Text>
            <StatusPill kind="success">Online</StatusPill>
          </Stack>
        </Drawer>
      </Section>

      <Section id="icons" title="Icons">
        <Group gap="lg">
          {Object.entries(Icons)
            .slice(0, 60)
            .map(([name, Ic]) => {
              const I = Ic as React.ComponentType<{ size?: number; "aria-hidden"?: boolean }>;
              return (
                <Tooltip key={name} label={name}>
                  <span style={{ display: "inline-flex", color: "var(--lp-text)" }} role="img" aria-label={name}>
                    <I size={22} aria-hidden />
                  </span>
                </Tooltip>
              );
            })}
        </Group>
      </Section>
    </Page>
  );
}
