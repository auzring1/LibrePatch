import { useEffective } from "../settings/useEffective";
import { Button, Checkbox, MultiSelect, NumberInput, SegmentedControl, Select, TextInput } from "@mantine/core";
import type { Filter } from "../api/client";
import { Icons, IconButton } from "../ui";
import "../ui/pageBits.css";

type Kind = "text" | "gb" | "int" | "bool" | "chassis" | "bitlocker";

interface FieldMeta {
  label: string;
  kind: Kind;
  cmps: string[];
}

const CHASSIS = [
  "desktop", "low-profile-desktop", "mini-tower", "tower", "all-in-one", "space-saving", "portable", "laptop", "notebook",
  "sub-notebook", "hand-held", "main-server-chassis", "tablet", "convertible", "detachable", "mini-pc", "stick-pc",
];
export const LAPTOP_CHASSIS = ["portable", "laptop", "notebook", "sub-notebook", "convertible", "detachable", "tablet"];
const BITLOCKER = ["protected", "unprotected", "encrypting", "decrypting", "unknown", "unsupported"];

// Mirrors the server's allow-list (internal/server/groups/filter.go).
const FIELDS: Record<string, FieldMeta> = {
  hostname: { label: "Hostname", kind: "text", cmps: ["contains", "prefix", "eq", "ne"] },
  chassis: { label: "Form factor", kind: "chassis", cmps: ["in"] },
  manufacturer: { label: "Manufacturer", kind: "text", cmps: ["contains", "eq", "ne"] },
  model: { label: "Model", kind: "text", cmps: ["contains", "eq", "ne"] },
  os_caption: { label: "Operating system", kind: "text", cmps: ["contains", "eq", "ne"] },
  os_build: { label: "OS build number", kind: "int", cmps: ["lt", "le", "gt", "ge", "eq", "ne"] },
  arch: { label: "Architecture", kind: "text", cmps: ["eq", "ne"] },
  agent_version: { label: "Agent version", kind: "text", cmps: ["eq", "ne", "prefix"] },
  ram_bytes: { label: "Memory (GB)", kind: "gb", cmps: ["lt", "le", "gt", "ge"] },
  online: { label: "Online", kind: "bool", cmps: ["eq"] },
  pending_reboot: { label: "Reboot pending", kind: "bool", cmps: ["eq"] },
  disk_bitlocker: { label: "Any disk BitLocker state", kind: "bitlocker", cmps: ["any"] },
};

const CMP_LABEL: Record<string, string> = {
  eq: "is", ne: "is not", contains: "contains", prefix: "starts with", in: "is one of", any: "is",
  lt: "<", le: "≤", gt: ">", ge: "≥",
};
const VERSION_CMPS = ["lt", "le", "eq", "ne", "ge", "gt"];

const GB = 1024 ** 3;
const options = (cmps: string[]) => cmps.map((c) => ({ value: c, label: CMP_LABEL[c] ?? c }));

export const newDeviceCondition = (): Filter => ({ op: "device", field: "chassis", cmp: "in", value: LAPTOP_CHASSIS });
export const newSoftwareCondition = (): Filter => ({ op: "software", title: "", match: "contains" });
export const newGroup = (op: "and" | "or" = "and"): Filter => ({ op, children: [newSoftwareCondition()] });

function defaultValue(kind: Kind): unknown {
  switch (kind) {
    case "chassis": return LAPTOP_CHASSIS;
    case "bool": return true;
    case "gb": return 8 * GB;
    case "int": return 0;
    case "bitlocker": return "unprotected";
    default: return "";
  }
}

function DeviceRow({ node, onChange }: { node: Filter; onChange: (n: Filter) => void }) {
  // The organization's custom device fields (Settings > Device defaults) can be used in a filter as text fields.
  const custom = useEffective().data?.devices.custom_fields ?? [];
  const all: Record<string, FieldMeta> = { ...FIELDS, ...Object.fromEntries(custom.map((f) => [`custom.${f.key}`, { label: f.label, kind: "text", cmps: ["eq", "ne", "contains", "prefix"] } as FieldMeta])) };
  const meta = all[node.field ?? ""] ?? FIELDS.hostname!;
  const setField = (field: string) => {
    const m = all[field]!;
    onChange({ op: "device", field, cmp: m.cmps[0]!, value: defaultValue(m.kind) });
  };
  const v = node.value;
  let input: React.ReactNode;
  switch (meta.kind) {
    case "chassis":
      input = <MultiSelect data={CHASSIS} value={Array.isArray(v) ? (v as string[]) : []} onChange={(x) => onChange({ ...node, value: x })} searchable w={320} aria-label="Form factors" />;
      break;
    case "bool":
      input = <Select data={[{ value: "true", label: "yes" }, { value: "false", label: "no" }]} value={String(v)} onChange={(x) => onChange({ ...node, value: x === "true" })} w={100} aria-label="Value" allowDeselect={false} />;
      break;
    case "bitlocker":
      input = <Select data={BITLOCKER} value={String(v)} onChange={(x) => onChange({ ...node, value: x ?? "unprotected" })} w={160} aria-label="BitLocker state" allowDeselect={false} />;
      break;
    case "gb":
      input = <NumberInput value={Number(v) / GB} min={0} max={4096} onChange={(x) => onChange({ ...node, value: Math.round(Number(x) * GB) })} w={120} aria-label="Gigabytes" />;
      break;
    case "int":
      input = <NumberInput value={Number(v)} min={0} onChange={(x) => onChange({ ...node, value: Number(x) })} w={140} aria-label="Value" />;
      break;
    default:
      input = <TextInput value={String(v ?? "")} onChange={(e) => onChange({ ...node, value: e.currentTarget.value })} maxLength={200} w={240} aria-label="Value" />;
  }
  return (
    <div className="lp-filter__cond">
      <Select data={Object.entries(all).map(([value, m]) => ({ value, label: m.label }))} value={node.field} onChange={(x) => x && setField(x)} w={210} aria-label="Field" allowDeselect={false} />
      <Select data={options(meta.cmps)} value={node.cmp} onChange={(x) => x && onChange({ ...node, cmp: x })} w={130} aria-label="Comparison" allowDeselect={false} disabled={meta.cmps.length === 1} />
      {input}
    </div>
  );
}

function SoftwareRow({ node, onChange }: { node: Filter; onChange: (n: Filter) => void }) {
  const ver = node.version;
  return (
    <div>
      <div className="lp-filter__cond">
        <span className="lp-filter__label">Has software</span>
        <TextInput placeholder="Product name, e.g. chrome" value={node.title ?? ""} onChange={(e) => onChange({ ...node, title: e.currentTarget.value })} maxLength={200} w={240} aria-label="Product name" />
        <Select data={[{ value: "contains", label: "name contains" }, { value: "exact", label: "name is exactly" }, { value: "prefix", label: "name starts with" }]} value={node.match ?? "contains"} onChange={(x) => onChange({ ...node, match: (x ?? "contains") as Filter["match"] })} w={160} aria-label="Name match" allowDeselect={false} />
        <TextInput placeholder="Publisher (optional)" value={node.publisher ?? ""} onChange={(e) => onChange({ ...node, publisher: e.currentTarget.value || undefined })} maxLength={200} w={190} aria-label="Publisher" />
      </div>
      <div className="lp-filter__cond">
        <Select
          data={[{ value: "", label: "any version" }, ...VERSION_CMPS.map((c) => ({ value: c, label: `version ${CMP_LABEL[c]}` }))]}
          value={ver?.cmp ?? ""}
          onChange={(x) => onChange({ ...node, version: x ? { cmp: x as NonNullable<Filter["version"]>["cmp"], value: ver?.value ?? "" } : undefined })}
          w={150}
          aria-label="Version comparison"
          allowDeselect={false}
        />
        {ver && <TextInput placeholder="e.g. 130" value={ver.value} onChange={(e) => onChange({ ...node, version: { ...ver, value: e.currentTarget.value } })} maxLength={100} w={140} aria-label="Version" />}
        <Select data={[{ value: "", label: "any install type" }, { value: "machine", label: "machine-wide" }, { value: "user", label: "per-user" }]} value={node.scope ?? ""} onChange={(x) => onChange({ ...node, scope: (x || undefined) as Filter["scope"] })} w={160} aria-label="Install type" allowDeselect={false} />
      </div>
    </div>
  );
}

interface RowProps {
  node: Filter;
  onChange: (n: Filter) => void;
  onRemove?: () => void;
  depth: number;
}

/** One entry of a group: a condition or nested group, with a NOT toggle. */
function Row({ node, onChange, onRemove, depth }: RowProps) {
  const negated = node.op === "not";
  const inner = negated ? node.children![0]! : node;
  const setInner = (n: Filter) => onChange(negated ? { op: "not", children: [n] } : n);
  return (
    <div className="lp-filter__row">
      <Checkbox label="NOT" checked={negated} onChange={(e) => onChange(e.currentTarget.checked ? { op: "not", children: [inner] } : inner)} mt={6} aria-label="Negate this condition" />
      <div className="lp-filter__body">
        {inner.op === "device" && <DeviceRow node={inner} onChange={setInner} />}
        {inner.op === "software" && <SoftwareRow node={inner} onChange={setInner} />}
        {(inner.op === "and" || inner.op === "or") && <FilterEditor node={inner} onChange={setInner} depth={depth + 1} />}
      </div>
      {onRemove && (
        <IconButton label="Remove condition" icon={<Icons.Close size={16} aria-hidden />} color="red" onClick={onRemove} mt={2} />
      )}
    </div>
  );
}

/** Edits a filter tree. The server validates it; this keeps the common shapes easy to build. */
export function FilterEditor({ node, onChange, depth = 0 }: { node: Filter; onChange: (n: Filter) => void; depth?: number }) {
  const children = node.children ?? [];
  const setChild = (i: number, c: Filter) => onChange({ ...node, children: children.map((x, j) => (j === i ? c : x)) });
  const remove = (i: number) => onChange({ ...node, children: children.filter((_, j) => j !== i) });
  return (
    <div className={depth === 0 ? "lp-filter lp-filter--root" : "lp-filter"}>
      <div className="lp-row">
        <SegmentedControl size="xs" value={node.op} onChange={(v) => onChange({ ...node, op: v as "and" | "or" })} data={[{ value: "and", label: "All of" }, { value: "or", label: "Any of" }]} aria-label="Combine conditions" />
        <span className="lp-hint">these conditions match</span>
      </div>
      {children.map((c, i) => (
        <Row key={i} node={c} depth={depth} onChange={(n) => setChild(i, n)} onRemove={children.length > 1 || depth > 0 ? () => remove(i) : undefined} />
      ))}
      <div className="lp-row">
        <Button size="xs" variant="light" leftSection={<Icons.Plus size={14} aria-hidden />} onClick={() => onChange({ ...node, children: [...children, newDeviceCondition()] })}>
          Device condition
        </Button>
        <Button size="xs" variant="light" leftSection={<Icons.Plus size={14} aria-hidden />} onClick={() => onChange({ ...node, children: [...children, newSoftwareCondition()] })}>
          Software condition
        </Button>
        {depth < 2 && (
          <Button size="xs" variant="subtle" leftSection={<Icons.Plus size={14} aria-hidden />} onClick={() => onChange({ ...node, children: [...children, newGroup(node.op === "and" ? "or" : "and")] })}>
            Nested group
          </Button>
        )}
      </div>
    </div>
  );
}
