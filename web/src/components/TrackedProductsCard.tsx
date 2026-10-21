import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Alert, Button, Checkbox, Group, Modal, Stack, TextInput } from "@mantine/core";
import { api, errorMessage, type VulnerabilityProduct } from "../api/client";
import { useSession } from "../api/session";
import { Card, DataTable, EmptyState, Icons, IconButton, StatusPill, toast, useConfirm, type Column } from "../ui";

/** The programs that are looked up in the vulnerability data, and as what (the CPE vendor and product the NVD uses). */
export function TrackedProductsCard() {
  const { can } = useSession();
  const canEdit = can("settings:integrations");
  const qc = useQueryClient();
  const confirm = useConfirm();
  const [adding, setAdding] = useState(false);
  const q = useQuery({ queryKey: ["vulnerabilities", "products"], queryFn: () => api<{ items: VulnerabilityProduct[] }>("GET", "/vulnerabilities/products") });
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["vulnerabilities"] });
  };
  const toggle = useMutation({
    mutationFn: (p: VulnerabilityProduct) => api("PUT", `/vulnerabilities/products/${p.id}`, { enabled: !p.enabled }),
    onSuccess: refresh,
    onError: (e) => toast.error(errorMessage(e)),
  });
  const del = useMutation({
    mutationFn: (id: string) => api("DELETE", `/vulnerabilities/products/${id}`),
    onSuccess: () => (toast.success("Removed."), refresh()),
    onError: (e) => toast.error(errorMessage(e)),
  });
  const columns: Column<VulnerabilityProduct>[] = [
    { id: "name", header: "Program (as the inventory names it)", required: true, primary: true, width: 280, value: (p) => p.name },
    { id: "vendor", header: "NVD vendor", width: 180, value: (p) => p.vendor, cell: (p) => <span className="lp-mono">{p.vendor}</span> },
    { id: "product", header: "NVD product", width: 200, value: (p) => p.product, cell: (p) => <span className="lp-mono">{p.product}</span> },
    { id: "devices", header: "Devices", align: "right", width: 90, value: (p) => p.devices, cell: (p) => <span className="lp-num">{p.devices}</span> },
    { id: "source", header: "From", width: 120, value: (p) => (p.source === "builtin" ? "Built in" : "You") },
    {
      id: "on",
      header: "Looked up",
      width: 120,
      value: (p) => (p.enabled ? "yes" : "no"),
      cell: (p) =>
        p.enabled ? (
          <StatusPill kind="success" size="sm">
            Yes
          </StatusPill>
        ) : (
          <StatusPill kind="neutral" size="sm">
            Off
          </StatusPill>
        ),
    },
  ];
  return (
    <Card
      title="Programs that are looked up"
      description="Windows itself is always checked, by its build number. For other programs the server needs to know what the NVD calls them: a program name from the software inventory on one side, a vendor and product on the other. A short list comes with the product; add the programs that matter to you."
      actions={
        canEdit ? (
          <Button size="xs" onClick={() => setAdding(true)} leftSection={<Icons.Plus size={14} aria-hidden />}>
            Add a program
          </Button>
        ) : undefined
      }
    >
      <DataTable<VulnerabilityProduct>
        id="vulnerability-products"
        label="Programs that are looked up"
        data={q.isLoading ? undefined : q.data?.items}
        loading={q.isLoading}
        error={q.error ? new Error(errorMessage(q.error)) : undefined}
        columns={columns}
        rowId={(p) => p.id}
        rowLabel={(p) => p.name}
        initialSort={{ id: "devices", desc: true }}
        exportName="vulnerability-programs"
        rowActions={
          canEdit
            ? (p) => (
                <>
                  <IconButton label={p.enabled ? `Stop looking up ${p.name}` : `Look up ${p.name}`} icon={p.enabled ? <Icons.Pause size={16} aria-hidden /> : <Icons.Play size={16} aria-hidden />} size="sm" onClick={() => toggle.mutate(p)} />
                  {p.source === "user" && (
                    <IconButton
                      label={`Remove ${p.name}`}
                      icon={<Icons.Trash size={16} aria-hidden />}
                      size="sm"
                      color="red"
                      onClick={async () => {
                        const ok = await confirm({ title: `Remove ${p.name}?`, message: "It is no longer looked up for vulnerabilities.", confirmLabel: "Remove", danger: true });
                        if (ok) del.mutate(p.id);
                      }}
                    />
                  )}
                </>
              )
            : undefined
        }
        empty={<EmptyState icon={<Icons.NavSoftware size={26} />} title="No programs yet" />}
      />
      {adding && <AddModal onClose={() => setAdding(false)} onDone={() => (setAdding(false), refresh())} />}
    </Card>
  );
}

function AddModal({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState("");
  const [vendor, setVendor] = useState("");
  const [product, setProduct] = useState("");
  const [error, setError] = useState("");
  const [sure, setSure] = useState(false);
  const add = useMutation({
    mutationFn: () => api("POST", "/vulnerabilities/products", { name: name.trim(), vendor: vendor.trim(), product: product.trim() }),
    onSuccess: () => (toast.success("Added. Its vulnerabilities appear after the next download."), onDone()),
    onError: (e) => setError(errorMessage(e)),
  });
  return (
    <Modal opened onClose={onClose} title="Add a program to look up">
      <form onSubmit={(e) => (e.preventDefault(), setError(""), add.mutate())}>
        <Stack>
          <TextInput label="Program name" description="As the software inventory shows it, for example Zoom Workplace. Versions and (x64) are ignored." value={name} onChange={(e) => setName(e.currentTarget.value)} required data-autofocus />
          <TextInput label="NVD vendor" description="Lower case, as the NVD writes it, for example zoom. You can look it up in the NVD's CPE search." value={vendor} onChange={(e) => setVendor(e.currentTarget.value)} required />
          <TextInput label="NVD product" description="For example zoom or notepad++." value={product} onChange={(e) => setProduct(e.currentTarget.value)} required />
          <Checkbox label="I checked the vendor and product names against the NVD" checked={sure} onChange={(e) => setSure(e.currentTarget.checked)} />
          {error && (
            <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
              {error}
            </Alert>
          )}
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={add.isPending} disabled={!name.trim() || !vendor.trim() || !product.trim() || !sure}>
              Add
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}
