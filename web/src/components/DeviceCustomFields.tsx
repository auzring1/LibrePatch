import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Select, TextInput } from "@mantine/core";
import { api, ApiError, errorMessage } from "../api/client";
import { useSession } from "../api/session";
import { useEffective } from "../settings/useEffective";
import { Card, Icons, toast } from "../ui";

/** The organization's custom fields (Settings > Device defaults) for one device; people with devices:write can edit them. */
export function CustomFieldsCard({ deviceId }: { deviceId: string }) {
  const { can } = useSession();
  const qc = useQueryClient();
  const defs = useEffective().data?.devices.custom_fields ?? [];
  const q = useQuery({ queryKey: ["device", deviceId, "fields"], queryFn: () => api<{ values: Record<string, string> }>("GET", `/devices/${deviceId}/fields`), enabled: defs.length > 0 });
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [errors, setErrors] = useState<Record<string, string>>({});
  useEffect(() => {
    if (q.data) setDraft(q.data.values);
  }, [q.data]);
  const save = useMutation({
    mutationFn: () => {
      const values: Record<string, string | null> = {};
      for (const f of defs) values[f.key] = (draft[f.key] ?? "").trim() === "" ? null : (draft[f.key] ?? "").trim();
      return api<{ values: Record<string, string> }>("PUT", `/devices/${deviceId}/fields`, { values });
    },
    onSuccess: (r) => {
      qc.setQueryData(["device", deviceId, "fields"], r);
      void qc.invalidateQueries({ queryKey: ["devices"] });
      setErrors({});
      toast.success("Device fields saved.");
    },
    onError: (e) => {
      if (e instanceof ApiError && e.status === 422) setErrors(e.fields);
      else toast.error(errorMessage(e));
    },
  });
  if (defs.length === 0) return null;
  const editable = can("devices:write");
  const dirty = JSON.stringify(Object.fromEntries(defs.map((f) => [f.key, draft[f.key] ?? ""]))) !== JSON.stringify(Object.fromEntries(defs.map((f) => [f.key, q.data?.values[f.key] ?? ""])));
  return (
    <Card
      title="Custom fields"
      description="Extra information your organization records about each device. The fields are set up under Settings > Device defaults."
      footer={
        editable ? (
          <Button onClick={() => save.mutate()} loading={save.isPending} disabled={!dirty} leftSection={<Icons.Save size={16} aria-hidden />}>
            Save fields
          </Button>
        ) : undefined
      }
    >
      <div style={{ display: "grid", gap: "var(--lp-space-4)", gridTemplateColumns: "repeat(auto-fit, minmax(230px, 1fr))" }}>
        {defs.map((f) =>
          f.type === "select" ? (
            <Select key={f.key} label={f.label} data={f.options} value={draft[f.key] ?? null} onChange={(v) => setDraft({ ...draft, [f.key]: v ?? "" })} clearable disabled={!editable} error={errors[f.key]} comboboxProps={{ withinPortal: true }} />
          ) : (
            <TextInput key={f.key} label={f.label} type={f.type === "date" ? "date" : "text"} value={draft[f.key] ?? ""} onChange={(e) => setDraft({ ...draft, [f.key]: e.currentTarget.value })} disabled={!editable} maxLength={200} error={errors[f.key]} />
          ),
        )}
      </div>
    </Card>
  );
}
