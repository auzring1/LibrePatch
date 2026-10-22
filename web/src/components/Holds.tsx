import { useMemo } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@mantine/core";
import { api, errorMessage } from "../api/client";
import { dateTime } from "../api/format";
import { Card, DataTable, EmptyState, Icons, StatusPill, toast, useConfirm, type Column } from "../ui";

export type Hold = { id: string; update_id: string; title?: string; ring_name: string; reason: string; created_at: string };

export function HoldsCard({ canEdit, always }: { canEdit: boolean; always?: boolean }) {
  const qc = useQueryClient();
  const confirm = useConfirm();
  const holds = useQuery({ queryKey: ["updates", "holds"], queryFn: () => api<{ items: Hold[] }>("GET", "/update-holds"), refetchInterval: 30_000 });
  const release = useMutation({
    mutationFn: (id: string) => api("POST", `/update-holds/${id}/release`, {}),
    onSuccess: () => (toast.success("Released. The update will continue to the next ring."), qc.invalidateQueries({ queryKey: ["updates"] })),
    onError: (e) => toast.error(errorMessage(e)),
  });
  const items = holds.data?.items ?? [];
  const columns = useMemo<Column<Hold>[]>(
    () => [
      { id: "update", header: "Update", required: true, wrap: true, width: 300, value: (h) => h.title || h.update_id },
      {
        id: "state",
        header: "State",
        width: 110,
        value: () => "held",
        cell: () => (
          <StatusPill kind="danger" size="sm" icon={Icons.Pause}>
            Held
          </StatusPill>
        ),
      },
      { id: "ring", header: "Ring", width: 140, value: (h) => h.ring_name },
      { id: "reason", header: "Reason", width: 280, wrap: true, value: (h) => h.reason },
      { id: "since", header: "Since", width: 170, value: (h) => new Date(h.created_at).getTime(), csv: (h) => h.created_at, cell: (h) => dateTime(h.created_at) },
    ],
    [],
  );
  if (holds.isLoading) return null;
  if (items.length === 0) {
    return always ? <EmptyState icon={<Icons.NavHeld size={26} />} title="No updates are held" description="An update is held when a ring's success threshold is missed, so later rings stop receiving it. Nothing is held right now." /> : null;
  }
  return (
    <Card title="Held updates" description="These updates failed a ring's success threshold, so later rings are not getting them. Look at the failures, then release the hold or decline the update.">
      <DataTable<Hold>
        id="update-holds"
        label="Held updates"
        data={items}
        columns={columns}
        rowId={(h) => h.id}
        rowLabel={(h) => h.title ?? h.update_id}
        initialSort={{ id: "since", desc: true }}
        searchPlaceholder="Search held updates…"
        simple
        exportName="held-updates"
        rowActions={(h) =>
          canEdit ? (
            <Button
              size="compact-xs"
              variant="default"
              leftSection={<Icons.Play size={12} aria-hidden />}
              aria-label={`Release hold ${h.title ?? h.update_id}`}
              onClick={async () => {
                if (await confirm({ title: "Release this hold?", message: "The update will continue to later rings despite the failures.", confirmLabel: "Release hold", danger: true })) release.mutate(h.id);
              }}
            >
              Release
            </Button>
          ) : null
        }
      />
    </Card>
  );
}

