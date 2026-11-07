import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Alert, Button, Select, Text } from "@mantine/core";
import { api, errorMessage, type OrgSettings } from "../api/client";
import { useSession } from "../api/session";
import { Card, Icons, Skel, toast } from "../ui";

const options = [
  { value: "report_only", label: "Report only: show per-user installs, never change them (default)" },
  { value: "update_in_place", label: "Update in place: update the per-user copy for each user" },
  { value: "convert_to_machine", label: "Convert: remove the per-user copy, then install machine-wide" },
  { value: "remove", label: "Remove per-user copies" },
];

export function SettingsPage() {
  const { can } = useSession();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["settings"], queryFn: () => api<OrgSettings>("GET", "/settings") });
  const [policy, setPolicy] = useState<string>("report_only");
  useEffect(() => {
    if (q.data) setPolicy(q.data.user_scope_policy);
  }, [q.data]);
  const save = useMutation({
    mutationFn: () => api("PUT", "/settings", { user_scope_policy: policy }),
    onSuccess: () => (toast.success("Settings saved."), qc.invalidateQueries({ queryKey: ["settings"] })),
    onError: (e) => toast.error(errorMessage(e)),
  });
  const editable = can("settings:write");
  return (
    <div style={{ maxWidth: 760 }}>
      {q.isLoading && (
        <Card>
          <div role="status" aria-label="Loading" style={{ display: "grid", gap: "var(--lp-space-3)" }}>
            <Skel w="35%" h={16} />
            <Skel h={36} />
            <Skel w="70%" h={12} />
          </div>
        </Card>
      )}
      {q.error && (
        <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
          {errorMessage(q.error)}
        </Alert>
      )}
      {q.data && (
        <Card
          title="Per-user installs"
          description="Per-user changes run in the signed-in user's own context, never as the system, and only for users whose profile is present on the device."
          footer={
            editable ? (
              <Button onClick={() => save.mutate()} loading={save.isPending} disabled={policy === q.data.user_scope_policy} leftSection={<Icons.Save size={16} aria-hidden />}>
                Save
              </Button>
            ) : (
              <Text size="sm" c="dimmed">
                Only administrators can change settings.
              </Text>
            )
          }
        >
          <Select
            label="Default policy for per-user installs"
            description="What a deployment does about copies of an app that users installed for themselves. Individual packages can override this on their catalog page."
            data={options}
            value={policy}
            onChange={(v) => setPolicy(v ?? "report_only")}
            disabled={!editable}
            allowDeselect={false}
          />
        </Card>
      )}
    </div>
  );
}
