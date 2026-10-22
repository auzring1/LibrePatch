import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Alert, Button, Checkbox, Group, Modal, Stack, Table, Text } from "@mantine/core";
import { errorMessage, type DeploymentPlan, type FleetUpdate } from "../api/client";
import { PRODUCT_NAME } from "../brand.generated";
import { Icons, toast } from "../ui";
import { deployUpdate } from "./updateDeploy";

const KEY = ["software-updates"];

/** Queues one "update" deployment per package and scope for the devices that have an older version. A package that comes from
 * the winget index is added to the catalog first. */
export function useDeployUpdates() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ items, confirm, force }: { items: FleetUpdate[]; confirm: boolean; force: boolean }) => {
      const results: { name: string; plan?: DeploymentPlan; error?: string }[] = [];
      for (const u of items) {
        for (const scope of ["machine", "user"] as const) {
          const ids = [...new Set(u.devices.filter((d) => d.scope === scope).map((d) => d.device_id))];
          if (ids.length === 0) continue;
          try {
            const plan = await deployUpdate({ update: u, name: `Update ${u.package_name} to ${u.latest_version}`, scope, deviceIds: ids, confirmUnverified: confirm, force });
            results.push({ name: u.package_name, plan });
          } catch (e) {
            results.push({ name: u.package_name, error: errorMessage(e) });
          }
        }
      }
      return results;
    },
    onSuccess: (results) => {
      for (const r of results) {
        if (r.error) toast.error(r.error, r.name);
        else toast.success(`${r.name}: update queued (${r.plan?.jobs ?? 0} job${r.plan?.jobs === 1 ? "" : "s"}). Follow it under Deployments.`);
      }
      void qc.invalidateQueries({ queryKey: ["deployments"] });
      void qc.invalidateQueries({ queryKey: ["catalog"] });
      void qc.invalidateQueries({ queryKey: KEY });
      void qc.invalidateQueries({ queryKey: ["vulnerabilities"] });
    },
  });
}

export function ConfirmDeployUpdates({ items, force, busy, onCancel, onConfirm }: { items: FleetUpdate[]; force: boolean; busy: boolean; onCancel: () => void; onConfirm: (confirmed: boolean) => void }) {
  const unverified = items.filter((u) => !u.verified);
  const toAdd = items.filter((u) => !u.in_catalog);
  const [ok, setOk] = useState(false);
  const devices = new Set(items.flatMap((u) => u.devices.map((d) => d.device_id))).size;
  return (
    <Modal opened onClose={onCancel} title={`Deploy ${items.length} update${items.length === 1 ? "" : "s"}`}>
      <Stack>
        <Table verticalSpacing={2} fz="sm" aria-label="Updates to deploy">
          <Table.Tbody>
            {items.map((u) => (
              <Table.Tr key={u.package_id}>
                <Table.Td>{u.package_name}</Table.Td>
                <Table.Td ff="monospace">→ {u.latest_version}</Table.Td>
                <Table.Td>
                  {u.devices.length} device{u.devices.length === 1 ? "" : "s"}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
        <Text size="sm" c="dimmed">
          Each update becomes a signed job on every device that has an older version ({devices} device{devices === 1 ? "" : "s"} in total). Older copies the new installer does not replace by itself are removed first.
        </Text>
        {toAdd.length > 0 && (
          <Alert color="blue" icon={<Icons.Info size={18} aria-hidden />} title="Added to your catalog first">
            {toAdd.map((u) => u.package_name).join(", ")} {toAdd.length === 1 ? "is" : "are"} not in your catalog yet. {PRODUCT_NAME} adds {toAdd.length === 1 ? "it" : "them"} from the winget repository now; each device downloads the installer from the vendor and checks it against the published SHA-256.
          </Alert>
        )}
        {force && (
          <Alert color="orange" icon={<Icons.Warning size={18} aria-hidden />} title="This app normally updates itself">
            {PRODUCT_NAME} leaves updates to the vendor's own updater by default. Continuing sets the package to push updates anyway (you can change this on its catalog page).
          </Alert>
        )}
        {unverified.length > 0 && (
          <Alert color="yellow" icon={<Icons.Warning size={18} aria-hidden />} title="Unverified packages">
            <Checkbox
              label={`${unverified.map((u) => u.package_name).join(", ")} ${unverified.length === 1 ? "has" : "have"} not been marked as verified. I accept deploying ${unverified.length === 1 ? "it" : "them"}; this is recorded in the audit log.`}
              checked={ok}
              onChange={(e) => setOk(e.currentTarget.checked)}
            />
          </Alert>
        )}
        <Group justify="flex-end">
          <Button variant="default" onClick={onCancel}>
            Cancel
          </Button>
          <Button onClick={() => onConfirm(ok)} loading={busy} disabled={unverified.length > 0 && !ok}>
            Deploy
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

