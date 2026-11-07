import { useSession } from "../api/session";
import { Card } from "../ui";
import { MissingUpdatesTab } from "./DeviceSoftware";

/** The "Software updates" tab: installed programs that have a newer version in the catalog (`deployments:read`). */
export function SoftwareUpdatesTab({ id, hostname, active }: { id: string; hostname: string; active: boolean }) {
  const { can } = useSession();
  if (!can("deployments:read")) return null;
  return (
    <Card title="Software updates" description="Installed programs that have a newer version in your catalog.">
      <MissingUpdatesTab id={id} hostname={hostname} active={active} />
    </Card>
  );
}
