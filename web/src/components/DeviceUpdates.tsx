import { useSession } from "../api/session";
import { Card } from "../ui";
import { WindowsUpdatesTab } from "./DeviceWindowsUpdates";

/** The "Windows updates" tab: the Windows update state and history of the device (`updates:read`). */
export function UpdatesTab({ id, active }: { id: string; active: boolean }) {
  const { can } = useSession();
  if (!can("updates:read")) return null;
  return (
    <Card title="Windows updates" description="What Windows reports as missing, hidden or failed on this device.">
      <WindowsUpdatesTab id={id} active={active} />
    </Card>
  );
}

export { SoftwareUpdatesTab } from "./DeviceSoftwareUpdates";
