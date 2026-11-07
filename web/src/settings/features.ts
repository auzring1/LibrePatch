import { useEffective, type Effective } from "./useEffective";

/** Parts of the console an administrator can switch off for the whole organization. */
export interface Features {
  /** Settings > Update defaults > "Manage Windows updates". On unless an administrator switched it off. */
  windowsUpdates: boolean;
}

/** Until the settings have loaded everything shows as on, so a page never flashes empty. */
export const featuresOf = (eff?: Pick<Effective, "updates">): Features => ({ windowsUpdates: eff?.updates?.windows_updates_enabled !== false });

export function useFeatures(): Features {
  return featuresOf(useEffective().data);
}
