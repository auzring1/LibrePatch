import { useEffective, type Effective } from "./useEffective";

/** Parts of the console an administrator can switch off for the whole organization. */
export interface Features {
  /** Settings > Update defaults > "Manage Windows updates". On unless an administrator switched it off. */
  windowsUpdates: boolean;
  /** Settings > Vulnerability data > "Look up known vulnerabilities". Off by default, so the Vulnerabilities pages are hidden until an administrator turns it on. */
  vulnerabilities: boolean;
}

/** Until the settings have loaded everything shows as on, so a page never flashes empty. */
export const featuresOf = (eff?: Pick<Effective, "updates" | "vulnerabilities">): Features => ({
  windowsUpdates: eff?.updates?.windows_updates_enabled !== false,
  vulnerabilities: eff?.vulnerabilities?.enabled !== false,
});

export function useFeatures(): Features {
  return featuresOf(useEffective().data);
}

/** The same, plus whether the settings have arrived: a page that replaces itself when a feature is off waits for that, so it never flashes the wrong one. */
export function useFeaturesLoaded(): { features: Features; loaded: boolean } {
  const q = useEffective();
  return { features: featuresOf(q.data), loaded: q.isSuccess };
}
