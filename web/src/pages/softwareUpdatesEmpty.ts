/**
 * What an empty "Software updates" list can honestly say. An empty list only means "up to date" when something was compared:
 * with an empty catalog and the winget source off, nothing is checked at all.
 */
export interface UpdatesEmptyInput {
  /** The winget index status; undefined while loading or when the person may not read the catalog. */
  index?: { enabled: boolean; package_count: number };
  /** How many packages the catalog holds; undefined while loading or when unknown. */
  catalogCount?: number;
}

export interface UpdatesEmpty {
  kind: "current" | "unchecked" | "waiting";
  title: string;
  description: string;
}

export function updatesEmpty({ index, catalogCount }: UpdatesEmptyInput): UpdatesEmpty {
  if (index && catalogCount !== undefined) {
    if (!index.enabled && catalogCount === 0) {
      return {
        kind: "unchecked",
        title: "Nothing to check against",
        description: "The catalog is empty and the winget source is turned off on this server, so installed programs are not compared with anything. Import a package into the catalog, or turn the winget source on (LIBREPATCH_WINGET_SOURCE, see the Runbook).",
      };
    }
    if (index.enabled && index.package_count === 0 && catalogCount === 0) {
      return {
        kind: "waiting",
        title: "Not checked yet",
        description: "The catalog is empty and the winget index has not been downloaded yet. It is fetched in the background shortly after the server starts; use Refresh now to fetch it at once.",
      };
    }
    if (!index.enabled) {
      return { kind: "current", title: "Everything in your catalog is up to date", description: "Every installed program that is in your catalog is at its newest allowed version on every device. The winget source is off, so other programs are not checked." };
    }
  }
  return { kind: "current", title: "Everything is up to date", description: "Every installed program that is in your catalog or the winget index is at its newest allowed version on every device." };
}
