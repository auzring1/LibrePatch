import { api, type DeploymentPlan, type PackageDetail, type PackageOverride } from "../api/client";

/** The part of an available update that decides how it is deployed (a device's list and the fleet list share it). */
export interface UpdateRef {
  package_id: string;
  package_name: string;
  in_catalog?: boolean;
  winget_id?: string;
  deployable: boolean;
}

/**
 * The catalog package to deploy. An update that comes from the winget index is not in the catalog yet: it is imported now
 * (the manifests are read from the winget repository, the same as "Import from winget", and the import is audited).
 */
export async function ensurePackage(u: UpdateRef): Promise<string> {
  if (u.in_catalog !== false) return u.package_id;
  const res = await api<{ package_id: string }>("POST", "/catalog/import", { identifier: u.winget_id ?? "" });
  return res.package_id;
}

/** Turns on "push updates even though the app updates itself" for a package, keeping its other overrides. */
export async function allowSelfUpdate(packageId: string): Promise<void> {
  const d = await api<PackageDetail>("GET", `/catalog/packages/${packageId}`);
  const o = d.override;
  const body: PackageOverride = {
    silent_args: o.silent_args ?? [],
    extra_detection: o.extra_detection ?? [],
    pin: o.pin ?? "",
    excluded: !!o.excluded,
    user_scope_policy: (o.user_scope_policy ?? "") as PackageOverride["user_scope_policy"],
    self_update_policy: "enforce",
  };
  await api("PUT", `/catalog/packages/${packageId}/overrides`, body);
}

/** Queues one update deployment for the given devices (adding the package to the catalog first when it is not there). */
export async function deployUpdate(opts: { update: UpdateRef; name: string; scope: string; deviceIds: string[]; confirmUnverified: boolean; force?: boolean }): Promise<DeploymentPlan> {
  const packageId = await ensurePackage(opts.update);
  if (opts.force && !opts.update.deployable) await allowSelfUpdate(packageId);
  return api<DeploymentPlan>("POST", "/deployments", {
    name: opts.name,
    action: "update",
    package_id: packageId,
    scope: opts.scope,
    device_ids: opts.deviceIds,
    unverified_confirmed: opts.confirmUnverified,
  });
}
