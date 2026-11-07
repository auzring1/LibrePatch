import { beforeEach, describe, expect, it, vi } from "vitest";

const calls: { method: string; path: string; body?: unknown }[] = [];
let detail: unknown = {};
vi.mock("../api/client", () => ({
  api: vi.fn(async (method: string, path: string, body?: unknown) => {
    calls.push({ method, path, body });
    if (path === "/catalog/import") return { package_id: "pkg-imported" };
    if (path.startsWith("/catalog/packages/") && method === "GET") return detail;
    if (path === "/deployments") return { deployment_id: "dep-1", devices: 1, jobs: 1 };
    return undefined;
  }),
}));

import { allowSelfUpdate, deployUpdate, ensurePackage } from "./updateDeploy";

const inCatalog = { package_id: "pkg-1", package_name: "7-Zip", in_catalog: true, deployable: true };
const fromIndex = { package_id: "00000000-0000-0000-0000-000000000000", package_name: "Google Chrome", in_catalog: false, winget_id: "Google.Chrome", deployable: false };

beforeEach(() => {
  calls.length = 0;
  detail = { override: { silent_args: ["/S"], extra_detection: [], pin: "< 3", excluded: false, user_scope_policy: "report_only", self_update_policy: "" } };
});

describe("ensurePackage", () => {
  it("uses the catalog package when there is one", async () => {
    expect(await ensurePackage(inCatalog)).toBe("pkg-1");
    expect(calls).toHaveLength(0);
  });
  it("imports a package that only the winget index knows", async () => {
    expect(await ensurePackage(fromIndex)).toBe("pkg-imported");
    expect(calls).toEqual([{ method: "POST", path: "/catalog/import", body: { identifier: "Google.Chrome" } }]);
  });
});

describe("allowSelfUpdate", () => {
  it("sets enforce and keeps the other overrides", async () => {
    await allowSelfUpdate("pkg-1");
    const put = calls.find((c) => c.method === "PUT");
    expect(put?.path).toBe("/catalog/packages/pkg-1/overrides");
    expect(put?.body).toEqual({ silent_args: ["/S"], extra_detection: [], pin: "< 3", excluded: false, user_scope_policy: "report_only", self_update_policy: "enforce" });
  });
});

describe("deployUpdate", () => {
  it("deploys a catalog package directly", async () => {
    await deployUpdate({ update: inCatalog, name: "n", scope: "machine", deviceIds: ["d1"], confirmUnverified: false });
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual(["POST /deployments"]);
    expect(calls[0]!.body).toMatchObject({ action: "update", package_id: "pkg-1", scope: "machine", device_ids: ["d1"], unverified_confirmed: false });
  });
  it("adds an index package to the catalog, enforces the update when forced, then deploys", async () => {
    await deployUpdate({ update: fromIndex, name: "n", scope: "machine", deviceIds: ["d1", "d2"], confirmUnverified: true, force: true });
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual(["POST /catalog/import", "GET /catalog/packages/pkg-imported", "PUT /catalog/packages/pkg-imported/overrides", "POST /deployments"]);
    expect(calls[3]!.body).toMatchObject({ package_id: "pkg-imported", device_ids: ["d1", "d2"], unverified_confirmed: true });
  });
  it("does not touch the overrides of an app that does not update itself", async () => {
    await deployUpdate({ update: { ...fromIndex, deployable: true }, name: "n", scope: "machine", deviceIds: ["d1"], confirmUnverified: false, force: true });
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual(["POST /catalog/import", "POST /deployments"]);
  });
});
