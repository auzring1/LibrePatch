import type { components } from "./schema";

export type Device = components["schemas"]["Device"];
export type Hardware = components["schemas"]["Hardware"];
export type EnrollmentToken = components["schemas"]["EnrollmentToken"];
export type AuditEntry = components["schemas"]["AuditEntry"];
export type SessionInfo = components["schemas"]["SessionInfo"];
export type DeviceSoftware = components["schemas"]["DeviceSoftware"];
export type SoftwareChange = components["schemas"]["SoftwareChange"];
export type DeviceUser = components["schemas"]["DeviceUser"];
export type SoftwareTitle = components["schemas"]["SoftwareTitle"];
export type TitleInstall = components["schemas"]["TitleInstall"];
export type Filter = components["schemas"]["Filter"];
export type Group = components["schemas"]["Group"];
export type GroupMembers = components["schemas"]["GroupMembers"];
export type Pkg = components["schemas"]["Package"];
export type PackageDetail = components["schemas"]["PackageDetail"];
export type OverlaySource = components["schemas"]["OverlaySource"];
export type Installer = components["schemas"]["Installer"];
export type PackageOverride = components["schemas"]["PackageOverride"];
export type Detection = components["schemas"]["Detection"];
export type ImportResult = components["schemas"]["ImportResult"];
export type CustomPackage = components["schemas"]["CustomPackage"];
export type OrgSettings = components["schemas"]["OrgSettings"];
export type MaintenanceWindow = components["schemas"]["MaintenanceWindow"];
export type DeploymentRequest = components["schemas"]["DeploymentRequest"];
export type DeploymentPlan = components["schemas"]["DeploymentPlan"];
export type DeploymentSummary = components["schemas"]["DeploymentSummary"];
export type DeploymentDetail = components["schemas"]["DeploymentDetail"];
export type DeploymentJob = components["schemas"]["DeploymentJob"];
export type DeviceJob = components["schemas"]["DeviceJob"];
export type AvailableUpdate = components["schemas"]["AvailableUpdate"];
export type UpdateCheck = components["schemas"]["UpdateCheck"];
export type FleetUpdate = components["schemas"]["FleetUpdate"];
export type WingetIndexStatus = components["schemas"]["WingetIndexStatus"];
export type WindowsUpdate = components["schemas"]["WindowsUpdate"];
export type UpdateRule = components["schemas"]["UpdateRule"];
export type UpdateRing = components["schemas"]["UpdateRing"];
export type UpdateSettings = components["schemas"]["UpdateSettings"];
export type RestartPolicy = components["schemas"]["RestartPolicy"];
export type WuPolicy = components["schemas"]["WuPolicy"];
export type DeviceWindowsUpdates = components["schemas"]["DeviceWindowsUpdates"];
export type Site = components["schemas"]["Site"];
export type UserAccount = components["schemas"]["User"];
export type RoleBinding = components["schemas"]["RoleBinding"];
export type ApiToken = components["schemas"]["ApiToken"];
export type SecurityKey = components["schemas"]["SecurityKey"];
export type MySecurity = components["schemas"]["MySecurity"];
export type AgentRelease = components["schemas"]["AgentRelease"];
export type AgentRollout = components["schemas"]["AgentRollout"];
export type AgentRolloutStatus = components["schemas"]["AgentRolloutStatus"];
export type SoftwarePolicy = components["schemas"]["SoftwarePolicy"];
export type SoftwareRollout = components["schemas"]["SoftwareRollout"];
export type SoftwareApprovals = components["schemas"]["SoftwareApprovals"];
export type SoftwareApprovalItem = components["schemas"]["SoftwareApprovalItem"];
export type ComplianceRow = components["schemas"]["ComplianceRow"];
export type ReportOverview = components["schemas"]["ReportOverview"];
export type LifecycleRow = components["schemas"]["LifecycleRow"];
export type LifecycleReport = components["schemas"]["LifecycleReport"];
export type JobDetail = components["schemas"]["JobDetail"];
export type Dashboard = components["schemas"]["Dashboard"];

let csrfToken = "";

/** Remember the synchronizer token returned by the auth endpoints. */
export function setCsrf(token: string | undefined) {
  csrfToken = token ?? "";
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    /** Per-field messages (invalid_branding). */
    public fields: Record<string, string> = {},
  ) {
    super(message);
  }
}

/** Calls the REST API. The session cookie is HttpOnly and sent automatically. */
export async function api<T>(method: "GET" | "POST" | "PUT" | "DELETE", path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && csrfToken) headers["X-CSRF-Token"] = csrfToken;
  const res = await fetch("/api/v1" + path, {
    method,
    headers,
    credentials: "same-origin",
    cache: "no-store",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 204) return undefined as T;
  const data = (await res.json().catch(() => ({}))) as { error?: { code?: string; message?: string; fields?: Record<string, string> } };
  if (!res.ok) {
    throw new ApiError(res.status, data.error?.code ?? "error", data.error?.message ?? `Request failed (HTTP ${res.status})`, data.error?.fields);
  }
  return data as T;
}

/** Uploads a file as a raw body (installer content). The server stores it by SHA-256. */
export async function uploadContent(file: File): Promise<{ sha256: string; size: number; file_name: string }> {
  const headers: Record<string, string> = { Accept: "application/json", "Content-Type": "application/octet-stream", "X-File-Name": file.name };
  if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
  const res = await fetch("/api/v1/catalog/content", { method: "POST", headers, credentials: "same-origin", cache: "no-store", body: file });
  const data = (await res.json().catch(() => ({}))) as { error?: { code?: string; message?: string }; sha256?: string; size?: number; file_name?: string };
  if (!res.ok) throw new ApiError(res.status, data.error?.code ?? "error", data.error?.message ?? `Upload failed (HTTP ${res.status})`);
  return data as { sha256: string; size: number; file_name: string };
}

/** Uploads an agent binary with its vendor-signed bundle (.lprel) in a header. */
export async function uploadAgentRelease(binary: File, bundle: File): Promise<AgentRelease> {
  const bytes = new Uint8Array(await bundle.arrayBuffer());
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  const headers: Record<string, string> = { Accept: "application/json", "Content-Type": "application/octet-stream", "X-Release-Bundle": btoa(bin) };
  if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
  const res = await fetch("/api/v1/agent-releases", { method: "POST", headers, credentials: "same-origin", cache: "no-store", body: binary });
  const data = (await res.json().catch(() => ({}))) as { error?: { code?: string; message?: string } };
  if (!res.ok) throw new ApiError(res.status, data.error?.code ?? "error", data.error?.message ?? `Upload failed (HTTP ${res.status})`);
  return data as AgentRelease;
}

export const errorMessage = (e: unknown) => (e instanceof Error ? e.message : "Something went wrong.");

export type PublicBranding = components["schemas"]["PublicBranding"];
export type BrandingView = components["schemas"]["BrandingView"];
export type BrandingSettings = components["schemas"]["BrandingSettings"];
export type Preferences = components["schemas"]["Preferences"];
export type Notification = components["schemas"]["Notification"];
export type BrandingAssetKind = components["schemas"]["BrandingAssetKind"];

/** Uploads one branding image as a raw PNG/JPEG body. The server re-encodes it; the result is the new view. */
export async function uploadBrandingAsset(kind: BrandingAssetKind, file: File): Promise<BrandingView> {
  const headers: Record<string, string> = { Accept: "application/json", "Content-Type": file.type };
  if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
  const res = await fetch(`/api/v1/settings/branding/assets/${kind}`, { method: "PUT", headers, credentials: "same-origin", cache: "no-store", body: file });
  const data = (await res.json().catch(() => ({}))) as { error?: { code?: string; message?: string } };
  if (!res.ok) throw new ApiError(res.status, data.error?.code ?? "error", data.error?.message ?? `Upload failed (HTTP ${res.status})`);
  return data as unknown as BrandingView;
}
