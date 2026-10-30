import { spawn, type ChildProcess } from "node:child_process";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import AxeBuilder from "@axe-core/playwright";
import { expect, request, test, type Page } from "@playwright/test";
import { totp } from "./totp";

const setupToken = process.env.LIBREPATCH_SETUP_TOKEN ?? "";
const agentBin = process.env.LIBREPATCH_AGENT_BIN ?? "";
const gateway = process.env.LIBREPATCH_GATEWAY ?? "127.0.0.1:18443";
const shots = process.env.LIBREPATCH_SCREENSHOTS ?? "";
const email = "admin@example.com";
const password = "Granite-Lantern-Pickle-42";
// Small PNGs made for these tests (a 220x64 logo, a 128x128 icon, a 32x32 favicon).
const fixture = (name: string) => join(process.cwd(), "e2e", "fixtures", name);

// Accessibility: every page that gets a screenshot is also scanned with axe (WCAG 2.0/2.1 A and AA). The run fails at the
// end with the full list, so one run shows everything.
const a11yIssues: string[] = [];
async function a11y(page: Page, name: string) {
  await page.waitForTimeout(450); // let dialogs and toasts finish fading in: axe would measure a half-transparent surface
  // With a dialog or panel open, the page behind it is covered by the overlay and not available to the user, so only the
  // dialog is scanned (the page itself was scanned in its own screenshot).
  const open = await page.locator('[role="dialog"]:visible').count();
  let b = new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]);
  if (open > 0) b = b.include('[role="dialog"]');
  const r = await b.analyze();
  for (const v of r.violations) {
    a11yIssues.push(`${name}: ${v.id} (${v.impact}) x${v.nodes.length}: ${v.help} :: ${v.nodes.slice(0, 2).map((n) => n.target.join(" ") + " :: " + (n.any[0]?.message ?? "")).join(" | ")}`);
  }
}

async function shot(page: Page, name: string) {
  await a11y(page, name); // with any toast still showing, as a person would see it
  if (!shots) return;
  // For the picture: top of the page, no toasts.
  for (let i = 0; i < 8; i++) {
    const close = page.getByRole("button", { name: "Dismiss notification" }).first();
    if (!(await close.isVisible().catch(() => false))) break;
    await close.click({ timeout: 1500 }).catch(() => undefined);
  }
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.mouse.move(0, 0);
  await page.screenshot({ path: join(shots, `${name}.png`), fullPage: true });
}

/**
 * The sidebar choice is saved on the account in the background. Reloading or leaving the page while that request is still on
 * its way cancels it (the database even logs "canceling statement due to user request"), so wait until the server has it.
 */
async function savedOnTheAccount(page: Page, collapsed: boolean) {
  await expect
    .poll(async () => ((await (await page.request.get("/api/v1/me/preferences")).json()) as { nav?: { collapsed?: boolean } }).nav?.collapsed ?? false, { timeout: 10_000 })
    .toBe(collapsed);
}

/** The main navigation (left column or drawer). */
const mainNav = (page: Page) => page.getByRole("navigation", { name: "Main" });

/** The account menu (top right) holds the account page, theme choice and sign out. */
async function openAccountMenu(page: Page) {
  await page.getByTestId("user-menu").click();
}
async function signOut(page: Page) {
  await openAccountMenu(page);
  await page.getByRole("menuitem", { name: "Sign out" }).click();
}

async function typeCode(page: Page, code: string) {
  await page.getByLabel("Authenticator code").fill(code);
}

test("first-run setup, MFA login, enrollment, live device, revoke, audit", async ({ page, browser }) => {
  expect(setupToken, "LIBREPATCH_SETUP_TOKEN must be set").not.toBe("");
  // Record every CSP violation; the console must run under the strict policy.
  const violations: string[] = [];
  page.on("console", (m) => {
    if (/Refused \(CSP\)/.test(m.text())) violations.push(m.text());
  });
  await page.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (e) => {
      console.error(`Refused (CSP): ${e.violatedDirective} ${e.blockedURI} sample=${e.sample} src=${e.sourceFile}:${e.lineNumber} url=${location.pathname}`);
    });
  });

  // --- Setup wizard ---
  await page.goto("/");
  await expect(page).toHaveURL(/\/setup$/);
  await page.getByLabel(/^Setup token/).fill(setupToken);
  await page.getByLabel(/^Administrator email/).fill(email);
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByAltText("Authenticator QR code")).toBeVisible();
  const secret = (await page.locator("pre").first().innerText()).trim();
  await page.getByLabel(/^Organization name/).fill("Acme Corp");
  await page.getByLabel(/^Your name/).fill("Ada Admin");
  // Mantine's required asterisk is part of the accessible name; address fields by order.
  const pw = page.locator('input[type="password"]');
  await expect(pw).toHaveCount(4);
  await pw.nth(0).fill(password);
  await pw.nth(1).fill(password);
  await pw.nth(2).fill("correct horse battery staple root");
  await pw.nth(3).fill("correct horse battery staple root");
  // The wizard takes an optional logo; it is validated in the browser first (SVG is refused).
  await page.locator('input[type="file"]').setInputFiles({ name: "evil.svg", mimeType: "image/svg+xml", buffer: Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>') });
  await expect(page.getByText(/SVG images are not accepted/)).toBeVisible();
  await page.locator('input[type="file"]').setInputFiles(fixture("logo.png"));
  await expect(page.getByTestId("setup-logo-preview")).toBeVisible();
  await shot(page, "01-setup");
  await typeCode(page, totp(secret, 0));
  await page.getByRole("button", { name: "Create organization" }).click();
  await expect(page.getByText("Store these recovery codes")).toBeVisible();
  await shot(page, "02-recovery-codes");
  await page.getByLabel("I have saved my recovery codes").check();
  await page.getByRole("button", { name: "Continue to sign in" }).click();

  // --- Login with MFA (next time step: the setup step was consumed) ---
  await expect(page).toHaveURL(/\/login$/);
  await page.getByLabel(/^Email/).fill(email);
  await page.locator('input[type="password"]').fill(password);
  await page.getByRole("button", { name: "Continue" }).click();
  await typeCode(page, totp(secret, 1));
  await page.getByRole("button", { name: "Verify" }).click();
  // The stack generated its own master key (scripts/gui-e2e.sh seeds that state): nothing works until it is saved (D109).
  await expect(page.getByRole("heading", { name: "Save your master key" })).toBeVisible();
  await a11y(page, "master-key");
  const masterKey = (await page.locator("pre").first().innerText()).trim();
  expect(masterKey).toMatch(/^([0-9a-f]{8}-){7}[0-9a-f]{8}$/);
  await expect(page.getByRole("button", { name: "Continue" })).toBeDisabled();
  await page.getByLabel("I have saved the master key somewhere other than this server").check();
  await page.getByLabel(/^Type the last six characters/).fill("000000");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByText(/not the end of the master key/)).toBeVisible();
  await page.getByLabel(/^Type the last six characters/).fill(masterKey.slice(-6));
  await page.getByRole("button", { name: "Continue" }).click();
  // The landing page is the dashboard; the device list is one click away.
  await expect(page.getByRole("heading", { name: "Dashboard", exact: true })).toBeVisible();
  await expect(page.getByLabel("Key numbers")).toBeVisible();
  // Apps that are out of date have a tile and a widget of their own, next to the Windows numbers.
  await expect(page.getByLabel("Key numbers").getByText("Apps out of date")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Apps out of date" })).toBeVisible();
  // A new installation starts with a short checklist; it can be put away.
  await expect(page.getByRole("heading", { name: "Getting started" })).toBeVisible();
  await expect(page.getByRole("list", { name: "Getting started steps" }).getByText("Add your first computer")).toBeVisible();
  await a11y(page, "dashboard");
  await shot(page, "01b-dashboard");
  await page.getByRole("button", { name: "Hide this" }).click();
  await expect(page.getByRole("heading", { name: "Getting started" })).toHaveCount(0);
  await mainNav(page).getByRole("link", { name: "Devices", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Devices", exact: true })).toBeVisible();
  await expect(page.getByText("No devices yet")).toBeVisible();
  // The organization name and logo from the wizard are in the top bar; the product keeps its default name.
  await expect(page.getByTestId("org-name")).toHaveText("Acme Corp");
  await expect(page.getByTestId("product-name")).toHaveText("LibrePatch");
  await expect(page.getByRole("img", { name: "Acme Corp logo" })).toBeVisible();
  await expect(page).toHaveTitle("Devices · Acme Corp · LibrePatch");

  // --- Enrollment token ---
  await mainNav(page).getByRole("link", { name: "Enrollment", exact: true }).click();
  await page.getByRole("button", { name: "New token" }).click();
  await page.getByLabel(/^Name/).fill("GUI test");
  await page.getByRole("button", { name: "Create" }).click();
  // The dialog shows the MSI commands and the exe commands (D112); a development build has no agent files to hand out, so
  // there are no download lines here.
  const msiCmd = (await page.locator("pre", { hasText: "msiexec /i librepatch-agent.msi" }).innerText()).trim();
  expect(msiCmd).toMatch(/msiexec \/i librepatch-agent\.msi \/qn \/norestart SERVER=\S+ TOKEN=LP1\./);
  const cmd = (await page.locator("pre", { hasText: "librepatch-agent.exe install" }).innerText()).trim();
  expect(cmd).toContain("librepatch-agent.exe install --server");
  await shot(page, "03-token");
  const enrollment = cmd.split("--token ")[1]!.trim();
  await page.keyboard.press("Escape");

  // --- Start a real agent; the device must appear live (SSE) ---
  let agent: ChildProcess | undefined;
  const agentDirs: string[] = [];
  if (agentBin) {
    const dir = mkdtempSync(join(tmpdir(), "lp-agent-"));
    agentDirs.push(dir);
    agent = spawn(agentBin, ["run", "--data-dir", dir, "--server", gateway, "--token", enrollment], { stdio: "ignore" });
  }
  try {
    await mainNav(page).getByRole("link", { name: "Devices", exact: true }).click();
    if (agentBin) {
      const row = page.getByTestId("device-row").first();
      await expect(row).toBeVisible({ timeout: 30_000 });
      await expect(row.getByText("online")).toBeVisible({ timeout: 30_000 });
      await shot(page, "04-devices");
      await row.click();
      await expect(page).toHaveURL(/\/devices\/[0-9a-f-]{36}$/);
      await expect(page.getByRole("tab", { name: "Hardware" })).toBeVisible();
      await page.getByRole("tab", { name: "Hardware" }).click();
      await expect(page.getByText("Memory")).toBeVisible();
      await shot(page, "05-device-hardware");

      // Software inventory: the dev agent on Linux reports dpkg packages.
      await page.getByRole("tab", { name: /^Installed software/ }).click();
      await expect(page.getByTestId("software-row").first()).toBeVisible({ timeout: 30_000 });
      await shot(page, "05-device-software");
      await page.getByLabel("Search Installed software").fill("zzz-no-such-package");
      await expect(page.getByText("No matching rows")).toBeVisible();
      await page.getByLabel("Search Installed software").fill("");
      // Users moved into Overview and the client certificates into Hardware; the tab follows the URL.
      await page.getByRole("tab", { name: "Overview" }).click();
      await expect(page.getByRole("heading", { name: "User profiles" })).toBeVisible();

      // Removing a user profile (D157). The dev agent reports no profiles, so the list and the device's answers are played back here:
      // the button is there for an idle profile, off for someone signed in, asks first, and only then sends the request.
      const profilePosts: string[] = [];
      await page.route(/\/api\/v1\/devices\/[0-9a-f-]{36}\/users$/, (route) =>
        route.fulfill({
          json: {
            items: [
              { sid: "S-1-5-21-1-2-3-1105", username: "old.user", domain: "CONTOSO", profile_path: "C:\\Users\\old.user", last_logon_at: "2026-01-02T10:00:00Z", loaded: false, is_admin: false },
              { sid: "S-1-5-21-1-2-3-1106", username: "here.now", domain: "CONTOSO", profile_path: "C:\\Users\\here.now", last_logon_at: "2026-10-30T10:00:00Z", loaded: true, is_admin: false },
            ],
          },
        }),
      );
      await page.route(/\/remove-profile$/, async (route) => {
        profilePosts.push(route.request().postData() ?? "");
        await route.fulfill({ status: 202, json: { job_id: "00000000-0000-7000-8000-000000000001" } });
      });
      await page.route(/\/api\/v1\/jobs\/00000000-0000-7000-8000-000000000001$/, (route) =>
        route.fulfill({ json: { id: "00000000-0000-7000-8000-000000000001", status: "succeeded", result: { message: "removed the profile of CONTOSO\\old.user (C:\\Users\\old.user); the account itself was not deleted" } } }),
      );
      await page.reload();
      await expect(page.getByRole("heading", { name: "User profiles" })).toBeVisible();
      await expect(page.getByRole("button", { name: "Remove the profile of CONTOSO\\old.user" })).toBeEnabled();
      await expect(page.getByRole("button", { name: /^Signed in now: sign them out/ })).toBeDisabled();
      await page.getByRole("button", { name: "Remove the profile of CONTOSO\\old.user" }).click();
      const dialog = page.getByRole("dialog");
      await expect(dialog.getByText("It cannot be undone.")).toBeVisible();
      await expect(dialog.getByText("The account itself is not deleted")).toBeVisible();
      await dialog.getByRole("button", { name: "Cancel" }).click();
      expect(profilePosts).toHaveLength(0);
      await page.getByRole("button", { name: "Remove the profile of CONTOSO\\old.user" }).click();
      await page.getByRole("dialog").getByRole("button", { name: "Remove profile" }).click();
      await expect(page.getByText(/the account itself was not deleted/).first()).toBeVisible({ timeout: 15_000 });
      expect(profilePosts).toEqual(['{"confirm":true}']);
      await page.unroute(/\/api\/v1\/devices\/[0-9a-f-]{36}\/users$/);
      await page.unroute(/\/remove-profile$/);
      await page.reload();
      await page.getByRole("tab", { name: "Hardware" }).click();
      await expect(page).toHaveURL(/\?tab=hardware$/);
      await expect(page.getByRole("heading", { name: "Device certificate" })).toBeVisible();
      await expect(page.getByRole("table", { name: "Certificates" })).toBeVisible();

      // Activity: the audit entries about this device (the enrollment is recorded against it).
      await page.getByRole("tab", { name: "Activity" }).click();
      await expect(page).toHaveURL(/\?tab=activity$/);
      await expect(page.getByRole("table", { name: "Device activity" })).toBeVisible();
      await expect(page.getByRole("table", { name: "Device activity" }).getByText("Device enrolled").first()).toBeVisible({ timeout: 15_000 });
      await shot(page, "05-device-activity");

      // Old links still work: the former tab names land on the tab that holds their content.
      const deviceUrl = page.url().split("?")[0]!;
      await page.goto(`${deviceUrl}?tab=certs`);
      await expect(page.getByRole("tab", { name: "Hardware" })).toHaveAttribute("aria-selected", "true");
      await expect(page).toHaveURL(/\?tab=hardware$/);
      await page.goto(`${deviceUrl}?tab=nonsense`);
      await expect(page.getByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");

      // Fleet-wide software search.
      await mainNav(page).getByRole("link", { name: "Inventory", exact: true }).click();
      await expect(page.getByRole("heading", { name: "Software", exact: true })).toBeVisible();
      await expect(page.getByTestId("title-row").first()).toBeVisible({ timeout: 15_000 });
      await page.getByLabel("Search software").fill("lib");
      await expect(page.getByTestId("title-row").first()).toBeVisible();
      await page.getByTestId("title-row").first().click();
      await expect(page.getByRole("table", { name: "Devices with this software" })).toBeVisible();
      await shot(page, "07-software");
      await page.keyboard.press("Escape");
      const download = page.waitForEvent("download");
      await page.getByRole("link", { name: "Export CSV" }).first().click();
      expect((await download).suggestedFilename()).toMatch(/^librepatch-software-.*\.csv$/);

      // Dynamic group: preview, save, list.
      await mainNav(page).getByRole("link", { name: "Groups", exact: true }).click();
      await page.getByRole("button", { name: "New group" }).click();
      await page.getByRole("textbox", { name: "Name", exact: true }).fill("Has lib packages");
      await page.getByLabel("Product name").fill("lib");
      await page.getByRole("button", { name: "Preview matches" }).click();
      await expect(page.getByTestId("preview-total")).toHaveText("1 matching device");
      await shot(page, "08-group-editor");
      await page.getByRole("button", { name: "Save group" }).click();
      await expect(page.getByTestId("group-row")).toHaveCount(1);
      await page.getByRole("button", { name: "Has lib packages" }).click();
      await expect(page.getByText("1 device")).toBeVisible();
      await page.keyboard.press("Escape");

      // Custom package -> deployment -> live job result (the Linux dev agent runs the uploaded script).
      const agentDir = agentDirs[0]!;
      await mainNav(page).getByRole("link", { name: "Catalog", exact: true }).click();
      await page.getByRole("button", { name: "Upload custom installer" }).click();
      const script = '#!/bin/sh\nmkdir -p "$(dirname "$0")/../../pf/Acme"\necho ok > "$(dirname "$0")/../../pf/Acme/tool.txt"\nexit 0\n';
      await page.getByLabel("Installer file").setInputFiles({ name: "install.sh", mimeType: "application/octet-stream", buffer: Buffer.from(script) });
      await page.getByLabel(/^Identifier/).fill("Acme.Tool");
      await page.getByRole("textbox", { name: /^Name/ }).fill("Acme Tool");
      await page.getByLabel(/^Version/).first().fill("1.0.0");
      await page.getByRole("combobox", { name: "Installer type" }).click();
      await page.getByRole("option", { name: "exe", exact: true }).click();
      await page.getByRole("combobox", { name: "Architecture" }).click();
      await page.getByRole("option", { name: "neutral" }).click();
      await page.getByLabel("Silent arguments").fill("/silent");
      await page.getByLabel("Detection file path").fill("%ProgramFiles%/Acme/tool.txt");
      await shot(page, "09-custom-upload");
      await page.getByRole("button", { name: "Upload and add" }).click();
      await expect(page.getByRole("heading", { name: "Acme Tool", exact: true })).toBeVisible();
      // The overrides read in plain words: a version choice instead of pin syntax, switches and detection rules kept behind "Advanced".
      await expect(page.getByText("Which version to install")).toBeVisible();
      await page.getByRole("combobox", { name: "Which version to install" }).click();
      await page.getByRole("option", { name: "Stay on one version" }).click();
      await expect(page.getByRole("combobox", { name: "Version to stay on" })).toBeVisible();
      await page.getByRole("button", { name: /Advanced: install switches/ }).click();
      await expect(page.getByLabel("Silent arguments")).toBeVisible();
      await shot(page, "10-package");
      await page.getByRole("link", { name: "Deploy", exact: true }).click();
      await page.getByRole("combobox", { name: "Devices" }).click();
      await page.getByRole("option").first().click();
      await page.keyboard.press("Escape");
      await shot(page, "11-deployment-new");
      await page.getByRole("button", { name: "Start deployment" }).click();
      await expect(page.getByText("Deployment queued")).toBeVisible();
      await page.getByRole("button", { name: "Watch progress" }).click();
      await expect(page.getByTestId("deployment-status")).toHaveText("completed", { timeout: 60_000 });
      await expect(page.getByTestId("job-row").getByText("succeeded")).toBeVisible();
      await shot(page, "12-deployment");
      await page.getByRole("button", { name: "Details" }).click();
      await expect(page.getByText("Timeline")).toBeVisible();
      await shot(page, "13-job-detail");
      await page.keyboard.press("Escape");
      expect(existsSync(join(agentDir, "pf", "Acme", "tool.txt"))).toBe(true);

      // Messages to the user (D124): the package lists its programs, and a deployment can choose to ask about them. The
      // Linux test agent cannot see people's programs, so it installs as before; the choice must still be kept and shown.
      await mainNav(page).getByRole("link", { name: "Catalog", exact: true }).click();
      await page.getByRole("link", { name: "Acme Tool" }).first().click();
      await page.getByRole("combobox", { name: "Programs this update replaces" }).fill("acme.exe");
      await page.keyboard.press("Enter");
      await page.getByRole("button", { name: "Save overrides" }).click();
      await expect(page.getByText("Overrides saved.")).toBeVisible();
      await page.getByRole("link", { name: "Deploy", exact: true }).click();
      await page.getByRole("combobox", { name: "Devices" }).click();
      await page.getByRole("option").first().click();
      await page.keyboard.press("Escape");
      await page.getByRole("textbox", { name: "Name", exact: true }).fill("Ask about Acme");
      await page.getByRole("combobox", { name: "If the program is open" }).click();
      await page.getByRole("option", { name: "Ask the user to close it" }).click();
      await expect(page.getByText("acme.exe")).toBeVisible();
      await shot(page, "13b-deployment-messages");
      await page.getByRole("button", { name: "Start deployment" }).click();
      await expect(page.getByText("Deployment queued")).toBeVisible();
      await page.getByRole("button", { name: "Watch progress" }).click();
      await expect(page.getByText("Messages to the user: asks the user to close the program")).toBeVisible();
      await expect(page.getByTestId("deployment-status")).toHaveText("completed", { timeout: 60_000 });

      // Static group.
      await mainNav(page).getByRole("link", { name: "Groups", exact: true }).click();
      await page.getByRole("button", { name: "New group" }).click();
      await page.getByText("Static (hand-picked)").click();
      await page.getByRole("textbox", { name: "Name", exact: true }).fill("Pilot ring");
      await page.getByRole("button", { name: "Save group" }).click();
      await page.getByRole("button", { name: "Pilot ring" }).click();
      await page.getByRole("combobox", { name: "Add devices" }).click();
      await page.getByRole("option").first().click();
      await page.keyboard.press("Escape");
      await page.getByRole("button", { name: "Add", exact: true }).click();
      await expect(page.getByText("1 device")).toBeVisible();
      await page.keyboard.press("Escape");

      // Settings (admin).
      await mainNav(page).getByRole("link", { name: "Settings", exact: true }).click();
      await expect(page.getByRole("heading", { name: "Settings", exact: true })).toBeVisible();

      // Windows updates: the dev agent reads scripted updates from wu-dev.json in its data directory.
      const wuDir = agentDirs[0]!;
      const secID = "11111111-1111-4111-8111-111111111111";
      const drvID = "22222222-2222-4222-8222-222222222222";
      writeFileSync(
        join(wuDir, "wu-dev.json"),
        JSON.stringify({
          updates: [
            { id: secID, revision: 200, title: "2026-10 Cumulative Update for Windows 11 (KB5099999)", kb: ["5099999"], classification: "Security Updates", severity: "Critical", release_date: Math.floor(Date.now() / 1000) - 20 * 86400 },
            { id: drvID, revision: 1, title: "Acme Corp - Net - 1.2.3.4", classification: "Updates" },
          ],
        }),
      );
      await mainNav(page).getByRole("link", { name: "Devices", exact: true }).click();
      await page.getByTestId("device-row").first().click();
      await page.getByRole("tab", { name: "Windows updates" }).click();
      await page.getByRole("button", { name: "Scan now" }).click();
      const devUpdates = page.getByRole("table", { name: "Windows updates on this device" });
      await expect(devUpdates.getByText("KB5099999", { exact: true })).toBeVisible({ timeout: 60_000 });
      await shot(page, "15-device-windows-updates");

      // Read-only views (D125): the Linux test agent reads scripted data from inspect-dev.json.
      writeFileSync(
        join(wuDir, "inspect-dev.json"),
        JSON.stringify({
          processes: [{ pid: 4242, parent_pid: 1, name: "acme-dev.exe", session: 1, threads: 4, working_set_kb: 20480, path: "C:\\Program Files\\Acme\\acme-dev.exe" }],
          services: [{ name: "AcmeSvc", display: "Acme Background Service", state: "running", start: "automatic", account: "LocalSystem", path: "C:\\Acme\\svc.exe" }],
          events: [{ time: Math.floor(Date.now() / 1000) - 600, level: 2, provider: "Acme-Disk", id: 7, message: "The device has a bad block." }],
        }),
      );
      await page.getByRole("tab", { name: "Inspect" }).click();
      await page.getByRole("button", { name: "Show", exact: true }).click();
      await expect(page.getByRole("table", { name: "Running programs" }).getByRole("cell", { name: "acme-dev.exe", exact: true })).toBeVisible({ timeout: 30_000 });
      await page.getByText("Services", { exact: true }).click();
      await page.getByRole("button", { name: "Show", exact: true }).click();
      await expect(page.getByRole("table", { name: "Services" }).getByText("Acme Background Service")).toBeVisible({ timeout: 30_000 });
      await page.getByText("Event log", { exact: true }).click();
      await page.getByRole("button", { name: "Show", exact: true }).click();
      await expect(page.getByRole("table", { name: "Event log" }).getByText("The device has a bad block.")).toBeVisible({ timeout: 30_000 });
      await shot(page, "15b-device-inspect");

      // Scripts (D127): scripts are on by default, and the test agent runs the text with /bin/sh.
      await mainNav(page).getByRole("link", { name: "Scripts", exact: true }).click();
      await page.getByRole("button", { name: "Add script" }).click();
      await page.getByRole("textbox", { name: "Name", exact: true }).fill("Say hello");
      await page.getByLabel("PowerShell").fill("echo hello-from-script");
      await page.getByRole("button", { name: "Save script" }).click();
      await expect(page.getByRole("table", { name: "Scripts" }).getByText("Say hello")).toBeVisible();
      await page.getByRole("button", { name: "Run Say hello" }).click();
      await page.getByRole("combobox", { name: "Devices" }).click();
      await page.getByRole("option").first().click();
      await page.keyboard.press("Escape");
      await page.getByLabel(/^Why are you running it/).fill("e2e check");
      await page.getByRole("checkbox", { name: /I have read the script/ }).check();
      await shot(page, "15c-script-run");
      await page.getByRole("button", { name: "Run", exact: true }).click();
      await expect(page.getByRole("button", { name: "Output" })).toBeVisible({ timeout: 60_000 });
      await page.getByRole("button", { name: "Output" }).click();
      await expect(page.getByText("hello-from-script", { exact: true })).toBeVisible();
      await shot(page, "15d-script-output");
      await page.keyboard.press("Escape");
      await page.keyboard.press("Escape");

      // Catalog: approve the security update, leave the other one pending.
      await mainNav(page).getByRole("link", { name: "Windows updates", exact: true }).click();
      await expect(page.getByRole("heading", { name: "Windows updates", exact: true })).toBeVisible();
      const secRow = page.getByRole("row", { name: /KB5099999/ });
      await expect(secRow).toBeVisible({ timeout: 15_000 });
      await secRow.getByRole("checkbox").check();
      await page.getByRole("button", { name: "Approve", exact: true }).click();
      await expect(secRow.getByText("approved")).toBeVisible({ timeout: 15_000 });
      await expect(page.getByRole("row", { name: /Acme Corp/ }).getByText("pending")).toBeVisible();
      await shot(page, "16-updates-catalog");

      // Policy: a ring over the saved group, a rule, and the update source.
      await mainNav(page).getByRole("link", { name: "Automations", exact: true }).click();
      await expect(page.getByRole("heading", { name: "Automations", exact: true })).toBeVisible();
      await page.getByRole("tab", { name: "Windows", exact: true }).click();
      await expect(page.getByRole("heading", { name: "Rings", exact: true })).toBeVisible();
      await page.getByRole("button", { name: "Add ring" }).click();
      await page.getByRole("dialog").getByLabel("Name").fill("Pilot");
      await page.getByRole("dialog").getByLabel("Groups").click();
      await page.getByRole("option", { name: "Has lib packages" }).click();
      await page.getByRole("dialog").getByRole("button", { name: "Save ring" }).click();
      await expect(page.getByRole("table", { name: "Update rings" }).getByText("Pilot")).toBeVisible({ timeout: 15_000 });
      await page.mouse.move(0, 0); // a hovered toast does not time out and would cover the next button
      await page.getByRole("button", { name: "Add rule" }).click();
      await page.getByRole("dialog").getByLabel("Name").fill("Critical security");
      await page.getByRole("dialog").getByLabel("Severities").click({ force: true });
      await page.getByRole("option", { name: "Critical" }).click();
      await page.getByRole("dialog").getByText("Add rule").click();
      await page.getByRole("dialog").getByRole("button", { name: "Save rule" }).click();
      await expect(page.getByRole("table", { name: "Auto-approval rules" }).getByText("Critical security")).toBeVisible({ timeout: 15_000 });
      await shot(page, "17-update-policy");

      // Install the other update by hand on the device; after a rescan it is no longer missing.
      await mainNav(page).getByRole("link", { name: "Devices", exact: true }).click();
      await page.getByTestId("device-row").first().click();
      await page.getByRole("tab", { name: "Windows updates" }).click();
      await devUpdates.getByRole("row", { name: /Acme Corp/ }).getByRole("checkbox").check();
      await page.getByRole("button", { name: "Install selected" }).click();
      await page.getByRole("dialog").getByRole("button", { name: "Install", exact: true }).click();
      await expect(page.getByText("Install queued.")).toBeVisible();
      await expect(async () => {
        await page.getByRole("button", { name: "Scan now" }).click();
        await expect(devUpdates.getByText("Acme Corp")).toHaveCount(0, { timeout: 15_000 });
      }).toPass({ timeout: 90_000 });

      // --- Vulnerabilities: feed files loaded by hand, a program mapped to the NVD, the page, the CVE dialog and the device tab ---
      const csrf = ((await (await page.request.get("/api/v1/auth/session")).json()) as { csrf_token: string }).csrf_token;
      // A state change needs the session's CSRF token and the console's own origin, as the browser would send them.
      const post = (path: string, data: unknown) => page.request.post(`/api/v1${path}`, { data, headers: { "X-CSRF-Token": csrf, Origin: new URL(page.url()).origin } });
      expect((await post("/vulnerabilities/products", { name: "bash", vendor: "gnu", product: "bash" })).status()).toBe(201);
      const nvdPage = { resultsPerPage: 1, startIndex: 0, totalResults: 1, vulnerabilities: [{ cve: { id: "CVE-2026-9001", published: "2026-09-30T00:00:00.000", lastModified: "2026-10-01T00:00:00.000", vulnStatus: "Analyzed",
        descriptions: [{ lang: "en", value: "A made-up bash vulnerability for the browser test." }], metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8, baseSeverity: "CRITICAL" } }] },
        configurations: [{ nodes: [{ operator: "OR", cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:gnu:bash:*:*:*:*:*:*:*:*", versionEndExcluding: "99.0" }] }] }] } }] };
      const kevFile = { catalogVersion: "e2e", vulnerabilities: [{ cveID: "CVE-2026-9001", vendorProject: "GNU", product: "Bash", vulnerabilityName: "GNU Bash e2e vulnerability", dateAdded: "2026-10-01", requiredAction: "Apply updates per vendor instructions.", dueDate: "2026-10-22", knownRansomwareCampaignUse: "Unknown" }] };
      expect((await post("/vulnerabilities/import", { kind: "nvd", data: JSON.stringify(nvdPage) })).status()).toBe(200);
      expect((await post("/vulnerabilities/import", { kind: "kev", data: JSON.stringify(kevFile) })).status()).toBe(200);
      expect((await post("/vulnerabilities/import", { kind: "kev", data: "not a catalog" })).status()).toBe(422);
      // A recent entry that names a product but no versions: the NVD does that when it does not know which versions are meant, so
      // a fully patched computer would be listed. It is left out until asked for, and the page says how many.
      const noVersionsPage = { resultsPerPage: 1, startIndex: 0, totalResults: 1, vulnerabilities: [{ cve: { id: "CVE-2026-9002", published: "2026-09-30T00:00:00.000", lastModified: "2026-10-01T00:00:00.000", vulnStatus: "Analyzed",
        descriptions: [{ lang: "en", value: "A made-up entry that names no versions, known as &quot;NoVersions&quot;." }], metrics: { cvssMetricV31: [{ cvssData: { baseScore: 7.5, baseSeverity: "HIGH" } }] },
        configurations: [{ nodes: [{ operator: "OR", cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:gnu:bash:*:*:*:*:*:*:*:*" }] }] }] } }] };
      expect((await post("/vulnerabilities/import", { kind: "nvd", data: JSON.stringify(noVersionsPage) })).status()).toBe(200);
      await mainNav(page).getByRole("link", { name: "Vulnerabilities", exact: true }).click();
      await expect(page.getByRole("heading", { name: "Vulnerabilities", exact: true })).toBeVisible();
      await expect(page.getByText("Known exploited", { exact: true })).toBeVisible();
      const cveRow = page.getByRole("table", { name: "Vulnerabilities" }).getByText("CVE-2026-9001");
      await expect(cveRow).toBeVisible({ timeout: 30_000 });
      await shot(page, "22c-vulnerabilities");
      await expect(page.getByRole("table", { name: "Vulnerabilities" }).getByText("CVE-2026-9002")).toHaveCount(0);
      await expect(page.getByText("Also show 1 entry where the NVD names no versions")).toBeVisible();
      await page.getByRole("switch", { name: /Also show 1 entry/ }).click({ force: true });
      await expect(page.getByRole("table", { name: "Vulnerabilities" }).getByText("CVE-2026-9002")).toBeVisible();
      await expect(page.getByText(/known as “?"?NoVersions/)).toBeVisible();
      await page.getByRole("switch", { name: /Also showing entries/ }).click({ force: true });
      await expect(page.getByRole("table", { name: "Vulnerabilities" }).getByText("CVE-2026-9002")).toHaveCount(0);
      await cveRow.click();
      const cd = page.getByRole("dialog");
      await expect(cd.getByText("GNU Bash e2e vulnerability")).toBeVisible();
      await expect(cd.getByText(/fix due 2026-10-22|fix is due today|fix was due 2026-10-22/)).toBeVisible();
      // The window says what can be done about it: here the program is in no catalog, so there is nothing to install from this page.
      await expect(cd.getByText("No update to offer from here")).toBeVisible();
      await expect(cd.getByRole("columnheader", { name: "What you can do" })).toBeVisible();
      await expect(cd.getByRole("button", { name: /^Update \d+ device/ })).toHaveCount(0);
      await cd.getByRole("link", { name: /^\S+$/ }).filter({ hasNotText: "NVD page" }).first().click();
      await expect(page).toHaveURL(/\?tab=vulnerabilities$/);
      await expect(page.getByRole("table", { name: "Known vulnerabilities on this device" }).getByText("CVE-2026-9001")).toBeVisible();
      const devVul = await (await page.request.get("/api/v1/vulnerabilities.csv")).text();
      expect(devVul).toContain("CVE-2026-9001");

      // On the device page already: refresh, missing updates, uninstall from the inventory, then revoke and delete.
      await shot(page, "05-device-detail");
      await page.getByRole("button", { name: /Refresh/ }).click();
      await expect(page.getByText("Device information refreshed.")).toBeVisible({ timeout: 30_000 });
      await page.getByRole("tab", { name: "Software updates" }).click();
      await expect(page.getByText(/No missing updates/)).toBeVisible();
      await page.getByRole("tab", { name: /^Installed software/ }).click();
      await expect(page.getByTestId("software-row").first()).toBeVisible();
      await expect(page.getByRole("button", { name: "Uninstall Software" })).toHaveCount(0); // the bulk bar appears with a selection
      await page.getByTestId("software-row").first().getByRole("checkbox").check();
      await expect(page.getByText("1 selected", { exact: true })).toBeVisible();
      await shot(page, "14-device-software-selected");
      await page.getByRole("button", { name: "Uninstall Software" }).click();
      await expect(page.getByRole("table", { name: "Programs to uninstall" })).toBeVisible();
      await page.getByRole("dialog").getByRole("button", { name: "Uninstall" }).click();
      await expect(page.getByText(/Uninstall queued for 1 program/)).toBeVisible();
      await page.getByRole("tab", { name: "Jobs" }).click();
      await expect(page.getByRole("table", { name: "Device jobs" }).getByText(/^Uninstall /).first()).toBeVisible({ timeout: 15_000 });
      await page.getByRole("button", { name: "More actions" }).click();
      await page.getByRole("menuitem", { name: "Revoke device" }).click();
      await page.getByLabel("Reason (recorded in the audit log)").fill("GUI test");
      // Revoking an enrolled computer tells its agent to uninstall itself first (D158); that is the default.
      await expect(page.getByRole("checkbox", { name: /Also uninstall the agent/ })).toBeChecked();
      await page.getByRole("button", { name: "Uninstall the agent and revoke" }).click();
      await expect(page.getByText(/being told to uninstall its agent/)).toBeVisible();
      // The test agent runs on Linux and cannot remove itself, so it answers "failed": the device stays active and is not revoked.
      await page.getByRole("tab", { name: "Jobs" }).click();
      const failed = page.getByRole("table", { name: "Device jobs" }).getByRole("row", { name: /Uninstall the agent, then revoke the device/ });
      await expect(failed).toBeVisible({ timeout: 15_000 });
      await expect(failed.getByText("Failed", { exact: true })).toBeVisible({ timeout: 30_000 });
      await expect(page.getByText(/^Revoked: /)).toHaveCount(0);
      // Revoking without the uninstall is one click away.
      await page.getByRole("button", { name: "More actions" }).click();
      await page.getByRole("menuitem", { name: "Revoke device" }).click();
      await page.getByLabel("Reason (recorded in the audit log)").fill("GUI test");
      await page.getByRole("checkbox", { name: /Also uninstall the agent/ }).uncheck({ force: true });
      await page.getByRole("button", { name: "Revoke device" }).click();
      await expect(page.getByText("Revoked: GUI test")).toBeVisible({ timeout: 15_000 });
      // A revoked device can be deleted; an active one cannot (no button).
      await page.getByRole("button", { name: "More actions" }).click();
      await page.getByRole("menuitem", { name: "Delete device" }).click();
      await page.getByRole("button", { name: "Delete permanently" }).click();
      await expect(page).toHaveURL(/localhost:\d+\/devices$/);
      await page.getByText("Revoked", { exact: true }).click();
      await expect(page.getByText("No devices yet")).toBeVisible();
    }
  } finally {
    agent?.kill();
  }

  // --- Identity: a site, a site-limited technician, a security key and an API token ---
  const origin = new URL(page.url()).origin;
  await mainNav(page).getByRole("link", { name: "Sites", exact: true }).click();
  await page.getByRole("button", { name: "Add site" }).click();
  await page.getByRole("dialog").getByLabel(/^Name/).fill("Branch office");
  await page.getByRole("dialog").getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("table", { name: "Sites" }).getByText("Branch office")).toBeVisible();
  await shot(page, "18-sites");

  await mainNav(page).getByRole("link", { name: "Users and roles", exact: true }).click();
  await page.getByRole("button", { name: "Add user" }).click();
  const dlg = page.getByRole("dialog");
  await dlg.getByLabel(/^Email/).fill("tech@example.com");
  await dlg.getByLabel(/^Name/).fill("Tess Tech");
  await dlg.getByLabel("Applies to").click();
  await page.getByRole("option", { name: "Site: Branch office" }).click();
  await dlg.getByRole("button", { name: "Create user" }).click();
  const temp = (await page.getByRole("dialog").locator("pre").first().innerText()).trim();
  expect(temp.length).toBeGreaterThanOrEqual(16);
  await page.keyboard.press("Escape");
  await expect(page.getByTestId("user-row").filter({ hasText: "tech@example.com" })).toContainText("site Branch office");
  // The users table shares its frame between its columns instead of scrolling sideways.
  const usersFrame = page.getByRole("region", { name: /Users table, scrollable/ });
  expect(await usersFrame.evaluate((el) => el.scrollWidth - el.clientWidth)).toBeLessThanOrEqual(1);
  await shot(page, "19-users");

  // The technician: forced password change, authenticator enrollment, and a console limited to devices.
  const techCtx = await browser.newContext({ baseURL: origin });
  const tp = await techCtx.newPage();
  await tp.goto("/login");
  await tp.getByLabel(/^Email/).fill("tech@example.com");
  await tp.locator('input[type="password"]').fill(temp);
  await tp.getByRole("button", { name: "Continue" }).click();
  await expect(tp.getByText("temporary password")).toBeVisible();
  await tp.getByLabel(/^New password/).fill("Quartz-Harbor-Violin-77");
  await tp.getByLabel(/^Repeat the new password/).fill("Quartz-Harbor-Violin-77");
  await tp.getByRole("button", { name: "Change password" }).click();
  await expect(tp.getByAltText("Authenticator QR code")).toBeVisible();
  const techSecret = (await tp.locator("pre").first().innerText()).trim();
  await typeCode(tp, totp(techSecret, 0));
  await tp.getByRole("button", { name: "Confirm" }).click();
  await tp.getByRole("button", { name: "I have saved them, continue" }).click();
  await expect(tp.getByRole("heading", { name: "Dashboard", exact: true })).toBeVisible();
  await expect(tp.getByRole("link", { name: "Devices", exact: true })).toBeVisible();
  for (const hidden of ["Inventory", "Groups", "Catalog", "Deployments", "Software updates", "Users and roles", "Audit log", "Settings"]) {
    await expect(tp.getByRole("link", { name: hidden, exact: true })).toHaveCount(0);
  }
  await shot(tp, "20-site-limited-console");
  await techCtx.close();

  // A security key (software authenticator through the browser's WebAuthn test API) and an API token.
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "usb", hasResidentKey: false, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  await openAccountMenu(page);
  await page.getByRole("menuitem", { name: "Account and security" }).click();
  await expect(page.getByRole("heading", { name: "Account security", exact: true })).toBeVisible();
  await page.getByLabel("Name for a new key").fill("Test key");
  await page.getByRole("button", { name: "Add security key" }).click();
  await expect(page.getByRole("table", { name: "Security keys" }).getByText("Test key")).toBeVisible();
  await page.getByLabel("Token name").fill("CI sync");
  await page.getByLabel("devices:read").check();
  await page.getByRole("button", { name: "Create token" }).click();
  await expect(page.getByText("Copy the token now")).toBeVisible();
  const apiToken = (await page.getByRole("alert").locator("pre").first().innerText()).trim();
  expect(apiToken).toMatch(/^lp_/);
  await shot(page, "21-account-security");
  const bare = await request.newContext({ baseURL: origin });
  expect((await bare.get("/api/v1/devices", { headers: { Authorization: `Bearer ${apiToken}` } })).status()).toBe(200);
  expect((await bare.get("/api/v1/audit", { headers: { Authorization: `Bearer ${apiToken}` } })).status()).toBe(403);
  await bare.dispose();

  // Sign out and back in with the security key instead of an authenticator code.
  await signOut(page);
  await expect(page).toHaveURL(/\/login$/);
  await page.getByLabel(/^Email/).fill(email);
  await page.locator('input[type="password"]').fill(password);
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByRole("button", { name: "Use a security key" }).click();
  await expect(page.getByRole("heading", { name: "Dashboard", exact: true })).toBeVisible();

  // --- Navigation: command palette, bell, folding groups, icon rail, pre-filtered links ---
  await page.keyboard.press("Control+k");
  const palette = page.getByRole("dialog", { name: "Search" });
  await expect(palette).toBeVisible();
  await palette.getByRole("combobox").fill("audit");
  await expect(palette.getByRole("option", { name: /Audit log/ })).toBeVisible();
  await a11y(page, "command-palette");
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/audit$/);
  await expect(page.getByRole("heading", { name: "Audit log", exact: true })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Breadcrumb" })).toContainText("Administration");
  await page.getByTestId("notifications").click();
  await expect(page.getByText("Needs attention")).toBeVisible();
  await page.keyboard.press("Escape");
  // Items of the bell can be dismissed, one by one or all at once (the server's side is covered by its own test; here the
  // answers are made up so there is something to dismiss).
  type Note = { id: string; kind: string; severity: string; title: string; detail: string; to: string; at: string };
  const note = (n: number): Note => ({ id: `job-${n}`, kind: "failed_job", severity: "warning", title: `Update ${n} failed on PC-${n}`, detail: "could not run", to: "/devices", at: new Date().toISOString() });
  let bellItems: Note[] = [note(1), note(2), note(3)];
  const dismissed: unknown[] = [];
  await page.route("**/api/v1/notifications", (r) => r.fulfill({ json: { items: bellItems, total: bellItems.length } }));
  await page.route("**/api/v1/notifications/dismiss", async (r) => {
    const body = r.request().postDataJSON() as { ids?: string[]; all?: boolean };
    dismissed.push(body);
    bellItems = body.all ? [] : bellItems.filter((i) => !(body.ids ?? []).includes(i.id));
    await r.fulfill({ status: 204 });
  });
  await page.reload();
  await page.getByTestId("notifications").click();
  await expect(page.getByText("Update 1 failed on PC-1")).toBeVisible();
  await a11y(page, "notifications");
  await shot(page, "24b-notifications");
  await page.getByRole("button", { name: "Dismiss: Update 1 failed on PC-1" }).click();
  await expect(page.getByText("Update 1 failed on PC-1")).toHaveCount(0);
  await expect(page.getByText("Update 2 failed on PC-2")).toBeVisible();
  expect(dismissed).toEqual([{ ids: ["job-1"] }]);
  await page.getByRole("button", { name: "Dismiss all" }).click();
  await expect(page.getByText("You are all caught up.")).toBeVisible();
  expect(dismissed[1]).toEqual({ all: true });
  await page.unroute("**/api/v1/notifications");
  await page.unroute("**/api/v1/notifications/dismiss");
  await page.keyboard.press("Escape");
  const endpoints = mainNav(page).getByRole("button", { name: "Endpoints" });
  await endpoints.click();
  await expect(endpoints).toHaveAttribute("aria-expanded", "false");
  await expect(mainNav(page).getByRole("link", { name: "Groups", exact: true })).toBeHidden();
  await endpoints.click();
  await expect(mainNav(page).getByRole("link", { name: "Groups", exact: true })).toBeVisible();
  // The one switch for the sidebar is in the top bar (there used to be a second one at the bottom of the sidebar).
  await expect(page.getByTestId("nav-rail-toggle")).toHaveCount(0);
  await page.getByTestId("topbar-nav-toggle").click();
  await expect(page.locator(".lp-shell")).toHaveAttribute("data-rail", "true");
  await shot(page, "24-nav-rail");
  await page.getByTestId("topbar-nav-toggle").click();
  await expect(page.locator(".lp-shell")).not.toHaveAttribute("data-rail", "true");
  await page.getByTestId("topbar-nav-toggle").click();
  await expect(page.locator(".lp-shell")).toHaveAttribute("data-rail", "true");
  await savedOnTheAccount(page, true);
  await page.reload();
  await expect(page.locator(".lp-shell")).toHaveAttribute("data-rail", "true"); // remembered on the account
  await page.getByTestId("topbar-nav-toggle").click();
  await expect(page.locator(".lp-shell")).not.toHaveAttribute("data-rail", "true");
  await savedOnTheAccount(page, false);
  await page.goto("/devices?state=offline");
  await expect(page.getByRole("heading", { name: "Devices", exact: true })).toBeVisible();
  // Held updates is not in the sidebar (Windows updates, Automations and the dashboard lead to it); the page itself still works.
  await expect(mainNav(page).getByRole("link", { name: "Held updates", exact: true })).toHaveCount(0);
  await expect(mainNav(page).getByRole("link", { name: "Agent updates", exact: true })).toBeVisible();
  await page.goto("/updates/held");
  await expect(page.getByRole("heading", { name: "Held updates", exact: true })).toBeVisible();
  // Software updates: the page for programs that are out of date, between "Held updates"-style pages in the Updates group.
  await mainNav(page).getByRole("link", { name: "Software updates", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Software updates", exact: true })).toBeVisible();
  await a11y(page, "software-updates");
  await mainNav(page).getByRole("link", { name: "Dashboard", exact: true }).click();

  // --- Automation: a software policy, the reports page, and the audit chain check ---
  // Software policies live on the Software tab of Automations (the first tab).
  await mainNav(page).getByRole("link", { name: "Automations", exact: true }).click();
  await expect(page.getByRole("tab", { name: "Software", exact: true })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("heading", { name: "Rings", exact: true })).toHaveCount(0); // rings are for Windows updates only (D148)
  await expect(page.getByRole("toolbar", { name: "Software policies controls" })).toBeVisible();
  await page.getByRole("button", { name: "Add policy" }).click();
  const pd = page.getByRole("dialog");
  await pd.getByLabel(/^Name/).fill("Keep Acme Tool current");
  await pd.getByLabel(/^Package/).click();
  await page.getByRole("option", { name: "Acme Tool" }).click();
  await pd.getByLabel(/^Groups/).click();
  await page.getByRole("option").first().click();
  await pd.getByText("Add policy").click(); // close the dropdown
  await pd.getByRole("button", { name: "Save policy" }).click();
  await expect(page.getByRole("table", { name: "Software policies" }).getByText("Keep Acme Tool current")).toBeVisible();
  await shot(page, "22-policies");
  await a11y(page, "automations-software");
  // The old addresses still lead to the right tab.
  await page.goto("/update-policy");
  await expect(page).toHaveURL(/\/automations\?tab=windows/);
  await expect(page.getByRole("tab", { name: "Windows", exact: true })).toHaveAttribute("aria-selected", "true");
  await a11y(page, "automations-windows");
  await page.goto("/policies");
  await expect(page).toHaveURL(/\/automations$/);
  // A policy that waits for approval of each new version (it no longer offers staged rollout through rings).
  await page.getByRole("button", { name: "Add policy" }).click();
  const sd = page.getByRole("dialog");
  await sd.getByLabel(/^Name/).fill("Staged Acme Tool");
  await sd.getByLabel(/^Package/).click();
  await page.getByRole("option", { name: "Acme Tool" }).click();
  await sd.getByLabel(/^Groups/).click();
  await page.getByRole("option").first().click();
  await sd.getByText("Add policy").click(); // close the dropdown
  await expect(sd.getByLabel(/Roll new versions out in stages/)).toHaveCount(0);
  await sd.getByLabel(/Wait for my approval of each new version/).check();
  await sd.getByRole("button", { name: "Save policy" }).click();
  await expect(page.getByRole("table", { name: "Software policies" }).getByText("Staged Acme Tool")).toBeVisible();
  const queue = await page.request.get("/api/v1/software/approvals");
  expect(queue.status()).toBe(200);
  const qj = await queue.json();
  expect(Object.keys(qj).sort()).toEqual(["holds", "pending", "recent"]);
  const pols = await (await page.request.get("/api/v1/policies")).json();
  const staged = pols.items.find((p: { name: string }) => p.name === "Staged Acme Tool");
  expect(staged.use_rings).toBe(false);
  expect(staged.require_approval).toBe(true);
  // Every policy says what its last check found (D132); a policy that was just made has not been checked yet.
  expect(staged.state).toBe("new");
  await expect(page.getByRole("table", { name: "Software policies" }).getByText("Not checked yet").first()).toBeVisible();
  // One policy for all apps: no package, a filter, and a preview of the apps it would handle.
  await page.getByRole("button", { name: "Add policy" }).click();
  const ad = page.getByRole("dialog");
  await ad.getByLabel(/^Name/).fill("Keep every app current");
  await ad.getByLabel(/^What it does/).click();
  await page.getByRole("option", { name: /all apps/ }).click();
  await expect(ad.getByLabel(/^Package/)).toHaveCount(0);
  await ad.getByLabel(/^Groups/).click();
  await page.getByRole("option").first().click();
  await ad.getByText("Add policy").click(); // close the dropdown
  await expect(ad.getByLabel(/Only apps that were verified on test machines/)).toBeChecked();
  await expect(ad.getByLabel(/Also update apps that update themselves/)).toBeChecked();
  await expect(ad.getByLabel("Apps this policy would handle")).toBeVisible();
  await shot(page, "22a-policy-all-apps");
  await ad.getByRole("button", { name: "Save policy" }).click();
  await expect(page.getByRole("table", { name: "Software policies" }).getByText("Keep every app current")).toBeVisible();
  const pols2 = await (await page.request.get("/api/v1/policies")).json();
  const everyApp = pols2.items.find((p: { name: string }) => p.name === "Keep every app current");
  expect(everyApp.kind).toBe("keep_all");
  expect(everyApp.package_id).toBeNull();
  expect(everyApp.filter.verified_only).toBe(true);
  expect(everyApp.filter.include_self_updating).toBe(true);
  // The Software updates page can start the same thing in a click.
  await mainNav(page).getByRole("link", { name: "Software updates", exact: true }).click();
  await page.getByRole("button", { name: "Automate all updates…" }).click();
  await expect(page.getByRole("dialog").getByLabel(/^Name/)).toHaveValue("Keep all apps updated");
  await page.getByRole("dialog").getByRole("button", { name: "Cancel" }).click();
  await mainNav(page).getByRole("link", { name: "Automations", exact: true }).click();

  // --- A signed catalog overlay, made here with Node's Ed25519 and accepted by the server's Go verifier ---
  await mainNav(page).getByRole("link", { name: "Catalog", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Overlays", exact: true })).toBeVisible();
  const ovKeys = generateKeyPairSync("ed25519");
  const ovPub = ovKeys.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
  const ovDoc = JSON.stringify({ format: "librepatch-overlay/1", name: "E2E overlay", version: 1, packages: [{ identifier: "7zip.7zip", self_updating: false, verified: true, verified_note: "Tested by the e2e run", silent_args: ["/S"] }] });
  const ovSig = edSign(null, Buffer.concat([Buffer.from("librepatch/overlay/v1\0"), Buffer.from(ovDoc)]), ovKeys.privateKey).toString("base64");
  const ovBundle = JSON.stringify({ format: "librepatch-overlay-bundle/1", overlay: JSON.parse(ovDoc), key_id: "e2e", signature: ovSig });
  await page.getByRole("button", { name: "Add overlay" }).click();
  const od = page.getByRole("dialog");
  await od.locator('input[type="file"]').setInputFiles({ name: "e2e.lpov", mimeType: "application/json", buffer: Buffer.from(ovBundle) });
  await od.getByLabel(/^Public key/).fill("00".repeat(32)); // the wrong key first: refused with a clear message
  await od.getByRole("button", { name: "Add overlay" }).click();
  await expect(od.getByText(/signature does not match/i)).toBeVisible();
  await od.getByLabel(/^Public key/).fill(ovPub);
  await od.getByRole("button", { name: "Add overlay" }).click();
  await expect(page.getByRole("table", { name: "Overlays" }).getByText("E2E overlay").first()).toBeVisible();
  const ovList = await (await page.request.get("/api/v1/catalog/overlays")).json();
  expect(ovList.items).toHaveLength(1);
  expect(ovList.items[0]).toMatchObject({ label: "E2E overlay", entries: 1, verified_entries: 1, status: "ok", kind: "upload" });
  const ovTpl = await page.request.get("/api/v1/catalog/overlay-template");
  expect(ovTpl.status()).toBe(200);
  expect((await ovTpl.json()).format).toBe("librepatch-overlay/1");
  await shot(page, "22b-overlays");

  await mainNav(page).getByRole("link", { name: "Reports", exact: true }).click();
  await expect(page.getByRole("heading", { name: /^(.* · )?Reports$/ })).toBeVisible();
  await expect(page.getByText("Patch compliant")).toBeVisible();
  // With no scanned device the headline says so instead of claiming 0% compliance.
  const cmp = (await (await page.request.get("/api/v1/reports/overview")).json()).compliance;
  const tile = page.getByLabel("Fleet summary").locator(".lp-tile", { hasText: "Patch compliant" });
  if ((cmp.compliant ?? 0) + (cmp.non_compliant ?? 0) === 0) {
    await expect(tile).toContainText("—");
    await expect(tile).not.toContainText("0%");
  }
  // The operating-system support report: its summary and its table are there, and the API answers with the data date.
  await expect(page.getByRole("heading", { name: "Operating system support" })).toBeVisible();
  const lifecycle = await page.request.get("/api/v1/reports/lifecycle");
  expect(lifecycle.status()).toBe(200);
  const lc = await lifecycle.json();
  expect(lc.data_as_of).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  expect(Object.keys(lc.summary).sort()).toEqual(["ending_soon", "supported", "unknown", "unsupported"]);
  const lcCsv = await page.request.get("/api/v1/reports/lifecycle.csv");
  expect(lcCsv.status()).toBe(200);
  expect(await lcCsv.text()).toContain("hostname,status,operating_system");
  await shot(page, "23-reports");

  // --- Settings: sections, search, validation, unsaved changes, secrets, export ---
  await mainNav(page).getByRole("link", { name: "Settings", exact: true }).click();
  const setNav = page.getByRole("navigation", { name: "Settings sections" });
  // The sidebar has one Settings link; the sections are listed inside the Settings page only.
  await expect(mainNav(page).getByRole("link", { name: "Branding", exact: true })).toHaveCount(0);
  for (const name of ["General", "Branding", "Appearance", "Security", "Notifications", "Update defaults", "Device defaults", "Downloads", "Scheduled reports", "Data and retention", "Integrations", "About"]) {
    await expect(setNav.getByRole("link", { name, exact: true })).toBeVisible();
  }
  // Search finds a setting by what it says, and jumps to it.
  await page.getByTestId("settings-search").fill("lockout");
  await expect(page.getByRole("list", { name: "Search results" }).getByRole("link", { name: /Lock an account after failed sign-ins/ })).toBeVisible();
  await page.getByRole("list", { name: "Search results" }).getByRole("link", { name: /Lock an account/ }).click();
  await expect(page).toHaveURL(/\/settings\/security\?field=lockout_threshold/);
  const threshold = page.getByLabel("Lock an account after failed sign-ins", { exact: true });
  await expect(threshold).toHaveValue("10");
  await a11y(page, "settings-security");
  await shot(page, "25-settings-security");
  // A value the server refuses is shown next to the field; nothing is saved.
  await threshold.fill("99");
  await expect(page.getByText("Enter a number from 3 to 20.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Save changes" })).toBeDisabled();
  await threshold.fill("7");
  await expect(page.getByRole("region", { name: "Unsaved changes" })).toBeVisible();
  // Leaving with unsaved changes asks first.
  await setNav.getByRole("link", { name: "Appearance", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "Leave without saving?" })).toBeVisible();
  await page.getByRole("button", { name: "Cancel" }).click();
  await expect(page).toHaveURL(/\/settings\/security/);
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByText("Security settings saved.")).toBeVisible();
  await expect(page.getByRole("region", { name: "Unsaved changes" })).toBeHidden();
  await page.reload();
  await expect(page.getByLabel("Lock an account after failed sign-ins", { exact: true })).toHaveValue("7");
  // The change is in the audit log with before and after.
  await page.goto("/audit");
  await expect(page.getByRole("heading", { name: "Audit log", exact: true })).toBeVisible();
  await expect(page.getByRole("row", { name: /settings\.update/ }).first()).toBeVisible();
  // Notifications: a mail password is write-only.
  await page.goto("/settings/notifications");
  await page.getByRole("switch", { name: /^Send e-mail/ }).check({ force: true });
  await page.getByLabel("Mail server", { exact: true }).fill("smtp.example.org");
  await page.getByLabel("From address", { exact: true }).fill("librepatch@example.org");
  await page.getByLabel("User name", { exact: true }).fill("mailer");
  await page.getByLabel("Password", { exact: true }).fill("a-secret-mail-password");
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByText("Notifications settings saved.")).toBeVisible();
  await page.reload();
  await expect(page.getByLabel("Password", { exact: true })).toHaveValue("");
  await expect(page.getByLabel("Password", { exact: true })).toHaveAttribute("placeholder", /Saved/);
  await expect(page.getByText("a-secret-mail-password")).toHaveCount(0);
  await a11y(page, "settings-notifications");
  await shot(page, "26-settings-notifications");
  // Integrations and Appearance render and pass the accessibility scan.
  await setNav.getByRole("link", { name: "Integrations", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Webhook reference" })).toBeVisible();
  await a11y(page, "settings-integrations");
  await setNav.getByRole("link", { name: "Appearance", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Themes" })).toBeVisible();
  await a11y(page, "settings-appearance");
  // The remaining sections render, explain themselves and pass the accessibility scan.
  for (const [name, heading] of [["Update defaults", "Update defaults"], ["Device defaults", "Device defaults"], ["Scheduled reports", "Scheduled reports"], ["Data and retention", "Data and retention"]] as const) {
    await setNav.getByRole("link", { name, exact: true }).click();
    await expect(page.getByRole("heading", { name: heading, exact: true })).toBeVisible();
    await a11y(page, `settings-${name.toLowerCase().replace(/ /g, "-")}`);
  }
  // Windows updates can be switched off for the whole organization: their pages, the Windows tab and the device tab go away, software stays.
  await setNav.getByRole("link", { name: "Update defaults", exact: true }).click();
  await page.getByRole("switch", { name: /^Manage Windows updates/ }).uncheck({ force: true });
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByText("Update defaults settings saved.")).toBeVisible();
  await expect(mainNav(page).getByRole("link", { name: "Windows updates", exact: true })).toHaveCount(0);
  await expect(mainNav(page).getByRole("link", { name: "Held updates", exact: true })).toHaveCount(0);
  await expect(mainNav(page).getByRole("link", { name: "Software updates", exact: true })).toBeVisible();
  await mainNav(page).getByRole("link", { name: "Automations", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Automations", exact: true })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Windows", exact: true })).toHaveCount(0);
  await page.goto("/automations?tab=windows"); // there is no Windows tab now: the Software tab shows instead
  await expect(page.getByRole("table", { name: "Software policies" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Rings", exact: true })).toHaveCount(0);
  await a11y(page, "automations-windows-off");
  await page.goto("/settings/updates");
  await page.getByRole("switch", { name: /^Manage Windows updates/ }).check({ force: true });
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByText("Update defaults settings saved.")).toBeVisible();
  await expect(mainNav(page).getByRole("link", { name: "Windows updates", exact: true })).toBeVisible();
  // "Ignore WSUS" turns the source "whatever the device is set to" into Windows Update on the internet, and says so on Automations.
  await page.getByRole("switch", { name: /^Ignore WSUS and check Microsoft directly/ }).check({ force: true });
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByText("Update defaults settings saved.").last()).toBeVisible();
  await page.goto("/automations?tab=windows");
  await expect(page.getByText("WSUS is ignored (Settings, Update defaults)")).toBeVisible();
  await expect(page.getByRole("textbox", { name: "Service", exact: true }).or(page.getByLabel("Service", { exact: true })).first()).toHaveValue("Windows Update (internet); WSUS is ignored");
  await page.goto("/settings/updates");
  await page.getByRole("switch", { name: /^Ignore WSUS and check Microsoft directly/ }).uncheck({ force: true });
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByText("Update defaults settings saved.").last()).toBeVisible();
  // A custom device field is defined here and then offered on the device page and in the device list.
  await setNav.getByRole("link", { name: "Device defaults", exact: true }).click();
  await page.getByRole("group", { name: "Custom device fields" }).getByRole("button", { name: "Add" }).click();
  await page.getByLabel("Key", { exact: true }).fill("asset_tag");
  await page.getByLabel("Label", { exact: true }).fill("Asset tag");
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByText("Device defaults settings saved.")).toBeVisible();
  await setNav.getByRole("link", { name: "Data and retention", exact: true }).click();
  await expect(page.getByText("Last backup")).toBeVisible();
  await setNav.getByRole("link", { name: "About", exact: true }).click();
  await expect(page.getByTestId("about-version")).toBeVisible();
  await expect(page.getByRole("link", { name: "Download support bundle" })).toHaveAttribute("href", "/api/v1/settings/support-bundle");
  await a11y(page, "settings-about");

  // --- Branding: administrators only, live contrast check, preview, images, reset ---
  await setNav.getByRole("link", { name: "Branding", exact: true }).click();
  await expect(page).toHaveURL(/\/settings\/branding$/);
  await expect(page).toHaveTitle("Branding · Acme Corp · LibrePatch");
  await expect(page.getByLabel("Organization name")).toHaveValue("Acme Corp");
  await expect(page.getByLabel("Product name")).toHaveValue("");
  await page.getByLabel("Organization name").fill("Example Clinic");
  await page.getByLabel("Product name").fill("PatchBoard");
  await expect(page.getByTestId("preview-org")).toHaveText("Example Clinic");
  await expect(page.getByTestId("preview-product")).toHaveText("PatchBoard");
  // A yellow accent fails WCAG AA (white text on it): the table says so and Save is blocked.
  await page.getByLabel("Accent color").fill("#ffd43b");
  await expect(page.getByTestId("contrast-accent_text_light")).toContainText("Fail");
  await expect(page.getByText(/cannot be saved until they pass the contrast checks/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Save changes" })).toBeDisabled();
  await shot(page, "27-branding-contrast-blocked");
  await page.getByLabel("Accent color").fill("#c92a2a");
  await expect(page.getByTestId("contrast-accent_text_light")).toContainText("Pass");
  await expect(page.getByRole("button", { name: "Save changes" })).toBeEnabled();
  await page.getByLabel("Secondary color (optional)").fill("#e8590c");
  await expect(page.getByTestId("contrast-secondary_ui_dark")).toContainText("Pass");
  await page.getByLabel("Headline").fill("Welcome to Example Clinic IT");
  await page.getByLabel("Welcome message").fill("Sign in with your work account.");
  await page.getByLabel(/^Footer or legal text/).fill("Authorized use only.");
  await page.getByLabel("Support email").fill("help@example.org");
  await page.getByLabel("Support link").fill("javascript:alert(1)");
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByText("The support link must be an https:// address")).toBeVisible(); // the server refuses it too
  await page.getByLabel("Support link").fill("https://example.org/help");
  await expect(page.getByTestId("preview-headline")).toHaveText("Welcome to Example Clinic IT");
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByText("Branding saved.")).toBeVisible();
  await page.mouse.move(0, 0);
  await expect(page.getByTestId("product-name")).toHaveText("PatchBoard");
  await expect(page.getByTestId("org-name")).toHaveText("Example Clinic");
  await expect(page).toHaveTitle("Branding · Example Clinic · PatchBoard");
  // Images: the browser refuses SVG and mismatched shapes; valid ones are applied at once.
  const slot = (k: string) => page.getByTestId(`slot-${k}`);
  await slot("icon").locator('input[type="file"]').setInputFiles({ name: "x.svg", mimeType: "image/svg+xml", buffer: Buffer.from("<svg/>") });
  await expect(slot("icon").getByRole("alert")).toContainText("SVG images are not accepted");
  await slot("icon").locator('input[type="file"]').setInputFiles(fixture("logo.png")); // 220x64 is not square
  await expect(slot("icon").getByRole("alert")).toContainText("needs a square image");
  await slot("icon").locator('input[type="file"]').setInputFiles(fixture("icon.png"));
  await expect(slot("icon").getByRole("img", { name: /current/ })).toBeVisible();
  await slot("favicon").locator('input[type="file"]').setInputFiles(fixture("favicon.png"));
  await expect(slot("favicon").getByRole("img", { name: /current/ })).toBeVisible();
  await slot("logo_light").locator('input[type="file"]').setInputFiles(fixture("logo.png"));
  await page.mouse.move(0, 0);
  await shot(page, "27-branding");
  // The printable report carries the organization name and logo.
  const report = await page.request.get("/api/v1/reports/compliance.html");
  expect(report.status()).toBe(200);
  expect(report.headers()["content-security-policy"]).toContain("default-src 'none'");
  const html = await report.text();
  expect(html).toContain("Example Clinic");
  expect(html).toContain("data:image/png;base64,");
  expect(html).not.toContain("<script");
  // Reset to defaults asks first, then clears everything.
  await page.getByRole("button", { name: "Reset to defaults" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Reset to defaults" }).click();
  await expect(page.getByText("Branding reset to the defaults.")).toBeVisible();
  await page.mouse.move(0, 0);
  await expect(page.getByLabel("Organization name")).toHaveValue("");
  await expect(page.getByTestId("product-name")).toHaveText("LibrePatch");
  await expect(page.getByRole("img", { name: /logo$/ })).toHaveCount(0);
  // What the signed-out sign-in page shows (checked after sign-out below).
  await page.getByLabel("Organization name").fill("Example Clinic");
  await page.getByLabel("Headline").fill("Welcome to Example Clinic IT");
  await page.getByLabel("Welcome message").fill("Sign in with your work account.");
  await page.getByLabel(/^Footer or legal text/).fill("Authorized use only.");
  await page.getByLabel("Support email").fill("help@example.org");
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByText("Branding saved.")).toBeVisible();
  await page.mouse.move(0, 0);
  await slot("logo_light").locator('input[type="file"]').setInputFiles(fixture("logo.png"));
  await expect(slot("logo_light").getByRole("img", { name: /current/ })).toBeVisible();

  // --- Themes: each one applies, is readable (axe, WCAG AA), is applied before the first paint and follows the account ---
  await mainNav(page).getByRole("link", { name: "Style guide", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Style guide", exact: true })).toBeVisible();
  const themeList: [string, string][] = [["light", "Light"], ["slate", "Slate"], ["dark", "Dark"], ["midnight", "Midnight"], ["contrast", "High contrast"]];
  for (const [id, name] of themeList) {
    await openAccountMenu(page);
    await page.getByRole("menuitem", { name, exact: true }).click();
    await page.keyboard.press("Escape");
    await expect(page.locator("html")).toHaveAttribute("data-theme", id);
    await page.mouse.move(0, 0);
    if (shots) await page.screenshot({ path: join(shots, `29-styleguide-${id}.png`), fullPage: true });
    await a11y(page, `styleguide-${id}`);
  }
  // The choice (Midnight) is saved on the account: no copy on this device, and still applied after a reload.
  await openAccountMenu(page);
  await page.getByRole("menuitem", { name: "Midnight", exact: true }).click();
  await page.keyboard.press("Escape");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "midnight");
  await page.evaluate(() => window.localStorage.removeItem("lp-theme"));
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "midnight"); // read back from the account
  // Before first paint: with the app bundle blocked, the theme is already on the page (public/theme-init.js).
  await page.route("**/assets/*.js", (r) => r.abort());
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "midnight");
  await page.unroute("**/assets/*.js");
  await page.reload();
  await expect(page.getByTestId("user-menu")).toBeVisible();
  await openAccountMenu(page);
  await page.getByRole("menuitem", { name: "Light", exact: true }).click();
  await page.keyboard.press("Escape");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");

  // --- Audit log ---
  await mainNav(page).getByRole("link", { name: "Audit log", exact: true }).click();
  await expect(page.getByRole("cell", { name: "setup.complete" })).toBeVisible();
  if (agentBin) await expect(page.getByRole("cell", { name: "device.revoke" })).toBeVisible();
  await expect(page.getByRole("cell", { name: "branding.update" }).first()).toBeVisible();
  await expect(page.getByRole("cell", { name: "branding.reset" })).toBeVisible();
  await page.getByRole("button", { name: "Verify the chain" }).click();
  await expect(page.getByText(/The chain is intact/)).toBeVisible({ timeout: 20_000 });
  await page.getByLabel("Action starts with").fill("user.");
  await page.getByRole("button", { name: "Filter" }).click();
  await expect(page.getByRole("cell", { name: "user.create" })).toBeVisible();
  await expect(page.getByRole("cell", { name: "setup.complete" })).toHaveCount(0);
  await shot(page, "06-audit");

  // --- Sign out ---
  await signOut(page);
  await expect(page).toHaveURL(/\/login$/);
  // The signed-out sign-in page carries the deployment's branding.
  await expect(page.getByTestId("login-headline")).toHaveText("Welcome to Example Clinic IT");
  await expect(page.getByTestId("login-message")).toHaveText("Sign in with your work account.");
  await expect(page.getByTestId("login-footer")).toContainText("Authorized use only.");
  await expect(page.getByRole("link", { name: "help@example.org" })).toHaveAttribute("href", "mailto:help@example.org");
  await expect(page.getByRole("img", { name: "Example Clinic logo" })).toBeVisible();
  await expect(page).toHaveTitle("Sign in · Example Clinic · LibrePatch");
  await shot(page, "28-branded-login");
  // The server also puts the title and favicon in the page itself, before any script runs.
  const shell = await (await page.request.get("/login")).text();
  expect(shell).toContain("<title>Example Clinic · LibrePatch</title>");
  expect(shell).toContain('id="branding-data"');

  expect(violations, "CSP violations").toEqual([]);
  expect(a11yIssues, "accessibility violations (axe, WCAG 2.1 AA)").toEqual([]);
});
