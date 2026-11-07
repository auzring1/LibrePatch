# Try LibrePatch on a test VM

This guide stands up a LibrePatch server, enrolls one Windows test machine and walks through the main features, including the
agent updating itself. Use a machine you can throw away or revert (a VM snapshot), not a production PC. Allow about an hour
for the core steps.

For a real installation use the [RUNBOOK](RUNBOOK.md). For a server in Docker Desktop on Windows 11, see
[FRESH-INSTALL-WINDOWS.md](FRESH-INSTALL-WINDOWS.md).

## You need

- **Server host:** any Linux machine or VM with Docker Engine 24+ and Compose v2, git and openssl. The Windows VM must reach it
  on 443 and 8443.
- **Windows test VM:** Windows 10 1809+, Windows 11 or Server 2019+, x64, with a local administrator account.
- **Build machine for the agent:** any OS with the Go version from `go.mod` (the server host is fine).
- An authenticator app on your phone.

The examples use the server name `librepatch.lab`. Use a real DNS name, or add `<server-ip> librepatch.lab` to the hosts file
(`C:\Windows\System32\drivers\etc\hosts`) on the VM and on the machine running your browser.

## 1. Start the server

```bash
git clone https://github.com/auzring1/librepatch.git && cd librepatch
cp deploy/.env.example deploy/.env
sed -i 's/^LIBREPATCH_HOSTNAME=.*/LIBREPATCH_HOSTNAME=librepatch.lab/' deploy/.env   # keep LIBREPATCH_CADDY_TLS=internal for a lab
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build
docker compose -f deploy/docker-compose.yml logs server | grep -A2 "setup token"
```

With `LIBREPATCH_CADDY_TLS=internal`, copy the lab certificate out and import it into your browser or OS trust store (or accept
the browser warning):

```bash
docker compose -f deploy/docker-compose.yml cp caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
```

## 2. First-run setup

Open `https://librepatch.lab`, paste the setup token, and follow the wizard: organization, your account, a CA root passphrase
(write it down offline) and the authenticator code. Save the recovery codes. When you first sign in, the console shows the
**master key**: save it somewhere other than the server.

## 3. Build and enroll the agent

```bash
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o librepatch-agent.exe ./cmd/librepatch-agent
```

Copy `librepatch-agent.exe` to `C:\Temp` on the VM. The file is not Authenticode-signed, so use **Unblock** in its Properties
dialog if SmartScreen warns. In the console, create a token under **Enrollment → New token** and copy the install command. On the
VM, in PowerShell as Administrator:

```powershell
cd C:\Temp
.\librepatch-agent.exe install --server librepatch.lab:8443 --token LP1.....
```

The device appears under **Devices** as **pending** without a page refresh. Approve it, and within about a minute it is
**online** with its hardware and software inventory. On the VM, `& "C:\Program Files\LibrePatch\Agent\slot-a\librepatch-agent.exe" status`
should say `connected`.

## 4. Things to try

- **Live status:** `Restart-Service LibrePatchAgent` on the VM. The device goes offline and back online within seconds.
- **Software:** import a package under **Catalog**, install it on the device, then update and uninstall it. Watch the
  job's progress live on the device's **Jobs** tab.
- **Windows updates:** run a scan from the device page, approve an update and install it. Set up rings with a
  maintenance window and a restart policy under **Windows updates → Rings, rules and sources**.
- **Access:** create a second user with the operator or read-only role, limited to one site, and check what they can and cannot see.
- **Backup:** take an encrypted backup and restore it into a fresh stack, as described in the [RUNBOOK](RUNBOOK.md) backup section.
- **Audit:** open **Audit log**, then verify the hash chain:
  `docker compose -f deploy/docker-compose.yml exec server /librepatch-server admin verify-audit`.
- **Revoke:** open the device, click **Revoke**. The device goes offline at once and `librepatch-agent.exe status` on the VM says
  it was revoked.

## 5. Agent self-update and rollback

This shows the agent installing a newer signed release of itself, and rolling itself back from a broken one.

1. **Build demo releases.** `scripts/release-demo.sh` makes a throw-away release key in `dist-demo/` (git-ignored) and three
   agents: 0.9.0 (install first), 0.9.1 (good) and 0.9.2 (deliberately broken), plus signed `.lprel` bundles for 0.9.1 and
   0.9.2. It prints a line `LIBREPATCH_RELEASE_PUBLIC_KEYS=<hex>`: add it to `deploy/.env` and recreate the server with
   `docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d server`. **Never use the demo key for real machines.**
2. **Install 0.9.0.** Uninstall any earlier agent on the VM, then install `librepatch-agent-0.9.0.exe` with a fresh token as in
   step 3. The device page shows version 0.9.0.
3. **Publish 0.9.1.** On the **Settings → Agent updates** page, use **Upload a release** to upload `librepatch-agent-0.9.1.exe` with its `.lprel`. An
   `.exe` paired with the wrong `.lprel`, or an edited `.lprel`, is refused. Make 0.9.1 the target release. Within about a minute
   the device runs an "Update the agent" job, the service restarts once, and the device shows 0.9.1.
4. **Roll back from a broken release.** To shorten the wait, set `"update_rollback_minutes": 2` in
   `C:\ProgramData\LibrePatch\config.json` and restart the service. Upload 0.9.2 and make it the target. It starts but never
   connects; about two minutes later the scheduled task `\LibrePatch\rollback-check` puts 0.9.1 back, the device is online again
   on 0.9.1, and the job ends **failed: did not become healthy**. Withdraw the 0.9.2 release afterwards.

If something fails on Windows, keep `C:\ProgramData\LibrePatch\logs\agent.log` and `rollback-check.log` and open an issue.

## 6. Clean up

On the VM, `& "C:\Program Files\LibrePatch\Agent\slot-a\librepatch-agent.exe" uninstall` removes the service, its files and the
device key. On the server host, `docker compose -f deploy/docker-compose.yml down -v` deletes the stack and **all its data**.
