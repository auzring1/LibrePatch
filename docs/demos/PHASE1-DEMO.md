# Phase 1 demo script

Goal: from a clean machine, stand up the server with `docker compose`, complete setup with MFA, enroll a fresh Windows VM, watch it appear live with hardware inventory, revoke it, and confirm it is cut off. Allow about 30 minutes.

## You need
- **Server host:** any Linux machine or VM with Docker Engine 24+ and Compose v2, git and openssl. The Windows VM must be able to reach it on 443 and 8443.
- **Windows test VM:** Windows 10 1809+, Windows 11 or Server 2019+, x64, freshly installed, with a local administrator account.
- **Build machine for the agent:** any OS with Go 1.27 (the server host is fine).
- An authenticator app on your phone (Microsoft Authenticator, 1Password, Google Authenticator, ...).

The examples below use the server name `librepatch.lab`. Use a real DNS name, or add `<server-ip> librepatch.lab` to `C:\Windows\System32\drivers\etc\hosts` on the VM and to the hosts file of the machine running your browser.

---

## Part A: Server (about 10 minutes)

1. **Get the code and create secrets.**
   ```bash
   git clone -b phase-1 https://github.com/auzring1/librepatch.git && cd current
   cp deploy/.env.example deploy/.env
   sed -i 's/^LIBREPATCH_HOSTNAME=.*/LIBREPATCH_HOSTNAME=librepatch.lab/' deploy/.env      # keep LIBREPATCH_CADDY_TLS=internal for a lab
   ```
   ✅ `deploy/.env` has your host name. (Passwords and the master key are created when the stack first starts.)

2. **Start the stack** (the first build takes a few minutes).
   ```bash
   docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build
   docker compose -f deploy/docker-compose.yml ps
   ```
   ✅ `caddy`, `server` and `postgres` are all `healthy`/`running`. `postgres` has **no** published port.

3. **Read the one-time setup token.**
   ```bash
   docker compose -f deploy/docker-compose.yml logs server | grep -A2 "setup token"
   ```

4. **Trust the lab certificate in your browser** (only needed with `LIBREPATCH_CADDY_TLS=internal`).
   ```bash
   docker compose -f deploy/docker-compose.yml cp caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
   ```
   Import `caddy-root.crt` into your browser or OS trust store. If you skip this, accept the browser warning for the lab.

## Part B: First-run setup and sign-in (about 5 minutes)

5. Open `https://librepatch.lab`. ✅ You are redirected to **Set up LibrePatch**.
6. Paste the setup token and your email, then click **Continue**.
   - 🔒 *Check:* a wrong token gives "The setup token is not valid".
7. Fill in the organization, your name and a password.
   - 🔒 *Check:* try `password123456` first. It is rejected as a breached password.
8. Enter a CA root passphrase (16+ characters) and **write it down offline**.
9. Scan the QR code, enter the 6-digit code, then click **Create organization**.
10. Save the recovery codes, tick the box, and click **Continue to sign in**.
11. Sign in with email, password and a fresh authenticator code. ✅ You land on **Devices**, which shows "No devices yet".
    - 🔒 *Check:* reusing the exact code you just used, within the same 30 seconds, is rejected (replay protection).

## Part C: Build the agent (about 2 minutes)

12. On the build machine:
    ```bash
    GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o librepatch-agent.exe ./cmd/librepatch-agent
    ls -l librepatch-agent.exe     # about 13 MB at the time of Phase 1 (budget now: 17 MiB)
    ```
    Copy `librepatch-agent.exe` to the Windows VM, for example to `C:\Temp`.
    > Phase 1 binaries are **not Authenticode-signed** yet (Phase 5), so SmartScreen may warn. Use **Unblock** in the file's Properties dialog.

## Part D: Enroll the Windows VM (about 5 minutes)

13. In the console, go to **Enrollment**, then **New token**. Use name `demo`, max uses `5`, valid for `24` hours, approval **on**. Click **Create** and copy the install command.
14. On the VM, open **PowerShell as Administrator**:
    ```powershell
    cd C:\Temp
    .\librepatch-agent.exe install --server librepatch.lab:8443 --token LP1.....
    ```
    ✅ The output ends with "Enrolled; waiting for an administrator to approve device ...".
15. In the console under **Devices**, ✅ the VM appears **without refreshing the page**, with status **pending**. Click it, then **Approve**.
16. Within about a minute, ✅ the device is **active** and **online**. Click it to see the OS and build, manufacturer and model, serial, CPU, memory, disks, network interfaces and logged-on user, plus the client certificate (90-day validity).
17. On the VM:
    ```powershell
    & "C:\Program Files\LibrePatch\Agent\slot-a\librepatch-agent.exe" status          # state: connected
    Get-Service LibrePatchAgent                                                      # Running
    (Get-Acl C:\ProgramData\LibrePatch).Access | ft IdentityReference,FileSystemRights   # only SYSTEM + Administrators
    Get-Content C:\ProgramData\LibrePatch\config.json                                # NO enrollment_token any more
    Get-NetTCPConnection -State Listen | ? OwningProcess -eq (Get-CimInstance Win32_Service -Filter "Name='LibrePatchAgent'").ProcessId   # nothing: no listening ports
    Get-Process -Id (Get-CimInstance Win32_Service -Filter "Name='LibrePatchAgent'").ProcessId | Select WS   # working set (target < 30 MB)
    certutil -csp "Microsoft Platform Crypto Provider" -key 2>$null | Select-String LibrePatch          # device key in the TPM, if the VM has a vTPM
    certutil -csp "Microsoft Software Key Storage Provider" -key 2>$null | Select-String LibrePatch     # otherwise here (non-exportable)
    ```
    - 🔒 *Check:* as a **standard (non-admin) user**, `Stop-Service LibrePatchAgent` is denied, and `Get-ChildItem C:\ProgramData\LibrePatch` is denied.

## Part E: Live status, revocation and audit (about 5 minutes)

18. **Live offline/online:** on the VM, run `Restart-Service LibrePatchAgent`. ✅ In the console the device goes **offline**, then **online** again within seconds.
19. **Re-enrollment protection (optional):** run `.\librepatch-agent.exe uninstall`, then `install` again with the same token. ✅ The new enrollment is **pending** and says it re-enrolls known hardware. Approving it revokes the old identity.
20. **Revoke:** in the console, open the device, click **Revoke**, enter the reason "demo", and confirm.
    ✅ Within a second the device shows **revoked** and **offline**.
    ✅ On the VM, `librepatch-agent.exe status` shows `rejected`: "This device was revoked by an administrator."
    ✅ The agent log `C:\ProgramData\LibrePatch\logs\agent.log` shows `"reason":"revoked"`, and the agent does not reconnect.
21. **Audit:** open the **Audit log**. ✅ It shows `setup.complete`, `auth.login`, `enrollment_token.create`, `device.enroll`, `device.approve`, `device.certificate_issue` and `device.revoke`, with actor, IP and time.
    ```bash
    docker compose -f deploy/docker-compose.yml exec server /librepatch-server admin verify-audit
    # -> audit chain intact: N entries verified
    ```
22. **Clean up the VM:** run `.\librepatch-agent.exe uninstall`. ✅ The service is gone, `C:\ProgramData\LibrePatch` is gone, and the device key is deleted.

## Optional security spot checks
- `curl -sI https://librepatch.lab/ --cacert caddy-root.crt` shows the `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options: DENY` and `X-Content-Type-Options` headers.
- `docker compose -f deploy/docker-compose.yml exec server id` fails, because the distroless image has no shell. `docker inspect` shows `ReadonlyRootfs=true`, `CapDrop=[ALL]` and user `65532`.
- Sign in with a wrong password 10 times: the account locks for 15 minutes (audited as `auth.lockout`). Clear it with `exec server /librepatch-server admin unlock --email ...`.
