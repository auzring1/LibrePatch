# Fresh install on Windows 11 (server in Docker, agents on Windows)

This guide takes you to a working LibrePatch stack: the server in Docker on a Windows 11 machine, and the agent on that machine and/or other Windows machines or VMs. If you are moving from a build with an earlier product name, follow [RUNBOOK](RUNBOOK.md) section 2a first.

Allow about 60 minutes, most of it waiting for downloads and the first Docker build.

**Terms used below**
- **Server machine:** the Windows 11 PC that runs Docker Desktop.
- **Ubuntu:** the Linux that lives inside Windows (WSL 2). The server steps run there, because the setup script is a bash script and the files must keep Linux permissions.
- **Agent machines:** every Windows machine that should be managed (it can be the server machine itself).

---

## Part 1: Prepare the server machine

Windows 11 (Home or Pro), 8 GB RAM or more, virtualization enabled in the BIOS/UEFI.

1. **WSL 2 with Ubuntu.** PowerShell as Administrator:
   ```powershell
   wsl --install -d Ubuntu
   ```
   Restart if asked, start "Ubuntu" from the Start menu and create a Linux user name and password.
2. **Docker Desktop** from docker.com (use the WSL 2 backend, which is the default). In Docker Desktop → Settings → Resources → **WSL integration**, switch on "Ubuntu" and apply.
3. **Check, inside Ubuntu:**
   ```bash
   docker version        # shows a Client and a Server section
   docker compose version
   sudo apt update && sudo apt install -y unzip openssl
   ```
4. **An authenticator app** on your phone (Microsoft Authenticator, Google Authenticator, 1Password, ...).
5. **Ports.** The console uses 80 and 443, the agents use 8443. Check that nothing else holds them (PowerShell): `netstat -ano | findstr ":443 :80 :8443"`. Windows features such as IIS ("World Wide Web Publishing Service") or other web servers must be stopped, or use other ports (see Troubleshooting).

---

## Part 2: Build and start the server

### 2.1 Get the code into Ubuntu

Download the ZIP of the repository from GitHub (the main branch → Code → Download ZIP) and extract it into **a new, empty location**. Never extract over an older copy. In Ubuntu, replace `YOURNAME` with your Windows user name:

```bash
cd ~
unzip /mnt/c/Users/YOURNAME/Downloads/LibrePatch-main.zip
cd LibrePatch-main                  # use the exact folder name that the ZIP created
```

Keep the project **inside Ubuntu** (`~/...`), not under `/mnt/c/...`. Files on the Windows drive lose their Linux permissions, and the secrets directory needs them.

### 2.2 Choose the server name and put it in the hosts file

The examples use `librepatch.lab`. Pick any name (it does not have to exist in DNS). On the server machine, PowerShell as Administrator:

```powershell
Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "127.0.0.1 librepatch.lab"
```

Every **other** machine that should open the console or run an agent needs the same line in its own hosts file, but with the **server machine's LAN IP** instead of `127.0.0.1` (find it with `ipconfig` on the server machine). A VM on the same PC also uses the server machine's LAN IP, not 127.0.0.1.

### 2.3 Create the settings

In Ubuntu, in the project folder:

```bash
cp deploy/.env.example deploy/.env
sed -i 's/^LIBREPATCH_HOSTNAME=.*/LIBREPATCH_HOSTNAME=librepatch.lab/' deploy/.env
```

Leave `LIBREPATCH_CADDY_TLS=internal` for a lab. If agents will reach the server by IP address instead of the name, also set `LIBREPATCH_GATEWAY_SANS=<the IP>` in `deploy/.env`.

✅ `grep ^LIBREPATCH_HOSTNAME deploy/.env` shows `librepatch.lab`. The database passwords and the master key are created for you when the stack first starts.

### 2.4 Start the stack

```bash
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build
docker compose -f deploy/docker-compose.yml ps -a
```

The first build downloads images and compiles the server and the web console; it takes several minutes.

✅ `server`, `caddy`, `postgres` and `maintenance` show `running`/`healthy` (`maintenance` runs the database migrations, then stays idle).

### 2.5 Read the setup token and trust the lab certificate

```bash
docker compose -f deploy/docker-compose.yml logs server | grep -A2 "setup token"
mkdir -p /mnt/c/Temp
docker compose -f deploy/docker-compose.yml cp caddy:/data/caddy/pki/authorities/local/root.crt /mnt/c/Temp/caddy-root.crt
```

Then PowerShell as Administrator:

```powershell
certutil -addstore -f ROOT C:\Temp\caddy-root.crt
```

This makes Edge and Chrome trust the console (Firefox needs the file imported in its own certificate settings). Caution: this root can vouch for any web site on this machine. Use it for the lab only, and remove it when you decommission the lab.

### 2.6 Open the firewall (only if other machines connect)

PowerShell as Administrator on the server machine:

```powershell
New-NetFirewallRule -DisplayName "LibrePatch console" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow -Profile Private
New-NetFirewallRule -DisplayName "LibrePatch agent gateway" -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow -Profile Private
```

If the network is classed as "Public", change the network profile to Private (Settings → Network & internet → your connection) or use `-Profile Any`.

### 2.7 First-run setup in the browser

1. Open `https://librepatch.lab`. You are sent to **Set up LibrePatch**.
2. Paste the setup token and your email. (A wrong token is rejected: that is expected.)
3. Fill in the organization name, your name and a password of at least 12 characters (common and breached passwords are refused).
4. Enter a **CA root passphrase** of at least 16 characters. **Write it down offline.** The server never stores it.
5. Scan the QR code with your authenticator app and enter the 6-digit code.
6. Save the **recovery codes**, tick the box and continue to sign in.
7. Sign in with email, password and a fresh authenticator code. ✅ You land on **Devices**, showing "No devices yet".

---

## Part 3: Build and install the agent

### 3.1 Build the agent program (no Go installation needed)

In Ubuntu, in the project folder. This compiles the Windows executable inside a throw-away Docker container:

```bash
docker run --rm -v "$PWD":/src -w /src \
  -e CGO_ENABLED=0 -e GOOS=windows -e GOARCH=amd64 \
  golang:1.27-alpine \
  go build -trimpath -ldflags "-s -w" -o /src/librepatch-agent.exe ./cmd/librepatch-agent
ls -l librepatch-agent.exe            # about 15 MB
cp librepatch-agent.exe /mnt/c/Temp/
```

(The first run downloads the Go modules and may fetch the Go 1.27.1 toolchain; it needs internet access.)

For another machine or VM, copy `C:\Temp\librepatch-agent.exe` to it (shared folder, USB stick or network share).

### 3.2 Create the enrollment command

In the console: **Enrollment → New token**. Name `lab`, maximum uses `5`, valid for `24` hours, **approval on**. Click **Create** and copy the install command. It is shown only once and looks like this:

```
librepatch-agent.exe install --server librepatch.lab:8443 --token LP1.eyJ...
```

### 3.3 Install on each agent machine (PowerShell as Administrator)

```powershell
cd C:\Temp
Unblock-File .\librepatch-agent.exe              # removes the "downloaded file" mark; the program is not code-signed yet
.\librepatch-agent.exe install --server librepatch.lab:8443 --token LP1.eyJ...
```

✅ The output ends with "Enrolled; waiting for an administrator to approve device ...". The agent machine must resolve `librepatch.lab` (hosts file, step 3.2) and reach port 8443 on the server machine.

### 3.4 Approve the device

In the console, **Devices**: ✅ the machine appears without refreshing, status **pending**. Open it and click **Approve**. Within about a minute it is **active** and **online**, with hardware inventory.

### 3.5 Check the agent on the machine

```powershell
Get-Service LibrePatchAgent                                                    # Running, display name "LibrePatch Agent"
& "C:\Program Files\LibrePatch\Agent\slot-a\librepatch-agent.exe" status        # state: connected
Get-Content C:\ProgramData\LibrePatch\logs\agent.log -Tail 20
```

✅ The names you see are all LibrePatch: service `LibrePatchAgent`, folders `C:\Program Files\LibrePatch` and `C:\ProgramData\LibrePatch`. The file properties of `librepatch-agent.exe` show company "The LibrePatch contributors" (the vendor) and product "LibrePatch".

---

## Part 4: Back up what cannot be recreated

Do this now, before you put anything of value on the server.

1. Save the **master key** the console showed when you first signed in (a password manager is ideal) and copy `deploy/.env` to a safe place **other than the server machine**. Without the master key the encrypted keys in the database cannot be read. If you did not save it, you can still print it: `docker compose -f deploy/docker-compose.yml exec server /librepatch-server show-master-key`.
2. Keep the **CA root passphrase** and the **recovery codes** offline.
3. Database backups with `maintenance backup` are described in `docs/RUNBOOK.md`, section 6.

---

## Troubleshooting

| Symptom | What to check |
|---|---|
| `docker compose ... up` says a port is already in use | Something else uses 80, 443 or 8443 (`netstat -ano \| findstr :443`; common: IIS, other web servers, VPN software). Stop it, or add `LIBREPATCH_HTTP_PORT=8080`, `LIBREPATCH_HTTPS_PORT=8444` and `LIBREPATCH_PUBLIC_PORT_SUFFIX=:8444` to `deploy/.env`, and use `https://librepatch.lab:8444`. |
| The database container stops with "the database already exists, but its saved passwords ... are missing" | The database volume survived but the `secrets_*` volumes did not. Run `docker compose ... down -v` to start over with an empty database (this deletes its data), or restore the secrets volumes. |
| Browser shows a certificate warning for the console | The Caddy root was not imported (step 3.5), or you opened the page by IP instead of `librepatch.lab`. |
| Console says "Cross-origin request rejected" | The address in the browser must be exactly `https://<LIBREPATCH_HOSTNAME>` (plus the port suffix, if you changed the port). |
| The agent install says it cannot connect / "chain does not match the pinned root" | The agent machine cannot resolve `librepatch.lab` to the server machine (hosts file), port 8443 is blocked (firewall), or a security product intercepts TLS on 8443. |
| The agent connects but the server log says the name is not in the certificate | You enrolled using an IP or another name. Use the name from the install command, or add the IP to `LIBREPATCH_GATEWAY_SANS` and recreate the server (`docker compose ... up -d server`). |
| The server container keeps restarting | `docker compose -f deploy/docker-compose.yml logs server`. A password or database-name error means old data was reused with the new build: stop the stack, run `docker compose ... down -v` (this deletes the database and the generated secrets) and start again. |
| Docker is very slow or runs out of disk | Docker Desktop → Settings → Resources; WSL 2 keeps its disk in a `.vhdx` file that you can shrink after pruning. |
| You lost the master key | If the stack still runs, print it with `show-master-key` (see Part 4). Otherwise the data cannot be decrypted: repeat Parts 1–2 for a fresh server and enroll the machines again. |

## Removing everything again later

- **Agent:** `& "C:\Program Files\LibrePatch\Agent\slot-a\librepatch-agent.exe" uninstall` (elevated PowerShell), then revoke or delete the device in the console. If it was installed from the MSI, uninstall it from Apps instead.
- **Server:** `docker compose -f deploy/docker-compose.yml down -v` deletes the stack and **all its data**; then delete the project folder and remove the Caddy root certificate from Windows (`Get-ChildItem Cert:\LocalMachine\Root | Where-Object Subject -like "*Caddy Local Authority*" | Remove-Item`).
