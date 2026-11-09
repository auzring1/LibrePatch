# Load testing

This document describes the load generator (`cmd/librepatch-loadsim`), which runs up to 10,000 simulated agents against a server, including a reconnect storm: the method, how to run it, what to tune on the host, what to measure and what we measured in a small development sandbox.

**Read the results as "measured in the dev sandbox, not a capacity statement".** The sandbox is a 4-CPU, 15.7 GiB virtual machine on which the server, the load generator and PostgreSQL all run at the same time, over the loopback interface. Real capacity needs a run on separate hosts (section 6).

## 1. What is simulated

Each simulated agent is a goroutine, one TLS connection and a few kilobytes of state. It speaks the real gateway protocol and reuses the agent's own code wherever that is possible:

| Part | Real or simulated |
|---|---|
| Enrollment | Real: token from the enrollment string, a fresh P-256 key, a CSR, the pinned-root TLS check (`core.PinnedTLS`), the same checks on the answer as the agent. The key is a software key held in memory (the real agent uses CNG). |
| Channel | Real: gRPC over TLS 1.3 with the device certificate (`core.MutualTLS`, `core.DialOptions`), `Hello` / `HelloAck`, `GoAway` handling, resync requests. |
| Reconnect | Real: the agent's `core.Backoff` (full jitter, 1 s base, 5 min cap), the 10-minute healthy reset, and "retry hint plus 0 to 30 s" after a server `GoAway`. |
| Inventory | Real protocol, fake data: the agent's own `inventory.Manager` produces the hardware, users and software reports (a full snapshot in 250-item chunks, then revisioned deltas, with acknowledgements and resync). Every agent starts from one shared, read-only fixture of N items (`--inventory-size`). |
| Heartbeats | Real message. A real agent sends one only when something changed or every 30 minutes; the tool sends one every `--heartbeat` (default 1 minute, jittered) as a deliberate stress multiple. The protocol has **no acknowledgement for a heartbeat**, so only the send time can be measured. |
| Jobs | Real: the server signs jobs when it creates them; the agent verifies each envelope with `envelope.Verifier` (signature before parsing, device and organization, validity window, replay ledger), sends `JobUpdate` `ACCEPTED`, then `SUCCEEDED` through an outbox that is resent after a reconnect until acknowledged. An `INVENTORY_FULL` job also triggers an inventory sync and a heartbeat, as in the real agent. Nothing is executed (a `wu_scan` job is a no-op). The tool creates the jobs through the REST API (`POST /devices/{id}/refresh` or `.../windows-updates/scan`) like an operator's script. |
| Not simulated | Windows collectors and CNG/TPM keys, certificate renewal, Windows Update snapshots, installers and content download, the user-context helper, self-update, real heartbeat cadence, many source addresses. |

Nothing in the server is relaxed for the test: no backdoor, no skipped check. The tool needs only what an operator has: an enrollment token and an API token. The one server change made for it is that the enrollment rate limits became configurable (`LIBREPATCH_ENROLL_RATE_PER_IP`, `LIBREPATCH_ENROLL_RATE_PER_TOKEN`).

## 2. Scenarios

* `steady`: ramp `--agents` at `--ramp-per-sec` (enrolling each one for real), wait until 99% are connected **and** their first inventory is acknowledged, then hold for `--duration` with heartbeats, inventory deltas (`--inventory-change-every`) and jobs (`--jobs-fraction`).
* `storm`: as `steady`, hold for `--storm-hold`, then drop every connection at once (`--storm-mode client`) and let each agent reconnect with its own backoff. The tool reports how long the fleet needs to reach 50%, 90%, 99% and 100% connected, the lowest connected count, how many attempts failed and how, then holds `--duration` more to show that it settles. `--storm-mode external` instead waits for you to restart the server (for example `kill -TERM`, then start it again): the clock starts when the connected count falls below 99%. `scripts/loadtest.sh --storm-mode server-restart` does this in local mode. A restart makes the server send `GoAway` with a 15 s retry hint, and the agents add up to 30 s of jitter, so that storm is spread out by design; the `client` mode is the harsh one.
* `churn`: for `--duration`, `--churn-per-sec` random agents per second drop and reconnect, each staying away up to `--churn-away`. It shows the steady cost of agents that come and go (laptops).

A run passes when 99% of the fleet is connected (95% for churn), the hold phases have fewer than 1% connection or protocol failures, the storm recovered to 99%, and every job the tool created completed.

## 3. What is measured

All latencies come from the client's clock, in the same process, and are histograms with about 3% resolution (`internal/loadsim/stats.go`). Each phase (`ramp`, `hold`, `storm`, `after-storm`, `churn`) has its own set.

| Metric | Meaning |
|---|---|
| `enroll` | Dial plus the `Enroll` RPC. Includes waiting for a free enrollment slot on the server. |
| `connect` | `NewClient` until the transport is ready: TCP, TLS 1.3 with the client certificate (the server checks the certificate against the database here), HTTP/2 settings. |
| `stream_open` | Opening the `Connect` stream on a ready transport (the server checks the device again). |
| `handshake` | `Hello` sent until `HelloAck` received. Includes the server's device lookup and its `SetDeviceOnline` write. |
| `ack_hardware`, `ack_inventory_users`, `ack_inventory_snapshot`, `ack_inventory_delta` | Report sent until the server's `Ack`, so a database write round trip. A snapshot is measured from the first chunk. |
| `heartbeat_send` | How long `Send` took. There is no server answer to measure. |
| Jobs: dispatch | REST request started until the agent verified the offer. |
| Jobs: result RTT | The agent sent the result until the server acknowledged it (so it recorded it). |
| Jobs: end to end | REST request started until the result was acknowledged. |
| Storm: `time_to_connected_s` | Seconds after the drop until 50/90/99/100% of the agents hold a stream **opened after the drop**. |
| `fail.*` counters | Failures by stage and class, for example `fail.connect.tls`, `fail.recv.reset`. These are the client's view of what the server refused or dropped. |
| `failed_session_age` | How old a stream was when it failed on its own. A cluster of equal ages points at a timer or a common event. |
| Server's own view | `GET /reports/overview` at the end: online and active devices as the server counts them. |
| Server process | With `--server-pid`: CPU, resident memory, threads and descriptors every 2 s, per phase. |
| PostgreSQL | With `--pg-url`: commits, rows inserted and updated per second, backends, active queries, lock waiters, and the audit entries written. |
| Kernel | `scripts/loadtest.sh` records TCP counters before and after each scenario: listen overflows and drops, aborts on timeout, resets, retransmissions, and packets dropped in the input queue (`softnet`). |

## 4. How to run

### 4.1 One command, local server

```
export LIBREPATCH_TEST_PG_URL='postgres://postgres:PASSWORD@127.0.0.1:5432/postgres?sslmode=disable'   # a superuser; any PostgreSQL 16
scripts/loadtest.sh --agents 1000 --scenarios "steady storm" --duration 2m
```

The script builds the server, the load generator and the bootstrap tool into `loadtest-results/<timestamp>/bin`, creates a fresh database on that PostgreSQL, starts the server binary (dev mode, HTTP on :18080, gateway on :18443, enrollment limits raised for the test), completes first-run setup through the REST API, runs the scenarios and writes `<scenario>.json`, `<scenario>.md`, `summary.md` and `server.log` there. It drops the database when it ends. It needs `psql`, `python3`, `openssl` and Go. `loadtest-results/` is git-ignored: it holds device private keys (`identities.json`) and an API token, so keep it private and delete it when done.

Options: `--agents`, `--scenarios`, `--duration`, `--ramp-per-sec`, `--heartbeat`, `--inventory-size`, `--inventory-change-every`, `--jobs-fraction`, `--storm-mode client|server-restart`, `--out`, `--ports HTTP:GATEWAY`, `--external`. The scenarios run in order on the same fleet identities (the identity cache), so the first one pays for enrollment and the later ones start from enrolled devices; because the simulated agents start without state, every run begins with a full inventory resync, as a fleet whose agents lost their local database would.

### 4.2 Against a server you already run

```
export LOADTEST_API=https://librepatch.example.com       # REST base URL
export LOADTEST_GATEWAY=agents.example.com:8443       # as in the gateway certificate
export LOADTEST_API_TOKEN=...                         # scopes: enrollment:write devices:read devices:write updates:write reports:read
scripts/loadtest.sh --external --agents 10000 --scenarios "steady storm"
```

For docker compose, start the stack as the README says, finish setup in the console, create an API token with those scopes, and use the variables above. This path (compose plus `--external`) is documented but **was not run here**: the sandbox has no Docker daemon. Raise the enrollment limits first (`LIBREPATCH_ENROLL_RATE_PER_IP`, `LIBREPATCH_ENROLL_RATE_PER_TOKEN`, in the compose environment) or enrolling the fleet takes about `agents / 10` minutes; and set the open-file limit of the server container (section 5). Do not point the tool at a production system: it enrolls thousands of devices and writes to the audit log.

### 4.3 The tool directly

```
go build -o librepatch-loadsim ./cmd/librepatch-loadsim
LIBREPATCH_LOADSIM_API_TOKEN=... ./librepatch-loadsim --api http://127.0.0.1:8080 --server localhost:8443 \
  --agents 10000 --ramp-per-sec 100 --scenario storm --identity-cache ids.json --report storm.json --report-md storm.md
```

`--enrollment LP1...` (or `LIBREPATCH_LOADSIM_ENROLLMENT`) uses an existing token; without it the tool mints one through the API. `--identity-cache FILE` keeps the enrolled identities (mode 0600, **contains private keys**), bound to the server's CA, so later runs skip enrollment. Run `./librepatch-loadsim -h` for every flag. The exit status is 2 when the success criteria are not met (`--no-fail` to ignore).

The in-process test `test/e2e/loadsim_test.go` runs 50 agents through the steady, storm and churn scenarios against the same server code in about 40 seconds, and `internal/loadsim/stats_test.go` tests the histogram, counters and recovery clock. Both run in `go test -race ./...`.

## 5. Host tuning for thousands of connections

* **Open files.** Each connection is one descriptor in the server and one in the load generator, plus database and log descriptors. Allow at least `agents + 1000` per process, in the shell that starts it: `ulimit -n 65536` (the hard limit must allow it: `/etc/security/limits.conf`, or `LimitNOFILE=65536` in a systemd unit). The sandbox allowed 20,000, which is why 10,000 agents is about the most it can hold per process. In docker compose set `ulimits: nofile: {soft: 65536, hard: 65536}` on the server service; `deploy/docker-compose.yml` does not set one today, and the default depends on the Docker installation. Go raises its own soft limit to the hard limit at start-up.
* **Ephemeral ports.** A load generator on one address can hold at most about 28,000 connections to one server address and port (`net.ipv4.ip_local_port_range`, default 32768-60999). A storm closes and reopens every connection, and closed sockets stay in TIME_WAIT for a minute, so 10,000 agents is the practical limit for one source address. Widen the range (`net.ipv4.ip_local_port_range="1024 65535"`), or generate load from several hosts or addresses.
* **Input queue.** If you run the load generator and the server on one host, set `net.core.netdev_max_backlog` well above its default of 1000 (the sandbox storm used 65536). With the default, the loopback input queue overflowed during a 10,000-agent storm, and the kernel then reset 250 to 1,700 established connections 30 to 70 seconds later (section 7). Across a real network, check the same counter on the server (`/proc/net/softnet_stat`).
* **Accept queue.** `net.core.somaxconn` (4096 in the sandbox) and `net.ipv4.tcp_max_syn_backlog` bound the connections waiting to be accepted; the script's `ListenOverflows`/`ListenDrops` lines tell you if they were exceeded (they were not).
* **Connection tracking.** A firewall or NAT between the fleet and the server needs a connection table for every agent (`net.netfilter.nf_conntrack_max`) and an idle timeout above the 90-second gRPC keepalive.
* **PostgreSQL.** The server's pool is fixed at 32 connections (`internal/server/store`); keep `max_connections` comfortably above that (and above any other users). The database in the sandbox ran with default settings (128 MB shared buffers, WAL on the same disk).
* **CPU and memory.** Expect roughly 150 to 200 KB of server memory per connected agent in this build (section 7) plus the base process, and about the same in the load generator. Give the two processes separate cores; `GOMAXPROCS` defaults to all of them.
* **Load generator placement.** For a capacity number, run the generator on one or more other hosts, with the server on the hardware you will use, and PostgreSQL where you will run it.

## 6. How to fill in a result table for your environment

Record the environment first (CPUs, RAM, kernel, PostgreSQL version and settings, open-file limit, whether the generator shares the host), then one row per run. `summary.md` has all the numbers.

| Run | Agents | Ramp to 99% (s) | connect p50 / p99 (ms) | handshake p50 / p99 (ms) | ack delta p50 / p99 (ms) | job end to end p50 / p99 (ms) | Storm: s to 99% | Failed attempts in the storm | Server CPU avg / peak (%) | Server RSS (MB) | DB commits/s avg / peak |
|---|---:|---:|---|---|---|---|---:|---:|---|---:|---|
| steady | | | | | | | | | | | |
| storm | | | | | | | | | | | |
| churn | | | | | | | | | | | |

## 7. Results from the development sandbox, in brief

**Not a capacity statement.** 4 vCPUs, 15.7 GiB RAM, PostgreSQL 16 with default settings, and the server, the load generator
and PostgreSQL all on the same machine over loopback. Every simulated agent had 120 software items.

| | Measured |
|---|---|
| 10,000 agents, steady state | Pass. 99% connected in about 106 s, limited by enrollment, not by connections. No jobs lost. |
| Enrollment throughput | About 70 to 95 devices per second at most. Enrollments are serialized by the token row lock and the audit-chain lock, and at most 8 run at once. |
| Reconnect storm (every connection dropped at once) | Pass. About 380 reconnects per second: 1,000 agents back in 2.7 s, 10,000 in about 26 s, 5,000 in 12 s. Some handshakes time out after 15 s and retry; all agents come back. |
| Server memory | About 155 KB per connected agent after D117 (about 800 MB at 5,000 agents), plus the base process. |
| Job end to end (API request to result acknowledged) | About 60 ms median, about 100 to 130 ms at p99, at 5,000 agents. |
| Console pages at 5,000 devices | Devices, dashboard and reports under 40 ms; the software and software-updates lists 0.3 to 0.7 s, and several seconds when most programs have an update (the answer itself is large). |
| Message sizes | A heartbeat is 35 bytes and a first full software snapshot of 120 items about 31 KB, so steady state sends almost nothing. |

The load test found and fixed three server problems: deadlocks when many devices sent the same software at once, enrollment
bursts starving TLS handshakes of database connections, and enrollment rate limits that could not be changed. Later passes
cut memory per connection and database work per reconnect (decision D116 to D118). Open points, such as a bounded handshake
queue for very large storms, are still open.

Still to do before trusting a number for your site: run section 4.2 against the real stack and network with the generator on
another host, run a soak of several hours, and repeat the 10,000-agent run with the current build.

## 8. Known gaps of the tool

* One process and one source address; no per-agent source addresses, no network impairment (latency, loss), no TLS inspection or proxy.
* Software keys and in-memory state; certificates are not renewed during a run (a run is shorter than a third of a certificate's life; the identity cache skips certificates that expire within an hour).
* Inventory is the same fixture for everyone, so the server's title table stays small (120 titles) and the per-device item count is fixed; real fleets have more variety. Deltas change 3 items.
* Heartbeats have no acknowledgement in the protocol, so no round trip is measured for them.
* Windows Update snapshots and content downloads are not exercised, and the `wu_scan` jobs are no-ops.
* The REST API is exercised only for tokens, job creation and the overview; the console's own load (SSE streams, device lists with 10,000 rows) is not tested.
* The server-process and PostgreSQL samplers need the same host (`--server-pid`, `--pg-url`); the kernel counters in the script cover the whole host.
