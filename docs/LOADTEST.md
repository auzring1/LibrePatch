# Load testing

Phase 6 asks for a load test with 10,000 simulated agents, including a reconnect storm. This document describes the tool (`cmd/librepatch-loadsim`), the method, how to run it, what to tune on the host, what to measure, what we measured in a small development sandbox, and the server defects the tool found.

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

Nothing in the server is relaxed for the test: no backdoor, no skipped check. The tool needs only what an operator has: an enrollment token and an API token. The one server change made for it is that the enrollment rate limits became configurable (section 8).

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
* **Input queue.** If you run the load generator and the server on one host, set `net.core.netdev_max_backlog` well above its default of 1000 (the sandbox storm used 65536). With the default, the loopback input queue overflowed during a 10,000-agent storm, and the kernel then reset 250 to 1,700 established connections 30 to 70 seconds later (section 7.3). Across a real network, check the same counter on the server (`/proc/net/softnet_stat`).
* **Accept queue.** `net.core.somaxconn` (4096 in the sandbox) and `net.ipv4.tcp_max_syn_backlog` bound the connections waiting to be accepted; the script's `ListenOverflows`/`ListenDrops` lines tell you if they were exceeded (they were not).
* **Connection tracking.** A firewall or NAT between the fleet and the server needs a connection table for every agent (`net.netfilter.nf_conntrack_max`) and an idle timeout above the 90-second gRPC keepalive.
* **PostgreSQL.** The server's pool is fixed at 32 connections (`internal/server/store`); keep `max_connections` comfortably above that (and above any other users). The database in the sandbox ran with default settings (128 MB shared buffers, WAL on the same disk).
* **CPU and memory.** Expect roughly 200 KB of server memory per connected agent in this build (section 7.1) plus the base process, and about the same in the load generator. Give the two processes separate cores; `GOMAXPROCS` defaults to all of them.
* **Load generator placement.** For a capacity number, run the generator on one or more other hosts, with the server on the hardware you will use, and PostgreSQL where you will run it.

## 6. How to fill in a result table for your environment

Record the environment first (CPUs, RAM, kernel, PostgreSQL version and settings, open-file limit, whether the generator shares the host), then one row per run. `summary.md` has all the numbers.

| Run | Agents | Ramp to 99% (s) | connect p50 / p99 (ms) | handshake p50 / p99 (ms) | ack delta p50 / p99 (ms) | job end to end p50 / p99 (ms) | Storm: s to 99% | Failed attempts in the storm | Server CPU avg / peak (%) | Server RSS (MB) | DB commits/s avg / peak |
|---|---:|---:|---|---|---|---|---:|---:|---|---:|---|
| steady | | | | | | | | | | | |
| storm | | | | | | | | | | | |
| churn | | | | | | | | | | | |

## 7. Results from the development sandbox

**Not a capacity statement.** 4 vCPUs, 15.7 GiB RAM, Linux 6.18, PostgreSQL 16.15 with default settings on the same machine, open-file limit 20,000, Go 1.27.1. The server (`librepatch-server serve`, dev mode, log level info), the load generator and PostgreSQL competed for the same four CPUs. Every simulated agent had 120 software items; heartbeats every 60 s; each agent changed 3 items about every 2 minutes; jobs for 1% of the fleet every 30 s (`inventory` kind; the server's own scheduler also queued a `wu_scan` job per device on its first connection). Ramp 100 agents per second. `netdev_max_backlog` was the default 1000 unless stated. Code at the commit that contains this file. Raw reports are not committed.

### 7.1 Steady state

| | 1,000 agents | 10,000 agents |
|---|---:|---:|
| Result | pass | pass |
| Ramp: 99% connected / first inventory acknowledged | 10.6 s / 10.8 s | 106 s / 108 s |
| Enrollments per second during the ramp | about 94 | about 94 (68 to 94 over five runs) |
| connect p50 / p99 (ms) | 15 / 45 | 14 / 49 |
| handshake (Hello to HelloAck) p50 / p99 (ms) | 10 / 35 | 10 / 39 |
| ack of the first software snapshot p50 / p99 (ms) | 31 / 74 | 30 / 87 |
| ack of a delta, hold phase p50 / p99 (ms) | 4.1 / 11.4 | 3.8 / 9.3 |
| heartbeat `Send` p50 / p99 (ms) | 0.05 / 0.15 | 0.03 / 0.11 |
| Jobs: created / completed / lost | 43 / 43 / 0 | 417 / 417 / 0 |
| Job dispatch p50 / p95 (ms) | 21 / 42 | 5.8 / 44 |
| Job result RTT p50 / p95 (ms) | 2.5 / 4.1 | 2.2 / 4.2 |
| Job end to end p50 / p95 / p99 (ms) | 77 / 104 / 110 | 62 / 104 / 121 |
| Server CPU, ramp avg / peak (% of one core) | 159 / 170 | 151 / 173 |
| Server CPU, hold avg / peak (%) | 4 / 55 | 28 / 115 |
| Server resident memory (hold) | 229 MB | 2.0 GB |
| Server descriptors | 1,039 | 10,057 |
| Load generator resident memory / goroutines | 200 MB / 9,028 | 2.1 GB / 90,039 |
| PostgreSQL commits per second, ramp avg / peak | 1,164 / 1,236 | 1,367 / 1,557 |
| PostgreSQL rows inserted per second, ramp | 10,251 | 11,630 |
| PostgreSQL commits per second, hold avg / peak | 71 / 372 | 341 / 814 |
| Server's own count at the end | 1,000 online of 1,000 | 10,000 online of 10,000 |

The 10,000-agent ramp is limited by enrollment (section 7.4), not by connections: it is about 10 times the 1,000-agent ramp, at the same 100 per second request rate. Server memory grows by about 200 KB per connected agent (229 MB to 2.0 GB over 9,000 agents) and the simulated agents cost about the same. The 10,000-agent steady and storm runs in this table were made with `net.core.netdev_max_backlog` raised to 65536 (section 7.3); the 1,000-agent runs used the default.

### 7.2 Reconnect storm (every connection dropped at once, real backoff)

| | 1,000 agents | 10,000 agents |
|---|---:|---:|
| Time until 50% / 90% / 99% / 100% connected | 2.5 / 2.7 / 2.7 / 2.7 s | 24.4 / 25.8 / 26.0 / 26.3 s |
| Lowest connected count after the drop | 0 | 82 |
| Reconnect attempts / failed attempts | 1,000 / 0 | 13,104 / 3,104 |
| Failed attempts by class | none | TLS handshake 2,976, EOF 114, reset 14 |
| connect p50 / p99 (ms) | 981 / 1,762 | 7,583 / 11,945 |
| handshake p50 / p99 (ms) | 747 / 1,359 | 7,852 / 21,206 |
| Server CPU during the storm, avg / peak (% of one core) | 136 / 136 | 171 / 230 |
| PostgreSQL commits per second during the storm, avg / peak | (phase shorter than the 5 s sample) | 1,969 / 4,813 |
| Rejections or rate limiting by the server | none | none logged (see below) |
| Jobs created just before the drop, dispatch p50 / p95 | 24 ms / 2.6 s | 6 ms / 4.9 s (p99 30 s) |
| After the storm | stable | stable |
| Result | pass | pass |

* The fleet reconnected at about **380 connections per second in both runs** (1,000 in 2.7 s, 10,000 in 26 s), so recovery time grows linearly with fleet size on this hardware.
* "Failed attempts" are connections that did not complete: the agent backed off and tried again, and all of them eventually did. The server logged no warning or error for them and no rate limiter is involved in a reconnect (the gateway has none for established devices): thousands of TLS handshakes, each followed by several database lookups, cannot finish within the server's 15-second connection timeout when they all arrive within one or two seconds (the agent's first retry delay is a random time up to 1 s). Handshake latency in the storm was 7.9 s at the median and 21 s at p99 (section 7.4, item 6).
* Eight 10,000-agent storms were run during development, with slightly different builds. Time to 99% was 23.1 to 32.2 s in all of them; failed attempts were 1,000 to 5,500. The 1,000-agent storm recovered in 2.7 to 5.2 s in the four runs.
* A storm after a **server restart** (`--storm-mode server-restart`) was implemented but not run for this table.

### 7.3 Kernel resets in the 10,000-agent storm (environment artifact, explained)

With the default `net.core.netdev_max_backlog` of 1000, all six 10,000-agent storms showed between 250 and 1,700 sessions that had been re-established during the storm being reset ("connection reset by peer") 30 to 70 seconds later, in groups, with nothing logged by the server (the last such run: 951 resets, recovery to 99% in 25.7 s). The kernel counter `TCPAbortOnTimeout` was exactly equal to the number of resets, `/proc/net/softnet_stat` showed packets dropped by the loopback input queue, and gRPC sets `TCP_USER_TIMEOUT` to its 20-second keepalive timeout, so a connection whose data stays unacknowledged for 20 s is aborted. With `net.core.netdev_max_backlog` raised to 65536 the two storms that were run (the table above, and one more) showed **no** `TCPAbortOnTimeout`, no resets and recovered in 26.0 and 23.1 s. It did not happen with 1,000 or 3,000 agents. So this is a property of running both ends on one host under CPU saturation, not of the server. On a real network the equivalent is a saturated NIC queue or middlebox; check the same counters on the server before concluding anything (`scripts/loadtest.sh` prints them).

### 7.4 Bottlenecks and defects found

Fixed, with a test each:

1. **Deadlocks in concurrent inventory ingest (server bug).** Every software snapshot upserted the device's titles with `INSERT ... ON CONFLICT DO UPDATE` in map-iteration (random) order, which locks every title the device has until commit. Devices with common software (every Windows machine has the same few hundred titles) that sent inventory at the same time deadlocked ("deadlock detected", SQLSTATE 40P01) and, when the lock waits were long, hit the statement timeout; the stream was closed with an error and the agent reconnected and resent. It appeared with only 50 agents. Titles are now created with `ON CONFLICT DO NOTHING` in sorted order and read back by a second statement, so a device that only references existing titles takes no lock on them. Test: `TestConcurrentSnapshotsOfCommonSoftwareDoNotDeadlock` (24 devices, 60 shared titles). Files: `db/queries/software.sql`, `internal/server/inventory/ingest.go`.
2. **An enrollment burst starved the mTLS handshakes of database connections (server bug).** Enrollment holds a transaction that waits for the enrollment-token row lock and for the audit-chain lock, so enrollments run one at a time anyway, but each one held one of the pool's 32 database connections while waiting. With 10,000 devices enrolling at 100 per second the pool was fully occupied by enrollments, every mTLS handshake (which looks the device up in the database, with a 5 s timeout) failed, and all agents retried. Before the fix the 10,000-agent steady run could not finish its ramp in 6 minutes (9,797 connected; 73,134 connection attempts, 63,336 of them failed TLS handshakes). At most 8 enrollment transactions now run at the same time (`gate` in `internal/server/gateway/gate.go`, test `TestGate*`); the others wait for a slot. After the fix the ramp finished in 106 to 147 s with no failed attempts, at the cost of long `enroll` latencies for the queued devices (p50 up to 22 s and p99 up to 39 s at 10,000 in some runs; an agent waits up to its 60 s call timeout and retries).
3. **Enrollment rate limits could not be changed although the protocol document said they could.** 10 enrollments per minute per source address and 60 per token (burst the same) were hard-coded, so enrolling a fleet from one NAT address takes `devices / 10` minutes (100 minutes for 1,000). They are now `LIBREPATCH_ENROLL_RATE_PER_IP` and `LIBREPATCH_ENROLL_RATE_PER_TOKEN` (attempts per minute, defaults unchanged at 10 and 60, test in `internal/server/config`). This is an operator setting, not a test backdoor; the test server raises it, nothing else is relaxed. The runbook says when to raise it.

Not fixed (design or larger changes), for the owner to decide:

4. **Enrollment throughput is about 70 to 95 devices per second at most**, with the 8-slot gate. Each enrollment locks the token row (`FOR UPDATE`, held to commit) and takes the global audit-chain advisory lock (for the `device.enroll` entry), so they serialize. Splitting a rollout over several tokens avoids only the first. Not isolated which of the two dominates.
5. **Database work per connection.** One connect costs at least nine round trips, three of them writes: the device-certificate and device lookups run in the TLS handshake and again for the stream (four reads), then `GetDevice`, `SetDeviceOnline`, `RevokeSupersededCerts`, the job dispatcher's queries, and `SetDeviceOffline` on disconnect. The storm drove PostgreSQL to about 2,000 commits per second on average and 4,800 at peak. Reusing the handshake's lookup for the stream of the same connection, or not revoking superseded certificates on every connect, would remove about half of it; but the "no cache" rule for revocation (PROTOCOL §7) is deliberate, so this is a design decision.
6. **The 15-second connection timeout turns a slow storm into a retry storm.** `grpc.ConnectionTimeout(15 s)` closes connections whose TLS handshake and HTTP/2 setup have not finished in 15 s; with 10,000 handshakes arriving at once, handshake latency is 10 to 20 s, so about 25% of the attempts are cut off and come back, which is extra work at the worst moment. A bounded number of concurrent handshakes (queueing instead of everyone being slow together) or a longer timeout would help; a naive limiter around the handshake would let idle connections hold all the slots, so it needs care. The agent's first retry delay (a random time up to 1 s) also puts a whole fleet's reconnects into about one second after a network blip; after a server restart the agents are spread over 15 to 45 s by the `GoAway` hint.
7. **Database pool of 32 connections is fixed.** At 10,000 agents with 60-second heartbeats the pool was never the limit after fix 2 (lock waiters at most 7 in the ramp, none in the hold), but it caps parallelism during storms.
8. **Heartbeats cost one autocommit `UPDATE` plus an event publication each.** At the real cadence (a heartbeat only when something changed or every 30 minutes) 10,000 agents produce about 6 per second; the test's 60-second cadence produced 167 per second and was easily absorbed (hold phase: server CPU 28% of one core on average, 341 commits per second including inventory deltas and jobs).
9. **Memory is about 200 KB per connected agent** in the server, mostly per-connection buffers and goroutines (two goroutines plus the transport's own). 10,000 agents need about 2 GB; 50,000 would need about 10 GB on this build.

### 7.5 What 10,000 meant here, and what was not reached

10,000 simulated agents did run, from one process, on one host: steady (pass) and storm (pass, with the kernel setting of 7.3). Limits met: the open-file limit of 20,000 per process (about 10,000 agents), the ephemeral port range (about 28,000 per source address; a storm needs the old sockets in TIME_WAIT as well) and the shared four CPUs. More than 10,000 agents was not tried. Nothing was run against docker compose, over a real network, with a separate load-generator host, with a least-privilege database role (the sandbox server used the superuser, as `scripts/gui-e2e.sh` does) or with TLS in front of the REST API.

## 8. Changes made to the product by this work

| Change | Why | Tested by |
|---|---|---|
| Software titles inserted with `DO NOTHING` in sorted order (`db/queries/software.sql`, `internal/server/inventory/ingest.go`) | Deadlocks and lock queueing between devices | `TestConcurrentSnapshotsOfCommonSoftwareDoNotDeadlock` |
| Enrollment gate of 8 transactions (`internal/server/gateway/gate.go`, `enroll.go`) | Enrollment bursts starved handshakes of database connections | `TestGateBoundsConcurrency`, `TestGateGivesUpWhenTheContextEnds`, `TestLoadsim*` |
| `LIBREPATCH_ENROLL_RATE_PER_IP`, `LIBREPATCH_ENROLL_RATE_PER_TOKEN` (`internal/server/config`) | Limits were hard-coded; defaults unchanged | `TestEnrollRateLimits*` |
| `core.PinnedTLS`, `core.MutualTLS`, `core.DialOptions` exported (`internal/agent/core`) | The load generator uses the agent's own trust and dial settings; no behaviour change | existing agent tests |

## 9. Known gaps of the tool

* One process and one source address; no per-agent source addresses, no network impairment (latency, loss), no TLS inspection or proxy.
* Software keys and in-memory state; certificates are not renewed during a run (a run is shorter than a third of a certificate's life; the identity cache skips certificates that expire within an hour).
* Inventory is the same fixture for everyone, so the server's title table stays small (120 titles) and the per-device item count is fixed; real fleets have more variety. Deltas change 3 items.
* Heartbeats have no acknowledgement in the protocol, so no round trip is measured for them.
* Windows Update snapshots and content downloads are not exercised, and the `wu_scan` jobs are no-ops.
* The REST API is exercised only for tokens, job creation and the overview; the console's own load (SSE streams, device lists with 10,000 rows) is not tested.
* The server-process and PostgreSQL samplers need the same host (`--server-pid`, `--pg-url`); the kernel counters in the script cover the whole host.

## 10. After the performance pass (D116 to D118)

Same sandbox as section 7 (4 vCPU, 15.7 GiB, PostgreSQL 16.15 with default settings, generator, server and database on one host, `scripts/loadtest.sh`, Go 1.27.2). Still **not a capacity statement**. `net.core.netdev_max_backlog` was 1000 for the first runs and 65536 from the storm runs on (section 7.3).

### 10.1 Memory and delivery at 5,000 agents (steady, heartbeat 30 s unless stated)

| | Before | After (read buffer 4 KiB) | After, 6 minute hold, heartbeat 5 min |
|---|---:|---:|---:|
| Result | pass | pass | pass |
| Server RSS peak, hold phase | 1014 MB | 797 MB | 773 MB (ramp peak 760 MB: no growth over 6 minutes) |
| Per connected agent | about 203 KB | about 159 KB | about 155 KB |
| Server CPU, hold, average / peak (% of one core) | 25 / 134 | 23 / 60 | 17 / 92 |
| Descriptors, hold peak | 5,055 | 5,051 | 5,057 |
| Jobs created / completed / lost | 215 / 215 / 0 | 216 / 216 / 0 | 1,215 / 1,215 / 0 |
| Job offer verified by the agent, p50 / p95 / p99 | 4.4 / 51 / 67 ms | 4.7 / 34 / 44 ms | 4.4 / 30 / 40 ms |
| Job end to end (REST request to result acknowledged), p50 / p99 | 68 / 131 ms | 61 / 131 ms | 60 / 102 ms |

One run each; the sandbox shares four cores between three processes, so differences of a few percent are noise. The memory difference (217 MB) is not.

### 10.2 Reconnect storm, 5,000 agents (every connection dropped at once, real backoff)

| | Before (`GetDeviceCert` + `GetDevice`, twice) | After (`CheckDeviceCert`) |
|---|---:|---:|
| Time until 50% / 90% / 99% / 100% connected | 11.3 / 11.8 / 12.0 / 12.0 s | 11.1 / 11.8 / 12.0 / 12.0 s |
| PostgreSQL transactions per second during the storm, average / peak | 3,052 / 6,008 | 2,025 / 3,837 |
| Server CPU during the storm, average / peak (% of one core) | 186 / 266 | 180 / 332 |
| Server RSS peak | 780 MB | 766 MB |

The storm is limited by TLS handshakes on the shared CPUs, so the recovery time did not move; the database work did. The "before" run reported FAIL only because of the loopback packet-drop artifact of section 7.3 (356 resets 30 s after the storm; `net.core.netdev_max_backlog` was raised before the second run), not because of the code.

### 10.3 Console pages at 5,000 devices and 600,000 install rows

Measured on the real server binary and a database seeded with SQL (5,000 devices, 400 products, 120 programs per device), PostgreSQL defaults, four requests each:

| Request | Before | After |
|---|---:|---:|
| `GET /devices?limit=50` | 12 to 19 ms | unchanged |
| `GET /devices/{id}` | 2 to 3 ms | unchanged |
| `GET /reports/overview` | 25 to 28 ms | unchanged |
| `GET /dashboard` | 30 to 39 ms | unchanged |
| `GET /software?limit=50` (default view) | 0.95 to 0.99 s | 0.26 to 0.30 s |
| `GET /software?limit=50&include_system=true` | about 1.0 s | unchanged |
| `GET /software/updates`, nothing to update | 1.46 to 1.96 s | 0.33 to 0.38 s |
| `GET /software/updates`, one product in ten has an update (2.7 MB answer) | 1.46 to 1.85 s | 0.62 to 0.67 s |
| `GET /software/updates`, half of the products have an update (13 MB answer) | 1.7 to 2.0 s | 2.1 to 3.0 s |
| `GET /software/updates`, every product has an update (26 MB answer) | 2.0 to 2.4 s | 2.7 to 3.3 s |

The last two rows are slower than before: the pass that matches the distinct programs costs about 0.35 s, and then every row has to be read anyway. Their answer (one entry per device and program) is what takes the time; paging it needs an API and console change.

### 10.4 Message sizes (protobuf, before gRPC framing and TLS)

Heartbeat 35 B, job update 46 B, hello 163 B, hardware report 293 B, software delta of 3 items 775 B, a restart job 308 B, the first full software snapshot of 120 items 30.9 KB (once per connection history, or after a resync). Steady state sends almost nothing, so message compression was not added (it would also need server support in every older server).

### 10.5 Restart latency, click to the agent's call to the operating system

From `test/e2e/latency_test.go` (real server, real agent core, real PostgreSQL, Linux dev platform, 4 vCPU):

| Situation | Before | After |
|---|---:|---:|
| Idle agent (10 clicks): API returns / job on the stream / OS call | 2.4 / 2.7 / 7.9 ms median (max 13 ms) | unchanged |
| A 6 s Windows Update scan is running | 5.53 s | 0.034 s |
| A 6 s hardware collection is running | 4.52 s | 0.024 s |
| The agent has just connected and is still sending its first inventory | 5.98 s | 0.029 s |

The Windows parts (the real Windows Update Agent, the BitLocker query, Windows' own countdown dialog) were not run; see the checklist.

### 10.6 Still to do before trusting the number for your site

* Run section 4.2 against the real stack (compose, the NAS, a real network) with the generator on another host.
* A soak of hours, watching memory, descriptors and goroutines of the server (the 6 minute hold above shows no growth, which is not a soak).
* 10,000 agents with the new build (section 7 was measured with the old one).
