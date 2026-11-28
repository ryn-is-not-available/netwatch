# NetWatch

> Declarative, event-driven distributed network observability platform with outbound-only mTLS agents, bitemporal topology graphs, and epoch-fenced high availability.

## Overview

NetWatch monitors distributed infrastructure across isolated management (`MGMT_NET`) and data (`DATA_NET`) planes without opening inbound listening ports on monitored nodes.

### Core Architecture

- **Control Plane (`control_plane/`):** Two active-passive FastAPI + gRPC replicas (`control-plane-1` on `:8000`, `control-plane-2` on `:8001`) using PostgreSQL advisory-lock leader election (`leader_epoch`) and fenced database writes (`elector.fenced_execute`).
- **Node Agents (`agent/`):** Outbound-only mTLS gRPC heartbeats (every 5s). Each heartbeat Ack carries probe commands and the current **peer list** (every other live node's `DATA_NET` address, so nodes need no hard-coded peers). The agent also runs ICMP peer probes (`ActiveProber`), collects host and per-interface metrics from `/proc` and `/sys` (name, MAC, IPs, oper state, bytes/errors/drops), and keeps a 1,000-tick in-memory ring buffer so no telemetry is lost during a NATS outage.
- **Ingestion & Bitemporal Storage (`worker/`, `db/`):** NATS JetStream (`TELEMETRY` stream) feeding a deduplicating batch worker (`boot_id`, `seq_id`) into PostgreSQL 16 + TimescaleDB hypertables with non-overlapping bitemporal `tstzrange` intervals (`valid_during`, `recorded_during`).
- **Web Console (`control_plane/ui/`):** Live Cytoscape.js topology map showing declared vs. observed links, drift highlights, a bitemporal time-travel slider, and operator controls (`Trace`, `Diagnose`, `Approve/Reject`, `Revoke`).

## Project Structure

```text
netwatch/
├── proto/               # gRPC service (ControlService) and message definitions
├── db/                  # PostgreSQL 16 + TimescaleDB schema, GIST constraints, hypertables
├── shared/              # Generated Protobuf stubs and shared schemas
├── control_plane/
│   ├── adapters/        # PostgreSQL advisory-lock LeaderElector & epoch fencing
│   ├── api/             # FastAPI REST console/API (:8000/:8001) & gRPC mTLS/TLS servers
│   ├── domain/          # LeaseManager, TopologyGraphEngine (Dijkstra + drift), AlertEvaluator
│   └── ui/              # Interactive Cytoscape.js topology & time-travel web UI
├── agent/               # Outbound node agent, RingBuffer, /proc collector, ActiveProber
├── worker/              # NATS JetStream consumer & TimescaleDB staging upsert worker
├── certs/               # PKI helpers (CA, server certs, node CSR signing); generated keys are gitignored
├── scripts/             # PKI bootstrap (gen_certs.py), proto codegen, and fault-injection verification
├── tests/               # Unit and integration test suite
└── docker-compose.yml   # Full 10-container local topology (DB, NATS, 2 CPs, worker, 5 nodes)
```

---

## Quick Start & Running the Stack

### Prerequisites

- Docker Engine & Docker Compose v2+
- PowerShell 7+ (or Windows PowerShell 5.1) and Python 3.12+ (for local unit tests)

**Configuration (optional):** every setting has a dev default. To override passwords, the join token or the JWT secret, copy `.env.example` to `.env` and edit it; Compose reads `.env` automatically.

```powershell
Copy-Item .env.example .env
```

**Health:** each container has a real healthcheck. Control planes report healthy when the REST API answers. Nodes are healthy while the control plane accepts their heartbeats, so a revoked or partitioned node shows as `unhealthy`. The worker is healthy while its ingest loop runs with a working database connection.

### 1. Start All Services

Build and launch TimescaleDB, NATS JetStream, `control-plane-1`, `control-plane-2`, `netwatch-worker`, and `node-1` through `node-5`:

```powershell
docker compose up -d --build
```

On the first run, the one-shot `cert-init` container creates the PKI in `certs/` (Root CA, control-plane and NATS server certificates, and `certs/public/ca.crt`) before the control planes start. Later runs keep the existing files. Generated keys and certificates are gitignored and never committed.

To create the PKI without Docker (needs `pip install cryptography`):

```powershell
python scripts/gen_certs.py
```

To rotate the PKI, stop the stack, delete the generated `*.key`/`*.crt` files and `certs/public/`, and start it again.

> **Key isolation:** only the control planes mount `certs/` (they need `ca.key` to sign node CSRs). Nodes and the worker mount `certs/public/ca.crt` at `/app/pki/ca.crt`; NATS mounts only `certs/nats/` (its server cert and key). A compromised node cannot mint certificates for other node IDs.

> **Telemetry security:** NATS requires TLS for every client (`tls://` URLs, verified against the NetWatch CA). Agents share one NATS user, so each agent also signs every telemetry message with the private key behind its enrolled client certificate (`Netwatch-Sig` header). Before writing anything, the worker checks three things: the subject `telemetry.<node>` matches the payload's `node_id`, the node is enrolled and not revoked, and the signature verifies against the certificate stored at enrollment. It also accepts the previous certificate, so a 24h key rotation drops nothing. Messages that fail are discarded and logged.

Verify all 10 long-running containers are up (`cert-init` shows as exited with code 0):

```powershell
docker compose ps -a
```

### 2. Service Endpoints

| Service | Container | Host Port(s) | Purpose |
| --- | --- | --- | --- |
| **Control Plane 1 (Primary)** | `control-plane-1` | `http://localhost:8000` | Web UI, REST API, gRPC (`50051` mTLS / `50052` TLS) |
| **Control Plane 2 (Standby)** | `control-plane-2` | `http://localhost:8001` | Warm HA replica (auto-promotes in `< 5s` on leader loss) |
| **TimescaleDB (PG 16)** | `timescaledb` | `localhost:5432` | Bitemporal topology, hypertables, `leader_epoch`, `audit_log` |
| **NATS JetStream** | `nats-server-1` | `4222` (client), `8222` (HTTP) | `TELEMETRY` stream (`telemetry.>`) |
| **Monitored Nodes (×5)** | `node-1` .. `node-5` | *None (outbound-only)* | Dual-homed on `MGMT_NET` and `DATA_NET` (Docker picks which is `eth0`/`eth1`; the agent finds the data interface by its `172.29.0.x` address) |

---

## Using the Application

### 1. Web Console

Open **http://localhost:8000** in your browser to access the NetWatch Console:

- **Live Topology Graph:** Displays declared links (dashed grey), observed healthy links (solid), and drift/degraded links (red), polling automatically every few seconds.
- **Time-Travel Slider:** Scrub backward in time (`?at=`) to see the network as it was, and add `?known_at=` to see what NetWatch believed at a given moment (see *Bitemporal History* below).
- **Operator Actions:** Trigger A → B path traces, inspect drift alerts, apply/dismiss recommendations, or revoke compromised nodes (`admin` role; all writes are recorded in the append-only `audit_log`). A revoked node is refused on heartbeat, probe submission and re-enrollment, and its links are closed.
- **Alerts:** the leader's `AlertEngine` checks every observed link every 5s using a 30s average. It raises a **packet loss** alert above 2% (`critical` from 20%) and a **latency** alert above the link's declared `expected_latency_ms` (20 ms for undeclared links). A rule must stay breached for 15s (`PENDING`) before it fires. It resolves only once loss is back at or below 1%, or latency at or below 80% of the SLO, so a value hovering at the threshold doesn't flap. Timers survive leader failover (`alert_timers`). Alerts for links that disappear are resolved. Separately, the `LeaseManager` raises one `Node unreachable` alert per offline node.
- **Writes go to the leader:** only the active leader accepts writes. The standby replica serves reads but answers writes with `503` (check `GET /health` for `is_leader`), so after a failover use the other port.

### 2. REST API Quick Examples (PowerShell)

**Obtain a JWT token (`viewer`, `operator` or `admin` role; dev only, the endpoint does not check credentials):**

```powershell
$auth = Invoke-RestMethod -Method Post "http://localhost:8000/auth/token" `
  -ContentType "application/json" `
  -Body '{"subject":"local-admin","role":"operator"}'
$headers = @{ Authorization = "Bearer $($auth.access_token)" }
```

**Query live topology (declared vs. observed links):**

```powershell
Invoke-RestMethod "http://localhost:8000/topology" -Headers $headers | ConvertTo-Json -Depth 4
```

**Query point-in-time historical topology (`at`):**

```powershell
$past = (Get-Date).AddMinutes(-5).ToUniversalTime().ToString("o")
Invoke-RestMethod "http://localhost:8000/topology?at=$([uri]::EscapeDataString($past))" -Headers $headers
```

**Trigger an asynchronous A → B path trace (`202 Accepted` + poll):**

```powershell
$trace = Invoke-RestMethod -Method Post "http://localhost:8000/paths/trace" `
  -Headers $headers -ContentType "application/json" `
  -Body '{"src_node_id":"node-1","dst_node_id":"node-4"}'
Start-Sleep -Seconds 3
Invoke-RestMethod "http://localhost:8000/paths/trace/$($trace.trace_id)" -Headers $headers
```

---

## Verification & Testing

### End-to-End Fault Injection & Lease Eviction

Stops `node-1` and checks that it is marked offline, that `LeaseManager` closes all its links within 14s and they stay closed (peers probing a dead node must not re-open them), and that exactly one `Node unreachable` alert is raised for it. It then restarts `node-1` and checks that it is healthy again, its links are restored and the alert is resolved. It exits with code 1 if any check fails. Point `-BaseUrl` at the current leader (`http://localhost:8001` after a failover):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\verify_fault_injection.ps1
```

### Unit Tests

Runtime dependencies are pinned per service in `requirements/` (the Dockerfiles install these); `requirements.txt` pulls in all of them plus the test tools:

```powershell
pip install -r requirements.txt
```
```powershell
pytest -v
```

### Continuous Integration

`.github/workflows/ci.yml` runs on every push and pull request. It runs the unit tests with coverage, then boots the full stack on the runner, waits for all 5 nodes to be healthy, checks every container's healthcheck, and runs the fault-injection script.

### Key Database Invariants (Developer Note)

- **Bitemporal History:** each `topology_links` row says the link existed with a given status during `valid_during`, and was NetWatch's belief during `recorded_during`. Rows are never edited except to end `recorded_during`. When the status changes, the current row is retired and two new versions are inserted: the old status, now with its end time, and the new status from that moment on (see `control_plane/domain/link_history.py`). `?at=T` answers *what was the network like at T*; `?known_at=K` answers *what did we believe at K*. The `no_overlapping_links` constraint excludes overlap in both time dimensions. Open rows use `tstzrange(NOW(), NULL, '[)')` (not `'infinity'`), so `upper_inf()` identifies the current row.
- **Link Status Window:** status comes from the trailing 30s of probe results, limited to the link's own segment (degraded above 2% loss, back up at 1% or below), not from a single 2-packet probe. A link reopened after an outage starts from its first successful probe, so the outage's failed probes don't mark it degraded.
- **Epoch Fencing:** Any control-plane mutation must execute through `elector.fenced_execute(conn, sql, params)` (REST handlers use `_require_leader(conn)`, the same `FOR SHARE` epoch check) to prevent split-brain writes during leader failover.
- **Takeover Grace:** A newly elected leader waits one full lease (`12s`) before marking nodes degraded or offline, because heartbeats are declined while no leader exists. Agents retry quickly (0.5–4s backoff, 2s RPC deadline) and remember the last control plane that accepted them.
- **Schema Lives in `db/init.sql`:** Control planes run no DDL at startup (two replicas racing on `CREATE TABLE IF NOT EXISTS` crashes one of them). Changing the schema means editing `init.sql` and recreating the database volume (`docker compose down -v`).

---

## Implementation Checklist

### Phase 1 · Playground & Contracts — Complete

- [x] **1.1** Git repository, folder skeleton, `.gitignore`, `.env.example`, and `requirements.txt`
- [x] **1.2** Root CA, server certificates (control-plane & NATS), and 24h node client certificates (`CN = node_id`)
- [x] **1.3** Protobuf definitions (`Enroll`, `Heartbeat`, `ProbeResult`, `Ack`), `ControlService` RPCs, and generated Python stubs
- [x] **1.4** PostgreSQL + TimescaleDB schema (`nodes`, `network_interfaces`, `topology_links` with GIST exclusion, `alerts`, `recommendations`, `node_commands`, `path_traces`, `leader_epoch`, append-only `audit_log`, hypertables)
- [x] **1.5** Docker Compose dual-network topology (`MGMT_NET` + `DATA_NET`), TimescaleDB (`172.28.0.30`), NATS JetStream, 2 control-plane replicas, and 5 dual-homed nodes

### Phase 2 · Agent & Telemetry — Complete

- [x] **2.1** Circular RAM `RingBuffer` (`1,000` ticks, monotonic `seq_id`, `boot_id`, unit tests)
- [x] **2.2** Host & interface collector (`/proc` CPU/RAM, per-interface rx/tx/errors/drops + MAC/IPs into `network_interfaces` / `interface_metrics`; data interface found by `DATA_IP`)
- [x] **2.3** Outbound-only mTLS agent (`Enroll`, 5s `Heartbeat` with zero listening ports, NATS JetStream publisher with `PubAck` draining)
- [x] **2.4** NATS JetStream batch worker with staging table deduplication (`ON CONFLICT DO NOTHING`)
- [x] **2.5** NATS outage resilience verified (0 lost ticks, 0 duplicate rows)

### Phase 3 · Control Plane — Complete

- [x] **3.1** PostgreSQL advisory-lock `LeaderElector` with monotonic epochs, `fenced_execute`, and `< 5s` failover
- [x] **3.2** mTLS/TLS gRPC server (`Enroll` CSR signing, `Heartbeat` + `SKIP LOCKED` command dispatch, `SubmitProbeResult`)
- [x] **3.3** `LeaseManager` (`DEGRADED > 7.5s`, `UNREACHABLE > 12s`, automatic closure of observed links)
- [x] **3.4** `TopologyGraphEngine` (Dijkstra shortest path on `admin_cost`, missing/extra link drift diff, `> 2%` packet loss rule)
- [x] **3.5** `AlertEvaluator` (`PENDING → FIRING` persisted timers, recovery hysteresis, fingerprint deduplication)
- [x] **3.6** Unit test suite (`LeaseManager`, `TopologyGraphEngine`, `>= 80%` coverage)

### Phase 4 · API, Probes & UI — Complete

- [x] **4.1** FastAPI REST API with JWT RBAC (`viewer`/`operator`), `POST /topology/desired`, bitemporal `GET /topology` (`at=`, `known_at=`), async `POST/GET /paths/trace`, audited node revocation & recommendation approval
- [x] **4.2** Agent `ActiveProber` (ICMP/peer RTT & packet loss probes reported via `SubmitProbeResult` with `TIMEOUT` handling)
- [x] **4.3** Cytoscape.js Web UI (`control_plane/ui/`) with declared/observed/drift styling, time-travel slider, live polling, and action controls

### Phase 5 · AI & Benchmarks — Next

- [ ] **5.1** Sandboxed read-only AI diagnostic worker (`/ai/diagnose`, strict JSON schema, citation verification, prompt-injection hardening)
- [ ] **5.2** Chaos injection (`tc netem` loss/delay) and `iperf3` congestion burst scripts
- [ ] **5.3** SNMP (`T0`) vs. NetWatch (`T1`) detection latency, overhead, and false-positive benchmarks
- [ ] **5.4** Wireshark `.pcap` captures and protocol annotations on `MGMT_NET` and `DATA_NET`
- [ ] **5.5** Final benchmark report & cold-start timing verification (`< 5 min`)
