# NetWatch

> Declarative, event-driven distributed network observability platform with outbound-only mTLS agents, bitemporal topology graphs, and audited read-only AI diagnostics.

## Overview

NetWatch monitors distributed infrastructure across isolated management (`MGMT_NET`) and data (`DATA_NET`) planes without opening inbound ports on monitored nodes.

### Core Architecture

* **Control Plane (`control_plane/`):** Stateless FastAPI + gRPC replicas with PostgreSQL advisory-lock leader election and epoch fencing (`Observe → Diff` drift reconciliation).
* **Node Agents (`agent/`):** Outbound-only gRPC heartbeats with piggybacked probe commands and a 1,000-tick circular RAM buffer for outage resilience.
* **Ingestion & Storage (`worker/`, `db/`):** NATS JetStream message bus feeding a deduplicating batch worker (`boot_id`, `seq_id`) into PostgreSQL 16 + TimescaleDB hypertables.
* **Web Console & AI Ops (`web_ui/`, `ai_worker/`):** Bitemporal topology time-travel visualization and a sandboxed, read-only diagnostic advisor.

## Project Structure

```text
netwatch/
├── proto/           # gRPC service and message definitions
├── db/              # PostgreSQL + TimescaleDB schema and bitemporal constraints
├── shared/          # Generated Protobuf stubs and shared schemas
├── control_plane/   # Domain logic, leader election, gRPC & REST servers
├── agent/           # Outbound node agent, ring buffer, and /proc collector
├── worker/          # NATS JetStream to TimescaleDB batch loader
├── ai_worker/       # Read-only LLM diagnostic worker with citation verification
├── web_ui/          # Interactive topology map and time-travel console
├── benchmarks/      # Chaos testing (tc netem, iperf3) and T0/T1 evaluations
└── tests/           # Unit and integration test suite
```