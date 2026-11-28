# Packet captures (node-1, 20 s)

Captured with `python scripts/benchmark.py capture`: `tcpdump` (256-byte snaplen) on both of node-1's
interfaces during normal operation, plus one path trace node-1 → node-3. Open them in Wireshark.
`summary.json` has the per-protocol counts.

## `node-1-mgmt.pcap`: MGMT_NET (172.28.0.0/24)

| Traffic | Peer | What it is |
|---|---|---|
| TCP 50051, TLS 1.3 | control planes 172.28.0.32 / .33 | gRPC with mutual TLS: `SendHeartbeat` every 5 s (Ack carries commands and the peer list) and `SubmitProbeResult` for each probe. In Wireshark the client sends a certificate (`CN=node-1`, issued by the NetWatch CA) in the handshake. |
| TCP 50052, TLS | control planes | `Enroll` (server-auth TLS only: the node has no certificate yet). Appears only at first start or on 24 h rotation, so it is absent from this capture. |
| TCP 4222, TLS | NATS 172.28.0.31 | JetStream publishes of 1 s telemetry ticks. Each message carries a `Netwatch-Sig` header (the agent's RSA signature), but inside TLS: no `PUB telemetry.` or `"cpu_pct"` appears on the wire. |

No plaintext markers (`PUB telemetry`, `CONNECT {`, `"cpu_pct"`, `SendHeartbeat`) occur in either file.
The node opens no listening ports: every connection is outbound.

Observation: most packets are gRPC, because the agent opens a new channel (TCP and TLS handshake) for every
heartbeat and every probe result. See the overhead row in `docs/BENCHMARK.md`; reusing channels would cut it.

## `node-1-data.pcap`: DATA_NET (172.29.0.0/24)

| Traffic | Peer | What it is |
|---|---|---|
| ICMP echo request/reply | the other nodes | The ActiveProber's mesh: 2 echo requests to each peer every 5 s. Peers come from the control plane's peer list, not from configuration. |
| UDP 33434+ / ICMP time-exceeded and port-unreachable | node-3 | `traceroute` for the path trace started from the console (the agent runs it when it receives the `run_trace` command). |

DATA_NET is an `internal` Docker network: it carries only measurement traffic, and the agents never use it to reach
the control plane.
