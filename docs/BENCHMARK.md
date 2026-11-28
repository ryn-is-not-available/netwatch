# NetWatch benchmark report

Measured on a local Docker Desktop stack (5 nodes, 2 control planes), generated from `docs/benchmark-results.json` by `python scripts/benchmark.py report`. Re-run the scripts to refresh.

## SNMP (T0) vs NetWatch (T1)

T0 is a classic NMS poller: `snmpget sysUpTime.0` per node every 60.0 s (1 s timeout, 2 retries) over MGMT_NET. T1 is NetWatch: 5 s heartbeats with 7.5 s / 12 s leases, 5 s DATA_NET probe mesh, 15 s alert pending window.

| Measure | SNMP poller (T0) | NetWatch (T1) |
|---|---|---|
| Frozen node (`docker pause node-4`): time to detect | 45.9 s (first failed poll) | 10.9 s (marked offline) |
| 30% DATA_NET loss on node-3 | not detected (management path unaffected) | links degraded in 3.8 s, alert in 19.8 s |
| MGMT_NET overhead per node | 323 B/min | 465874 B/min (heartbeats, 1 s signed telemetry, probe results; all TLS) |
| DATA_NET overhead per node | none | 21803 B/min (ICMP probe mesh) |
| False positives in 120 s steady state | 0 failed polls of 10 | 0 alerts |

**Reading it:** NetWatch spends far more management bandwidth. The captures show most of it is gRPC: the agent opens a new TLS channel for every heartbeat and probe result, so reusing one channel per control plane is the obvious next optimisation (1 s signed telemetry over NATS is the smaller share). It buys two things with that bandwidth. It detects a dead node within one lease rather than one polling interval. And it sees data-plane degradation that a management-plane poller cannot see at all. SNMP's detection time depends on where in its polling cycle the failure lands, so it varies between near zero and one full interval plus timeouts.

## Chaos scenarios (5.2)

| Scenario | Detection | Recovery |
|---|---|---|
| 30% loss on node-3 | degraded 5.8 s, alert 24.9 s | 36.6 s |
| +80 ms on node-2 | latency alert 18.5 s | 31.0 s |
| iperf3 500M node-1 → node-4 | NetWatch rx peak 503.2 Mbit/s vs iperf3 500.0 Mbit/s | - |

## Packet captures (5.4)

`docs/captures/` holds 20 s captures from node-1 on both networks (open them in Wireshark); `summary.json` has the counts below. Annotations are in `docs/captures/README.md`.

| Interface | Packets | gRPC mTLS :50051 | NATS TLS :4222 | ICMP | traceroute UDP | Plaintext markers |
|---|---|---|---|---|---|---|
| MGMT_NET (eth1) | 354 | 294 | 60 | 0 | 0 | none |
| DATA_NET (eth0) | 102 | 0 | 0 | 80 | 8 | none |

## Cold start (5.5)

From empty volumes (`docker compose down -v`, images cached) to a working mesh; target under 300 s. CI repeats this on every push on a fresh runner (`benchmark.py cold-start` in `.github/workflows/ci.yml`).

| Milestone | Seconds |
|---|---|
| compose up returned | 29.5 |
| api login | 29.7 |
| five nodes healthy | 30.8 |
| telemetry flowing | 31.8 |
| links observed | 46.2 |
| total | 46.2 |

Source: GitHub Actions run 46145333325 (ubuntu-latest, fresh runner, images built in a prior step).
