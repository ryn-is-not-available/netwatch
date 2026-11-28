# NetWatch demo scenario (planning S8)

A repeatable demonstration, about 10 minutes: the network in normal operation, then four
failures, each one detected by NetWatch (T1) and compared with classic SNMP monitoring (T0).
`scripts/demo.py` drives every step, checks the expected result and undoes each fault, so the demo
can be rehearsed unattended and run live with pauses.

## Before the demo

1. Start the stack and wait until everything is healthy (about 1 minute from cold):

   ```powershell
   docker compose up -d
   ```
   ```powershell
   docker compose ps
   ```

2. Open three browser tabs:

   | Tab | URL | Sign in |
   | --- | --- | --- |
   | NetWatch console | http://localhost:8000 | `admin` / `ADMIN_PASSWORD` (dev `netwatch-admin-dev`) |
   | Grafana T1, NetWatch overview | http://localhost:3000/d/netwatch-overview | `admin` / `GRAFANA_ADMIN_PASSWORD` (dev `netwatch-grafana-dev`) |
   | Grafana T0, SNMP baseline | http://localhost:3000/d/snmp-baseline | same |

3. Rehearse once unattended. Every act must print `PASS`:

   ```powershell
   python scripts/demo.py
   ```

For the live demo, run it with pauses and a longer hold so there is time to show each screen:

```powershell
python scripts/demo.py --pause --hold 30
```

## The acts

Times were measured with `python scripts/demo.py` on the lab stack (Docker Desktop, 5 nodes) on
2026-11-28. They are counted from when the fault is in place; for *stop* and *failover*, that's
when `docker stop` returns.

### Act 1: normal operation

| Show | Expected |
| --- | --- |
| Console map | 5 green nodes, links solid, no open alert, no pending fix |
| Grafana T1 | *Nodes up* 5, *Links up* 20 (full mesh, both directions), *Lossy links* 0, *Open alerts* 0, one leader; latency well under 1 ms |
| Grafana T0 | 5 SNMP agents answering, 0 interfaces down, 0 errors |

Talking points:
- Two measurement planes: SNMP polls each node's own counters over MGMT_NET, while NetWatch
  probes the paths *between* nodes on DATA_NET.
- Nodes never accept a NetWatch connection: the agents dial out over mTLS.

### Act 2: degraded link (30 % packet loss on node-3)

`tc netem loss 30%` on node-3's DATA_NET interface.

| | Measured |
| --- | --- |
| T1: node-3's links marked lossy (> 2 %) | 8.8 s |
| T1: packet-loss alert open | 28.0 s (the alert must hold for 15 s before firing, to avoid flapping) |
| node-3 itself | stays up, because its heartbeats use MGMT_NET |
| **T0: SNMP errors + discards on node-3** | **+0: SNMP doesn't see it** |
| Recovery after the fault is removed | all green in 30.5 s (the alert waits for loss ≤ 1 %) |

Show the red links and their hover card in the console (loss per direction), *Link packet loss*
on Grafana T1, and the flat *Interface errors* panel on T0. Optionally press **AI diagnose**
during the hold (needs `GEMINI_API_KEY`). In an earlier test with 40 % loss, it named node-3 as the
common factor and cited the affected links.

### Act 3: link cut (node-4 disconnected from DATA_NET)

`docker network disconnect data_net node-4`, then reconnected with its address `172.29.0.13`.

| | Measured |
| --- | --- |
| T1: all 4 links from node-4 down (100 % loss, *Links up* 20 → 12) | 27.8 s |
| T1: alert open | 27.9 s |
| node-4 itself | stays up: only its data path is cut |
| **T0: SNMP agent on node-4** | **still answers, so SNMP reports nothing wrong** |
| Recovery after reconnecting | all green in 37.9 s |

This is the clearest T0 vs T1 difference: the node is healthy, so SNMP is happy, but it can no
longer reach anyone on the data network.

### Act 4: node failure (node-5 stopped)

`docker stop node-5`, then `docker start node-5`.

| | Measured |
| --- | --- |
| T1: node-5 *offline* (no heartbeat for 12 s) | 12.6 s |
| T1: *Node unreachable* alert | 12.7 s |
| T0: SNMP agent on node-5 | down at its next poll (every 15 s) |
| Recovery after start | all green in 16.2 s |

Show node-5 turning red in the console, then its links disappearing. On Grafana T1, show the
*Node health* timeline.

### Act 5: control-plane failover (the leader is stopped)

`docker stop` on whichever control plane is leader, then `docker start`.

| | Measured |
| --- | --- |
| Standby takes over | 0.8–0.9 s after `docker stop` returns |
| Nodes lost during the failover | none (5 up) |
| Old leader back as standby | 1.8 s after `docker start` |

Show the console still working on the other port, and Grafana T1's *Leader* panel changing name.
*Leaders (must be 1)* stays at 1.

## Summary for the jury

| Failure | NetWatch (T1) | SNMP (T0) |
| --- | --- | --- |
| 30 % loss on a node's data path | links flagged in about 9 s, alert in about 28 s | not seen (0 errors) |
| Data link cut | links down and alert in about 28 s | not seen (agent still answers) |
| Node down | offline and alert in about 13 s | lost at the next poll (up to 15 s) |
| Control-plane crash | standby leader in under 1 s, no data lost | – |

More detailed numbers (overhead, cold start, captures) are in `docs/BENCHMARK.md`.

## If something goes wrong during the demo

- **An act prints `FAIL`:** the script still undoes the fault. Check `docker compose ps` and rerun
  that act alone, for example `python scripts/demo.py --acts cut`.
- **A leftover netem qdisc** (after a hard kill):

  ```powershell
  python scripts/chaos.py clear
  ```

- **node-4 left without its data network** (after a hard kill during act 3):

  ```powershell
  docker network connect --ip 172.29.0.13 data_net node-4
  ```

- **A container left stopped:**

  ```powershell
  docker compose up -d
  ```
