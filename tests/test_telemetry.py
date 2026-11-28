"""Collector, peer directory, prober targeting and worker interface ingestion."""
from datetime import datetime, timezone
import json
from unittest.mock import MagicMock, patch

from agent.collector import MetricsCollector, parse_ip_addr, parse_proc_net_dev
from agent.config import AgentConfig
from agent.peers import PeerDirectory
from agent.prober import ActiveProber
from tests.fakes import FakeConnection, FakeCursor
from worker.main import _flush_batch_to_db, _parse_tick

PROC_NET_DEV = """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:    1000      10    0    0    0     0          0         0     1000      10    0    0    0     0       0          0
  eth0:  500000    4000    2    5    0     0          0         0   300000    2500    1    3    0     0       0          0
  eth1:   70000     600    0    0    0     0          0         0    80000     700    0    0    0     0       0          0
"""

IP_ADDR = """1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: eth0    inet 172.29.0.10/24 brd 172.29.0.255 scope global eth0\\       valid_lft forever preferred_lft forever
3: eth1@if12    inet 172.28.0.40/24 brd 172.28.0.255 scope global eth1\\       valid_lft forever preferred_lft forever
"""


def _write_proc(tmp_path):
    (tmp_path / "net_dev").write_text(PROC_NET_DEV)
    (tmp_path / "stat").write_text("cpu  100 0 100 800 0 0 0 0 0 0\n")
    (tmp_path / "meminfo").write_text("MemTotal: 2048000 kB\nMemAvailable: 1024000 kB\n")
    (tmp_path / "uptime").write_text("1234.5 100.0\n")
    for iface, mac, state in (("eth0", "02:42:ac:1d:00:0a", "up"), ("eth1", "02:42:ac:1c:00:28", "unknown")):
        (tmp_path / "sys" / iface).mkdir(parents=True)
        (tmp_path / "sys" / iface / "address").write_text(mac + "\n")
        (tmp_path / "sys" / iface / "operstate").write_text(state + "\n")


def _collector(tmp_path) -> MetricsCollector:
    _write_proc(tmp_path)
    with patch.object(MetricsCollector, "_read_ipv4_addrs", return_value=parse_ip_addr(IP_ADDR)):
        c = MetricsCollector(
            data_ip="172.29.0.10",
            proc_stat_path=str(tmp_path / "stat"),
            proc_meminfo_path=str(tmp_path / "meminfo"),
            proc_net_dev_path=str(tmp_path / "net_dev"),
            proc_uptime_path=str(tmp_path / "uptime"),
            sys_class_net_path=str(tmp_path / "sys"),
        )
    return c


def test_parsers() -> None:
    counters = parse_proc_net_dev(PROC_NET_DEV)
    assert set(counters) == {"lo", "eth0", "eth1"}
    assert counters["eth0"][0] == 500000 and counters["eth0"][8] == 300000
    assert parse_ip_addr(IP_ADDR) == {"lo": ["127.0.0.1"], "eth0": ["172.29.0.10"], "eth1": ["172.28.0.40"]}


def test_collector_detects_data_iface_by_ip_and_reports_interfaces(tmp_path) -> None:
    c = _collector(tmp_path)
    assert c.data_iface == "eth0"  # found by DATA_IP, not assumed to be eth1

    with patch.object(MetricsCollector, "_read_ipv4_addrs", return_value=parse_ip_addr(IP_ADDR)):
        m = c.collect()

    assert c.latest() is m
    assert (m.rx_bytes, m.tx_bytes, m.rx_drops, m.tx_drops) == (500000, 300000, 5, 3)
    assert round(m.mem_pct) == 50
    by_name = {i.name: i for i in m.interfaces}
    assert set(by_name) == {"eth0", "eth1"}  # loopback excluded
    eth0 = by_name["eth0"]
    assert (eth0.mac, eth0.ips, eth0.oper_status) == ("02:42:ac:1d:00:0a", ["172.29.0.10"], "up")
    assert (eth0.rx_errors, eth0.tx_errors) == (2, 1)
    assert by_name["eth1"].oper_status == "up"  # 'unknown' (veth) maps to up


def test_peer_directory_excludes_self_and_maps_ips() -> None:
    d = PeerDirectory("node-1")
    d.update({"node-1": "172.29.0.10", "node-2": "172.29.0.11", "node-3": "", "node-4": "172.29.0.13"})
    assert d.snapshot() == {"node-2": "172.29.0.11", "node-4": "172.29.0.13"}
    assert d.node_for_ip("172.29.0.13") == "node-4"
    assert d.ip_for("node-9") is None


def _config() -> AgentConfig:
    return AgentConfig(
        node_id="node-1",
        data_ip="172.29.0.10",
        cp_addrs=("cp1:50051",),
        join_token="t",
        nats_url="nats://x",
        ca_cert_path=MagicMock(),
        cert_dir=MagicMock(),
    )


def test_prober_probes_only_directory_peers() -> None:
    peers = PeerDirectory("node-1")
    peers.update({"node-2": "172.29.0.11", "node-6": "172.29.0.15"})
    prober = ActiveProber(_config(), peers)
    with patch.object(prober, "run_icmp_probe", return_value=(True, 0.1, 0.0, 0.0, "")) as icmp, \
         patch.object(prober, "submit_probe_result") as submit:
        prober.probe_all_peers_once()
    assert [c.args[0] for c in icmp.call_args_list] == ["172.29.0.11", "172.29.0.15"]
    assert [c.kwargs["dst_node_id"] for c in submit.call_args_list] == ["node-2", "node-6"]


def test_trace_command_uses_destination_ip_from_payload() -> None:
    prober = ActiveProber(_config(), PeerDirectory("node-1"))
    with patch.object(prober, "run_traceroute", return_value=(True, 0.2, 0.0, 0.0, [])) as tr, \
         patch.object(prober, "submit_probe_result"):
        prober.execute_trace_command({"trace_id": "t-1", "dst_node_id": "node-7", "dst_data_ip": "172.29.0.16"})
    tr.assert_called_once_with("node-7", "172.29.0.16")


def _tick_bytes(node_id: str, seq: int, ifaces: list[dict]) -> bytes:
    return json.dumps({
        "timestamp": datetime(2026, 11, 28, 12, 0, seq, tzinfo=timezone.utc).isoformat(),
        "node_id": node_id, "boot_id": "b-1", "seq_id": seq,
        "cpu_pct": 1.0, "mem_pct": 2.0, "uptime_sec": 10, "data_iface": "eth0",
        "rx_bytes": 1, "tx_bytes": 2, "rx_drops": 0, "tx_drops": 0,
        "interfaces": ifaces,
    }).encode()


def test_worker_ingests_interfaces_and_skips_unenrolled_nodes() -> None:
    eth0 = {"name": "eth0", "mac": "02:42:ac:1d:00:0a", "ips": ["172.29.0.10"], "oper_status": "up",
            "rx_bytes": 10, "tx_bytes": 20, "rx_errors": 0, "tx_errors": 0}
    ticks = [
        _parse_tick(_tick_bytes("node-1", 1, [eth0])),
        _parse_tick(_tick_bytes("node-1", 2, [eth0])),
        _parse_tick(_tick_bytes("ghost", 1, [dict(eth0)])),
    ]
    # Upserts (one per node/interface in the batch): node-1/eth0 -> id, ghost/eth0 -> no row.
    cur = FakeCursor(fetchone_queue=[("iface-uuid-1",), None])
    conn = FakeConnection(cur)

    assert _flush_batch_to_db(conn, ticks) == 3
    assert conn.committed

    upserts = [p for sql, p in cur.executed if "INSERT INTO network_interfaces" in sql]
    assert len(upserts) == 2 and upserts[0][3] == ["172.29.0.10"]
    node_rows = [p for sql, p in cur.executed if "INSERT INTO node_metrics" in sql]
    assert len(node_rows) == 3  # node_metrics has no FK: every tick is kept
    # Interface metrics only for the enrolled node, one row per tick, linked to its interface id.
    metric_rows = [p for sql, p in cur.executed if "INSERT INTO interface_metrics" in sql]
    assert [(r[1], r[2], r[3]) for r in metric_rows] == [("iface-uuid-1", "eth0", "node-1")] * 2
