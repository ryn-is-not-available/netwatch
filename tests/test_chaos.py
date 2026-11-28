"""Chaos toolkit helpers: DATA_NET interface discovery and alert matching (docker/API faked)."""
import importlib.util
from pathlib import Path
from unittest.mock import MagicMock, patch

_spec = importlib.util.spec_from_file_location("chaos", Path(__file__).resolve().parents[1] / "scripts" / "chaos.py")
chaos = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(chaos)

IP_OUT = """1: lo    inet 127.0.0.1/8 scope host lo
2: eth0    inet 172.28.0.44/24 brd 172.28.0.255 scope global eth0
3: eth1@if9    inet 172.29.0.14/24 brd 172.29.0.255 scope global eth1"""


def test_data_iface_is_found_by_address_not_name() -> None:
    with patch.object(chaos, "docker", return_value=IP_OUT):
        assert chaos.data_iface("node-5") == ("eth1", "172.29.0.14")


def test_open_alerts_match_node_as_source_or_destination() -> None:
    api = MagicMock()
    api.call.return_value = [
        {"status": "new", "message": "Packet loss 33.3% on node-1->node-3 (> 2% for 15s)", "affected_node_id": "node-1"},
        {"status": "new", "message": "Packet loss 50.0% on node-3->node-4 (> 2% for 15s)", "affected_node_id": "node-3"},
        {"status": "resolved", "message": "Packet loss 40.0% on node-2->node-3 (> 2% for 15s)", "affected_node_id": "node-2"},
        {"status": "new", "message": "Packet loss 9.0% on node-1->node-30 (> 2% for 15s)", "affected_node_id": "node-1"},
        {"status": "new", "message": "Latency 90.0 ms on node-5->node-3 (> 20 ms SLO for 15s)", "affected_node_id": "node-5"},
    ]
    hits = chaos.open_alerts(api, "node-3", "Packet loss")
    assert [h["message"].split(" on ")[1].split(" ")[0] for h in hits] == ["node-1->node-3", "node-3->node-4"]


def test_netem_is_always_removed_even_on_error() -> None:
    calls = []
    with patch.object(chaos, "data_iface", return_value=("eth0", "172.29.0.12")), \
         patch.object(chaos, "docker", side_effect=lambda *a, **k: calls.append(a) or ""):
        try:
            with chaos.netem("node-3", ["loss", "30%"]):
                raise KeyboardInterrupt
        except KeyboardInterrupt:
            pass
    assert calls[0][:6] == ("exec", "node-3", "tc", "qdisc", "replace", "dev")
    assert calls[-1] == ("exec", "node-3", "tc", "qdisc", "del", "dev", "eth0", "root")
