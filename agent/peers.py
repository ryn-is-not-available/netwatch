"""Thread-safe directory of probe targets, refreshed from every heartbeat Ack.

The control plane is the source of truth for which nodes exist and are live; agents no
longer carry a hard-coded peer list, so adding a node needs no agent change.
"""
import logging
import threading

logger = logging.getLogger("netwatch.agent.peers")


class PeerDirectory:
    def __init__(self, self_node_id: str) -> None:
        self._self = self_node_id
        self._lock = threading.Lock()
        self._peers: dict[str, str] = {}

    def update(self, peers: dict[str, str]) -> None:
        cleaned = {nid: ip for nid, ip in peers.items() if nid and ip and nid != self._self}
        with self._lock:
            if cleaned == self._peers:
                return
            added = sorted(set(cleaned) - set(self._peers))
            removed = sorted(set(self._peers) - set(cleaned))
            self._peers = cleaned
        logger.info("Peer directory updated: %d peer(s) (+%s -%s)", len(cleaned), added or "[]", removed or "[]")

    def snapshot(self) -> dict[str, str]:
        with self._lock:
            return dict(self._peers)

    def ip_for(self, node_id: str) -> str | None:
        with self._lock:
            return self._peers.get(node_id)

    def node_for_ip(self, ip: str) -> str | None:
        with self._lock:
            return next((nid for nid, peer_ip in self._peers.items() if peer_ip == ip), None)
