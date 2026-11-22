import os
import re
import subprocess
from dataclasses import dataclass
from typing import Optional
from concurrent.futures import ThreadPoolExecutor


@dataclass(frozen=True)
class NeighborStatus:
    ip: str
    reachable: bool
    rtt_ms: Optional[float]


@dataclass(frozen=True)
class SystemMetrics:
    cpu_pct: float
    mem_used_mb: float
    mem_total_mb: float
    mem_pct: float
    data_iface: str
    rx_bytes: int
    tx_bytes: int
    rx_drops: int
    tx_drops: int
    neighbors: list[NeighborStatus]


class MetricsCollector:
    _RTT_RE = re.compile(r"time=([0-9]+(?:\.[0-9]+)?)\s*ms", re.IGNORECASE)

    def __init__(
        self,
        data_ip: Optional[str] = None,
        data_iface: Optional[str] = None,
        peer_ips: Optional[list[str]] = None,
        proc_stat_path: str = "/proc/stat",
        proc_meminfo_path: str = "/proc/meminfo",
        proc_net_dev_path: str = "/proc/net/dev",
    ) -> None:
        self.data_ip = data_ip if data_ip is not None else os.getenv("DATA_IP", "")
        self.data_iface = data_iface if data_iface is not None else self._detect_data_iface()
        self.peer_ips = peer_ips if peer_ips is not None else self._default_peers()
        self.proc_stat_path = proc_stat_path
        self.proc_meminfo_path = proc_meminfo_path
        self.proc_net_dev_path = proc_net_dev_path
        self._prev_cpu: Optional[tuple[int, int]] = None  # (idle, total)

    def _detect_data_iface(self) -> str:
        if not self.data_ip:
            return "eth0"

        try:
            proc = subprocess.run(
                ["ip", "-o", "-4", "addr", "show"],
                capture_output=True,
                text=True,
                check=False,
                timeout=2,
            )
        except OSError:
            return "eth0"

        if proc.returncode != 0:
            return "eth0"

        target_cidr = f"{self.data_ip}/"
        for line in proc.stdout.splitlines():
            parts = line.split()
            # Format: "2: eth0    inet 172.29.0.10/24 brd ... scope global eth0"
            if len(parts) >= 4 and parts[2] == "inet":
                if any(tok == self.data_ip or tok.startswith(target_cidr) for tok in parts[3:]):
                    return parts[1].rstrip(":")

        return "eth0"

    def _default_peers(self) -> list[str]:
        all_ips = [f"172.29.0.{i}" for i in range(10, 15)]
        return [ip for ip in all_ips if ip != self.data_ip]

    def read_cpu_pct(self) -> float:
        with open(self.proc_stat_path, "r", encoding="utf-8") as f:
            first_line = f.readline().strip()

        parts = first_line.split()
        if not parts or parts[0] != "cpu" or len(parts) < 5:
            raise ValueError(f"Unexpected /proc/stat cpu line: {first_line!r}")

        values = [int(x) for x in parts[1:]]
        idle = values[3]
        iowait = values[4] if len(values) > 4 else 0
        idle_all = idle + iowait
        total = sum(values)

        if self._prev_cpu is None:
            self._prev_cpu = (idle_all, total)
            return 0.0

        prev_idle, prev_total = self._prev_cpu
        self._prev_cpu = (idle_all, total)

        delta_idle = idle_all - prev_idle
        delta_total = total - prev_total
        if delta_total <= 0:
            return 0.0

        pct = (1.0 - (delta_idle / delta_total)) * 100.0
        return max(0.0, min(100.0, pct))

    def read_mem_info(self) -> tuple[float, float, float]:
        mem_total_kb: Optional[int] = None
        mem_avail_kb: Optional[int] = None

        with open(self.proc_meminfo_path, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2:
                    continue
                if parts[0] == "MemTotal:":
                    mem_total_kb = int(parts[1])
                elif parts[0] == "MemAvailable:":
                    mem_avail_kb = int(parts[1])

                if mem_total_kb is not None and mem_avail_kb is not None:
                    break

        if mem_total_kb is None or mem_avail_kb is None:
            raise ValueError("Could not find MemTotal and MemAvailable in /proc/meminfo")

        total_mb = mem_total_kb / 1024.0
        used_mb = (mem_total_kb - mem_avail_kb) / 1024.0
        used_pct = ((mem_total_kb - mem_avail_kb) / mem_total_kb) * 100.0 if mem_total_kb > 0 else 0.0
        return used_mb, total_mb, used_pct

    def read_net_counters(self) -> dict[str, int]:
        with open(self.proc_net_dev_path, "r", encoding="utf-8") as f:
            for line in f:
                if ":" not in line:
                    continue
                iface_part, stats_part = line.split(":", 1)
                iface = iface_part.strip()
                if iface == self.data_iface:
                    cols = [int(x) for x in stats_part.split()]
                    if len(cols) < 12:
                        raise ValueError(f"Unexpected /proc/net/dev columns for {iface!r}")
                    return {
                        "rx_bytes": cols[0],
                        "tx_bytes": cols[8],
                        "rx_drops": cols[3],
                        "tx_drops": cols[11],
                    }

        raise KeyError(f"Interface {self.data_iface!r} not found in {self.proc_net_dev_path}")

    def _ping_one(self, ip: str) -> NeighborStatus :
        cmd = ["ping", "-I", self.data_iface, "-c", "1", "-W", "1", ip]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=2
            )
            reachable = proc.returncode == 0
            match = self._RTT_RE.search(proc.stdout)
            rtt_ms = float(match.group(1)) if match else None
        except (OSError, subprocess.TimeoutExpired):
            reachable = False
            rtt_ms = None 

        return NeighborStatus(ip=ip,reachable=reachable,rtt_ms=rtt_ms)
    



    def probe_neighbors(self) -> list[NeighborStatus]:
        results: list[NeighborStatus] = []
        
        for ip in self.peer_ips:
            results.append(self._ping_one(ip))
        
        return results

    def collect(self) -> SystemMetrics:
        cpu_pct = self.read_cpu_pct()
        mem_used_mb, mem_total_mb, mem_pct = self.read_mem_info()
        net = self.read_net_counters()
        neighbors = self.probe_neighbors()
        return SystemMetrics(
            cpu_pct=cpu_pct,
            mem_used_mb=mem_used_mb,
            mem_total_mb=mem_total_mb,
            mem_pct=mem_pct,
            data_iface=self.data_iface,
            rx_bytes=net["rx_bytes"],
            tx_bytes=net["tx_bytes"],
            rx_drops=net["rx_drops"],
            tx_drops=net["tx_drops"],
            neighbors=neighbors,
        )