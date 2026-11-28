"""Host and interface metrics read from /proc and /sys (one sample per collect() call).

Peer reachability is *not* measured here: the ActiveProber owns probing and reports it to
the control plane over gRPC, so pinging neighbours on every 1s tick would only duplicate it.
"""
from dataclasses import dataclass, field
import os
from pathlib import Path
import subprocess
import threading
from typing import Optional

# /sys/class/net/<if>/operstate -> network_interfaces.oper_status
_OPER_STATE_MAP = {"up": "up", "down": "down", "lowerlayerdown": "down", "dormant": "dormant"}


@dataclass(frozen=True)
class InterfaceStats:
    name: str
    mac: str
    ips: list[str]
    oper_status: str
    rx_bytes: int
    tx_bytes: int
    rx_errors: int
    tx_errors: int
    rx_drops: int
    tx_drops: int


@dataclass(frozen=True)
class SystemMetrics:
    cpu_pct: float
    mem_used_mb: float
    mem_total_mb: float
    mem_pct: float
    uptime_sec: float
    data_iface: str
    rx_bytes: int
    tx_bytes: int
    rx_drops: int
    tx_drops: int
    interfaces: list[InterfaceStats] = field(default_factory=list)


def parse_proc_net_dev(text: str) -> dict[str, list[int]]:
    """Returns {iface: [16 counters]} from /proc/net/dev content."""
    counters: dict[str, list[int]] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        iface_part, stats_part = line.split(":", 1)
        cols = [int(x) for x in stats_part.split()]
        if len(cols) >= 12:
            counters[iface_part.strip()] = cols
    return counters


def parse_ip_addr(text: str) -> dict[str, list[str]]:
    """Returns {iface: [ipv4, ...]} from `ip -o -4 addr show` output."""
    addrs: dict[str, list[str]] = {}
    for line in text.splitlines():
        # "2: eth0    inet 172.29.0.10/24 brd 172.29.0.255 scope global eth0"
        parts = line.split()
        if len(parts) >= 4 and parts[2] == "inet":
            addrs.setdefault(parts[1].rstrip(":").split("@")[0], []).append(parts[3].split("/")[0])
    return addrs


class MetricsCollector:
    def __init__(
        self,
        data_ip: Optional[str] = None,
        data_iface: Optional[str] = None,
        proc_stat_path: str = "/proc/stat",
        proc_meminfo_path: str = "/proc/meminfo",
        proc_net_dev_path: str = "/proc/net/dev",
        proc_uptime_path: str = "/proc/uptime",
        sys_class_net_path: str = "/sys/class/net",
    ) -> None:
        self.data_ip = data_ip if data_ip is not None else os.getenv("DATA_IP", "")
        self.proc_stat_path = proc_stat_path
        self.proc_meminfo_path = proc_meminfo_path
        self.proc_net_dev_path = proc_net_dev_path
        self.proc_uptime_path = proc_uptime_path
        self.sys_class_net = Path(sys_class_net_path)
        self._prev_cpu: Optional[tuple[int, int]] = None  # (idle, total)
        self._latest: Optional[SystemMetrics] = None
        self._lock = threading.Lock()
        self.data_iface = data_iface if data_iface is not None else self._detect_data_iface()

    # --- interface discovery ---

    def _read_ipv4_addrs(self) -> dict[str, list[str]]:
        try:
            proc = subprocess.run(
                ["ip", "-o", "-4", "addr", "show"],
                capture_output=True,
                text=True,
                check=False,
                timeout=2,
            )
        except (OSError, subprocess.TimeoutExpired):
            return {}
        return parse_ip_addr(proc.stdout) if proc.returncode == 0 else {}

    def _detect_data_iface(self) -> str:
        if self.data_ip:
            for iface, ips in self._read_ipv4_addrs().items():
                if self.data_ip in ips:
                    return iface
        return "eth0"

    def _read_sys(self, iface: str, attr: str, default: str) -> str:
        try:
            return (self.sys_class_net / iface / attr).read_text(encoding="utf-8").strip() or default
        except OSError:
            return default

    # --- host metrics ---

    def read_cpu_pct(self) -> float:
        with open(self.proc_stat_path, "r", encoding="utf-8") as f:
            first_line = f.readline().strip()

        parts = first_line.split()
        if not parts or parts[0] != "cpu" or len(parts) < 5:
            raise ValueError(f"Unexpected /proc/stat cpu line: {first_line!r}")

        values = [int(x) for x in parts[1:]]
        idle_all = values[3] + (values[4] if len(values) > 4 else 0)
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
        return max(0.0, min(100.0, (1.0 - (delta_idle / delta_total)) * 100.0))

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

    def read_uptime_sec(self) -> float:
        with open(self.proc_uptime_path, "r", encoding="utf-8") as f:
            raw = f.read().strip().split()
        if not raw:
            raise ValueError(f"Empty {self.proc_uptime_path}")
        uptime = float(raw[0])
        if uptime < 0:
            raise ValueError(f"Negative uptime in {self.proc_uptime_path}: {uptime}")
        return uptime

    # --- interface metrics ---

    def read_interfaces(self) -> list[InterfaceStats]:
        with open(self.proc_net_dev_path, "r", encoding="utf-8") as f:
            counters = parse_proc_net_dev(f.read())
        addrs = self._read_ipv4_addrs()

        stats: list[InterfaceStats] = []
        for iface in sorted(counters):
            if iface == "lo":
                continue
            c = counters[iface]
            oper = self._read_sys(iface, "operstate", "up").lower()
            stats.append(
                InterfaceStats(
                    name=iface,
                    mac=self._read_sys(iface, "address", "00:00:00:00:00:00"),
                    ips=addrs.get(iface, []),
                    oper_status=_OPER_STATE_MAP.get(oper, "up"),
                    rx_bytes=c[0],
                    rx_errors=c[2],
                    rx_drops=c[3],
                    tx_bytes=c[8],
                    tx_errors=c[10],
                    tx_drops=c[11],
                )
            )
        return stats

    def read_net_counters(self) -> dict[str, int]:
        """DATA_NET interface counters (kept as top-level fields of each tick)."""
        with open(self.proc_net_dev_path, "r", encoding="utf-8") as f:
            counters = parse_proc_net_dev(f.read())
        if self.data_iface not in counters:
            raise KeyError(f"Interface {self.data_iface!r} not found in {self.proc_net_dev_path}")
        c = counters[self.data_iface]
        return {"rx_bytes": c[0], "tx_bytes": c[8], "rx_drops": c[3], "tx_drops": c[11]}

    # --- sampling ---

    def collect(self) -> SystemMetrics:
        with self._lock:
            cpu_pct = self.read_cpu_pct()
            mem_used_mb, mem_total_mb, mem_pct = self.read_mem_info()
            interfaces = self.read_interfaces()
            data = next((i for i in interfaces if i.name == self.data_iface), None)
            if data is None:
                raise KeyError(f"Interface {self.data_iface!r} not found in {self.proc_net_dev_path}")
            metrics = SystemMetrics(
                cpu_pct=cpu_pct,
                mem_used_mb=mem_used_mb,
                mem_total_mb=mem_total_mb,
                mem_pct=mem_pct,
                uptime_sec=self.read_uptime_sec(),
                data_iface=self.data_iface,
                rx_bytes=data.rx_bytes,
                tx_bytes=data.tx_bytes,
                rx_drops=data.rx_drops,
                tx_drops=data.tx_drops,
                interfaces=interfaces,
            )
            self._latest = metrics
            return metrics

    def latest(self) -> Optional[SystemMetrics]:
        """Most recent sample from collect(). Readers use this instead of re-reading /proc/stat,
        whose CPU delta state belongs to the collector loop."""
        return self._latest
