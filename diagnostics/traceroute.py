"""
traceroute.py — Route tracing with hop-by-hop latency.

Uses subprocess to invoke the system traceroute/tracert command
and parses the output into a structured hop list. Falls back
to a pure-Python TCP-based implementation for restricted
environments.
"""

import subprocess
import platform
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Hop:
    number: int
    ip: Optional[str]
    hostname: Optional[str]
    latency_ms: list[float] = field(default_factory=list)
    timed_out: bool = False

    @property
    def avg_latency_ms(self) -> Optional[float]:
        if self.latency_ms:
            return round(sum(self.latency_ms) / len(self.latency_ms), 2)
        return None


@dataclass
class TracerouteResult:
    destination: str
    destination_ip: Optional[str]
    hops: list[Hop] = field(default_factory=list)
    reached: bool = False
    total_hops: int = 0
    error: Optional[str] = None


def traceroute(host: str, max_hops: int = 30, timeout: int = 3) -> TracerouteResult:
    """
    Trace the network path to a host using the system command.
    Parses output into structured Hop objects.
    """
    system = platform.system().lower()

    # Resolve destination IP
    try:
        dest_ip = socket.gethostbyname(host)
    except socket.gaierror:
        dest_ip = None

    result = TracerouteResult(destination=host, destination_ip=dest_ip)

    # Build platform-appropriate command
    if system == "windows":
        cmd = ["tracert", "-h", str(max_hops), "-w", str(timeout * 1000), host]
    elif system == "darwin":
        cmd = ["traceroute", "-m", str(max_hops), "-w", str(timeout), host]
    else:
        cmd = ["traceroute", "-m", str(max_hops), "-w", str(timeout),
               "-n", host]  # -n skips reverse DNS for speed

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max_hops * timeout + 10
        )
        output = proc.stdout + proc.stderr
        hops = _parse_traceroute_output(output, system)
        result.hops = hops
        result.total_hops = len(hops)
        result.reached = any(
            h.ip == dest_ip for h in hops if h.ip
        )

    except FileNotFoundError:
        # traceroute not available — use TCP fallback
        result = _tcp_traceroute(host, dest_ip, max_hops, timeout)

    except subprocess.TimeoutExpired:
        result.error = "Traceroute timed out"

    except Exception as e:
        result.error = str(e)

    return result


def _parse_traceroute_output(output: str, system: str) -> list[Hop]:
    """Parse system traceroute/tracert output into Hop objects."""
    hops = []

    if system == "windows":
        # Windows: "  1     1 ms     1 ms     1 ms  192.168.1.1"
        pattern = re.compile(
            r"^\s*(\d+)\s+((?:\d+\s*ms|\*)\s+(?:\d+\s*ms|\*)\s+(?:\d+\s*ms|\*))\s+([\d.]+|[\w.-]+)?",
            re.MULTILINE
        )
        for match in pattern.finditer(output):
            hop_num  = int(match.group(1))
            latency_str = match.group(2)
            addr = match.group(3)

            latencies = [
                float(m) for m in re.findall(r"(\d+)\s*ms", latency_str)
            ]
            timed_out = latency_str.count("*") >= 2

            hop = Hop(
                number=hop_num,
                ip=addr if addr and re.match(r"[\d.]+", addr) else None,
                hostname=addr if addr and not re.match(r"[\d.]+", addr) else None,
                latency_ms=latencies,
                timed_out=timed_out
            )
            hops.append(hop)

    else:
        # Unix: " 1  192.168.1.1  0.812 ms  0.543 ms  0.498 ms"
        for line in output.splitlines():
            line = line.strip()
            if not line or not line[0].isdigit():
                continue

            hop_num_match = re.match(r"^(\d+)", line)
            if not hop_num_match:
                continue

            hop_num = int(hop_num_match.group(1))
            timed_out = line.count("*") >= 2

            ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            latencies = [float(m) for m in re.findall(r"([\d.]+)\s*ms", line)]

            hop = Hop(
                number=hop_num,
                ip=ip_match.group(1) if ip_match else None,
                hostname=None,
                latency_ms=latencies,
                timed_out=timed_out
            )
            hops.append(hop)

    return hops


def _tcp_traceroute(
    host: str,
    dest_ip: Optional[str],
    max_hops: int,
    timeout: int
) -> TracerouteResult:
    """
    TCP-based path simulation — used when ICMP traceroute is
    unavailable. Attempts connections with increasing TTL simulation
    by probing via TCP to port 80.
    """
    result = TracerouteResult(
        destination=host,
        destination_ip=dest_ip,
        error="System traceroute unavailable. TCP path probe used."
    )

    # Simplified: just show final hop reachability
    for attempt in range(1, 4):
        start = time.monotonic()
        try:
            with socket.create_connection((host, 80), timeout=timeout):
                latency = round((time.monotonic() - start) * 1000, 2)
                hop = Hop(
                    number=attempt,
                    ip=dest_ip,
                    hostname=host,
                    latency_ms=[latency],
                    timed_out=False
                )
                result.hops.append(hop)
                result.reached = True
                break
        except Exception:
            hop = Hop(
                number=attempt, ip=None,
                hostname=None, timed_out=True
            )
            result.hops.append(hop)

    result.total_hops = len(result.hops)
    return result
