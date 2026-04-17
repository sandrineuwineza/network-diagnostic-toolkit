"""
ping.py — ICMP ping and TCP-based reachability checker.

Uses subprocess for ICMP ping (platform-aware) and falls back
to TCP socket for environments without raw socket privileges
(e.g., shared hosting, Railway containers).
"""

import subprocess
import socket
import time
import platform
from dataclasses import dataclass
from typing import Optional


@dataclass
class PingResult:
    host: str
    reachable: bool
    method: str           # "icmp" or "tcp"
    latency_ms: Optional[float]
    packet_loss_pct: float
    packets_sent: int
    packets_received: int
    error: Optional[str] = None


def ping_icmp(host: str, count: int = 4, timeout: int = 3) -> PingResult:
    """
    Run a platform-aware ICMP ping using the system ping command.
    Works on Linux, macOS, and Windows.
    """
    system = platform.system().lower()

    if system == "windows":
        cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), host]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(timeout), host]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout * count + 5
        )
        output = result.stdout + result.stderr

        # Parse latency
        latency = _parse_latency(output, system)

        # Parse packet loss
        loss = _parse_packet_loss(output)

        received = int(round(count * (1 - loss / 100)))
        reachable = result.returncode == 0 and received > 0

        return PingResult(
            host=host,
            reachable=reachable,
            method="icmp",
            latency_ms=latency,
            packet_loss_pct=loss,
            packets_sent=count,
            packets_received=received
        )

    except subprocess.TimeoutExpired:
        return PingResult(
            host=host,
            reachable=False,
            method="icmp",
            latency_ms=None,
            packet_loss_pct=100.0,
            packets_sent=count,
            packets_received=0,
            error="Ping timed out"
        )
    except Exception as e:
        return ping_tcp(host)  # Graceful fallback


def ping_tcp(host: str, port: int = 80, timeout: int = 3) -> PingResult:
    """
    TCP-based connectivity check — used as fallback when ICMP
    is not available (containerised environments, Railway, etc.).
    """
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency_ms = (time.monotonic() - start) * 1000
            return PingResult(
                host=host,
                reachable=True,
                method=f"tcp:{port}",
                latency_ms=round(latency_ms, 2),
                packet_loss_pct=0.0,
                packets_sent=1,
                packets_received=1
            )
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return PingResult(
            host=host,
            reachable=False,
            method=f"tcp:{port}",
            latency_ms=None,
            packet_loss_pct=100.0,
            packets_sent=1,
            packets_received=0,
            error=str(e)
        )


def ping_sweep(hosts: list[str], count: int = 4) -> list[PingResult]:
    """
    Run ping diagnostics against a list of hosts.
    Returns results in order.
    """
    results = []
    for host in hosts:
        result = ping_icmp(host, count=count)
        results.append(result)
    return results


def _parse_latency(output: str, system: str) -> Optional[float]:
    """Extract average round-trip time from ping output."""
    import re
    if system == "windows":
        match = re.search(r"Average = (\d+)ms", output)
        return float(match.group(1)) if match else None
    else:
        match = re.search(r"(?:rtt|round-trip)[^=]*=\s*[\d.]+/([\d.]+)", output)
        return float(match.group(1)) if match else None


def _parse_packet_loss(output: str) -> float:
    """Extract packet loss percentage from ping output."""
    import re
    match = re.search(r"(\d+(?:\.\d+)?)%\s*packet loss", output)
    return float(match.group(1)) if match else 100.0
