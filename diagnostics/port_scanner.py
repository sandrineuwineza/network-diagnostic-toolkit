"""
port_scanner.py — TCP port connectivity scanner.

Checks whether TCP ports are open, closed, or filtered.
Includes a curated list of well-known service port mappings
relevant to IT support and network engineering.
"""

import socket
import time
import concurrent.futures
from dataclasses import dataclass
from typing import Optional


# Common ports a Technical Support Engineer would check
WELL_KNOWN_PORTS: dict[int, str] = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    67:   "DHCP Server",
    68:   "DHCP Client",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    161:  "SNMP",
    389:  "LDAP",
    443:  "HTTPS",
    445:  "SMB",
    465:  "SMTPS",
    587:  "SMTP (Submission)",
    636:  "LDAPS",
    993:  "IMAPS",
    995:  "POP3S",
    1194: "OpenVPN",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Alt",
    8443: "HTTPS Alt",
    8888: "Jupyter",
    27017:"MongoDB",
}

PORT_GROUPS = {
    "web":      [80, 443, 8080, 8443],
    "remote":   [22, 23, 3389, 5900],
    "database": [1433, 1521, 3306, 5432, 6379, 27017],
    "mail":     [25, 110, 143, 465, 587, 993, 995],
    "common":   [22, 25, 53, 80, 443, 3389, 8080],
}


@dataclass
class PortResult:
    host: str
    port: int
    service: str
    state: str            # "open" | "closed" | "filtered"
    latency_ms: Optional[float]
    banner: Optional[str] = None


def scan_port(host: str, port: int, timeout: float = 2.0) -> PortResult:
    """
    Attempt a TCP connection to a single port.
    Returns open/closed/filtered based on the result.
    """
    service = WELL_KNOWN_PORTS.get(port, "unknown")
    start = time.monotonic()

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            latency_ms = round((time.monotonic() - start) * 1000, 2)

            # Attempt banner grab (best-effort)
            banner = None
            try:
                sock.settimeout(1.0)
                raw = sock.recv(256)
                banner = raw.decode("utf-8", errors="replace").strip()
            except Exception:
                pass

            return PortResult(
                host=host,
                port=port,
                service=service,
                state="open",
                latency_ms=latency_ms,
                banner=banner
            )

    except ConnectionRefusedError:
        return PortResult(
            host=host, port=port, service=service,
            state="closed", latency_ms=None
        )
    except (socket.timeout, OSError):
        return PortResult(
            host=host, port=port, service=service,
            state="filtered", latency_ms=None
        )


def scan_ports(
    host: str,
    ports: list[int],
    timeout: float = 2.0,
    max_workers: int = 50
) -> list[PortResult]:
    """
    Scan multiple ports concurrently using a thread pool.
    Returns results sorted by port number.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_port, host, port, timeout): port
            for port in ports
        }
        results = []
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    return sorted(results, key=lambda r: r.port)


def scan_port_group(host: str, group: str, timeout: float = 2.0) -> list[PortResult]:
    """
    Scan a named group of ports (e.g., 'web', 'database', 'mail').
    """
    if group not in PORT_GROUPS:
        raise ValueError(
            f"Unknown group '{group}'. "
            f"Valid groups: {', '.join(PORT_GROUPS.keys())}"
        )
    return scan_ports(host, PORT_GROUPS[group], timeout)


def scan_common(host: str) -> list[PortResult]:
    """Scan the most commonly checked ports in IT support scenarios."""
    return scan_ports(host, PORT_GROUPS["common"])


def open_ports_summary(results: list[PortResult]) -> dict:
    """Return a structured summary of scan results."""
    open_ports   = [r for r in results if r.state == "open"]
    closed_ports = [r for r in results if r.state == "closed"]
    filtered     = [r for r in results if r.state == "filtered"]

    return {
        "total_scanned": len(results),
        "open":          len(open_ports),
        "closed":        len(closed_ports),
        "filtered":      len(filtered),
        "open_services": [
            {"port": r.port, "service": r.service, "latency_ms": r.latency_ms}
            for r in open_ports
        ]
    }
