"""
diagnostics package — Network Diagnostic Toolkit

Exports the core diagnostic functions for use in both
the CLI (main.py) and the web dashboard (app.py).
"""

from .ping        import ping_icmp, ping_tcp, ping_sweep, PingResult
from .dns_check   import resolve_domain, bulk_dns_check, DNSResult
from .port_scanner import scan_ports, scan_common, scan_port_group, PortResult
from .http_check  import check_endpoint, bulk_check, HTTPResult
from .traceroute  import traceroute, TracerouteResult

__all__ = [
    "ping_icmp", "ping_tcp", "ping_sweep", "PingResult",
    "resolve_domain", "bulk_dns_check", "DNSResult",
    "scan_ports", "scan_common", "scan_port_group", "PortResult",
    "check_endpoint", "bulk_check", "HTTPResult",
    "traceroute", "TracerouteResult",
]

__version__ = "1.0.0"
__author__  = "Sandrine Uwineza"
