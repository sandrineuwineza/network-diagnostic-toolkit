"""
dns_check.py — DNS resolution validator.

Checks A, AAAA, MX, CNAME, and NS records for a given domain.
Also measures DNS resolution latency and validates against
multiple resolvers for consistency.
"""

import socket
import time
from dataclasses import dataclass, field
from typing import Optional


# Well-known public DNS resolvers for consistency check
PUBLIC_RESOLVERS = {
    "Google Primary":    "8.8.8.8",
    "Google Secondary":  "8.8.4.4",
    "Cloudflare":        "1.1.1.1",
    "OpenDNS":           "208.67.222.222",
}


@dataclass
class DNSRecord:
    record_type: str
    values: list[str]
    ttl: Optional[int] = None


@dataclass
class DNSResult:
    domain: str
    resolvable: bool
    resolution_ms: Optional[float]
    ipv4_addresses: list[str] = field(default_factory=list)
    ipv6_addresses: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    cname: Optional[str] = None
    nameservers: list[str] = field(default_factory=list)
    error: Optional[str] = None


def resolve_domain(domain: str) -> DNSResult:
    """
    Resolve a domain and collect all available record types.
    Uses the system default resolver.
    """
    start = time.monotonic()

    result = DNSResult(domain=domain, resolvable=False, resolution_ms=None)

    # A records (IPv4)
    try:
        addr_info = socket.getaddrinfo(domain, None, socket.AF_INET)
        result.ipv4_addresses = list({r[4][0] for r in addr_info})
        result.resolvable = True
        result.resolution_ms = round((time.monotonic() - start) * 1000, 2)
    except socket.gaierror as e:
        result.error = f"A record resolution failed: {e}"

    # AAAA records (IPv6)
    try:
        addr_info6 = socket.getaddrinfo(domain, None, socket.AF_INET6)
        result.ipv6_addresses = list({r[4][0] for r in addr_info6})
    except socket.gaierror:
        pass

    # MX records (requires dnspython if available, else skip)
    try:
        import dns.resolver
        mx_answers = dns.resolver.resolve(domain, "MX")
        result.mx_records = [str(r.exchange).rstrip(".") for r in mx_answers]
    except Exception:
        pass  # dnspython not required — MX left empty

    # NS records
    try:
        import dns.resolver
        ns_answers = dns.resolver.resolve(domain, "NS")
        result.nameservers = [str(r.target).rstrip(".") for r in ns_answers]
    except Exception:
        pass

    # CNAME
    try:
        import dns.resolver
        cname_answers = dns.resolver.resolve(domain, "CNAME")
        result.cname = str(cname_answers[0].target).rstrip(".")
    except Exception:
        pass

    return result


def bulk_dns_check(domains: list[str]) -> list[DNSResult]:
    """Resolve multiple domains and return all results."""
    return [resolve_domain(d) for d in domains]


def check_resolver_consistency(domain: str) -> dict[str, list[str]]:
    """
    Check whether multiple public DNS resolvers return the same
    IP addresses for a domain. Inconsistency can indicate DNS
    hijacking, propagation delay, or split-horizon DNS.
    """
    results = {}
    original_resolver = None

    for resolver_name, resolver_ip in PUBLIC_RESOLVERS.items():
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [resolver_ip]
            resolver.lifetime = 3
            answers = resolver.resolve(domain, "A")
            results[resolver_name] = sorted([r.address for r in answers])
        except Exception as e:
            results[resolver_name] = [f"ERROR: {e}"]

    return results


def format_dns_summary(result: DNSResult) -> str:
    """Return a human-readable summary of a DNS result."""
    lines = [f"Domain: {result.domain}"]
    lines.append(f"Resolvable: {'YES' if result.resolvable else 'NO'}")

    if result.resolution_ms:
        lines.append(f"Resolution time: {result.resolution_ms} ms")

    if result.ipv4_addresses:
        lines.append(f"IPv4 (A): {', '.join(result.ipv4_addresses)}")

    if result.ipv6_addresses:
        lines.append(f"IPv6 (AAAA): {result.ipv6_addresses[0]}")

    if result.mx_records:
        lines.append(f"MX: {', '.join(result.mx_records)}")

    if result.nameservers:
        lines.append(f"NS: {', '.join(result.nameservers)}")

    if result.cname:
        lines.append(f"CNAME: {result.cname}")

    if result.error:
        lines.append(f"Error: {result.error}")

    return "\n".join(lines)
