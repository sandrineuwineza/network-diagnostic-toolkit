"""
target_guard.py — input validation and abuse protection for diagnostic targets.

The web dashboard runs every check from the server it is deployed on. Without
these guards, a public deployment could be used to:

  * pass options to the system ping/traceroute binaries (a host such as "-f"),
  * probe private networks or cloud metadata services (169.254.169.254) that
    are reachable from the server but not from the internet (SSRF).

Private, loopback, link-local and reserved addresses are blocked by default.
When running the toolkit on your own machine to diagnose your own network,
set ALLOW_PRIVATE_TARGETS=1 to allow them.

Known limitation: a hostname is resolved here and again by the diagnostic
itself, so a domain whose DNS answer changes between the two lookups (DNS
rebinding) is not fully covered. Rate limiting the public demo is recommended.
"""

import ipaddress
import os
import re
import socket
from urllib.parse import urlsplit

# RFC 1123 hostname: labels of 1–63 letters, digits or hyphens, not starting or
# ending with a hyphen, 253 characters at most, optional trailing dot.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)


class TargetError(ValueError):
    """Raised when a diagnostic target is malformed or not allowed."""


def private_targets_allowed() -> bool:
    return os.environ.get("ALLOW_PRIVATE_TARGETS", "0") == "1"


def _parse_ip(host: str):
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def _ensure_public(host: str) -> None:
    """Reject hosts that are, or resolve to, non-public addresses."""
    ip = _parse_ip(host)
    candidates = [ip] if ip else []
    if not ip:
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror:
            return  # Unresolvable: the diagnostic itself will report the failure.
        candidates = [_parse_ip(info[4][0].split("%")[0]) for info in infos]

    for address in candidates:
        if address is not None and not address.is_global:
            raise TargetError(
                "Private, loopback and reserved addresses cannot be checked on this "
                "deployment. Run the toolkit locally with ALLOW_PRIVATE_TARGETS=1 "
                "to diagnose your own network."
            )


def validate_host(host: str, *, check_public: bool = True) -> str:
    """Return a cleaned hostname or IP address, or raise TargetError."""
    host = (host or "").strip()
    if not host:
        raise TargetError("host is required")
    if host.startswith("-"):
        raise TargetError("invalid host")
    if _parse_ip(host) is None and not _HOSTNAME_RE.match(host):
        raise TargetError("invalid host: use a domain name or an IP address")
    if check_public and not private_targets_allowed():
        _ensure_public(host)
    return host


def validate_url(url: str) -> str:
    """Return a URL with an http(s) scheme whose host passes validate_host()."""
    url = (url or "").strip()
    if not url:
        raise TargetError("url is required")
    candidate = url if "://" in url else f"https://{url}"
    parts = urlsplit(candidate)
    if parts.scheme not in ("http", "https"):
        raise TargetError("only http and https URLs can be checked")
    validate_host(parts.hostname or "")
    return candidate
