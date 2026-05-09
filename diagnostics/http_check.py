"""
http_check.py — HTTP/HTTPS endpoint health checker.

Validates endpoint reachability, TLS certificates, response
codes, redirect chains, and response time. Critical for
application support scenarios where a web service is reported
as "down" or "slow".
"""

import urllib.request
import urllib.error
import urllib.parse
import ssl
import socket
import time
import json
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


@dataclass
class SSLInfo:
    valid: bool
    subject: Optional[str]
    issuer: Optional[str]
    expires: Optional[str]
    days_until_expiry: Optional[int]
    error: Optional[str] = None


@dataclass
class HTTPResult:
    url: str
    reachable: bool
    status_code: Optional[int]
    status_text: str
    response_ms: Optional[float]
    content_type: Optional[str]
    content_length_bytes: Optional[int]
    redirect_chain: list[str] = field(default_factory=list)
    final_url: Optional[str] = None
    ssl_info: Optional[SSLInfo] = None
    server_header: Optional[str] = None
    error: Optional[str] = None

    @property
    def status_category(self) -> str:
        if not self.status_code:
            return "error"
        if self.status_code < 300:
            return "success"
        if self.status_code < 400:
            return "redirect"
        if self.status_code < 500:
            return "client_error"
        return "server_error"


def check_ssl_certificate(hostname: str) -> SSLInfo:
    """
    Retrieve and validate the TLS certificate for a hostname.
    Checks expiry date and reports days remaining.
    """
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((hostname, 443), timeout=5),
            server_hostname=hostname
        ) as conn:
            cert = conn.getpeercert()

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer", []))
        expiry_str = cert.get("notAfter", "")

        expiry_dt = None
        days_left = None
        if expiry_str:
            expiry_dt = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry_dt - datetime.utcnow()).days

        return SSLInfo(
            valid=True,
            subject=subject.get("commonName"),
            issuer=issuer.get("organizationName"),
            expires=expiry_dt.strftime("%Y-%m-%d") if expiry_dt else None,
            days_until_expiry=days_left
        )

    except ssl.SSLCertVerificationError as e:
        return SSLInfo(valid=False, subject=None, issuer=None,
                       expires=None, days_until_expiry=None,
                       error=f"Certificate verification failed: {e}")
    except Exception as e:
        return SSLInfo(valid=False, subject=None, issuer=None,
                       expires=None, days_until_expiry=None,
                       error=str(e))


def check_endpoint(
    url: str,
    timeout: int = 10,
    follow_redirects: bool = True,
    check_ssl: bool = True
) -> HTTPResult:
    """
    Perform a full HTTP/HTTPS health check against a URL.
    Records status, latency, redirect chain, and SSL details.
    """
    # Normalise URL
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname
    redirect_chain = []

    # SSL check (HTTPS only)
    ssl_info = None
    if check_ssl and parsed.scheme == "https":
        ssl_info = check_ssl_certificate(hostname)

    # HTTP request
    start = time.monotonic()
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": (
                    "NetworkDiagnosticToolkit/1.0 "
                    "(Technical Support Engineer Tool; "
                    "github.com/sandrineuwineza/network-diagnostic-toolkit)"
                )
            }
        )

        ctx = ssl.create_default_context() if parsed.scheme == "https" else None
        # Allow self-signed in diagnostic mode
        if ctx:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            response_ms = round((time.monotonic() - start) * 1000, 2)
            final_url = response.geturl()
            status = response.status
            headers = response.headers

            content_length = None
            cl = headers.get("Content-Length")
            if cl:
                try:
                    content_length = int(cl)
                except ValueError:
                    pass

            return HTTPResult(
                url=url,
                reachable=True,
                status_code=status,
                status_text=_status_text(status),
                response_ms=response_ms,
                content_type=headers.get("Content-Type"),
                content_length_bytes=content_length,
                redirect_chain=redirect_chain,
                final_url=final_url if final_url != url else None,
                ssl_info=ssl_info,
                server_header=headers.get("Server")
            )

    except urllib.error.HTTPError as e:
        response_ms = round((time.monotonic() - start) * 1000, 2)
        return HTTPResult(
            url=url,
            reachable=True,
            status_code=e.code,
            status_text=_status_text(e.code),
            response_ms=response_ms,
            content_type=None,
            content_length_bytes=None,
            ssl_info=ssl_info,
            error=str(e.reason)
        )

    except urllib.error.URLError as e:
        return HTTPResult(
            url=url,
            reachable=False,
            status_code=None,
            status_text="Unreachable",
            response_ms=None,
            content_type=None,
            content_length_bytes=None,
            ssl_info=ssl_info,
            error=str(e.reason)
        )

    except Exception as e:
        return HTTPResult(
            url=url,
            reachable=False,
            status_code=None,
            status_text="Error",
            response_ms=None,
            content_type=None,
            content_length_bytes=None,
            error=str(e)
        )


def bulk_check(urls: list[str], timeout: int = 10) -> list[HTTPResult]:
    """Check multiple endpoints and return all results."""
    return [check_endpoint(url, timeout=timeout) for url in urls]


def _status_text(code: int) -> str:
    STATUS_MAP = {
        200: "OK", 201: "Created", 204: "No Content",
        301: "Moved Permanently", 302: "Found", 304: "Not Modified",
        400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
        404: "Not Found", 405: "Method Not Allowed",
        429: "Too Many Requests", 500: "Internal Server Error",
        502: "Bad Gateway", 503: "Service Unavailable",
        504: "Gateway Timeout",
    }
    return STATUS_MAP.get(code, f"HTTP {code}")
