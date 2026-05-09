"""
test_diagnostics.py — Unit and integration tests for Network Diagnostic Toolkit.

Run with:  python -m pytest tests/ -v
"""

import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from diagnostics.ping        import ping_tcp, PingResult
from diagnostics.dns_check   import resolve_domain, bulk_dns_check, format_dns_summary
from diagnostics.port_scanner import scan_port, scan_ports, open_ports_summary, WELL_KNOWN_PORTS
from diagnostics.http_check  import check_endpoint, _status_text
from reports.report_generator import generate_markdown_report, generate_json_report


# ── DNS Tests ────────────────────────────────────────────────────────────────

class TestDNS:
    def test_resolve_known_domain(self):
        result = resolve_domain("google.com")
        assert result.resolvable is True
        assert len(result.ipv4_addresses) > 0
        assert result.resolution_ms is not None

    def test_resolve_invalid_domain(self):
        result = resolve_domain("this-domain-absolutely-does-not-exist-xyz123.com")
        assert result.resolvable is False
        assert result.error is not None

    def test_bulk_dns_check(self):
        domains = ["google.com", "github.com"]
        results = bulk_dns_check(domains)
        assert len(results) == 2
        assert all(r.resolvable for r in results)

    def test_format_summary(self):
        result = resolve_domain("google.com")
        summary = format_dns_summary(result)
        assert "google.com" in summary
        assert "Resolvable" in summary


# ── Port Scanner Tests ────────────────────────────────────────────────────────

class TestPortScanner:
    def test_scan_open_port(self):
        """Port 80/443 on a public server should be open."""
        result = scan_port("google.com", 80, timeout=5)
        assert result.port == 80
        assert result.state in ("open", "filtered")  # might be redirected

    def test_scan_closed_port(self):
        """High uncommon port should be closed."""
        result = scan_port("google.com", 39999, timeout=3)
        assert result.state in ("closed", "filtered")

    def test_scan_multiple_ports(self):
        results = scan_ports("google.com", [80, 443], timeout=5)
        assert len(results) == 2
        assert results[0].port < results[1].port  # sorted

    def test_summary(self):
        results = scan_ports("google.com", [80, 443, 39999], timeout=5)
        summary = open_ports_summary(results)
        assert "total_scanned" in summary
        assert summary["total_scanned"] == 3

    def test_well_known_ports_mapping(self):
        assert WELL_KNOWN_PORTS[80]  == "HTTP"
        assert WELL_KNOWN_PORTS[443] == "HTTPS"
        assert WELL_KNOWN_PORTS[22]  == "SSH"


# ── HTTP Tests ────────────────────────────────────────────────────────────────

class TestHTTP:
    def test_check_valid_endpoint(self):
        result = check_endpoint("https://httpbin.org/get", timeout=10)
        assert result.reachable is True
        assert result.status_code == 200
        assert result.response_ms is not None

    def test_check_http_not_found(self):
        result = check_endpoint("https://httpbin.org/status/404", timeout=10)
        assert result.status_code == 404

    def test_check_unreachable_host(self):
        result = check_endpoint("https://this-host-does-not-exist-xyz.com", timeout=3)
        assert result.reachable is False
        assert result.error is not None

    def test_url_normalisation(self):
        """Should add https:// when scheme is missing."""
        result = check_endpoint("httpbin.org/get", timeout=10)
        assert result.url.startswith("https://")

    def test_status_text(self):
        assert _status_text(200) == "OK"
        assert _status_text(404) == "Not Found"
        assert _status_text(503) == "Service Unavailable"
        assert _status_text(999) == "HTTP 999"  # unknown code


# ── TCP Ping Tests ────────────────────────────────────────────────────────────

class TestPing:
    def test_tcp_ping_reachable(self):
        result = ping_tcp("google.com", port=80, timeout=5)
        assert result.reachable is True
        assert result.latency_ms is not None
        assert result.latency_ms > 0

    def test_tcp_ping_unreachable(self):
        result = ping_tcp("this-host-does-not-exist-xyz123.com", timeout=2)
        assert result.reachable is False

    def test_ping_result_structure(self):
        result = ping_tcp("google.com", port=80)
        assert isinstance(result, PingResult)
        assert result.packets_sent == 1


# ── Report Generator Tests ────────────────────────────────────────────────────

class TestReports:
    def test_markdown_report_no_data(self):
        report = generate_markdown_report(target="test.com")
        assert "# Network Diagnostic Report" in report
        assert "test.com" in report

    def test_json_report_structure(self):
        report = generate_json_report(target="test.com")
        assert report["target"] == "test.com"
        assert "timestamp" in report
        assert "ping" in report
        assert "dns" in report
        assert "ports" in report
        assert "http" in report
        assert "traceroute" in report

    def test_markdown_with_dns(self):
        dns_result = resolve_domain("google.com")
        report = generate_markdown_report(
            target="google.com",
            dns_result=dns_result
        )
        assert "DNS Resolution" in report
        assert "google.com" in report

    def test_ticket_id_in_report(self):
        report = generate_markdown_report(
            target="example.com",
            ticket_id="INC-2026-0042"
        )
        assert "INC-2026-0042" in report


# ── Flask App Tests ───────────────────────────────────────────────────────────

class TestFlaskApp:
    @pytest.fixture
    def client(self):
        from app import app
        app.config["TESTING"] = True
        with app.test_client() as c:
            yield c

    def test_index_returns_200(self, client):
        r = client.get("/")
        assert r.status_code == 200

    def test_health_endpoint(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        data = r.get_json()
        assert data["status"] == "healthy"

    def test_api_dns_missing_domain(self, client):
        r = client.post("/api/dns", json={})
        assert r.status_code == 400

    def test_api_ping_missing_host(self, client):
        r = client.post("/api/ping", json={})
        assert r.status_code == 400

    def test_api_ports_invalid_group(self, client):
        r = client.post("/api/ports", json={"host": "google.com", "group": "invalid_group"})
        assert r.status_code == 400
