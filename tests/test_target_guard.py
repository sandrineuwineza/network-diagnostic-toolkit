"""Tests for diagnostics.target_guard: input validation and SSRF protection."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app import app  # noqa: E402
from diagnostics.target_guard import TargetError, validate_host, validate_url  # noqa: E402


@pytest.fixture(autouse=True)
def public_mode(monkeypatch):
    """Tests run as a public deployment unless a test opts in to private targets."""
    monkeypatch.delenv("ALLOW_PRIVATE_TARGETS", raising=False)


class TestValidateHost:
    @pytest.mark.parametrize("host", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
    def test_public_ips_allowed(self, host):
        assert validate_host(host) == host

    @pytest.mark.parametrize(
        "host",
        ["127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1", "169.254.169.254", "::1", "0.0.0.0"],
    )
    def test_non_public_ips_blocked(self, host):
        with pytest.raises(TargetError):
            validate_host(host)

    @pytest.mark.parametrize("host", ["-f", "-c 1000 example.com", "exa mple.com", "bad_host!", "a" * 300])
    def test_malformed_hosts_rejected(self, host):
        with pytest.raises(TargetError):
            validate_host(host)

    def test_empty_host_rejected(self):
        with pytest.raises(TargetError):
            validate_host("   ")

    def test_private_allowed_when_opted_in(self, monkeypatch):
        monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "1")
        assert validate_host("192.168.1.1") == "192.168.1.1"

    def test_format_only_check_skips_public_rule(self):
        assert validate_host("10.0.0.5", check_public=False) == "10.0.0.5"


class TestValidateUrl:
    def test_scheme_added_when_missing(self):
        assert validate_url("8.8.8.8/health") == "https://8.8.8.8/health"

    @pytest.mark.parametrize("url", ["ftp://8.8.8.8", "file:///etc/passwd", "gopher://8.8.8.8"])
    def test_non_http_schemes_rejected(self, url):
        with pytest.raises(TargetError):
            validate_url(url)

    def test_cloud_metadata_url_blocked(self):
        with pytest.raises(TargetError):
            validate_url("http://169.254.169.254/latest/meta-data/")


class TestApiGuards:
    @pytest.fixture
    def client(self):
        app.config["TESTING"] = True
        with app.test_client() as c:
            yield c

    @pytest.mark.parametrize("endpoint", ["/api/ping", "/api/ports", "/api/traceroute", "/api/full-scan"])
    def test_loopback_target_rejected(self, client, endpoint):
        r = client.post(endpoint, json={"host": "127.0.0.1"})
        assert r.status_code == 400
        assert "error" in r.get_json()

    def test_option_injection_rejected(self, client):
        r = client.post("/api/ping", json={"host": "-f"})
        assert r.status_code == 400

    def test_metadata_url_rejected(self, client):
        r = client.post("/api/http", json={"url": "http://169.254.169.254/latest/meta-data/"})
        assert r.status_code == 400

    def test_non_numeric_limit_returns_400(self, client):
        r = client.post("/api/ping", json={"host": "8.8.8.8", "count": "many"})
        assert r.status_code == 400
