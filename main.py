#!/usr/bin/env python3
"""
main.py — Network Diagnostic Toolkit CLI

A systematic network troubleshooting tool for Technical Support
Engineers. Run individual diagnostic modules or a full sweep
with a single command.

Author:  Sandrine Uwineza
GitHub:  github.com/sandrineuwineza/network-diagnostic-toolkit
License: MIT
"""

import argparse
import sys
import json
import os
from datetime import datetime


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netdiag",
        description=(
            "Network Diagnostic Toolkit — systematic troubleshooting "
            "for Technical Support Engineers"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full diagnostic sweep
  python main.py --host google.com --all

  # Ping + DNS only
  python main.py --host 8.8.8.8 --ping --dns

  # Port scan with specific ports
  python main.py --host example.com --ports 80 443 22 3306

  # HTTP health check
  python main.py --url https://example.com --http

  # Full sweep and save report
  python main.py --host google.com --all --report reports/output.md
        """
    )

    # Target
    target = parser.add_argument_group("Target")
    target.add_argument("--host", "-H",   help="Hostname or IP address to diagnose")
    target.add_argument("--url",  "-u",   help="URL for HTTP health check")
    target.add_argument("--urls",         nargs="+", help="Multiple URLs for bulk HTTP check")
    target.add_argument("--hosts",        nargs="+", help="Multiple hosts for ping sweep")

    # Diagnostics
    diag = parser.add_argument_group("Diagnostics")
    diag.add_argument("--all",            action="store_true", help="Run all diagnostics")
    diag.add_argument("--ping",           action="store_true", help="ICMP/TCP ping test")
    diag.add_argument("--dns",            action="store_true", help="DNS resolution check")
    diag.add_argument("--ports",          nargs="+", type=int, metavar="PORT", help="TCP port scan")
    diag.add_argument("--port-group",     choices=["web","remote","database","mail","common"],
                                          help="Scan a named port group")
    diag.add_argument("--http",           action="store_true", help="HTTP/HTTPS health check")
    diag.add_argument("--traceroute",     action="store_true", help="Traceroute / path trace")

    # Options
    opts = parser.add_argument_group("Options")
    opts.add_argument("--count",          type=int, default=4, help="Ping packet count (default: 4)")
    opts.add_argument("--timeout",        type=int, default=3, help="Timeout per probe in seconds (default: 3)")
    opts.add_argument("--max-hops",       type=int, default=30, help="Max traceroute hops (default: 30)")

    # Output
    out = parser.add_argument_group("Output")
    out.add_argument("--report",          metavar="FILE", help="Save Markdown report to file")
    out.add_argument("--json",            action="store_true", help="Output raw JSON to stdout")
    out.add_argument("--quiet", "-q",     action="store_true", help="Suppress progress output")
    out.add_argument("--analyst",         default="Sandrine Uwineza", help="Analyst name for report")
    out.add_argument("--ticket",          help="Ticket ID to include in report header")

    return parser


def run_diagnostics(args) -> dict:
    """Execute the requested diagnostic modules and return results."""
    from diagnostics import (
        ping_icmp, resolve_domain, scan_ports, scan_port_group,
        scan_common, check_endpoint, bulk_check, traceroute
    )
    from reports import generate_markdown_report, generate_json_report, save_report

    host = args.host
    results = {}

    run_all = args.all

    # ── Ping ──────────────────────────────────────────────────────────────────
    if (run_all or args.ping) and host:
        _print(args, f"\n🔍 Pinging {host}...")
        result = ping_icmp(host, count=args.count, timeout=args.timeout)
        results["ping"] = result
        if not args.json:
            _print_ping(args, result)

    # ── DNS ───────────────────────────────────────────────────────────────────
    if (run_all or args.dns) and host:
        _print(args, f"\n🌐 Resolving DNS for {host}...")
        result = resolve_domain(host)
        results["dns"] = result
        if not args.json:
            _print_dns(args, result)

    # ── Port Scan ─────────────────────────────────────────────────────────────
    if host:
        port_results = None
        if args.ports:
            _print(args, f"\n🔌 Scanning ports {args.ports} on {host}...")
            port_results = scan_ports(host, args.ports, timeout=args.timeout)
        elif args.port_group:
            _print(args, f"\n🔌 Scanning '{args.port_group}' port group on {host}...")
            port_results = scan_port_group(host, args.port_group, timeout=args.timeout)
        elif run_all:
            _print(args, f"\n🔌 Scanning common ports on {host}...")
            port_results = scan_common(host)

        if port_results:
            results["ports"] = port_results
            if not args.json:
                _print_ports(args, port_results)

    # ── HTTP Check ────────────────────────────────────────────────────────────
    http_results = None
    if run_all or args.http:
        urls_to_check = []
        if args.urls:
            urls_to_check = args.urls
        elif args.url:
            urls_to_check = [args.url]
        elif host:
            urls_to_check = [f"https://{host}", f"http://{host}"]

        if urls_to_check:
            _print(args, f"\n📡 Checking HTTP endpoints...")
            http_results = bulk_check(urls_to_check, timeout=args.timeout)
            results["http"] = http_results
            if not args.json:
                _print_http(args, http_results)

    # ── Traceroute ────────────────────────────────────────────────────────────
    if (run_all or args.traceroute) and host:
        _print(args, f"\n🗺️  Tracing route to {host}...")
        result = traceroute(host, max_hops=args.max_hops, timeout=args.timeout)
        results["traceroute"] = result
        if not args.json:
            _print_traceroute(args, result)

    # ── Report Generation ─────────────────────────────────────────────────────
    if results:
        report_data = generate_json_report(
            target=host or args.url or "unknown",
            ping_result=results.get("ping"),
            dns_result=results.get("dns"),
            port_results=results.get("ports"),
            http_results=results.get("http"),
            traceroute_result=results.get("traceroute")
        )

        if args.json:
            print(json.dumps(report_data, indent=2, default=str))

        if args.report:
            md = generate_markdown_report(
                target=host or args.url or "unknown",
                ping_result=results.get("ping"),
                dns_result=results.get("dns"),
                port_results=results.get("ports"),
                http_results=results.get("http"),
                traceroute_result=results.get("traceroute"),
                analyst=args.analyst,
                ticket_id=args.ticket
            )
            path = save_report(md, args.report)
            _print(args, f"\n✅ Report saved to: {path}")

    return results


# ── Terminal Output Formatters ─────────────────────────────────────────────────

def _print(args, msg: str):
    if not args.quiet:
        print(msg)


def _print_ping(args, r):
    status = "✅ REACHABLE" if r.reachable else "❌ UNREACHABLE"
    _print(args, f"   {status} via {r.method}")
    if r.latency_ms:
        _print(args, f"   Latency: {r.latency_ms} ms avg")
    _print(args, f"   Packet loss: {r.packet_loss_pct}% ({r.packets_received}/{r.packets_sent} received)")
    if r.error:
        _print(args, f"   ⚠️  {r.error}")


def _print_dns(args, r):
    status = "✅ RESOLVES" if r.resolvable else "❌ FAILED"
    _print(args, f"   {status} in {r.resolution_ms} ms")
    if r.ipv4_addresses:
        _print(args, f"   A records: {', '.join(r.ipv4_addresses)}")
    if r.ipv6_addresses:
        _print(args, f"   AAAA:       {r.ipv6_addresses[0]}")
    if r.mx_records:
        _print(args, f"   MX:         {', '.join(r.mx_records)}")
    if r.error:
        _print(args, f"   ⚠️  {r.error}")


def _print_ports(args, results):
    open_ports = [r for r in results if r.state == "open"]
    _print(args, f"   {len(open_ports)}/{len(results)} ports open")
    for r in results:
        icon = {"open": "✅", "closed": "❌", "filtered": "🔶"}.get(r.state, "?")
        latency = f" ({r.latency_ms} ms)" if r.latency_ms else ""
        _print(args, f"   {icon} {r.port:5d}/tcp  {r.service:<20} {r.state}{latency}")


def _print_http(args, results):
    for r in results:
        icon = "✅" if r.reachable and r.status_code and r.status_code < 400 else "❌"
        code = f" {r.status_code}" if r.status_code else ""
        ms   = f" ({r.response_ms} ms)" if r.response_ms else ""
        _print(args, f"   {icon} {r.url}")
        _print(args, f"      Status: {r.status_text}{code}{ms}")
        if r.ssl_info and r.ssl_info.valid:
            _print(args, f"      TLS:    Valid — expires {r.ssl_info.expires} ({r.ssl_info.days_until_expiry} days)")
        elif r.ssl_info and not r.ssl_info.valid:
            _print(args, f"      TLS:    ⚠️  {r.ssl_info.error}")
        if r.error:
            _print(args, f"      Error:  {r.error}")


def _print_traceroute(args, r):
    dest = f"{r.destination} ({r.destination_ip})" if r.destination_ip else r.destination
    reached = "✅ Reached" if r.reached else "❌ Not reached"
    _print(args, f"   {reached} — {r.total_hops} hops to {dest}")
    for hop in r.hops:
        ip = hop.ip or "* * *"
        latency = f"{hop.avg_latency_ms} ms" if hop.avg_latency_ms else "timeout"
        _print(args, f"   {hop.number:3d}  {ip:<20}  {latency}")


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not (args.host or args.url or args.urls or args.hosts):
        parser.print_help()
        sys.exit(0)

    print("\n" + "═" * 60)
    print("  Network Diagnostic Toolkit — github.com/sandrineuwineza")
    print("═" * 60)
    print(f"  Target:  {args.host or args.url or 'see --host/--url'}")
    print(f"  Time:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("═" * 60)

    try:
        run_diagnostics(args)
    except KeyboardInterrupt:
        print("\n\n⚠️  Diagnostic interrupted by user.")
        sys.exit(1)

    print("\n" + "═" * 60 + "\n")


if __name__ == "__main__":
    main()
