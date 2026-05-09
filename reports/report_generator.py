"""
report_generator.py — Structured incident report generator.

Converts diagnostic results into professional Markdown and
JSON reports suitable for ticket documentation, knowledge-base
articles, and post-incident reviews.
"""

import json
import os
from datetime import datetime, timezone
from typing import Optional
from dataclasses import asdict


def generate_markdown_report(
    target: str,
    ping_result=None,
    dns_result=None,
    port_results=None,
    http_results=None,
    traceroute_result=None,
    analyst: str = "Sandrine Uwineza",
    ticket_id: Optional[str] = None
) -> str:
    """
    Generate a professional Markdown incident diagnostic report.
    """
    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S UTC")
    date_str  = now.strftime("%Y-%m-%d")

    lines = [
        "# Network Diagnostic Report",
        "",
        f"| Field | Value |",
        f"|---|---|",
        f"| **Target** | `{target}` |",
        f"| **Generated** | {timestamp} |",
        f"| **Analyst** | {analyst} |",
    ]

    if ticket_id:
        lines.append(f"| **Ticket ID** | {ticket_id} |")

    lines.append("")
    lines.append("---")
    lines.append("")

    # Executive summary
    lines.append("## Executive Summary")
    lines.append("")

    summary_items = []
    if ping_result:
        status = "✅ Reachable" if ping_result.reachable else "❌ Unreachable"
        latency = f" ({ping_result.latency_ms} ms avg)" if ping_result.latency_ms else ""
        summary_items.append(f"- **Connectivity:** {status}{latency}")
        summary_items.append(f"- **Packet Loss:** {ping_result.packet_loss_pct}%")

    if dns_result:
        dns_status = "✅ Resolves" if dns_result.resolvable else "❌ DNS Failure"
        summary_items.append(f"- **DNS Resolution:** {dns_status}")
        if dns_result.ipv4_addresses:
            summary_items.append(f"- **IPv4:** {', '.join(dns_result.ipv4_addresses)}")

    if http_results:
        for hr in http_results:
            icon = "✅" if hr.reachable and hr.status_code and hr.status_code < 400 else "❌"
            code = f" {hr.status_code}" if hr.status_code else ""
            ms   = f" ({hr.response_ms} ms)" if hr.response_ms else ""
            summary_items.append(f"- **HTTP{code}:** {icon} {hr.status_text}{ms} — `{hr.url}`")

    lines.extend(summary_items)
    lines.append("")
    lines.append("---")
    lines.append("")

    # Ping section
    if ping_result:
        lines.append("## 1. Connectivity (Ping)")
        lines.append("")
        lines.append(f"| Parameter | Value |")
        lines.append(f"|---|---|")
        lines.append(f"| Host | `{ping_result.host}` |")
        lines.append(f"| Method | {ping_result.method} |")
        lines.append(f"| Reachable | {'Yes ✅' if ping_result.reachable else 'No ❌'} |")
        lines.append(f"| Latency (avg) | {f'{ping_result.latency_ms} ms' if ping_result.latency_ms else 'N/A'} |")
        lines.append(f"| Packets Sent | {ping_result.packets_sent} |")
        lines.append(f"| Packets Received | {ping_result.packets_received} |")
        lines.append(f"| Packet Loss | {ping_result.packet_loss_pct}% |")
        if ping_result.error:
            lines.append(f"| Error | {ping_result.error} |")
        lines.append("")

    # DNS section
    if dns_result:
        lines.append("## 2. DNS Resolution")
        lines.append("")
        lines.append(f"| Parameter | Value |")
        lines.append(f"|---|---|")
        lines.append(f"| Domain | `{dns_result.domain}` |")
        lines.append(f"| Resolvable | {'Yes ✅' if dns_result.resolvable else 'No ❌'} |")
        lines.append(f"| Resolution Time | {f'{dns_result.resolution_ms} ms' if dns_result.resolution_ms else 'N/A'} |")
        if dns_result.ipv4_addresses:
            lines.append(f"| A Records (IPv4) | {', '.join(f'`{ip}`' for ip in dns_result.ipv4_addresses)} |")
        if dns_result.ipv6_addresses:
            lines.append(f"| AAAA Records (IPv6) | `{dns_result.ipv6_addresses[0]}` |")
        if dns_result.mx_records:
            lines.append(f"| MX Records | {', '.join(dns_result.mx_records)} |")
        if dns_result.nameservers:
            lines.append(f"| Nameservers | {', '.join(dns_result.nameservers)} |")
        if dns_result.error:
            lines.append(f"| Error | ⚠️ {dns_result.error} |")
        lines.append("")

    # Port scan section
    if port_results:
        lines.append("## 3. Port Scan")
        lines.append("")
        open_ports   = [r for r in port_results if r.state == "open"]
        closed_ports = [r for r in port_results if r.state == "closed"]
        filtered     = [r for r in port_results if r.state == "filtered"]

        lines.append(f"**Summary:** {len(open_ports)} open · {len(closed_ports)} closed · {len(filtered)} filtered")
        lines.append("")

        if open_ports:
            lines.append("### Open Ports")
            lines.append("")
            lines.append("| Port | Service | Latency | Banner |")
            lines.append("|---|---|---|---|")
            for r in open_ports:
                banner = f"`{r.banner[:40]}...`" if r.banner and len(r.banner) > 40 else (f"`{r.banner}`" if r.banner else "—")
                lines.append(f"| {r.port} | {r.service} | {r.latency_ms} ms | {banner} |")
            lines.append("")

        if closed_ports or filtered:
            lines.append("### Closed / Filtered Ports")
            lines.append("")
            lines.append("| Port | Service | State |")
            lines.append("|---|---|---|")
            for r in closed_ports + filtered:
                lines.append(f"| {r.port} | {r.service} | {r.state} |")
            lines.append("")

    # HTTP section
    if http_results:
        lines.append("## 4. HTTP/HTTPS Health")
        lines.append("")
        for hr in http_results:
            icon = "✅" if hr.reachable and hr.status_code and hr.status_code < 400 else "❌"
            lines.append(f"### {icon} `{hr.url}`")
            lines.append("")
            lines.append(f"| Parameter | Value |")
            lines.append(f"|---|---|")
            lines.append(f"| Status | {hr.status_code} — {hr.status_text} |")
            lines.append(f"| Response Time | {f'{hr.response_ms} ms' if hr.response_ms else 'N/A'} |")
            if hr.content_type:
                lines.append(f"| Content-Type | {hr.content_type} |")
            if hr.server_header:
                lines.append(f"| Server | {hr.server_header} |")
            if hr.final_url:
                lines.append(f"| Redirected To | `{hr.final_url}` |")
            if hr.ssl_info:
                ssl = hr.ssl_info
                ssl_status = "Valid ✅" if ssl.valid else f"Invalid ❌ ({ssl.error})"
                lines.append(f"| TLS Certificate | {ssl_status} |")
                if ssl.subject:
                    lines.append(f"| TLS Subject | {ssl.subject} |")
                if ssl.expires:
                    expiry_warn = " ⚠️ EXPIRING SOON" if ssl.days_until_expiry and ssl.days_until_expiry < 30 else ""
                    lines.append(f"| TLS Expires | {ssl.expires} ({ssl.days_until_expiry} days){expiry_warn} |")
            if hr.error:
                lines.append(f"| Error | ⚠️ {hr.error} |")
            lines.append("")

    # Traceroute section
    if traceroute_result:
        lines.append("## 5. Traceroute")
        lines.append("")
        dest = traceroute_result.destination
        dest_ip = traceroute_result.destination_ip or "unresolved"
        reached = "Yes ✅" if traceroute_result.reached else "No ❌"
        lines.append(f"**Destination:** `{dest}` ({dest_ip})  |  **Reached:** {reached}  |  **Total hops:** {traceroute_result.total_hops}")
        lines.append("")

        if traceroute_result.hops:
            lines.append("| Hop | IP Address | Avg Latency | Status |")
            lines.append("|---|---|---|---|")
            for hop in traceroute_result.hops:
                ip = f"`{hop.ip}`" if hop.ip else "* * *"
                latency = f"{hop.avg_latency_ms} ms" if hop.avg_latency_ms else "timeout"
                status = "⏱️ Timeout" if hop.timed_out else "✅"
                lines.append(f"| {hop.number} | {ip} | {latency} | {status} |")
            lines.append("")

        if traceroute_result.error:
            lines.append(f"> ⚠️ Note: {traceroute_result.error}")
            lines.append("")

    # Footer
    lines.append("---")
    lines.append("")
    lines.append(f"*Report generated by [Network Diagnostic Toolkit](https://github.com/sandrineuwineza/network-diagnostic-toolkit) · {timestamp}*")

    return "\n".join(lines)


def generate_json_report(
    target: str,
    ping_result=None,
    dns_result=None,
    port_results=None,
    http_results=None,
    traceroute_result=None
) -> dict:
    """Generate a structured JSON report for API consumption."""
    return {
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ping": _safe_dict(ping_result),
        "dns": _safe_dict(dns_result),
        "ports": [_safe_dict(r) for r in (port_results or [])],
        "http": [_safe_dict(r) for r in (http_results or [])],
        "traceroute": _safe_dict(traceroute_result),
    }


def save_report(content: str, path: str, fmt: str = "md") -> str:
    """Save a report to disk and return the absolute path."""
    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return os.path.abspath(path)


def _safe_dict(obj) -> Optional[dict]:
    if obj is None:
        return None
    try:
        return asdict(obj)
    except Exception:
        return {"value": str(obj)}
