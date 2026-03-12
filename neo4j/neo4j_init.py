"""
AEGIS Phase 3 – Neo4j Graph Schema Initialiser

Idempotent: safe to rerun. Uses MERGE throughout so nodes and
relationships are created only if absent, and updated in-place if
already present.

Usage
-----
    python neo4j_init.py

Environment variables
---------------------
    NEO4J_URL       bolt://neo4j:7687  (default)
    NEO4J_USER      neo4j              (default)
    NEO4J_PASSWORD  neo4j
"""

from __future__ import annotations

import os
import sys
import textwrap
from datetime import datetime, timezone
from typing import Any

from dotenv import load_dotenv
from neo4j import GraphDatabase, Driver

load_dotenv()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

NEO4J_URL      = os.getenv("NEO4J_URL",      "bolt://neo4j:7687")
NEO4J_USER     = os.getenv("NEO4J_USER",     "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "neo4j")

if not NEO4J_PASSWORD:
    sys.exit("ERROR: NEO4J_PASSWORD environment variable is required.")


# ---------------------------------------------------------------------------
# Schema: constraints
# ---------------------------------------------------------------------------

CONSTRAINTS = [
    ("Asset_id_unique",           "Asset",        "id"),
    ("Vulnerability_cve_unique",  "Vulnerability", "cve_id"),
    ("ThreatActor_name_unique",   "ThreatActor",  "name"),
    ("TTP_mitre_id_unique",       "TTP",          "mitre_id"),
    ("AttackPath_id_unique",      "AttackPath",   "id"),
]


# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------

# ── Assets (15) ─────────────────────────────────────────────────────────────
# criticality: 1 (low) → 5 (mission-critical)
ASSETS: list[dict[str, Any]] = [
    # Web tier
    dict(id="AS-001", name="web-prod-01",   type="web_server",   os="Ubuntu 22.04",  criticality=3, sector="finance",   ip="10.10.1.11"),
    dict(id="AS-002", name="web-prod-02",   type="web_server",   os="Ubuntu 22.04",  criticality=3, sector="finance",   ip="10.10.1.12"),
    dict(id="AS-003", name="api-gateway-01",type="api_gateway",  os="Ubuntu 22.04",  criticality=4, sector="finance",   ip="10.10.1.20"),

    # Database tier
    dict(id="AS-004", name="db-primary-01", type="database",     os="RHEL 9.2",      criticality=5, sector="finance",   ip="10.10.2.11"),
    dict(id="AS-005", name="db-replica-01", type="database",     os="RHEL 9.2",      criticality=4, sector="finance",   ip="10.10.2.12"),
    dict(id="AS-006", name="db-analytics",  type="database",     os="Windows Server 2022", criticality=3, sector="finance", ip="10.10.2.20"),

    # Identity / AD
    dict(id="AS-007", name="dc-primary",    type="domain_controller", os="Windows Server 2022", criticality=5, sector="finance", ip="10.10.3.10"),
    dict(id="AS-008", name="dc-secondary",  type="domain_controller", os="Windows Server 2022", criticality=5, sector="finance", ip="10.10.3.11"),
    dict(id="AS-009", name="adfs-01",       type="identity_provider", os="Windows Server 2019", criticality=4, sector="finance", ip="10.10.3.20"),

    # Network access
    dict(id="AS-010", name="vpn-gw-01",     type="vpn_gateway",  os="FortiOS 7.4",   criticality=4, sector="finance",   ip="203.0.113.10"),
    dict(id="AS-011", name="vpn-gw-02",     type="vpn_gateway",  os="FortiOS 7.4",   criticality=4, sector="finance",   ip="203.0.113.11"),

    # Workstations
    dict(id="AS-012", name="ws-exec-001",   type="workstation",  os="Windows 11",    criticality=3, sector="finance",   ip="10.10.5.101"),
    dict(id="AS-013", name="ws-dev-042",    type="workstation",  os="macOS 14",      criticality=2, sector="finance",   ip="10.10.5.142"),
    dict(id="AS-014", name="ws-ops-007",    type="workstation",  os="Windows 11",    criticality=2, sector="finance",   ip="10.10.5.107"),

    # Build / CI
    dict(id="AS-015", name="ci-runner-01",  type="build_server", os="Ubuntu 22.04",  criticality=3, sector="finance",   ip="10.10.6.10"),
]

# ── Vulnerabilities (assigned to assets below) ───────────────────────────────
VULNERABILITIES: list[dict[str, Any]] = [
    dict(cve_id="CVE-2024-21762", cvss=9.8,  epss=0.93, description="Fortinet FortiOS out-of-bounds write in SSL-VPN (unauthenticated RCE)"),
    dict(cve_id="CVE-2024-21893", cvss=8.2,  epss=0.81, description="Ivanti Connect Secure SSRF in SAML component"),
    dict(cve_id="CVE-2023-46805", cvss=8.2,  epss=0.97, description="Ivanti Connect Secure authentication bypass"),
    dict(cve_id="CVE-2024-3400",  cvss=10.0, epss=0.98, description="PAN-OS GlobalProtect command injection (CVSS 10 — actively exploited)"),
    dict(cve_id="CVE-2023-34362", cvss=9.8,  epss=0.96, description="MOVEit Transfer SQL injection (CL0P ransomware campaign)"),
    dict(cve_id="CVE-2024-1709",  cvss=10.0, epss=0.95, description="ConnectWise ScreenConnect authentication bypass"),
    dict(cve_id="CVE-2022-47966", cvss=9.8,  epss=0.88, description="Zoho ManageEngine multiple products unauthenticated RCE"),
    dict(cve_id="CVE-2023-27350", cvss=9.8,  epss=0.94, description="PaperCut NG/MF authentication bypass with RCE"),
    dict(cve_id="CVE-2024-21887", cvss=9.1,  epss=0.92, description="Ivanti Connect Secure command injection (chained with CVE-2023-46805)"),
    dict(cve_id="CVE-2023-42793", cvss=9.8,  epss=0.89, description="JetBrains TeamCity authentication bypass (pre-auth RCE)"),
    dict(cve_id="CVE-2023-44487", cvss=7.5,  epss=0.88, description="HTTP/2 Rapid Reset DDoS (affects nginx, Apache, IIS)"),
    dict(cve_id="CVE-2024-23897", cvss=9.8,  epss=0.86, description="Jenkins arbitrary file read via CLI (path-traversal to RCE)"),
    dict(cve_id="CVE-2021-44228", cvss=10.0, epss=0.99, description="Log4Shell — Apache Log4j2 JNDI RCE (ubiquitous Java logging)"),
    dict(cve_id="CVE-2023-4966",  cvss=9.4,  epss=0.97, description="Citrix Bleed — NetScaler sensitive token disclosure (session hijack)"),
    dict(cve_id="CVE-2024-0519",  cvss=8.8,  epss=0.72, description="Google Chromium V8 OOB memory access (browser-side initial access)"),
]

# ── Asset → Vulnerability mapping ───────────────────────────────────────────
ASSET_VULNS: list[tuple[str, str]] = [
    # VPN gateways – FortiOS CVE
    ("AS-010", "CVE-2024-21762"),
    ("AS-011", "CVE-2024-21762"),
    # API gateway – HTTP/2 Rapid Reset
    ("AS-003", "CVE-2023-44487"),
    # Web servers – Log4Shell (Java app stack), HTTP/2
    ("AS-001", "CVE-2021-44228"),
    ("AS-001", "CVE-2023-44487"),
    ("AS-002", "CVE-2021-44228"),
    # DB analytics – Windows + ManageEngine
    ("AS-006", "CVE-2022-47966"),
    # Domain controllers – HTTP/2 (IIS), Citrix Bleed
    ("AS-007", "CVE-2023-44487"),
    ("AS-008", "CVE-2023-4966"),
    # ADFS – token disclosure
    ("AS-009", "CVE-2023-4966"),
    # CI runner – Jenkins, TeamCity, Log4Shell
    ("AS-015", "CVE-2024-23897"),
    ("AS-015", "CVE-2023-42793"),
    ("AS-015", "CVE-2021-44228"),
    # Executive workstation – browser vuln
    ("AS-012", "CVE-2024-0519"),
]

# ── Threat Actors (5) ────────────────────────────────────────────────────────
THREAT_ACTORS: list[dict[str, Any]] = [
    dict(
        name="Volt Typhoon",
        aliases=["BRONZE SILHOUETTE", "Dev-0391"],
        sector_targets=["government", "defense", "utilities", "communications", "finance"],
        nation_state=True,
        active=True,
    ),
    dict(
        name="APT29",
        aliases=["Cozy Bear", "Midnight Blizzard", "The Dukes"],
        sector_targets=["government", "defense", "technology", "healthcare", "finance"],
        nation_state=True,
        active=True,
    ),
    dict(
        name="Lazarus Group",
        aliases=["HIDDEN COBRA", "Zinc", "APT38"],
        sector_targets=["finance", "cryptocurrency", "defense", "government"],
        nation_state=True,
        active=True,
    ),
    dict(
        name="LockBit",
        aliases=["LockBit 3.0", "ABCD"],
        sector_targets=["finance", "healthcare", "manufacturing", "legal", "government"],
        nation_state=False,
        active=True,
    ),
    dict(
        name="BlackCat",
        aliases=["ALPHV", "Noberus"],
        sector_targets=["finance", "healthcare", "energy", "retail"],
        nation_state=False,
        active=True,
    ),
]

# ── TTPs (20 from MITRE ATT&CK) ─────────────────────────────────────────────
TTPS: list[dict[str, Any]] = [
    # Initial Access
    dict(mitre_id="T1190",    tactic="Initial Access",         technique="Exploit Public-Facing Application",   platform=["Linux", "Windows", "Network"]),
    dict(mitre_id="T1133",    tactic="Initial Access",         technique="External Remote Services",            platform=["Linux", "Windows", "Network"]),
    dict(mitre_id="T1566.001",tactic="Initial Access",         technique="Phishing: Spearphishing Attachment",  platform=["Linux", "Windows", "macOS"]),
    dict(mitre_id="T1566.002",tactic="Initial Access",         technique="Phishing: Spearphishing Link",        platform=["Linux", "Windows", "macOS"]),
    dict(mitre_id="T1195.002",tactic="Initial Access",         technique="Supply Chain Compromise: Software",   platform=["Linux", "Windows", "macOS"]),

    # Execution
    dict(mitre_id="T1059.001",tactic="Execution",              technique="Command and Scripting: PowerShell",   platform=["Windows"]),
    dict(mitre_id="T1059.004",tactic="Execution",              technique="Command and Scripting: Unix Shell",   platform=["Linux", "macOS"]),
    dict(mitre_id="T1053.005",tactic="Execution",              technique="Scheduled Task/Job: Scheduled Task",  platform=["Windows"]),

    # Persistence
    dict(mitre_id="T1078",    tactic="Persistence",            technique="Valid Accounts",                      platform=["Linux", "Windows", "macOS", "Cloud"]),
    dict(mitre_id="T1505.003",tactic="Persistence",            technique="Server Software Component: Web Shell",platform=["Linux", "Windows"]),

    # Privilege Escalation
    dict(mitre_id="T1068",    tactic="Privilege Escalation",   technique="Exploitation for Privilege Escalation",platform=["Linux", "Windows", "macOS"]),
    dict(mitre_id="T1134",    tactic="Privilege Escalation",   technique="Access Token Manipulation",           platform=["Windows"]),

    # Credential Access
    dict(mitre_id="T1003.001",tactic="Credential Access",      technique="OS Credential Dumping: LSASS Memory", platform=["Windows"]),
    dict(mitre_id="T1555.003",tactic="Credential Access",      technique="Credentials from Password Stores: Browser", platform=["Linux", "Windows", "macOS"]),

    # Lateral Movement
    dict(mitre_id="T1021.001",tactic="Lateral Movement",       technique="Remote Services: Remote Desktop Protocol", platform=["Windows"]),
    dict(mitre_id="T1021.002",tactic="Lateral Movement",       technique="Remote Services: SMB/Windows Admin Shares", platform=["Windows"]),
    dict(mitre_id="T1550.002",tactic="Lateral Movement",       technique="Use Alternate Auth: Pass the Hash",   platform=["Windows"]),

    # Collection / Exfiltration
    dict(mitre_id="T1005",    tactic="Collection",             technique="Data from Local System",              platform=["Linux", "Windows", "macOS"]),
    dict(mitre_id="T1041",    tactic="Exfiltration",           technique="Exfiltration Over C2 Channel",        platform=["Linux", "Windows", "macOS"]),

    # Impact
    dict(mitre_id="T1486",    tactic="Impact",                 technique="Data Encrypted for Impact (Ransomware)", platform=["Linux", "Windows", "macOS"]),
]

# ── Threat Actor → TTP assignments ──────────────────────────────────────────
# (actor_name, [mitre_ids])
ACTOR_TTPS: list[tuple[str, list[str]]] = [
    ("Volt Typhoon", [
        "T1190", "T1133", "T1078", "T1505.003",
        "T1021.001", "T1021.002", "T1005",
    ]),
    ("APT29", [
        "T1566.001", "T1566.002", "T1078", "T1059.001",
        "T1053.005", "T1003.001", "T1550.002", "T1041",
    ]),
    ("Lazarus Group", [
        "T1195.002", "T1566.001", "T1059.001", "T1068",
        "T1134", "T1003.001", "T1005", "T1041",
    ]),
    ("LockBit", [
        "T1190", "T1133", "T1059.001", "T1078",
        "T1068", "T1550.002", "T1486",
    ]),
    ("BlackCat", [
        "T1190", "T1566.001", "T1059.001", "T1059.004",
        "T1068", "T1003.001", "T1021.001", "T1486",
    ]),
]

# ── TTP PRECEDES chains (mitre_id_from, mitre_id_to, transition_probability)
# Represents realistic kill-chain progressions seen in incident reports.
TTP_PRECEDES: list[tuple[str, str, float]] = [
    # Initial Access → Execution
    ("T1190",     "T1059.001", 0.65),
    ("T1190",     "T1059.004", 0.55),
    ("T1190",     "T1505.003", 0.70),
    ("T1133",     "T1059.001", 0.60),
    ("T1133",     "T1078",     0.80),
    ("T1566.001", "T1059.001", 0.50),
    ("T1566.002", "T1555.003", 0.45),
    ("T1195.002", "T1059.001", 0.75),

    # Execution → Persistence
    ("T1059.001", "T1078",     0.55),
    ("T1059.001", "T1053.005", 0.40),
    ("T1059.004", "T1505.003", 0.60),
    ("T1505.003", "T1078",     0.65),

    # Persistence → Privilege Escalation
    ("T1078",     "T1068",     0.45),
    ("T1078",     "T1134",     0.50),
    ("T1053.005", "T1068",     0.35),

    # Privilege Escalation → Credential Access
    ("T1068",     "T1003.001", 0.75),
    ("T1134",     "T1003.001", 0.80),
    ("T1068",     "T1555.003", 0.40),

    # Credential Access → Lateral Movement
    ("T1003.001", "T1550.002", 0.85),
    ("T1003.001", "T1021.001", 0.70),
    ("T1550.002", "T1021.002", 0.75),
    ("T1555.003", "T1021.001", 0.45),

    # Lateral Movement → Collection
    ("T1021.001", "T1005",     0.70),
    ("T1021.002", "T1005",     0.65),

    # Collection → Exfiltration / Impact
    ("T1005",     "T1041",     0.60),
    ("T1005",     "T1486",     0.50),
    ("T1041",     "T1486",     0.30),  # exfil then ransomware (double-extortion)
]

# ── Attack Paths (representative simulation scenarios) ───────────────────────
ATTACK_PATHS: list[dict[str, Any]] = [
    dict(
        id="AP-001",
        name="VPN Exploit → DC Compromise",
        steps=["T1190", "T1059.004", "T1078", "T1068", "T1003.001", "T1550.002", "T1021.002"],
        success_probability=0.28,
        target_asset_ids=["AS-010", "AS-007"],
    ),
    dict(
        id="AP-002",
        name="Spearphish → Credential Harvest → Lateral",
        steps=["T1566.001", "T1059.001", "T1555.003", "T1078", "T1021.001", "T1005"],
        success_probability=0.19,
        target_asset_ids=["AS-012", "AS-007", "AS-004"],
    ),
    dict(
        id="AP-003",
        name="Supply Chain → CI Runner → Source Exfil",
        steps=["T1195.002", "T1059.001", "T1053.005", "T1068", "T1005", "T1041"],
        success_probability=0.15,
        target_asset_ids=["AS-015", "AS-004"],
    ),
    dict(
        id="AP-004",
        name="Web Shell Persistence → Ransomware",
        steps=["T1190", "T1505.003", "T1078", "T1068", "T1003.001", "T1550.002", "T1005", "T1486"],
        success_probability=0.22,
        target_asset_ids=["AS-001", "AS-004", "AS-006"],
    ),
]


# ---------------------------------------------------------------------------
# Schema creation
# ---------------------------------------------------------------------------

def create_constraints(driver: Driver) -> None:
    print("\n── Constraints ─────────────────────────────────────────────────────")
    with driver.session() as s:
        for name, label, prop in CONSTRAINTS:
            s.run(textwrap.dedent(f"""
                CREATE CONSTRAINT {name} IF NOT EXISTS
                FOR (n:{label}) REQUIRE n.{prop} IS UNIQUE
            """))
            print(f"  ✓ {label}.{prop}")


# ---------------------------------------------------------------------------
# Node creation helpers
# ---------------------------------------------------------------------------

def _merge_nodes(driver: Driver, label: str, key_prop: str,
                 nodes: list[dict], extra_props: list[str]) -> int:
    """Generic MERGE-and-SET for a node list. Returns count of nodes processed."""
    set_clause = ", ".join(f"n.{p} = row.{p}" for p in extra_props)
    cypher = textwrap.dedent(f"""
        UNWIND $rows AS row
        MERGE (n:{label} {{{key_prop}: row.{key_prop}}})
        SET {set_clause}
    """)
    with driver.session() as s:
        s.run(cypher, rows=nodes)
    return len(nodes)


def create_assets(driver: Driver) -> int:
    n = _merge_nodes(driver, "Asset", "id", ASSETS,
                     ["name", "type", "os", "criticality", "sector", "ip"])
    print(f"  ✓ Asset            × {n}")
    return n


def create_vulnerabilities(driver: Driver) -> int:
    n = _merge_nodes(driver, "Vulnerability", "cve_id", VULNERABILITIES,
                     ["cvss", "epss", "description"])
    print(f"  ✓ Vulnerability    × {n}")
    return n


def create_threat_actors(driver: Driver) -> int:
    n = _merge_nodes(driver, "ThreatActor", "name", THREAT_ACTORS,
                     ["aliases", "sector_targets", "nation_state", "active"])
    print(f"  ✓ ThreatActor      × {n}")
    return n


def create_ttps(driver: Driver) -> int:
    n = _merge_nodes(driver, "TTP", "mitre_id", TTPS,
                     ["tactic", "technique", "platform"])
    print(f"  ✓ TTP              × {n}")
    return n


def create_attack_paths(driver: Driver) -> int:
    now = datetime.now(timezone.utc).isoformat()
    rows = [
        {
            "id":                   ap["id"],
            "name":                 ap["name"],
            "steps":                ap["steps"],
            "success_probability":  ap["success_probability"],
            "simulation_run_at":    now,
        }
        for ap in ATTACK_PATHS
    ]
    n = _merge_nodes(driver, "AttackPath", "id", rows,
                     ["name", "steps", "success_probability", "simulation_run_at"])
    print(f"  ✓ AttackPath       × {n}")
    return n


# ---------------------------------------------------------------------------
# Relationship creation
# ---------------------------------------------------------------------------

def create_asset_vuln_rels(driver: Driver) -> int:
    rows = [{"asset_id": a, "cve_id": c} for a, c in ASSET_VULNS]
    with driver.session() as s:
        s.run(textwrap.dedent("""
            UNWIND $rows AS row
            MATCH (a:Asset          {id:     row.asset_id})
            MATCH (v:Vulnerability  {cve_id: row.cve_id})
            MERGE (a)-[:HAS_VULNERABILITY]->(v)
        """), rows=rows)
    print(f"  ✓ HAS_VULNERABILITY × {len(rows)}")
    return len(rows)


def create_actor_ttp_rels(driver: Driver) -> int:
    rows = [
        {"actor": actor, "mitre_id": mid}
        for actor, mids in ACTOR_TTPS
        for mid in mids
    ]
    with driver.session() as s:
        s.run(textwrap.dedent("""
            UNWIND $rows AS row
            MATCH (a:ThreatActor {name:     row.actor})
            MATCH (t:TTP         {mitre_id: row.mitre_id})
            MERGE (a)-[:USES]->(t)
        """), rows=rows)
    print(f"  ✓ USES             × {len(rows)}")
    return len(rows)


def create_ttp_precedes_rels(driver: Driver) -> int:
    rows = [
        {"from_id": f, "to_id": t, "prob": p}
        for f, t, p in TTP_PRECEDES
    ]
    with driver.session() as s:
        s.run(textwrap.dedent("""
            UNWIND $rows AS row
            MATCH (a:TTP {mitre_id: row.from_id})
            MATCH (b:TTP {mitre_id: row.to_id})
            MERGE (a)-[r:PRECEDES]->(b)
            SET r.transition_probability = row.prob
        """), rows=rows)
    print(f"  ✓ PRECEDES         × {len(rows)}")
    return len(rows)


def create_attack_path_rels(driver: Driver) -> int:
    # TARGETS
    target_rows = [
        {"path_id": ap["id"], "asset_id": asset_id}
        for ap in ATTACK_PATHS
        for asset_id in ap["target_asset_ids"]
    ]
    with driver.session() as s:
        s.run(textwrap.dedent("""
            UNWIND $rows AS row
            MATCH (p:AttackPath {id: row.path_id})
            MATCH (a:Asset      {id: row.asset_id})
            MERGE (p)-[:TARGETS]->(a)
        """), rows=target_rows)
    print(f"  ✓ TARGETS          × {len(target_rows)}")

    # USES_TTP
    ttp_rows = [
        {"path_id": ap["id"], "mitre_id": mid}
        for ap in ATTACK_PATHS
        for mid in ap["steps"]
    ]
    with driver.session() as s:
        s.run(textwrap.dedent("""
            UNWIND $rows AS row
            MATCH (p:AttackPath {id:       row.path_id})
            MATCH (t:TTP        {mitre_id: row.mitre_id})
            MERGE (p)-[:USES_TTP]->(t)
        """), rows=ttp_rows)
    print(f"  ✓ USES_TTP         × {len(ttp_rows)}")

    return len(target_rows) + len(ttp_rows)


# ---------------------------------------------------------------------------
# Summary query
# ---------------------------------------------------------------------------

def print_summary(driver: Driver) -> None:
    print("\n── Graph Summary ───────────────────────────────────────────────────")
    with driver.session() as s:
        # Node counts by label
        result = s.run("""
            CALL apoc.meta.stats()
            YIELD labels
            RETURN labels
        """)
        row = result.single()
        if row:
            for label, count in sorted(row["labels"].items()):
                if count > 0:
                    print(f"  {label:<20} {count:>4} nodes")
        else:
            # Fallback without APOC
            for label in ["Asset", "Vulnerability", "ThreatActor", "TTP", "AttackPath"]:
                r = s.run(f"MATCH (n:{label}) RETURN count(n) AS c").single()
                print(f"  {label:<20} {r['c']:>4} nodes")

        # Relationship counts
        print()
        for rel in ["HAS_VULNERABILITY", "USES", "PRECEDES", "TARGETS", "USES_TTP"]:
            r = s.run(f"MATCH ()-[r:{rel}]->() RETURN count(r) AS c").single()
            print(f"  [:{rel}]  {r['c']:>4} relationships")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    print("AEGIS Neo4j Initialiser")
    print(f"Connecting to {NEO4J_URL} as {NEO4J_USER}…")

    driver = GraphDatabase.driver(NEO4J_URL, auth=(NEO4J_USER, NEO4J_PASSWORD))
    driver.verify_connectivity()
    print("Connected.\n")

    print("── Constraints ─────────────────────────────────────────────────────")
    create_constraints(driver)

    print("\n── Nodes ───────────────────────────────────────────────────────────")
    create_assets(driver)
    create_vulnerabilities(driver)
    create_threat_actors(driver)
    create_ttps(driver)
    create_attack_paths(driver)

    print("\n── Relationships ───────────────────────────────────────────────────")
    create_asset_vuln_rels(driver)
    create_actor_ttp_rels(driver)
    create_ttp_precedes_rels(driver)
    create_attack_path_rels(driver)

    print_summary(driver)

    driver.close()
    print("\n✓ Initialisation complete.")


if __name__ == "__main__":
    main()
