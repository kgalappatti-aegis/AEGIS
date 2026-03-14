"""
AEGIS Infrastructure Sync — CSV Row Mapper

Pure functions that transform a raw ServiceNow CMDB CSV row into an
AssetRecord dataclass. No I/O — testable in isolation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class AssetRecord:
    """Normalised asset record for Neo4j + Redis ingestion."""

    # Neo4j Asset node fields
    sys_id: str
    name: str
    fqdn: str
    ip_address: str
    asset_type: str        # server | network | cloud | endpoint
    subtype: str           # u_asset_subtype verbatim
    criticality: int       # u_criticality_score, coerced to int 1–10
    os: str
    os_version: str
    environment: str
    location: str
    department: str
    classification: str
    operational: bool      # operational_status == "Operational"
    manufacturer: str
    model: str
    sys_class: str
    description: str

    # Redis enrichment fields (stored as hash, not in Neo4j)
    owner_email: str
    support_group: str
    last_discovered: str
    business_criticality: str


# Map u_asset_subtype → asset_type category
SUBTYPE_TO_TYPE: dict[str, str] = {
    "Domain Controller":     "server",
    "Database Server":       "server",
    "Application Server":    "server",
    "File Server":           "server",
    "Legacy Server":         "server",
    "Firewall":              "network",
    "VPN Concentrator":      "network",
    "Load Balancer":         "network",
    "Switch":                "network",
    "Cloud Database":        "cloud",
    "Cloud Storage":         "cloud",
    "Cloud VM":              "cloud",
    "Kubernetes Cluster":    "cloud",
    "Workstation":           "endpoint",
    "Executive Workstation": "endpoint",
}

# Fallback criticality when u_criticality_score is missing
_CLASSIFICATION_CRITICALITY: dict[str, int] = {
    "Critical": 8,
    "High": 6,
    "Medium": 4,
    "Low": 2,
}


def map_row(row: dict) -> Optional[AssetRecord]:
    """
    Convert a raw CSV row dict to an AssetRecord.
    Returns None if the row should be skipped (retired, absent, etc.).
    """
    if row.get("operational_status", "").lower() != "operational":
        return None
    if row.get("install_status", "").lower() in ("retired", "absent"):
        return None

    subtype = row.get("u_asset_subtype", "").strip()
    asset_type = SUBTYPE_TO_TYPE.get(subtype, "server")

    # Coerce criticality — fall back to classification-derived default
    try:
        criticality = max(1, min(10, int(row.get("u_criticality_score", 5) or 5)))
    except (ValueError, TypeError):
        criticality = _CLASSIFICATION_CRITICALITY.get(
            row.get("business_criticality", "Low"), 4
        )

    return AssetRecord(
        sys_id=row["sys_id"].strip(),
        name=row["name"].strip(),
        fqdn=row.get("fqdn", "").strip(),
        ip_address=row.get("ip_address", "").strip(),
        asset_type=asset_type,
        subtype=subtype,
        criticality=criticality,
        os=row.get("os", "").strip(),
        os_version=row.get("os_version", "").strip(),
        environment=row.get("environment", "Production").strip(),
        location=row.get("location", "").strip(),
        department=row.get("department", "").strip(),
        classification=row.get("classification", "Internal").strip(),
        operational=True,
        manufacturer=row.get("manufacturer", "").strip(),
        model=row.get("model_id", "").strip(),
        sys_class=row.get("sys_class_name", "").strip(),
        description=row.get("short_description", "").strip(),
        owner_email=row.get("owned_by", "").strip(),
        support_group=row.get("support_group", "").strip(),
        last_discovered=row.get("last_discovered", "").strip(),
        business_criticality=row.get("business_criticality", "Low").strip(),
    )
