"""
Unit tests for misp.normalizer

All tests are pure-function tests — no Redis, no network.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Ensure the misp package is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from normalizer import (
    extract_cves,
    extract_mitre_techniques,
    extract_threat_actors,
    extract_tlp,
    misp_event_dedup_key,
    misp_threat_level_to_priority,
    normalize_misp_event,
)


# ---------------------------------------------------------------------------
# extract_mitre_techniques
# ---------------------------------------------------------------------------

class TestExtractMitreTechniques:
    def test_single_technique(self):
        tags = [{"name": 'mitre-attack-pattern="Spearphishing Attachment - T1566.001"'}]
        result = extract_mitre_techniques(tags)
        assert len(result) == 1
        assert result[0]["technique_id"] == "T1566.001"
        assert result[0]["name"] == "Spearphishing Attachment"

    def test_multiple_techniques(self):
        tags = [
            {"name": 'mitre-attack-pattern="Exploit Public-Facing Application - T1190"'},
            {"name": 'mitre-attack-pattern="Valid Accounts - T1078"'},
        ]
        result = extract_mitre_techniques(tags)
        assert len(result) == 2
        ids = {t["technique_id"] for t in result}
        assert ids == {"T1190", "T1078"}

    def test_deduplication(self):
        tags = [
            {"name": 'mitre-attack-pattern="Phishing - T1566"'},
            {"name": 'mitre-attack-pattern="Phishing - T1566"'},
        ]
        result = extract_mitre_techniques(tags)
        assert len(result) == 1

    def test_no_matching_tags(self):
        tags = [{"name": "tlp:white"}, {"name": "type:malware"}]
        assert extract_mitre_techniques(tags) == []

    def test_empty_tags(self):
        assert extract_mitre_techniques([]) == []

    def test_subtechnique_id(self):
        tags = [{"name": 'mitre-attack-pattern="Supply Chain Compromise: Compromise Software Supply Chain - T1195.002"'}]
        result = extract_mitre_techniques(tags)
        assert result[0]["technique_id"] == "T1195.002"


# ---------------------------------------------------------------------------
# extract_threat_actors
# ---------------------------------------------------------------------------

class TestExtractThreatActors:
    def test_single_actor(self):
        tags = [{"name": 'threat-actor="APT29"'}]
        assert extract_threat_actors(tags) == ["APT29"]

    def test_multiple_actors(self):
        tags = [
            {"name": 'threat-actor="APT29"'},
            {"name": 'threat-actor="Lazarus Group"'},
        ]
        actors = extract_threat_actors(tags)
        assert set(actors) == {"APT29", "Lazarus Group"}

    def test_deduplication(self):
        tags = [
            {"name": 'threat-actor="APT29"'},
            {"name": 'threat-actor="APT29"'},
        ]
        assert len(extract_threat_actors(tags)) == 1

    def test_no_actors(self):
        tags = [{"name": "tlp:green"}]
        assert extract_threat_actors(tags) == []


# ---------------------------------------------------------------------------
# extract_cves
# ---------------------------------------------------------------------------

class TestExtractCves:
    def test_cve_in_value(self):
        attrs = [{"value": "CVE-2024-12345", "type": "vulnerability"}]
        assert extract_cves(attrs) == ["CVE-2024-12345"]

    def test_cve_in_comment(self):
        attrs = [{"value": "something", "comment": "Related to CVE-2023-44487"}]
        assert extract_cves(attrs) == ["CVE-2023-44487"]

    def test_multiple_cves(self):
        attrs = [
            {"value": "CVE-2024-1234"},
            {"value": "CVE-2024-5678", "comment": "Also see CVE-2023-9999"},
        ]
        cves = extract_cves(attrs)
        assert set(cves) == {"CVE-2024-1234", "CVE-2024-5678", "CVE-2023-9999"}

    def test_case_insensitive(self):
        attrs = [{"value": "cve-2024-1111"}]
        assert extract_cves(attrs) == ["CVE-2024-1111"]

    def test_no_cves(self):
        attrs = [{"value": "8.8.8.8", "type": "ip-dst"}]
        assert extract_cves(attrs) == []

    def test_empty_attributes(self):
        assert extract_cves([]) == []


# ---------------------------------------------------------------------------
# extract_tlp
# ---------------------------------------------------------------------------

class TestExtractTlp:
    def test_default_green(self):
        assert extract_tlp([]) == "tlp:green"

    def test_tlp_white(self):
        tags = [{"name": "tlp:white"}]
        assert extract_tlp(tags) == "tlp:green"  # green is more restrictive

    def test_tlp_amber(self):
        tags = [{"name": "tlp:amber"}]
        assert extract_tlp(tags) == "tlp:amber"

    def test_tlp_red(self):
        tags = [{"name": "tlp:red"}]
        assert extract_tlp(tags) == "tlp:red"

    def test_most_restrictive_wins(self):
        tags = [{"name": "tlp:green"}, {"name": "tlp:amber"}, {"name": "tlp:white"}]
        assert extract_tlp(tags) == "tlp:amber"

    def test_case_insensitive(self):
        tags = [{"name": "TLP:RED"}]
        assert extract_tlp(tags) == "tlp:red"


# ---------------------------------------------------------------------------
# misp_threat_level_to_priority
# ---------------------------------------------------------------------------

class TestThreatLevelToPriority:
    def test_high(self):
        assert misp_threat_level_to_priority("1") == "P0"

    def test_medium(self):
        assert misp_threat_level_to_priority("2") == "P1"

    def test_low(self):
        assert misp_threat_level_to_priority("3") == "P2"

    def test_undefined(self):
        assert misp_threat_level_to_priority("4") == "P3"

    def test_unknown_defaults_p2(self):
        assert misp_threat_level_to_priority("99") == "P2"


# ---------------------------------------------------------------------------
# normalize_misp_event
# ---------------------------------------------------------------------------

def _make_misp_event(**overrides) -> dict:
    """Factory for a minimal MISP event dict."""
    event = {
        "Event": {
            "id": "12345",
            "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "info": "Test MISP Event — APT Campaign Targeting VPN Appliances",
            "threat_level_id": "1",
            "analysis": "2",
            "date": "2026-03-13",
            "publish_timestamp": "1710288000",
            "Tag": [
                {"name": 'mitre-attack-pattern="Exploit Public-Facing Application - T1190"'},
                {"name": 'threat-actor="Volt Typhoon"'},
                {"name": "tlp:amber"},
            ],
            "Attribute": [
                {"value": "CVE-2024-21887", "type": "vulnerability"},
                {"value": "10.0.0.1", "type": "ip-dst", "comment": "C2 server"},
            ],
            "Galaxy": [],
        }
    }
    event["Event"].update(overrides)
    return event


class TestNormalizeMispEvent:
    def test_basic_normalization(self):
        result = normalize_misp_event(_make_misp_event())
        assert result["source_type"] == "misp"
        assert result["priority"] == "P0"  # threat_level_id=1
        assert result["routing_target"] == "triage"
        assert "event_id" in result
        assert "ingested_at" in result

    def test_raw_payload_contains_misp_fields(self):
        result = normalize_misp_event(_make_misp_event())
        payload = json.loads(result["raw_payload"])
        assert payload["misp_event_id"] == "12345"
        assert payload["misp_uuid"] == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        assert "CVE-2024-21887" in payload["cve_ids"]
        assert payload["cve_id"] == "CVE-2024-21887"
        assert "T1190" in payload["misp_techniques"]
        assert "Volt Typhoon" in payload["threat_actors"]
        assert payload["tlp"] == "tlp:amber"

    def test_no_cves(self):
        event = _make_misp_event(Attribute=[{"value": "malware.exe", "type": "filename"}])
        result = normalize_misp_event(event)
        payload = json.loads(result["raw_payload"])
        assert payload["cve_ids"] == []
        assert payload["cve_id"] is None

    def test_galaxy_cluster_tags_extracted(self):
        event = _make_misp_event(
            Tag=[],
            Galaxy=[{
                "type": "mitre-attack-pattern",
                "GalaxyCluster": [
                    {"tag_name": 'mitre-attack-pattern="Phishing - T1566"'},
                ],
            }],
        )
        result = normalize_misp_event(event)
        payload = json.loads(result["raw_payload"])
        assert "T1566" in payload["misp_techniques"]

    def test_priority_mapping(self):
        for level, expected in [("1", "P0"), ("2", "P1"), ("3", "P2"), ("4", "P3")]:
            result = normalize_misp_event(_make_misp_event(threat_level_id=level))
            assert result["priority"] == expected, f"threat_level_id={level}"


# ---------------------------------------------------------------------------
# misp_event_dedup_key
# ---------------------------------------------------------------------------

class TestDedupKey:
    def test_returns_uuid(self):
        event = {"Event": {"uuid": "abc-123"}}
        assert misp_event_dedup_key(event) == "abc-123"

    def test_unwrapped_event(self):
        event = {"uuid": "xyz-789"}
        assert misp_event_dedup_key(event) == "xyz-789"

    def test_missing_uuid(self):
        event = {"Event": {"id": "123"}}
        assert misp_event_dedup_key(event) == ""
