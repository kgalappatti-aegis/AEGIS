"""
AEGIS Simulation Agent – SVG Layout Engine

Pre-computes x, y, w, h coordinates for path visualisation so the
frontend can render SVG without any layout math.
"""

from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# Kill-chain tactic order (ATT&CK canonical)
# ---------------------------------------------------------------------------

TACTIC_ORDER: list[str] = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]
TACTIC_INDEX: dict[str, int] = {t: i for i, t in enumerate(TACTIC_ORDER)}


# ---------------------------------------------------------------------------
# Layout constants
# ---------------------------------------------------------------------------

CELL_W = 130       # TTP node width
CELL_H = 36        # TTP node height
ASSET_W = 110      # asset node width
GAP_X = 20         # horizontal gap between columns
GAP_Y = 30         # vertical gap between stacked nodes
MARGIN_X = 30      # left margin
MARGIN_Y = 60      # top margin (room for header row)


# ---------------------------------------------------------------------------
# Part 4 — Coordinate layout engine
# ---------------------------------------------------------------------------

def compute_layout(
    ttp_sequence: list[dict[str, Any]],
    coverage_map: dict[str, str],
    sigma_map: dict[str, str],
    prob_map: dict[str, float],
    entry_asset: dict[str, Any] | None = None,
    exit_assets: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """
    Assign x, y, w, h to every node so the frontend can render the SVG.

    Parameters
    ----------
    ttp_sequence : ordered list of TTP dicts from Neo4j path
        Each must have: mitre_id, name, tactic
    coverage_map : { mitre_id: "none"|"partial"|"detected" }
    sigma_map    : { mitre_id: hint_string }
    prob_map     : { mitre_id: transition_probability }
    entry_asset  : optional entry asset dict (id, name)
    exit_assets  : optional list of exit asset dicts

    Returns
    -------
    list of node dicts ready for the frontend.
    """
    if not ttp_sequence:
        return []

    # Default assets
    if entry_asset is None:
        entry_asset = {"id": "ASSET-EXT", "name": "External"}
    if exit_assets is None:
        exit_assets = [{"id": "ASSET-TARGET", "name": "Target"}]

    # 1. Group TTPs by tactic, preserving path order within each group
    tactic_groups: dict[str, list[dict]] = {}
    seen_tactics: list[str] = []
    for ttp in ttp_sequence:
        tactic = ttp.get("tactic", "")
        if tactic not in tactic_groups:
            tactic_groups[tactic] = []
            seen_tactics.append(tactic)
        tactic_groups[tactic].append(ttp)

    # 2. Sort by kill-chain order
    sorted_tactics = sorted(seen_tactics, key=lambda t: TACTIC_INDEX.get(t, 99))

    result: list[dict[str, Any]] = []

    # 3. Entry asset at column 0
    result.append({
        "id": entry_asset["id"],
        "name": entry_asset["name"],
        "type": "asset",
        "x": MARGIN_X,
        "y": MARGIN_Y,
        "w": ASSET_W,
        "h": CELL_H,
    })

    # 4. TTP columns — one per tactic present in the path
    for col_offset, tactic in enumerate(sorted_tactics, start=1):
        nodes_in_col = tactic_groups[tactic]
        x = MARGIN_X + col_offset * (CELL_W + GAP_X)
        for row, ttp in enumerate(nodes_in_col):
            mid = ttp.get("mitre_id", ttp.get("id", ""))
            cov = coverage_map.get(mid, "none")
            result.append({
                "id": mid,
                "name": ttp.get("name", mid),
                "type": "ttp",
                "tactic": tactic,
                "prob": prob_map.get(mid, 0.5),
                "cov": cov,
                "penalty": cov in ("partial", "detected"),
                "sig": sigma_map.get(mid, ""),
                "x": x,
                "y": MARGIN_Y + row * (CELL_H + GAP_Y),
                "w": CELL_W,
                "h": CELL_H,
            })

    # 5. Exit assets at the rightmost column
    exit_col = len(sorted_tactics) + 1
    exit_x = MARGIN_X + exit_col * (CELL_W + GAP_X)

    # 6. Center alignment — compute median y of TTP nodes
    ttp_ys = [n["y"] for n in result if n["type"] == "ttp"]
    median_y = _median(ttp_ys) if ttp_ys else MARGIN_Y

    # Shift single-node tactic columns to the median
    cols_by_x: dict[int, list[dict]] = {}
    for n in result:
        if n["type"] == "ttp":
            cols_by_x.setdefault(n["x"], []).append(n)
    for col_nodes in cols_by_x.values():
        if len(col_nodes) == 1:
            col_nodes[0]["y"] = median_y

    # Also centre the entry asset
    result[0]["y"] = median_y

    # Place exit assets centred around the median
    for row, asset in enumerate(exit_assets):
        result.append({
            "id": asset.get("id", f"ASSET-EXIT-{row}"),
            "name": asset.get("name", "Target"),
            "type": "asset",
            "x": exit_x,
            "y": median_y + row * (CELL_H + GAP_Y),
            "w": ASSET_W,
            "h": CELL_H,
        })

    return result


def _median(values: list[float]) -> float:
    s = sorted(values)
    n = len(s)
    if n == 0:
        return 0.0
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2.0


# ---------------------------------------------------------------------------
# Part 5 — Blind spot detection
# ---------------------------------------------------------------------------

def detect_blind_spots(layout_nodes: list[dict[str, Any]]) -> list[str]:
    """
    A blind spot is a high-probability TTP with no detection coverage.
    """
    return [
        node["id"]
        for node in layout_nodes
        if node.get("type") == "ttp"
        and node.get("cov") == "none"
        and node.get("prob", 0.0) >= 0.7
    ]


def compute_path_stats(
    layout_nodes: list[dict[str, Any]],
) -> tuple[int, int]:
    """Return (detections_count, hop_count) for a path."""
    ttp_nodes = [n for n in layout_nodes if n.get("type") == "ttp"]
    detections_count = sum(1 for n in ttp_nodes if n.get("cov") == "detected")
    hop_count = len(ttp_nodes)
    return detections_count, hop_count


# ---------------------------------------------------------------------------
# Part 6 — Edge builder
# ---------------------------------------------------------------------------

def build_edges(
    ttp_sequence: list[dict[str, Any]],
    prob_map: dict[str, float],
    entry_asset_id: str = "ASSET-EXT",
    exit_asset_id: str = "ASSET-TARGET",
) -> list[dict[str, Any]]:
    """
    Build edge list from a sequential TTP path.

    Prepends entry_asset → first TTP and appends last TTP → exit_asset.
    """
    edges: list[dict[str, Any]] = []
    if not ttp_sequence:
        return edges

    first_mid = ttp_sequence[0].get("mitre_id", ttp_sequence[0].get("id", ""))
    edges.append({"from": entry_asset_id, "to": first_mid, "p": 1.0})

    for i in range(len(ttp_sequence) - 1):
        from_id = ttp_sequence[i].get("mitre_id", ttp_sequence[i].get("id", ""))
        to_id = ttp_sequence[i + 1].get("mitre_id", ttp_sequence[i + 1].get("id", ""))
        p = prob_map.get(from_id, 0.5)
        edges.append({"from": from_id, "to": to_id, "p": p})

    last_mid = ttp_sequence[-1].get("mitre_id", ttp_sequence[-1].get("id", ""))
    edges.append({"from": last_mid, "to": exit_asset_id, "p": 1.0})

    return edges


def compute_path_p_breach(edges: list[dict[str, Any]]) -> float:
    """Product of all edge probabilities."""
    p = 1.0
    for e in edges:
        p *= e.get("p", 1.0)
    return round(p, 6)


# ---------------------------------------------------------------------------
# Part 8 — Synthetic fallback path
# ---------------------------------------------------------------------------

def build_synthetic_path(
    coverage_map: dict[str, str],
    sigma_map: dict[str, str],
) -> tuple[list[dict], list[dict], list[str]]:
    """
    Build a minimal 3-node synthetic path when Neo4j returns no results.

    Returns (layout_nodes, edges, blind_spots).
    """
    synthetic_ttps = [
        {"mitre_id": "T1190", "name": "Exploit Public-Facing Application",
         "tactic": "initial-access"},
        {"mitre_id": "T1059", "name": "Command and Scripting Interpreter",
         "tactic": "execution"},
        {"mitre_id": "T1486", "name": "Data Encrypted for Impact",
         "tactic": "impact"},
    ]

    prob_map = {t["mitre_id"]: 0.5 for t in synthetic_ttps}

    layout = compute_layout(
        synthetic_ttps, coverage_map, sigma_map, prob_map,
    )
    edges = build_edges(synthetic_ttps, prob_map)
    blind_spots = detect_blind_spots(layout)

    return layout, edges, blind_spots


# ---------------------------------------------------------------------------
# Strategy label helper
# ---------------------------------------------------------------------------

_STRATEGY_LABELS = {
    "evasion_first": "Evasion-first",
    "shortest_path": "Shortest path",
    "lateral_movement": "Lateral movement",
    "vuln_amplified": "Vuln-amplified",
    "full_landscape": "Full landscape",
    "actor_emulation": "Actor emulation",
}


def path_label(strategy: str, rank: int) -> str:
    base = _STRATEGY_LABELS.get(strategy, strategy.replace("_", " ").title())
    if rank > 0:
        return f"{base} #{rank + 1}"
    return base
