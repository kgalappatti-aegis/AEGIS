/**
 * AEGIS Kill Chain Flow – Interactive SVG kill chain diagram
 *
 * Renders a simulation finding's attack paths as an SVG node-edge diagram.
 * Nodes have pre-computed x, y, w, h from the layout engine.
 *
 * Used in:
 *   1. Advisory card expansion (ADVISORIES tab)
 *   2. Event detail panel (EVENTS tab, when simulation data exists)
 */

import { useState, useEffect, useRef, useCallback } from 'react';

// ── Design tokens (mirror App.jsx C object) ──────────────────────────────────

const C = {
  bg:          '#0a0e1a',
  surface:     '#0f1623',
  card:        '#141d2e',
  border:      '#1e2d45',
  borderBright:'#2a3f5f',
  text:        '#cdd9ec',
  textBright:  '#e8f0fc',
  muted:       '#5a7294',
  teal:        '#00d4aa',
  amber:       '#f5c518',
  orange:      '#ff8c22',
  red:         '#ff4455',
  blue:        '#4a9eff',
  green:       '#34d399',
  purple:      '#a855f7',
};

// Node fill colors by coverage
const COV_FILL = {
  none:     '#C1121F',
  partial:  '#F4A261',
  detected: '#2D9B4A',
};
const ASSET_FILL    = '#334D5C';
const EDGE_COLOR    = '#8FA8B2';
const BLIND_STROKE  = '#028090';
const ACTIVE_PATH   = '#028090';

const API_BASE = `${window.location.protocol}//${window.location.host}`;

// ── Fetch helper ─────────────────────────────────────────────────────────────

async function fetchSimulation(eventId) {
  try {
    const res = await fetch(`${API_BASE}/api/simulation/${encodeURIComponent(eventId)}`);
    if (res.status === 404) return { status: 'pending' };
    if (!res.ok) return { status: 'error' };
    const data = await res.json();
    return { status: 'ok', data };
  } catch {
    return { status: 'error' };
  }
}

// ── Main component ───────────────────────────────────────────────────────────

export default function KillChainFlow({ eventId, finding: findingProp }) {
  const [finding, setFinding]       = useState(findingProp || null);
  const [fetchState, setFetchState] = useState(findingProp ? 'ok' : 'loading');
  const [activeIdx, setActiveIdx]   = useState(0);
  const [svgOpacity, setSvgOpacity] = useState(1);
  const [selectedNode, setSelectedNode] = useState(null);
  const mountedRef = useRef(true);

  // Fetch on mount if no finding prop
  useEffect(() => {
    mountedRef.current = true;
    if (findingProp) {
      setFinding(findingProp);
      setFetchState('ok');
      return;
    }
    if (!eventId) { setFetchState('error'); return; }

    setFetchState('loading');
    fetchSimulation(eventId).then(result => {
      if (!mountedRef.current) return;
      if (result.status === 'ok') {
        setFinding(result.data);
        setFetchState('ok');
      } else {
        setFetchState(result.status);
      }
    });
    return () => { mountedRef.current = false; };
  }, [eventId, findingProp]);

  // Path switching with fade animation
  const switchPath = useCallback((idx) => {
    if (idx === activeIdx) return;
    setSvgOpacity(0);
    setTimeout(() => {
      setActiveIdx(idx);
      setSelectedNode(null);
      setSvgOpacity(1);
    }, 150);
  }, [activeIdx]);

  // ── Loading state ────────────────────────────────────────────────────────
  if (fetchState === 'loading') return <SkeletonLoader />;
  if (fetchState === 'pending') return <PendingState />;
  if (fetchState === 'error' || !finding) {
    return (
      <div style={{ color: C.muted, fontSize: 11, padding: 16 }}>
        Failed to load simulation data.
      </div>
    );
  }

  const paths = finding.paths || [];
  if (paths.length === 0) {
    return (
      <div style={{ color: C.muted, fontSize: 11, padding: 16 }}>
        No attack paths available.
      </div>
    );
  }

  const activePath   = paths[activeIdx] || paths[0];
  const nodes        = activePath.nodes || [];
  const edges        = activePath.edges || [];
  const blindSpots   = new Set(activePath.blindSpots || []);
  const ttpNodes     = nodes.filter(n => n.type === 'ttp');
  const hopCount     = activePath.hopCount ?? ttpNodes.length;
  const detectCount  = activePath.detectionsCount ?? 0;

  // Compute SVG viewBox from node coordinates
  const allX = nodes.map(n => n.x + n.w);
  const allY = nodes.map(n => n.y + n.h);
  const svgW = Math.max(...allX) + 40;
  const svgH = Math.max(...allY) + 60;

  // Build node lookup for edge rendering
  const nodeMap = {};
  for (const n of nodes) nodeMap[n.id] = n;

  // Group TTP nodes by tactic for labels
  const tacticGroups = {};
  for (const n of ttpNodes) {
    const t = n.tactic || 'unknown';
    if (!tacticGroups[t]) tacticGroups[t] = [];
    tacticGroups[t].push(n);
  }

  return (
    <div style={{
      background: C.surface,
      border: `1px solid ${C.border}`,
      borderRadius: 6,
      overflow: 'hidden',
    }}>
      {/* Header bar */}
      <HeaderBar finding={finding} activePath={activePath} hopCount={hopCount} detectCount={detectCount} />

      {/* Path selector */}
      {paths.length > 1 && (
        <PathSelector
          paths={paths}
          activeIdx={activeIdx}
          onSelect={switchPath}
        />
      )}

      {/* SVG diagram */}
      <div style={{
        padding: '12px 16px',
        overflowX: 'auto',
        transition: 'opacity 150ms ease',
        opacity: svgOpacity,
      }}>
        <svg
          width="100%"
          viewBox={`0 0 ${svgW} ${svgH}`}
          style={{ display: 'block', minWidth: svgW }}
        >
          <defs>
            <marker
              id="arrow"
              viewBox="0 0 10 10"
              refX="9"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill={EDGE_COLOR} fillOpacity="0.6" />
            </marker>
            <marker
              id="arrow-blind"
              viewBox="0 0 10 10"
              refX="9"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill={BLIND_STROKE} fillOpacity="0.8" />
            </marker>
          </defs>

          {/* Edges */}
          {edges.map((edge, i) => {
            const from = nodeMap[edge.from];
            const to   = nodeMap[edge.to];
            if (!from || !to) return null;

            const isBlind = blindSpots.has(edge.from) || blindSpots.has(edge.to);
            return (
              <EdgePath
                key={i}
                from={from}
                to={to}
                p={edge.p}
                isBlind={isBlind}
              />
            );
          })}

          {/* Nodes */}
          {nodes.map(node => (
            <NodeRect
              key={node.id}
              node={node}
              isBlind={blindSpots.has(node.id)}
              isSelected={selectedNode === node.id}
              onClick={() => {
                if (node.type === 'ttp') {
                  setSelectedNode(selectedNode === node.id ? null : node.id);
                }
              }}
            />
          ))}

          {/* Tactic labels */}
          {Object.entries(tacticGroups).map(([tactic, group]) => {
            const xs = group.map(n => n.x);
            const ws = group.map(n => n.w);
            const maxY = Math.max(...group.map(n => n.y + n.h));
            const centerX = (Math.min(...xs) + Math.max(...xs.map((x, i) => x + ws[i]))) / 2;
            return (
              <text
                key={tactic}
                x={centerX}
                y={maxY + 18}
                textAnchor="middle"
                fill={C.muted}
                fontSize={8}
                fontFamily="inherit"
                letterSpacing="0.08em"
              >
                {tactic.toUpperCase().replace(/-/g, ' ')}
              </text>
            );
          })}
        </svg>
      </div>

      {/* Legend */}
      <LegendRow />

      {/* Node detail drawer */}
      {selectedNode && nodeMap[selectedNode]?.type === 'ttp' && (
        <NodeDetail
          node={nodeMap[selectedNode]}
          isBlind={blindSpots.has(selectedNode)}
          onClose={() => setSelectedNode(null)}
        />
      )}
    </div>
  );
}

// ── Header bar ───────────────────────────────────────────────────────────────

function HeaderBar({ finding, activePath, hopCount, detectCount }) {
  const pill = (label, value, color) => (
    <div style={{ textAlign: 'center' }}>
      <div style={{ color: C.muted, fontSize: 8, letterSpacing: '0.1em', marginBottom: 2 }}>
        {label}
      </div>
      <div style={{ color, fontSize: 14, fontWeight: 700, lineHeight: 1, fontVariantNumeric: 'tabular-nums' }}>
        {value}
      </div>
    </div>
  );

  const pBreachStr = activePath.p_breach != null
    ? (activePath.p_breach * 100).toFixed(1) + '%'
    : '---';

  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '10px 16px',
      borderBottom: `1px solid ${C.border}`,
      flexWrap: 'wrap',
      gap: 10,
    }}>
      {/* Left: identity */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        {finding.event_id && (
          <span style={{
            padding: '2px 8px',
            background: `${C.teal}18`,
            color: C.teal,
            border: `1px solid ${C.teal}44`,
            borderRadius: 3,
            fontSize: 10,
            fontWeight: 600,
          }}>
            {finding.event_id.length > 16
              ? finding.event_id.slice(0, 16) + '...'
              : finding.event_id}
          </span>
        )}
        {finding.cve && (
          <span style={{ color: C.amber, fontSize: 11, fontWeight: 700 }}>
            {finding.cve}
          </span>
        )}
        {finding.synthetic_path && (
          <span style={{
            padding: '1px 6px',
            background: 'rgba(90,114,148,0.12)',
            color: C.muted,
            fontSize: 9,
            borderRadius: 2,
          }}>
            SYNTHETIC
          </span>
        )}
      </div>

      {/* Right: metric pills */}
      <div style={{ display: 'flex', gap: 20 }}>
        {pill('P(BREACH)', pBreachStr, C.red)}
        {pill('RISK', finding.risk_score ?? '---', C.amber)}
        {pill('HOPS', hopCount, C.teal)}
        {pill('DETECTIONS', detectCount, C.green)}
      </div>
    </div>
  );
}

// ── Path selector ────────────────────────────────────────────────────────────

function PathSelector({ paths, activeIdx, onSelect }) {
  return (
    <div style={{
      display: 'flex',
      gap: 4,
      padding: '8px 16px',
      borderBottom: `1px solid ${C.border}`,
      overflowX: 'auto',
    }}>
      {paths.map((p, i) => {
        const active = i === activeIdx;
        return (
          <button
            key={i}
            onClick={() => onSelect(i)}
            style={{
              background: active ? ACTIVE_PATH : C.card,
              color: active ? '#fff' : C.muted,
              border: `1px solid ${active ? ACTIVE_PATH : C.border}`,
              padding: '4px 12px',
              borderRadius: 3,
              fontSize: 10,
              fontWeight: active ? 600 : 400,
              fontFamily: 'inherit',
              whiteSpace: 'nowrap',
              cursor: 'pointer',
              transition: 'all 0.15s',
            }}
          >
            {p.label || `Path ${i + 1}`} (P={p.p_breach != null ? p.p_breach.toFixed(2) : '?'})
          </button>
        );
      })}
    </div>
  );
}

// ── SVG Node ─────────────────────────────────────────────────────────────────

function NodeRect({ node, isBlind, isSelected, onClick }) {
  const isAsset = node.type === 'asset';
  const isTtp   = node.type === 'ttp';

  let fill, fillOpacity;
  if (isAsset) {
    fill = ASSET_FILL;
    fillOpacity = 0.9;
  } else {
    fill = COV_FILL[node.cov] || COV_FILL.none;
    fillOpacity = isBlind ? 0.35 : 0.85;
  }

  const strokeColor  = isSelected ? C.teal : (isBlind ? BLIND_STROKE : 'none');
  const strokeDash   = isBlind ? '4,3' : 'none';
  const strokeWidth  = isSelected ? 1.5 : (isBlind ? 1.2 : 0);
  const cursor       = isTtp ? 'pointer' : 'default';

  return (
    <g onClick={onClick} style={{ cursor }}>
      <rect
        x={node.x}
        y={node.y}
        width={node.w}
        height={node.h}
        rx={3}
        fill={fill}
        fillOpacity={fillOpacity}
        stroke={strokeColor}
        strokeWidth={strokeWidth}
        strokeDasharray={strokeDash}
      />
      {isAsset ? (
        <text
          x={node.x + node.w / 2}
          y={node.y + node.h / 2 + 3.5}
          textAnchor="middle"
          fill="#fff"
          fontSize={10}
          fontFamily="inherit"
          fontWeight={600}
        >
          {node.name}
        </text>
      ) : (
        <>
          <text
            x={node.x + 6}
            y={node.y + 12}
            fill="#fff"
            fontSize={8}
            fontFamily="inherit"
            fontWeight={600}
            fillOpacity={0.85}
          >
            {node.id}
          </text>
          <text
            x={node.x + 6}
            y={node.y + 24}
            fill="#fff"
            fontSize={9}
            fontFamily="inherit"
            fillOpacity={0.7}
          >
            {truncText(node.name, 18)}
          </text>
        </>
      )}
    </g>
  );
}

function truncText(s, max) {
  if (!s) return '';
  return s.length > max ? s.slice(0, max - 1) + '...' : s;
}

// ── SVG Edge ─────────────────────────────────────────────────────────────────

function EdgePath({ from, to, p, isBlind }) {
  // From right-edge midpoint to left-edge midpoint
  const x1 = from.x + from.w;
  const y1 = from.y + from.h / 2;
  const x2 = to.x;
  const y2 = to.y + to.h / 2;

  // Control points for cubic bezier
  const dx = (x2 - x1) * 0.4;
  const d = `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;

  // Label position at midpoint
  const mx = (x1 + x2) / 2;
  const my = (y1 + y2) / 2 - 6;

  const color   = isBlind ? BLIND_STROKE : EDGE_COLOR;
  const opacity = isBlind ? 0.7 : 0.5;
  const dash    = isBlind ? '5,4' : 'none';
  const marker  = isBlind ? 'url(#arrow-blind)' : 'url(#arrow)';

  return (
    <g>
      <path
        d={d}
        fill="none"
        stroke={color}
        strokeWidth={1.2}
        strokeOpacity={opacity}
        strokeDasharray={dash}
        markerEnd={marker}
      />
      {p != null && p !== 1.0 && (
        <text
          x={mx}
          y={my}
          textAnchor="middle"
          fill={C.muted}
          fontSize={7}
          fontFamily="inherit"
        >
          p={typeof p === 'number' ? p.toFixed(2) : p}
        </text>
      )}
    </g>
  );
}

// ── Legend row ────────────────────────────────────────────────────────────────

function LegendRow() {
  const items = [
    { label: 'No detection', color: COV_FILL.none,     dash: false },
    { label: 'Partial',      color: COV_FILL.partial,  dash: false },
    { label: 'Detected',     color: COV_FILL.detected, dash: false },
    { label: 'Asset',        color: ASSET_FILL,        dash: false },
    { label: 'Blind spot',   color: BLIND_STROKE,      dash: true  },
  ];

  return (
    <div style={{
      display: 'flex',
      gap: 16,
      padding: '8px 16px',
      borderTop: `1px solid ${C.border}`,
      flexWrap: 'wrap',
    }}>
      {items.map(item => (
        <div key={item.label} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
          <span style={{
            display: 'inline-block',
            width: 14,
            height: 10,
            borderRadius: 2,
            background: item.dash ? 'transparent' : item.color,
            border: item.dash ? `1.5px dashed ${item.color}` : 'none',
            opacity: 0.85,
          }} />
          <span style={{ color: C.muted, fontSize: 9, letterSpacing: '0.04em' }}>
            {item.label}
          </span>
        </div>
      ))}
    </div>
  );
}

// ── Node detail drawer ───────────────────────────────────────────────────────

function NodeDetail({ node, isBlind, onClose }) {
  const covLabel = { none: 'None', partial: 'Partial', detected: 'Detected' }[node.cov] || 'Unknown';
  const covColor = { none: C.red, partial: C.orange, detected: C.green }[node.cov] || C.muted;

  const handleAsk = () => {
    window.dispatchEvent(new CustomEvent('aegis:prompt', {
      detail: `Explain MITRE ATT&CK ${node.id}: ${node.name} and how to detect it with Sigma rules`,
    }));
  };

  return (
    <div style={{
      borderTop: `1px solid ${C.border}`,
      padding: '14px 16px',
      background: C.card,
    }}>
      {/* Header */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'flex-start',
        marginBottom: 12,
      }}>
        <div>
          <div style={{ color: C.teal, fontSize: 13, fontWeight: 700, marginBottom: 2 }}>
            {node.id}
          </div>
          <div style={{ color: C.textBright, fontSize: 12, fontWeight: 600 }}>
            {node.name}
          </div>
        </div>
        <button
          onClick={onClose}
          style={{
            background: 'none',
            border: 'none',
            color: C.muted,
            fontSize: 14,
            cursor: 'pointer',
            padding: '0 4px',
          }}
        >
          x
        </button>
      </div>

      {/* Detail grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
        gap: 12,
        marginBottom: 12,
      }}>
        <DetailField label="TACTIC" value={(node.tactic || '---').toUpperCase().replace(/-/g, ' ')} color={C.purple} />
        <DetailField
          label="TRANSITION PROB"
          value={node.prob != null ? node.prob.toFixed(3) : '---'}
          color={C.text}
        />
        <DetailField label="DETECTION" value={covLabel} color={covColor} />
        <DetailField
          label="PENALTY"
          value={node.penalty ? 'Yes (-0.15)' : 'No'}
          color={node.penalty ? C.orange : C.muted}
        />
        {isBlind && (
          <DetailField label="BLIND SPOT" value="Yes" color={BLIND_STROKE} />
        )}
      </div>

      {/* Sigma hint */}
      {node.sig && (
        <div style={{ marginBottom: 12 }}>
          <div style={{ color: C.muted, fontSize: 9, fontWeight: 600, letterSpacing: '0.1em', marginBottom: 4 }}>
            SIGMA HINT
          </div>
          <div style={{
            background: 'rgba(0,212,170,0.05)',
            borderLeft: `2px solid ${C.teal}44`,
            padding: '8px 10px',
            borderRadius: 3,
          }}>
            <pre style={{
              color: C.text,
              fontSize: 10,
              lineHeight: 1.6,
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word',
              margin: 0,
              fontFamily: 'inherit',
            }}>
              {node.sig}
            </pre>
          </div>
        </div>
      )}

      {/* Ask button */}
      <button
        onClick={handleAsk}
        style={{
          background: 'none',
          border: `1px solid ${C.border}`,
          color: C.teal,
          fontSize: 10,
          fontWeight: 600,
          padding: '5px 12px',
          borderRadius: 3,
          cursor: 'pointer',
          letterSpacing: '0.04em',
          transition: 'border-color 0.15s',
        }}
      >
        Ask about this technique &#8599;
      </button>
    </div>
  );
}

function DetailField({ label, value, color }) {
  return (
    <div>
      <div style={{ color: C.muted, fontSize: 8, fontWeight: 600, letterSpacing: '0.1em', marginBottom: 3 }}>
        {label}
      </div>
      <div style={{ color, fontSize: 11, fontWeight: 600 }}>
        {value}
      </div>
    </div>
  );
}

// ── Skeleton loader ──────────────────────────────────────────────────────────

function SkeletonLoader() {
  const barStyle = (w, delay) => ({
    width: w,
    height: 10,
    background: C.border,
    borderRadius: 3,
    marginBottom: 8,
    animation: `skeletonPulse 1.2s ease-in-out ${delay}s infinite`,
  });

  return (
    <div style={{ padding: 16 }}>
      <style>{`
        @keyframes skeletonPulse {
          0%, 100% { opacity: 0.3; }
          50% { opacity: 0.7; }
        }
      `}</style>
      <div style={barStyle('60%', 0)} />
      <div style={barStyle('80%', 0.15)} />
      <div style={barStyle('45%', 0.3)} />
    </div>
  );
}

// ── Pending state ────────────────────────────────────────────────────────────

function PendingState() {
  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      gap: 10,
      padding: 16,
      color: C.muted,
      fontSize: 11,
    }}>
      <style>{`
        @keyframes kcfSpin {
          to { transform: rotate(360deg); }
        }
      `}</style>
      <span style={{
        display: 'inline-block',
        width: 14,
        height: 14,
        border: `2px solid ${C.border}`,
        borderTopColor: C.teal,
        borderRadius: '50%',
        animation: 'kcfSpin 0.8s linear infinite',
      }} />
      Simulation pending...
    </div>
  );
}
