/**
 * AEGIS ATT&CK Matrix Heatmap
 *
 * 14-column tactic grid with technique cells colored by hit count.
 * Toolbar: actor filter, view mode toggle (heatmap/list), stats cards.
 * Click-to-detail panel. WebSocket optimistic updates.
 */

import { useState, useEffect, useCallback, useRef } from 'react';

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

// ── ATT&CK tactic columns (canonical order) ──────────────────────────────────

const TACTICS = [
  { id: 'reconnaissance',       label: 'Recon'          },
  { id: 'resource-development',  label: 'Resource Dev'   },
  { id: 'initial-access',        label: 'Initial Access' },
  { id: 'execution',             label: 'Execution'      },
  { id: 'persistence',           label: 'Persistence'    },
  { id: 'privilege-escalation',  label: 'Priv Esc'       },
  { id: 'defense-evasion',       label: 'Def Evasion'    },
  { id: 'credential-access',     label: 'Cred Access'    },
  { id: 'discovery',             label: 'Discovery'      },
  { id: 'lateral-movement',      label: 'Lateral Mvmt'   },
  { id: 'collection',            label: 'Collection'     },
  { id: 'command-and-control',   label: 'C2'             },
  { id: 'exfiltration',          label: 'Exfiltration'   },
  { id: 'impact',                label: 'Impact'         },
];

// ── Known techniques (from neo4j_init.py) ────────────────────────────────────

const KNOWN_TECHNIQUES = [
  { id: 'T1190',     name: 'Exploit Public-Facing App',     tactic: 'initial-access'       },
  { id: 'T1133',     name: 'External Remote Services',      tactic: 'initial-access'       },
  { id: 'T1566.001', name: 'Spearphishing Attachment',      tactic: 'initial-access'       },
  { id: 'T1566.002', name: 'Spearphishing Link',            tactic: 'initial-access'       },
  { id: 'T1195.002', name: 'Compromise Supply Chain',       tactic: 'initial-access'       },
  { id: 'T1059.001', name: 'PowerShell',                    tactic: 'execution'            },
  { id: 'T1059.004', name: 'Unix Shell',                    tactic: 'execution'            },
  { id: 'T1053.005', name: 'Scheduled Task',                tactic: 'execution'            },
  { id: 'T1078',     name: 'Valid Accounts',                tactic: 'persistence'          },
  { id: 'T1505.003', name: 'Web Shell',                     tactic: 'persistence'          },
  { id: 'T1068',     name: 'Exploitation for Priv Esc',     tactic: 'privilege-escalation' },
  { id: 'T1134',     name: 'Access Token Manipulation',     tactic: 'privilege-escalation' },
  { id: 'T1003.001', name: 'LSASS Memory',                  tactic: 'credential-access'    },
  { id: 'T1555.003', name: 'Credentials from Web Browsers', tactic: 'credential-access'    },
  { id: 'T1021.001', name: 'Remote Desktop Protocol',       tactic: 'lateral-movement'     },
  { id: 'T1021.002', name: 'SMB/Windows Admin Shares',      tactic: 'lateral-movement'     },
  { id: 'T1550.002', name: 'Pass the Hash',                 tactic: 'lateral-movement'     },
  { id: 'T1005',     name: 'Data from Local System',        tactic: 'collection'           },
  { id: 'T1041',     name: 'Exfiltration Over C2',          tactic: 'exfiltration'         },
  { id: 'T1486',     name: 'Data Encrypted for Impact',     tactic: 'impact'               },
];

const ACTORS = ['All', 'Volt Typhoon', 'APT29', 'Lazarus Group', 'LockBit', 'BlackCat'];

// ── Heat color ramp ──────────────────────────────────────────────────────────

function heatColor(hits, maxHits) {
  if (!hits || hits === 0) return { bg: 'transparent', text: C.muted };
  const ratio = Math.min(hits / Math.max(maxHits, 1), 1);
  if (ratio <= 0.25)      return { bg: 'rgba(74,158,255,0.18)',  text: C.blue   };
  if (ratio <= 0.5)       return { bg: 'rgba(0,212,170,0.20)',   text: C.teal   };
  if (ratio <= 0.75)      return { bg: 'rgba(245,197,24,0.22)',  text: C.amber  };
  return                          { bg: 'rgba(255,68,85,0.25)',   text: C.red    };
}

function priorityColor(p) {
  if (!p) return C.muted;
  if (p === 'P0') return C.red;
  if (p === 'P1') return C.orange;
  if (p === 'P2') return C.amber;
  return C.blue;
}

// ── API fetch ────────────────────────────────────────────────────────────────

const API_BASE = `${window.location.protocol}//${window.location.host}`;

async function fetchMatrix() {
  try {
    const res = await fetch(`${API_BASE}/api/attack-matrix`);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

// ── Component ────────────────────────────────────────────────────────────────

export default function AttackMatrix({ wsRef }) {
  const [data, setData]           = useState(null);      // { techniques: {}, lastUpdated }
  const [actor, setActor]         = useState('All');
  const [viewMode, setViewMode]   = useState('heatmap'); // heatmap | list
  const [selected, setSelected]   = useState(null);      // technique id
  const [loading, setLoading]     = useState(true);
  const mountedRef                = useRef(true);

  // Initial fetch
  useEffect(() => {
    mountedRef.current = true;
    fetchMatrix().then(d => {
      if (mountedRef.current) {
        setData(d);
        setLoading(false);
      }
    });
    return () => { mountedRef.current = false; };
  }, []);

  // WebSocket optimistic update: listen for ttp_update messages
  const handleWsMessage = useCallback((e) => {
    let msg;
    try { msg = JSON.parse(e.data); } catch { return; }
    if (msg.type === 'ttp_update' && msg.payload) {
      setData(prev => {
        if (!prev) return prev;
        const techs = { ...prev.techniques };
        const p = msg.payload;
        if (p.mitre_id) {
          const existing = techs[p.mitre_id] || { hits: 0, maxPriority: null, actors: [] };
          techs[p.mitre_id] = {
            hits: (existing.hits || 0) + (p.hits_delta || 1),
            maxPriority: p.priority || existing.maxPriority,
            actors: p.actor
              ? [...new Set([...(existing.actors || []), p.actor])]
              : existing.actors,
          };
        }
        return { ...prev, techniques: techs, lastUpdated: Date.now() };
      });
    }
  }, []);

  useEffect(() => {
    const ws = wsRef?.current;
    if (!ws) return;
    ws.addEventListener('message', handleWsMessage);
    return () => ws.removeEventListener('message', handleWsMessage);
  }, [wsRef, handleWsMessage]);

  // Derive display data
  const techniques = data?.techniques || {};
  const maxHits = Object.values(techniques).reduce((m, t) => Math.max(m, t.hits || 0), 1);

  // Filter by actor
  const filteredTechs = actor === 'All'
    ? KNOWN_TECHNIQUES
    : KNOWN_TECHNIQUES.filter(t => {
        const entry = techniques[t.id];
        return entry?.actors?.includes(actor);
      });

  // Group by tactic
  const byTactic = {};
  for (const t of filteredTechs) {
    if (!byTactic[t.tactic]) byTactic[t.tactic] = [];
    byTactic[t.tactic].push(t);
  }

  // Stats
  const totalHits      = Object.values(techniques).reduce((s, t) => s + (t.hits || 0), 0);
  const activeTechs    = Object.values(techniques).filter(t => (t.hits || 0) > 0).length;
  const coveredTactics = new Set(Object.keys(byTactic).filter(t => byTactic[t]?.some(
    tech => (techniques[tech.id]?.hits || 0) > 0
  ))).size;

  const selectedTech = selected
    ? { ...KNOWN_TECHNIQUES.find(t => t.id === selected), ...(techniques[selected] || {}) }
    : null;

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div>
      {/* Toolbar */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: 16,
        marginBottom: 16,
        flexWrap: 'wrap',
      }}>
        {/* Actor filter */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ color: C.muted, fontSize: 10, letterSpacing: '0.08em' }}>ACTOR</span>
          <select
            value={actor}
            onChange={e => setActor(e.target.value)}
            style={{
              background: C.card,
              color: C.text,
              border: `1px solid ${C.border}`,
              borderRadius: 3,
              padding: '4px 8px',
              fontSize: 11,
              fontFamily: 'inherit',
              outline: 'none',
            }}
          >
            {ACTORS.map(a => <option key={a} value={a}>{a}</option>)}
          </select>
        </div>

        {/* View mode toggle */}
        <div style={{ display: 'flex', gap: 0 }}>
          {['heatmap', 'list'].map(mode => (
            <button
              key={mode}
              onClick={() => setViewMode(mode)}
              style={{
                background: viewMode === mode ? `${C.teal}1a` : 'transparent',
                border: `1px solid ${viewMode === mode ? C.teal : C.border}`,
                color: viewMode === mode ? C.teal : C.muted,
                fontSize: 11,
                fontWeight: 600,
                padding: '4px 14px',
                borderRadius: mode === 'heatmap' ? '3px 0 0 3px' : '0 3px 3px 0',
                letterSpacing: '0.05em',
                marginLeft: mode === 'list' ? -1 : 0,
              }}
            >
              {mode.toUpperCase()}
            </button>
          ))}
        </div>

        {/* Stats */}
        <div style={{ display: 'flex', gap: 20, marginLeft: 'auto' }}>
          <StatMini label="TOTAL HITS" value={totalHits} color={C.teal} />
          <StatMini label="ACTIVE TTPs" value={activeTechs} color={C.amber} />
          <StatMini label="TACTICS HIT" value={`${coveredTactics}/14`} color={C.purple} />
        </div>
      </div>

      {loading ? (
        <div style={{
          padding: 48,
          textAlign: 'center',
          color: C.muted,
          fontSize: 12,
        }}>
          Loading ATT&CK matrix data...
        </div>
      ) : (
        <div style={{ display: 'flex', gap: 16 }}>
          {/* Matrix area */}
          <div style={{ flex: 1, minWidth: 0 }}>
            {viewMode === 'heatmap'
              ? <HeatmapGrid
                  byTactic={byTactic}
                  techniques={techniques}
                  maxHits={maxHits}
                  selected={selected}
                  onSelect={setSelected}
                />
              : <ListView
                  byTactic={byTactic}
                  techniques={techniques}
                  maxHits={maxHits}
                  selected={selected}
                  onSelect={setSelected}
                />
            }
          </div>

          {/* Detail panel */}
          {selectedTech && (
            <DetailPanel
              tech={selectedTech}
              onClose={() => setSelected(null)}
            />
          )}
        </div>
      )}
    </div>
  );
}

// ── Stat mini card ───────────────────────────────────────────────────────────

function StatMini({ label, value, color }) {
  return (
    <div>
      <div style={{ color: C.muted, fontSize: 9, fontWeight: 600, letterSpacing: '0.1em', marginBottom: 2 }}>
        {label}
      </div>
      <div style={{ color, fontSize: 18, fontWeight: 700, lineHeight: 1, fontVariantNumeric: 'tabular-nums' }}>
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
    </div>
  );
}

// ── Heatmap grid ─────────────────────────────────────────────────────────────

function HeatmapGrid({ byTactic, techniques, maxHits, selected, onSelect }) {
  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: `repeat(${TACTICS.length}, minmax(80px, 1fr))`,
      gap: 1,
      background: C.border,
      border: `1px solid ${C.border}`,
      borderRadius: 6,
      overflow: 'hidden',
    }}>
      {/* Header row */}
      {TACTICS.map(tactic => (
        <div key={tactic.id} style={{
          background: C.surface,
          padding: '8px 4px',
          textAlign: 'center',
          color: C.muted,
          fontSize: 9,
          fontWeight: 600,
          letterSpacing: '0.06em',
          lineHeight: 1.3,
        }}>
          {tactic.label.toUpperCase()}
        </div>
      ))}

      {/* Technique cells — iterate rows */}
      {Array.from({ length: Math.max(...TACTICS.map(t => (byTactic[t.id] || []).length), 1) }).map((_, row) => (
        TACTICS.map(tactic => {
          const techs = byTactic[tactic.id] || [];
          const tech = techs[row];
          if (!tech) {
            return (
              <div key={`${tactic.id}-${row}`} style={{
                background: C.card,
                minHeight: 42,
              }} />
            );
          }
          const entry = techniques[tech.id] || {};
          const hits = entry.hits || 0;
          const heat = heatColor(hits, maxHits);
          const isSelected = selected === tech.id;
          return (
            <button
              key={tech.id}
              onClick={() => onSelect(isSelected ? null : tech.id)}
              style={{
                background: isSelected ? `${C.teal}22` : (hits > 0 ? heat.bg : C.card),
                border: isSelected ? `1px solid ${C.teal}` : '1px solid transparent',
                padding: '6px 5px',
                textAlign: 'left',
                minHeight: 42,
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'center',
                gap: 2,
                cursor: 'pointer',
                transition: 'background 0.15s, border-color 0.15s',
              }}
            >
              <div style={{
                color: hits > 0 ? heat.text : C.muted,
                fontSize: 9,
                fontWeight: 600,
                lineHeight: 1.2,
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}>
                {tech.id}
              </div>
              <div style={{
                color: hits > 0 ? C.text : `${C.muted}88`,
                fontSize: 8,
                lineHeight: 1.2,
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}>
                {tech.name}
              </div>
              {hits > 0 && (
                <div style={{
                  color: heat.text,
                  fontSize: 10,
                  fontWeight: 700,
                  fontVariantNumeric: 'tabular-nums',
                }}>
                  {hits}
                </div>
              )}
            </button>
          );
        })
      ))}
    </div>
  );
}

// ── List view ────────────────────────────────────────────────────────────────

function ListView({ byTactic, techniques, maxHits, selected, onSelect }) {
  const thStyle = {
    padding: '8px 12px',
    textAlign: 'left',
    color: C.muted,
    fontSize: 9,
    fontWeight: 600,
    letterSpacing: '0.1em',
    borderBottom: `1px solid ${C.border}`,
    background: C.card,
    whiteSpace: 'nowrap',
  };

  const allTechs = TACTICS.flatMap(t => (byTactic[t.id] || []).map(tech => ({
    ...tech,
    ...(techniques[tech.id] || {}),
  }))).sort((a, b) => (b.hits || 0) - (a.hits || 0));

  return (
    <div style={{
      background: C.surface,
      border: `1px solid ${C.border}`,
      borderRadius: 6,
      overflow: 'hidden',
    }}>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr>
            {['TTP ID', 'NAME', 'TACTIC', 'HITS', 'PRIORITY', 'ACTORS'].map(h => (
              <th key={h} style={thStyle}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {allTechs.length === 0 ? (
            <tr>
              <td colSpan={6} style={{
                padding: 28,
                textAlign: 'center',
                color: C.muted,
                fontSize: 12,
              }}>
                No technique data available.
              </td>
            </tr>
          ) : (
            allTechs.map(tech => {
              const hits = tech.hits || 0;
              const heat = heatColor(hits, maxHits);
              const isSelected = selected === tech.id;
              const td = (extra = {}) => ({
                padding: '7px 12px',
                fontSize: 11,
                color: C.text,
                borderBottom: `1px solid ${C.border}44`,
                whiteSpace: 'nowrap',
                cursor: 'pointer',
                background: isSelected ? `${C.teal}11` : 'transparent',
                ...extra,
              });
              return (
                <tr
                  key={tech.id}
                  onClick={() => onSelect(isSelected ? null : tech.id)}
                  style={{ transition: 'background 0.12s' }}
                >
                  <td style={td({ color: hits > 0 ? heat.text : C.muted, fontWeight: 600 })}>{tech.id}</td>
                  <td style={td()}>{tech.name}</td>
                  <td style={td({ color: C.muted })}>{tech.tactic}</td>
                  <td style={td({
                    color: hits > 0 ? heat.text : C.muted,
                    fontWeight: 700,
                    fontVariantNumeric: 'tabular-nums',
                  })}>
                    {hits}
                  </td>
                  <td style={td({ color: priorityColor(tech.maxPriority) })}>
                    {tech.maxPriority || '---'}
                  </td>
                  <td style={td({ color: C.purple, fontSize: 10 })}>
                    {(tech.actors || []).join(', ') || '---'}
                  </td>
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
}

// ── Detail panel ─────────────────────────────────────────────────────────────

function DetailPanel({ tech, onClose }) {
  const hits = tech.hits || 0;
  const actors = tech.actors || [];

  return (
    <div style={{
      width: 300,
      flexShrink: 0,
      background: C.card,
      border: `1px solid ${C.border}`,
      borderRadius: 6,
      padding: '16px 18px',
      alignSelf: 'flex-start',
      position: 'sticky',
      top: 130,
    }}>
      {/* Close */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <span style={{ color: C.teal, fontSize: 13, fontWeight: 700 }}>{tech.id}</span>
        <button
          onClick={onClose}
          style={{
            background: 'none',
            border: 'none',
            color: C.muted,
            fontSize: 16,
            cursor: 'pointer',
            padding: '0 4px',
          }}
        >
          x
        </button>
      </div>

      {/* Name */}
      <div style={{ color: C.textBright, fontSize: 14, fontWeight: 600, marginBottom: 12, lineHeight: 1.4 }}>
        {tech.name}
      </div>

      {/* Tactic */}
      <div style={{ marginBottom: 14 }}>
        <div style={{ color: C.muted, fontSize: 9, letterSpacing: '0.1em', marginBottom: 4 }}>TACTIC</div>
        <div style={{ color: C.purple, fontSize: 11 }}>{tech.tactic}</div>
      </div>

      {/* Hits */}
      <div style={{ marginBottom: 14 }}>
        <div style={{ color: C.muted, fontSize: 9, letterSpacing: '0.1em', marginBottom: 4 }}>SIMULATION HITS</div>
        <div style={{ color: hits > 0 ? C.amber : C.muted, fontSize: 28, fontWeight: 700, lineHeight: 1 }}>
          {hits}
        </div>
      </div>

      {/* Priority */}
      {tech.maxPriority && (
        <div style={{ marginBottom: 14 }}>
          <div style={{ color: C.muted, fontSize: 9, letterSpacing: '0.1em', marginBottom: 4 }}>MAX PRIORITY</div>
          <span style={{
            display: 'inline-block',
            padding: '2px 8px',
            background: `${priorityColor(tech.maxPriority)}22`,
            color: priorityColor(tech.maxPriority),
            border: `1px solid ${priorityColor(tech.maxPriority)}44`,
            borderRadius: 3,
            fontSize: 11,
            fontWeight: 700,
          }}>
            {tech.maxPriority}
          </span>
        </div>
      )}

      {/* Actors */}
      {actors.length > 0 && (
        <div style={{ marginBottom: 14 }}>
          <div style={{ color: C.muted, fontSize: 9, letterSpacing: '0.1em', marginBottom: 6 }}>
            THREAT ACTORS
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {actors.map(a => (
              <span key={a} style={{
                padding: '2px 8px',
                background: 'rgba(168,85,247,0.12)',
                color: C.purple,
                border: '1px solid rgba(168,85,247,0.3)',
                borderRadius: 3,
                fontSize: 10,
              }}>
                {a}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Heat bar */}
      <div style={{ marginBottom: 8 }}>
        <div style={{ color: C.muted, fontSize: 9, letterSpacing: '0.1em', marginBottom: 6 }}>
          HEAT LEVEL
        </div>
        <div style={{
          height: 6,
          background: C.surface,
          borderRadius: 3,
          overflow: 'hidden',
        }}>
          <div style={{
            height: '100%',
            width: `${Math.min((hits / Math.max(hits, 10)) * 100, 100)}%`,
            background: `linear-gradient(90deg, ${C.blue}, ${C.teal}, ${C.amber}, ${C.red})`,
            borderRadius: 3,
            transition: 'width 0.3s',
          }} />
        </div>
      </div>
    </div>
  );
}
