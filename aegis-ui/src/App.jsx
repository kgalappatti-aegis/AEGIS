/**
 * AEGIS Dashboard – App.jsx
 *
 * WebSocket message types handled:
 *   { type: "event",    payload: {...}, ts: number }
 *   { type: "stats",    payload: {...}, ts: number }
 *   { type: "advisory", payload: {...}, ts: number }
 */

import { useState, useEffect, useRef, useCallback } from 'react';
import AttackMatrix from './components/AttackMatrix';
import KillChainFlow from './components/KillChainFlow';

// ── Config ───────────────────────────────────────────────────────────────────

const WS_URL = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws`;
const MAX_EVENTS     = 100;
const MAX_ADVISORIES = 100;
const RECONNECT_MS   = 3_000;
const FLASH_MS       = 700;

// ── Design tokens ────────────────────────────────────────────────────────────

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
  adv:         '#22d3ee',
  amber:       '#f5c518',
  orange:      '#ff8c22',
  red:         '#ff4455',
  blue:        '#4a9eff',
  green:       '#34d399',
  purple:      '#a855f7',
  // Priority aliases
  P0: '#ff4455',
  P1: '#ff8c22',
  P2: '#f5c518',
  P3: '#4a9eff',
};

const PRIORITY_BG = {
  P0: 'rgba(255,68,85,0.14)',
  P1: 'rgba(255,140,34,0.14)',
  P2: 'rgba(245,197,24,0.12)',
  P3: 'rgba(74,158,255,0.12)',
};

const TLP_STYLE = {
  RED:   { bg: 'rgba(255,68,85,0.14)',   color: '#ff4455', border: 'rgba(255,68,85,0.5)'   },
  AMBER: { bg: 'rgba(255,140,34,0.14)',  color: '#ff8c22', border: 'rgba(255,140,34,0.5)'  },
  GREEN: { bg: 'rgba(52,211,153,0.14)',  color: '#34d399', border: 'rgba(52,211,153,0.5)'  },
  CLEAR: { bg: 'rgba(90,114,148,0.12)',  color: '#94a3b8', border: 'rgba(90,114,148,0.4)'  },
};

const STAGE_CFG = {
  ingested:  { color: C.muted,  label: 'INGESTED'  },
  triaged:   { color: C.orange, label: 'TRIAGED'   },
  simulated: { color: C.purple, label: 'SIMULATED' },
  detected:  { color: C.teal,   label: 'DETECTED'  },
  advisory:  { color: C.green,  label: 'ADVISORY'  },
};

const ROUTING_COLOR = {
  triage:     C.orange,
  simulation: C.purple,
  detection:  C.green,
  advisory:   C.adv,
};

// ── Helpers ──────────────────────────────────────────────────────────────────

function fmtTime(ts) {
  const d = ts ? new Date(typeof ts === 'number' ? ts : ts) : new Date();
  return d.toLocaleTimeString('en-US', { hour12: false });
}

function fmtPBreach(v) {
  const n = parseFloat(v);
  return isNaN(n) ? '—' : (n * 100).toFixed(1) + '%';
}

function shortId(s, len = 12) {
  if (!s) return '—';
  return s.length > len ? s.slice(0, len) + '…' : s;
}

let _uidCounter = 0;
function uid() { return ++_uidCounter; }

// ── Shared atoms ─────────────────────────────────────────────────────────────

function PriorityPill({ priority }) {
  const color = C[priority] || C.muted;
  const bg    = PRIORITY_BG[priority] || 'rgba(90,114,148,0.12)';
  return (
    <span style={{
      display: 'inline-block',
      padding: '1px 7px',
      background: bg,
      color,
      border: `1px solid ${color}66`,
      borderRadius: 3,
      fontSize: 10,
      fontWeight: 700,
      letterSpacing: '0.06em',
    }}>
      {priority || '—'}
    </span>
  );
}

function TlpBadge({ tlp }) {
  const s = TLP_STYLE[tlp] || TLP_STYLE.CLEAR;
  return (
    <span style={{
      display: 'inline-block',
      padding: '1px 6px',
      background: s.bg,
      color: s.color,
      border: `1px solid ${s.border}`,
      borderRadius: 3,
      fontSize: 10,
      fontWeight: 600,
      letterSpacing: '0.08em',
    }}>
      TLP:{tlp || 'CLEAR'}
    </span>
  );
}

function StagePill({ stage }) {
  const cfg = STAGE_CFG[stage] || { color: C.muted, label: (stage || '—').toUpperCase() };
  return <span style={{ color: cfg.color, fontSize: 11 }}>{cfg.label}</span>;
}

function ConfidenceMark({ confidence }) {
  const color = { high: C.green, medium: C.amber, low: C.muted }[confidence] || C.muted;
  return (
    <span style={{ color, fontSize: 11 }}>
      <span style={{ fontSize: 8, verticalAlign: 'middle', marginRight: 4 }}>●</span>
      {(confidence || 'unknown').toUpperCase()}
    </span>
  );
}

function ExpandToggle({ label, count, expanded, color, onClick }) {
  return (
    <button
      onClick={onClick}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        background: 'none',
        border: `1px solid ${C.border}`,
        color: color || C.muted,
        fontSize: 11,
        fontWeight: 600,
        padding: '3px 10px',
        borderRadius: 3,
        letterSpacing: '0.06em',
        transition: 'border-color 0.15s, color 0.15s',
      }}
    >
      <span style={{ fontSize: 9 }}>{expanded ? '▾' : '▸'}</span>
      {label} ({count})
    </button>
  );
}

// ── Advisory Card ─────────────────────────────────────────────────────────────

function AdvisoryCard({ adv, isNew }) {
  const [sigma,  setSigma]  = useState(false);
  const [gaps,   setGaps]   = useState(false);
  const [chain,  setChain]  = useState(false);

  const borderColor = C[adv.priority] || C.muted;

  const sigmaRules  = Array.isArray(adv.sigma_rules)        ? adv.sigma_rules        : [];
  const covGaps     = Array.isArray(adv.coverage_gaps)       ? adv.coverage_gaps      : [];
  const immActions  = (Array.isArray(adv.immediate_actions)  ? adv.immediate_actions  : []).slice(0, 3);
  const detActions  = (Array.isArray(adv.detection_actions)  ? adv.detection_actions  : []).slice(0, 3);
  const mitreTechs  = Array.isArray(adv.mitre_techniques)    ? adv.mitre_techniques   : [];

  return (
    <div
      className={isNew ? 'card-new' : ''}
      style={{
        background: C.card,
        border: `1px solid ${C.border}`,
        borderLeft: `3px solid ${borderColor}`,
        borderRadius: 6,
        padding: '16px 20px',
        marginBottom: 10,
      }}
    >
      {/* ── Top row: pills + timestamp ─────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
        <div style={{ display: 'flex', gap: 7, alignItems: 'center', flexWrap: 'wrap' }}>
          <PriorityPill priority={adv.priority} />
          <TlpBadge     tlp={adv.tlp} />
          <ConfidenceMark confidence={adv.confidence} />
        </div>
        <span style={{ color: C.muted, fontSize: 11, flexShrink: 0, marginLeft: 12 }}>
          {fmtTime(adv.created_at || adv.ts)}
        </span>
      </div>

      {/* ── CVE + threat actor ─────────────────────────────────────────── */}
      <div style={{ marginBottom: 6, display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <span style={{ color: C.amber, fontSize: 13, fontWeight: 700 }}>
          {adv.cve_id || 'CVE-UNKNOWN'}
        </span>
        {adv.threat_actor && (
          <span style={{ color: C.purple, fontSize: 11 }}>
            ▸ {adv.threat_actor}
          </span>
        )}
      </div>

      {/* ── Title ─────────────────────────────────────────────────────── */}
      <div style={{
        color: C.textBright,
        fontSize: 15,
        fontWeight: 600,
        lineHeight: 1.45,
        marginBottom: 12,
      }}>
        {adv.title || '(no title)'}
      </div>

      {/* ── Metrics row ───────────────────────────────────────────────── */}
      <div style={{ display: 'flex', gap: 28, marginBottom: 14, alignItems: 'flex-end' }}>
        <div>
          <div style={{ color: C.muted, fontSize: 9, letterSpacing: '0.1em', marginBottom: 3 }}>P(BREACH)</div>
          <div style={{ color: C.red, fontSize: 24, fontWeight: 700, lineHeight: 1 }}>
            {fmtPBreach(adv.p_breach)}
          </div>
        </div>
        <div>
          <div style={{ color: C.muted, fontSize: 9, letterSpacing: '0.1em', marginBottom: 3 }}>RISK SCORE</div>
          <div style={{ color: C.orange, fontSize: 24, fontWeight: 700, lineHeight: 1 }}>
            {adv.risk_score != null ? adv.risk_score : '—'}
          </div>
        </div>
        {adv.source_type && (
          <div style={{ marginLeft: 'auto', textAlign: 'right' }}>
            <div style={{ color: C.muted, fontSize: 9, letterSpacing: '0.1em', marginBottom: 3 }}>SOURCE</div>
            <div style={{ color: C.muted, fontSize: 12 }}>{adv.source_type.toUpperCase()}</div>
          </div>
        )}
      </div>

      {/* ── Executive summary ─────────────────────────────────────────── */}
      {adv.executive_summary && (
        <div style={{
          color: C.text,
          fontSize: 12,
          lineHeight: 1.75,
          marginBottom: 14,
          padding: '10px 13px',
          background: `rgba(0,212,170,0.05)`,
          borderRadius: 4,
          borderLeft: `2px solid ${C.teal}44`,
        }}>
          {adv.executive_summary}
        </div>
      )}

      {/* ── Two-column action lists ────────────────────────────────────── */}
      {(immActions.length > 0 || detActions.length > 0) && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 14 }}>
          <ActionList label="IMMEDIATE ACTIONS" items={immActions} bulletColor={C.red} />
          <ActionList label="DETECTION ACTIONS" items={detActions} bulletColor={C.teal} />
        </div>
      )}

      {/* ── Expandable sections ───────────────────────────────────────── */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 10, flexWrap: 'wrap' }}>
        {adv.event_id && (
          <ExpandToggle
            label="KILL CHAIN"
            count={1}
            expanded={chain}
            color={C.purple}
            onClick={() => setChain(v => !v)}
          />
        )}
        {sigmaRules.length > 0 && (
          <ExpandToggle
            label="SIGMA RULES"
            count={sigmaRules.length}
            expanded={sigma}
            color={C.teal}
            onClick={() => setSigma(v => !v)}
          />
        )}
        {covGaps.length > 0 && (
          <ExpandToggle
            label="COVERAGE GAPS"
            count={covGaps.length}
            expanded={gaps}
            color={C.orange}
            onClick={() => setGaps(v => !v)}
          />
        )}
      </div>

      {chain && adv.event_id && (
        <div style={{ marginBottom: 10 }}>
          <KillChainFlow eventId={adv.event_id} />
        </div>
      )}

      {sigma && sigmaRules.length > 0 && (
        <SigmaSection rules={sigmaRules} />
      )}

      {gaps && covGaps.length > 0 && (
        <GapsSection gaps={covGaps} />
      )}

      {/* ── MITRE technique pills ──────────────────────────────────────── */}
      {mitreTechs.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginTop: 6 }}>
          {mitreTechs.map((t, i) => (
            <span key={i} style={{
              padding: '2px 8px',
              background: 'rgba(168,85,247,0.12)',
              color: C.purple,
              border: `1px solid rgba(168,85,247,0.3)`,
              borderRadius: 3,
              fontSize: 10,
            }}>
              {t}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function ActionList({ label, items, bulletColor }) {
  return (
    <div>
      <div style={{
        color: C.muted,
        fontSize: 9,
        fontWeight: 600,
        letterSpacing: '0.1em',
        marginBottom: 7,
      }}>
        {label}
      </div>
      {items.length === 0
        ? <span style={{ color: C.muted, fontSize: 11 }}>—</span>
        : items.map((a, i) => (
            <div key={i} style={{ display: 'flex', gap: 7, marginBottom: 5, alignItems: 'flex-start' }}>
              <span style={{ color: bulletColor, flexShrink: 0, marginTop: 1 }}>▸</span>
              <span style={{ color: C.text, fontSize: 11, lineHeight: 1.55 }}>{a}</span>
            </div>
          ))
      }
    </div>
  );
}

function SigmaSection({ rules }) {
  return (
    <div style={{
      borderLeft: `2px solid rgba(0,212,170,0.25)`,
      paddingLeft: 12,
      marginBottom: 10,
    }}>
      {rules.map((rule, i) => (
        <div key={i} style={{
          marginBottom: 8,
          padding: '8px 10px',
          background: 'rgba(0,212,170,0.05)',
          borderRadius: 4,
        }}>
          {typeof rule === 'string' ? (
            <pre style={{
              color: C.text,
              fontSize: 10,
              lineHeight: 1.6,
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word',
              margin: 0,
            }}>{rule}</pre>
          ) : (
            <>
              <div style={{ color: C.teal, fontSize: 11, fontWeight: 600, marginBottom: 4 }}>
                {rule.title || `Rule ${i + 1}`}
                {rule.mitre_technique && (
                  <span style={{ color: C.muted, fontWeight: 400, marginLeft: 10, fontSize: 10 }}>
                    [{rule.mitre_technique}]
                  </span>
                )}
                {rule.priority && (
                  <span style={{
                    marginLeft: 8,
                    fontSize: 9,
                    padding: '1px 5px',
                    background: 'rgba(255,140,34,0.15)',
                    color: C.orange,
                    borderRadius: 2,
                  }}>
                    {rule.priority.toUpperCase()}
                  </span>
                )}
              </div>
              {rule.logsource && (
                <div style={{ color: C.muted, fontSize: 10, marginBottom: 4 }}>
                  logsource: {rule.logsource}
                </div>
              )}
              {rule.detection_logic && (
                <pre style={{
                  color: C.text,
                  fontSize: 10,
                  lineHeight: 1.6,
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                  margin: 0,
                }}>{rule.detection_logic}</pre>
              )}
            </>
          )}
        </div>
      ))}
    </div>
  );
}

function GapsSection({ gaps }) {
  return (
    <div style={{
      borderLeft: `2px solid rgba(255,140,34,0.25)`,
      paddingLeft: 12,
      marginBottom: 10,
    }}>
      {gaps.map((gap, i) => (
        <div key={i} style={{ display: 'flex', gap: 10, marginBottom: 5, fontSize: 11 }}>
          {typeof gap === 'string' ? (
            <>
              <span style={{ color: C.orange, flexShrink: 0 }}>!</span>
              <span style={{ color: C.text }}>{gap}</span>
            </>
          ) : (
            <>
              <span style={{ color: C.amber, minWidth: 80, flexShrink: 0, fontWeight: 600 }}>
                {gap.ttp_id}
              </span>
              <span style={{ color: C.text, lineHeight: 1.55 }}>{gap.gap_description}</span>
            </>
          )}
        </div>
      ))}
    </div>
  );
}

// ── Event table row ───────────────────────────────────────────────────────────

function EventRow({ ev, isNew, isSelected, onClick }) {
  const td = (extra = {}) => ({
    padding: '7px 13px',
    fontSize: 11,
    color: C.text,
    borderBottom: `1px solid ${C.border}44`,
    whiteSpace: 'nowrap',
    ...extra,
  });

  const routingColor = ROUTING_COLOR[ev.routing_target] || C.muted;

  return (
    <tr
      className={isNew ? 'row-new' : ''}
      onClick={onClick}
      style={{
        transition: 'background 0.12s',
        background: isSelected ? `${C.teal}0d` : 'transparent',
        cursor: 'pointer',
      }}
    >
      <td style={td({ color: C.muted })}>{fmtTime(ev.ts || ev.ingested_at)}</td>
      <td style={td({ color: C.teal,  fontFamily: 'inherit' })}>{shortId(ev.event_id)}</td>
      <td style={td({ color: C.amber })}>{ev.cve_id || ev.source_type || '—'}</td>
      <td style={td()}><PriorityPill priority={ev.priority} /></td>
      <td style={td()}><StagePill stage={ev.stage} /></td>
      <td style={td({
        color: ev.relevance_score != null ? C.teal : C.muted,
        fontVariantNumeric: 'tabular-nums',
      })}>
        {ev.relevance_score != null ? parseFloat(ev.relevance_score).toFixed(3) : '—'}
      </td>
      <td style={td({ color: routingColor })}>
        {ev.routing_target || '—'}
      </td>
    </tr>
  );
}

// ── Events view ───────────────────────────────────────────────────────────────

function EventsView({ events, newIds }) {
  const [filter, setFilter] = useState('all');
  const [selectedEvId, setSelectedEvId] = useState(null);

  const filtered = filter === 'all' ? events : events.filter(e => e.priority === filter);
  const selectedEv = selectedEvId ? events.find(e => e.event_id === selectedEvId) : null;
  const hasSimData = selectedEv && ['simulated', 'detected', 'advisory'].includes(selectedEv.stage);

  const filterBtnStyle = (f) => {
    const active = filter === f;
    const color  = f === 'all' ? C.teal : (C[f] || C.teal);
    return {
      background: active ? `${color}1a` : 'transparent',
      border: `1px solid ${active ? color : C.border}`,
      color: active ? color : C.muted,
      fontSize: 11,
      fontWeight: 600,
      padding: '3px 11px',
      borderRadius: 3,
      letterSpacing: '0.05em',
      transition: 'all 0.15s',
    };
  };

  const thStyle = {
    padding: '8px 13px',
    textAlign: 'left',
    color: C.muted,
    fontSize: 9,
    fontWeight: 600,
    letterSpacing: '0.1em',
    borderBottom: `1px solid ${C.border}`,
    background: C.card,
    whiteSpace: 'nowrap',
  };

  return (
    <div>
      {/* Filter bar */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 12, alignItems: 'center' }}>
        <span style={{ color: C.muted, fontSize: 10, marginRight: 4, letterSpacing: '0.08em' }}>
          FILTER
        </span>
        {['all', 'P0', 'P1', 'P2', 'P3'].map(f => (
          <button key={f} onClick={() => setFilter(f)} style={filterBtnStyle(f)}>
            {f.toUpperCase()}
          </button>
        ))}
        <span style={{ color: C.muted, fontSize: 10, marginLeft: 8 }}>
          {filtered.length.toLocaleString()} events
        </span>
      </div>

      {/* Table */}
      <div style={{
        background: C.surface,
        border: `1px solid ${C.border}`,
        borderRadius: 6,
        overflow: 'hidden',
      }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              {['TIME', 'EVENT ID', 'CVE / SOURCE', 'PRIORITY', 'STAGE', 'RELEVANCE', 'ROUTING'].map(h => (
                <th key={h} style={thStyle}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={7} style={{
                  padding: 28,
                  textAlign: 'center',
                  color: C.muted,
                  fontSize: 12,
                }}>
                  Waiting for events…
                </td>
              </tr>
            ) : (
              filtered.map(ev => (
                <EventRow
                  key={ev._uid}
                  ev={ev}
                  isNew={newIds.has(ev._uid)}
                  isSelected={selectedEvId === ev.event_id}
                  onClick={() => setSelectedEvId(
                    selectedEvId === ev.event_id ? null : ev.event_id
                  )}
                />
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* ── Event detail panel with kill chain ─────────────────────────── */}
      {selectedEv && (
        <div style={{
          marginTop: 12,
          background: C.card,
          border: `1px solid ${C.border}`,
          borderRadius: 6,
          overflow: 'hidden',
        }}>
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            padding: '10px 16px',
            borderBottom: `1px solid ${C.border}`,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ color: C.teal, fontSize: 12, fontWeight: 700 }}>
                {selectedEv.event_id}
              </span>
              <PriorityPill priority={selectedEv.priority} />
              <StagePill stage={selectedEv.stage} />
              {selectedEv.cve_id && (
                <span style={{ color: C.amber, fontSize: 11, fontWeight: 600 }}>
                  {selectedEv.cve_id}
                </span>
              )}
            </div>
            <button
              onClick={() => setSelectedEvId(null)}
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

          {/* Triage scores row */}
          <div style={{
            display: 'flex',
            gap: 24,
            padding: '10px 16px',
            borderBottom: hasSimData ? `1px solid ${C.border}` : 'none',
          }}>
            {[
              { label: 'RELEVANCE',   value: selectedEv.relevance_score, color: C.teal   },
              { label: 'INFRA MATCH', value: selectedEv.infrastructure_match, color: C.blue },
              { label: 'EXPLOIT',     value: selectedEv.exploitability, color: C.orange },
              { label: 'URGENCY',     value: selectedEv.temporal_urgency, color: C.amber },
            ].map(m => (
              <div key={m.label}>
                <div style={{ color: C.muted, fontSize: 8, letterSpacing: '0.1em', marginBottom: 2 }}>
                  {m.label}
                </div>
                <div style={{
                  color: m.value != null ? m.color : C.muted,
                  fontSize: 14,
                  fontWeight: 700,
                  fontVariantNumeric: 'tabular-nums',
                }}>
                  {m.value != null ? parseFloat(m.value).toFixed(3) : '---'}
                </div>
              </div>
            ))}
          </div>

          {/* Kill chain (only when simulation data should exist) */}
          {hasSimData && selectedEv.event_id && (
            <KillChainFlow eventId={selectedEv.event_id} />
          )}
        </div>
      )}
    </div>
  );
}

// ── Advisories view ───────────────────────────────────────────────────────────

function AdvisoriesView({ advisories, newIds }) {
  return (
    <div>
      <div style={{ color: C.muted, fontSize: 10, letterSpacing: '0.08em', marginBottom: 12 }}>
        {advisories.length} ADVISORIES RECEIVED
      </div>

      {advisories.length === 0 ? (
        <div style={{
          background: C.surface,
          border: `1px solid ${C.border}`,
          borderRadius: 6,
          padding: '52px 32px',
          textAlign: 'center',
          color: C.muted,
          fontSize: 12,
          lineHeight: 1.8,
        }}>
          No advisories yet.<br />
          They will appear here as events complete the full pipeline.
        </div>
      ) : (
        advisories.map(adv => (
          <AdvisoryCard
            key={adv._uid}
            adv={adv}
            isNew={newIds.has(adv._uid)}
          />
        ))
      )}
    </div>
  );
}

// ── Stat bar ──────────────────────────────────────────────────────────────────

function StatBar({ stats, advisoryCount }) {
  const s  = stats || {};
  const qd = s.queue_depths || {};

  const cells = [
    { label: 'TOTAL',       value: s.total_ingested ?? '—',           color: C.textBright },
    { label: 'P0 CRITICAL', value: s.by_priority?.P0 ?? '—',          color: C.red        },
    { label: 'TRIAGED',     value: s.triaged_count  ?? '—',           color: C.orange     },
    { label: 'AVG RELEV',   value: s.avg_relevance  ?? '—',           color: C.teal       },
    { label: 'Q:TRIAGE',    value: qd.triage        ?? '—',           color: C.muted      },
    { label: 'Q:SIM',       value: qd.simulation    ?? '—',           color: C.purple     },
    { label: 'ADVISORIES',  value: advisoryCount,                      color: C.green      },
  ];

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(7, 1fr)',
      background: C.surface,
      borderBottom: `1px solid ${C.border}`,
    }}>
      {cells.map((cell, i) => (
        <div key={cell.label} style={{
          padding: '10px 16px',
          borderRight: i < 6 ? `1px solid ${C.border}` : 'none',
        }}>
          <div style={{
            color: C.muted,
            fontSize: 9,
            fontWeight: 600,
            letterSpacing: '0.1em',
            marginBottom: 5,
          }}>
            {cell.label}
          </div>
          <div style={{
            color: cell.color,
            fontSize: 22,
            fontWeight: 700,
            lineHeight: 1,
            fontVariantNumeric: 'tabular-nums',
          }}>
            {typeof cell.value === 'number' ? cell.value.toLocaleString() : cell.value}
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Tab bar ───────────────────────────────────────────────────────────────────

function TabBar({ activeTab, onSwitch, unread }) {
  return (
    <div style={{
      display: 'flex',
      background: C.surface,
      borderBottom: `1px solid ${C.border}`,
      padding: '0 24px',
    }}>
      {[
        { id: 'events',     label: 'EVENTS'     },
        { id: 'advisories', label: 'ADVISORIES' },
        { id: 'attack',     label: 'ATT&CK'     },
      ].map(tab => {
        const active = activeTab === tab.id;
        return (
          <button
            key={tab.id}
            onClick={() => onSwitch(tab.id)}
            style={{
              background: 'none',
              border: 'none',
              borderBottom: `2px solid ${active ? C.teal : 'transparent'}`,
              color: active ? C.teal : C.muted,
              fontSize: 11,
              fontWeight: active ? 600 : 400,
              letterSpacing: '0.1em',
              padding: '11px 20px',
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              transition: 'color 0.15s, border-color 0.15s',
            }}
          >
            {tab.label}
            {tab.id === 'advisories' && unread > 0 && (
              <span style={{
                background: C.red,
                color: '#fff',
                fontSize: 9,
                fontWeight: 700,
                padding: '1px 5px',
                borderRadius: 8,
                minWidth: 18,
                textAlign: 'center',
                lineHeight: '14px',
                display: 'inline-block',
              }}>
                {unread > 99 ? '99+' : unread}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}

// ── Header ────────────────────────────────────────────────────────────────────

function Header({ wsStatus }) {
  const dotColor = { connected: C.green, disconnected: C.red, connecting: C.amber }[wsStatus] || C.muted;
  const pulse    = wsStatus === 'connected';

  return (
    <header style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 24px',
      height: 54,
      background: C.surface,
      borderBottom: `1px solid ${C.border}`,
      position: 'sticky',
      top: 0,
      zIndex: 100,
    }}>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 10 }}>
        <span style={{
          fontSize: '1.2rem',
          fontWeight: 800,
          letterSpacing: '0.14em',
          color: C.teal,
        }}>
          AEGIS
        </span>
        <span style={{ fontSize: '0.72rem', color: C.muted, letterSpacing: '0.08em' }}>
          SECURITY OPERATIONS
        </span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{
          width: 8,
          height: 8,
          borderRadius: '50%',
          background: dotColor,
          display: 'inline-block',
          boxShadow: pulse ? `0 0 6px ${dotColor}` : 'none',
          animation: pulse ? 'pulse 2s infinite' : 'none',
        }} />
        <span style={{ color: dotColor, fontSize: 11, fontWeight: 600 }}>
          {wsStatus.toUpperCase()}
        </span>
      </div>
    </header>
  );
}

// ── App (root) ────────────────────────────────────────────────────────────────

export default function App() {
  const [wsStatus,   setWsStatus]   = useState('connecting');
  const [activeTab,  setActiveTab]  = useState('events');
  const [unread,     setUnread]     = useState(0);
  const [events,     setEvents]     = useState([]);
  const [advisories, setAdvisories] = useState([]);
  const [newEvIds,   setNewEvIds]   = useState(new Set());
  const [newAdvIds,  setNewAdvIds]  = useState(new Set());
  const [stats,      setStats]      = useState(null);

  const wsRef        = useRef(null);
  const retryRef     = useRef(null);
  const activeTabRef = useRef(activeTab);

  useEffect(() => { activeTabRef.current = activeTab; }, [activeTab]);

  // Flash a uid in a Set for FLASH_MS then clear it
  const flash = useCallback((setter, id) => {
    setter(prev => new Set(prev).add(id));
    setTimeout(() => setter(prev => { const s = new Set(prev); s.delete(id); return s; }), FLASH_MS);
  }, []);

  const connect = useCallback(() => {
    if (wsRef.current) wsRef.current.close();
    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;
    setWsStatus('connecting');

    ws.onopen  = () => setWsStatus('connected');
    ws.onerror = () => ws.close();
    ws.onclose = () => {
      setWsStatus('disconnected');
      retryRef.current = setTimeout(connect, RECONNECT_MS);
    };

    ws.onmessage = (e) => {
      let msg;
      try { msg = JSON.parse(e.data); } catch { return; }

      if (msg.type === 'event') {
        const ev = { ...msg.payload, ts: msg.ts, _uid: uid() };
        setEvents(prev => {
          // Deduplicate by event_id — update existing or prepend new
          const eid = ev.event_id;
          if (eid && prev.some(e => e.event_id === eid)) {
            return prev.map(e => e.event_id === eid ? { ...ev, _uid: e._uid } : e);
          }
          return [ev, ...prev].slice(0, MAX_EVENTS);
        });
        flash(setNewEvIds, ev._uid);

      } else if (msg.type === 'stats') {
        setStats(msg.payload);

      } else if (msg.type === 'advisory') {
        const adv = { ...msg.payload, ts: msg.ts, _uid: uid() };
        setAdvisories(prev => {
          const eid = adv.event_id;
          if (eid && prev.some(a => a.event_id === eid)) {
            return prev.map(a => a.event_id === eid ? { ...adv, _uid: a._uid } : a);
          }
          return [adv, ...prev].slice(0, MAX_ADVISORIES);
        });
        flash(setNewAdvIds, adv._uid);
        if (activeTabRef.current !== 'advisories') {
          setUnread(n => n + 1);
        }
      }
    };
  }, [flash]);

  useEffect(() => {
    connect();
    return () => {
      clearTimeout(retryRef.current);
      wsRef.current?.close();
    };
  }, [connect]);

  const handleTabSwitch = (tab) => {
    setActiveTab(tab);
    if (tab === 'advisories') setUnread(0);
  };

  return (
    <div style={{ minHeight: '100vh', background: C.bg }}>
      <Header wsStatus={wsStatus} />
      <TabBar activeTab={activeTab} onSwitch={handleTabSwitch} unread={unread} />
      <StatBar stats={stats} advisoryCount={advisories.length} />

      <div style={{ padding: '16px 24px', maxWidth: 1600, margin: '0 auto' }}>
        {activeTab === 'events' && (
          <EventsView events={events} newIds={newEvIds} />
        )}
        {activeTab === 'advisories' && (
          <AdvisoriesView advisories={advisories} newIds={newAdvIds} />
        )}
        {activeTab === 'attack' && (
          <AttackMatrix wsRef={wsRef} />
        )}
      </div>
    </div>
  );
}
