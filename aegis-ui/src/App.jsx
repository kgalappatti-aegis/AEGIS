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
const MAX_INBOUND    = 200;
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
  ingested:         { color: C.muted,  label: 'INGESTED'  },
  routed:           { color: C.blue,   label: 'ROUTED'    },
  triaged:          { color: C.orange, label: 'TRIAGED'   },
  simulated:        { color: C.purple, label: 'SIMULATED' },
  detected:         { color: C.teal,   label: 'DETECTED'  },
  advisory:         { color: C.green,  label: 'ADVISORY'  },
  pending_approval: { color: C.amber,  label: 'PENDING APPROVAL' },
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
  const [artExp, setArtExp] = useState(false);

  const borderColor = C[adv.priority] || C.muted;

  const sigmaRules  = Array.isArray(adv.sigma_rules)        ? adv.sigma_rules        : [];
  const covGaps     = Array.isArray(adv.coverage_gaps)       ? adv.coverage_gaps      : [];
  const immActions  = (Array.isArray(adv.immediate_actions)  ? adv.immediate_actions  : []).slice(0, 3);
  const detActions  = (Array.isArray(adv.detection_actions)  ? adv.detection_actions  : []).slice(0, 3);
  const mitreTechs  = Array.isArray(adv.mitre_techniques)    ? adv.mitre_techniques   : [];
  const valTests    = Array.isArray(adv.validation_tests)    ? adv.validation_tests   : [];

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
        {valTests.length > 0 && (
          <ExpandToggle
            label="VALIDATION TESTS"
            count={valTests.length}
            expanded={artExp}
            color={C.blue}
            onClick={() => setArtExp(v => !v)}
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

      {artExp && valTests.length > 0 && (
        <ValidationTestsSection tests={valTests} />
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

      {/* ── Feedback widget ───────────────────────────────────────────── */}
      {adv.advisory_id && <FeedbackWidget advisoryId={adv.advisory_id} eventId={adv.event_id} />}
    </div>
  );
}

function FeedbackWidget({ advisoryId, eventId }) {
  const [rating, setRating]     = useState(0);
  const [comment, setComment]   = useState('');
  const [sent, setSent]         = useState(false);
  const [hover, setHover]       = useState(0);

  const submit = async () => {
    if (rating < 1) return;
    try {
      await fetch('/api/feedback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ advisory_id: advisoryId, event_id: eventId, rating, comment }),
      });
      setSent(true);
    } catch { /* ignore */ }
  };

  if (sent) {
    return (
      <div style={{ marginTop: 10, color: C.green, fontSize: 11 }}>
        Feedback submitted — thank you.
      </div>
    );
  }

  return (
    <div style={{ marginTop: 12, paddingTop: 10, borderTop: `1px solid ${C.border}` }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
        <span style={{ color: C.muted, fontSize: 10, letterSpacing: '0.08em' }}>RATE THIS ADVISORY</span>
        <div style={{ display: 'flex', gap: 2 }}>
          {[1,2,3,4,5].map(n => (
            <button
              key={n}
              onClick={() => setRating(n)}
              onMouseEnter={() => setHover(n)}
              onMouseLeave={() => setHover(0)}
              style={{
                background: 'none',
                border: 'none',
                fontSize: 16,
                color: n <= (hover || rating) ? C.amber : C.border,
                cursor: 'pointer',
                padding: '0 1px',
                transition: 'color 0.1s',
              }}
            >
              ★
            </button>
          ))}
        </div>
        {rating > 0 && (
          <button
            onClick={submit}
            style={{
              background: C.teal + '22',
              border: `1px solid ${C.teal}55`,
              color: C.teal,
              fontSize: 10,
              fontWeight: 600,
              padding: '3px 10px',
              borderRadius: 3,
              cursor: 'pointer',
            }}
          >
            SEND
          </button>
        )}
      </div>
      {rating > 0 && (
        <input
          type="text"
          value={comment}
          onChange={e => setComment(e.target.value)}
          placeholder="Optional comment…"
          style={{
            width: '100%',
            background: C.surface,
            border: `1px solid ${C.border}`,
            borderRadius: 3,
            color: C.text,
            fontSize: 11,
            padding: '5px 10px',
            outline: 'none',
          }}
        />
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

function ValidationTestsSection({ tests }) {
  // Group tests by technique_id
  const byTechnique = {};
  for (const t of tests) {
    const tid = t.technique_id || 'unknown';
    if (!byTechnique[tid]) byTechnique[tid] = [];
    byTechnique[tid].push(t);
  }

  return (
    <div style={{
      borderLeft: `2px solid rgba(74,158,255,0.25)`,
      paddingLeft: 12,
      marginBottom: 10,
    }}>
      {Object.entries(byTechnique).map(([tid, group]) => (
        <div key={tid} style={{ marginBottom: 10 }}>
          <div style={{
            color: C.blue,
            fontSize: 11,
            fontWeight: 700,
            marginBottom: 6,
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}>
            <span style={{
              padding: '1px 7px',
              background: 'rgba(74,158,255,0.12)',
              border: '1px solid rgba(74,158,255,0.3)',
              borderRadius: 3,
              fontSize: 10,
            }}>
              {tid}
            </span>
            <span style={{ color: C.muted, fontWeight: 400, fontSize: 10 }}>
              {group.length} test{group.length > 1 ? 's' : ''}
            </span>
          </div>
          {group.map((t, i) => (
            <div key={i} style={{
              padding: '8px 10px',
              marginBottom: 4,
              background: 'rgba(74,158,255,0.04)',
              borderRadius: 4,
            }}>
              <div style={{
                color: C.textBright,
                fontSize: 11,
                fontWeight: 600,
                marginBottom: 4,
              }}>
                {t.name || `Test ${i + 1}`}
              </div>
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
                {t.executor && (
                  <span style={{
                    color: C.muted,
                    fontSize: 10,
                    padding: '1px 6px',
                    background: C.surface,
                    borderRadius: 2,
                    border: `1px solid ${C.border}`,
                  }}>
                    {t.executor}
                  </span>
                )}
                {t.platforms && (
                  <span style={{ color: C.muted, fontSize: 10 }}>
                    {Array.isArray(t.platforms) ? t.platforms.join(', ') : t.platforms}
                  </span>
                )}
                {t.auto_generated_guid && (
                  <span style={{ color: C.muted, fontSize: 9, fontFamily: 'monospace' }}>
                    {t.auto_generated_guid}
                  </span>
                )}
              </div>
              {t.github_url && (
                <a
                  href={t.github_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{
                    color: C.blue,
                    fontSize: 10,
                    textDecoration: 'none',
                    marginTop: 4,
                    display: 'inline-block',
                  }}
                >
                  View on GitHub ↗
                </a>
              )}
            </div>
          ))}
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

// ── Ingestion view ────────────────────────────────────────────────────────────

function MiniBar({ label, value, max, color }) {
  const pct = max > 0 ? Math.min((value / max) * 100, 100) : 0;
  return (
    <div style={{ marginBottom: 6 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
        <span style={{ color: C.muted, fontSize: 10, letterSpacing: '0.06em' }}>{label}</span>
        <span style={{ color, fontSize: 11, fontWeight: 700, fontVariantNumeric: 'tabular-nums' }}>
          {value.toLocaleString()}
        </span>
      </div>
      <div style={{ height: 6, background: `${color}15`, borderRadius: 3, overflow: 'hidden' }}>
        <div style={{
          height: '100%',
          width: `${pct}%`,
          background: color,
          borderRadius: 3,
          transition: 'width 0.4s ease',
        }} />
      </div>
    </div>
  );
}

function IngestionView({ inbound, stats, newIds, stages }) {
  const [filter, setFilter] = useState('all');

  const s = stats || {};
  const bp = s.by_priority || {};
  const br = s.by_routing || {};
  const total = (bp.P0 || 0) + (bp.P1 || 0) + (bp.P2 || 0) + (bp.P3 || 0) || 1;
  const routingTotal = Object.values(br).reduce((a, b) => a + b, 0) || 1;

  const filtered = filter === 'all' ? inbound : inbound.filter(e => e.priority === filter);

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
    position: 'sticky',
    top: 0,
    zIndex: 1,
  };

  const td = (extra = {}) => ({
    padding: '7px 13px',
    fontSize: 11,
    color: C.text,
    borderBottom: `1px solid ${C.border}44`,
    whiteSpace: 'nowrap',
    ...extra,
  });

  return (
    <div>
      {/* ── Charts row ──────────────────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
        {/* Priority distribution */}
        <div style={{
          background: C.surface,
          border: `1px solid ${C.border}`,
          borderRadius: 6,
          padding: 16,
        }}>
          <div style={{ color: C.muted, fontSize: 9, fontWeight: 600, letterSpacing: '0.1em', marginBottom: 12 }}>
            PRIORITY DISTRIBUTION
          </div>
          {[
            { label: 'P0 — CRITICAL', value: bp.P0 || 0, color: C.P0 },
            { label: 'P1 — HIGH',     value: bp.P1 || 0, color: C.P1 },
            { label: 'P2 — MEDIUM',   value: bp.P2 || 0, color: C.P2 },
            { label: 'P3 — LOW',      value: bp.P3 || 0, color: C.P3 },
          ].map(p => (
            <MiniBar key={p.label} {...p} max={total} />
          ))}
        </div>

        {/* Routing targets */}
        <div style={{
          background: C.surface,
          border: `1px solid ${C.border}`,
          borderRadius: 6,
          padding: 16,
        }}>
          <div style={{ color: C.muted, fontSize: 9, fontWeight: 600, letterSpacing: '0.1em', marginBottom: 12 }}>
            ROUTING TARGETS
          </div>
          {Object.keys(br).length === 0 ? (
            <div style={{ color: C.muted, fontSize: 11, padding: 12 }}>No routing data yet</div>
          ) : (
            Object.entries(br).sort((a, b) => b[1] - a[1]).map(([target, count]) => (
              <MiniBar
                key={target}
                label={target.toUpperCase()}
                value={count}
                max={routingTotal}
                color={ROUTING_COLOR[target] || C.muted}
              />
            ))
          )}
        </div>
      </div>

      {/* ── Filter bar ──────────────────────────────────────────────────── */}
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

      {/* ── Table ───────────────────────────────────────────────────────── */}
      <div style={{
        background: C.surface,
        border: `1px solid ${C.border}`,
        borderRadius: 6,
        overflow: 'hidden',
        maxHeight: 'calc(100vh - 340px)',
        overflowY: 'auto',
      }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              {['TIME', 'EVENT ID', 'CVE / SOURCE', 'PRIORITY', 'STAGE', 'ROUTING', 'DESCRIPTION'].map(h => (
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
                  Waiting for inbound events…
                </td>
              </tr>
            ) : (
              filtered.map(ev => {
                const routingColor = ROUTING_COLOR[ev.routing_target] || C.muted;
                return (
                  <tr
                    key={ev._uid}
                    className={newIds.has(ev._uid) ? 'row-new' : ''}
                    style={{ transition: 'background 0.12s' }}
                  >
                    <td style={td({ color: C.muted })}>{fmtTime(ev.ts || ev.ingested_at)}</td>
                    <td style={td({ color: C.teal, fontFamily: 'inherit' })}>{shortId(ev.event_id)}</td>
                    <td style={td({ color: C.amber })}>{ev.cve_id || ev.source_type || '—'}</td>
                    <td style={td()}><PriorityPill priority={ev.priority} /></td>
                    <td style={td()}><StagePill stage={stages[ev.event_id] || 'ingested'} /></td>
                    <td style={td({ color: routingColor })}>{ev.routing_target || '—'}</td>
                    <td style={td({
                      color: C.muted,
                      maxWidth: 260,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                    })}>
                      {ev.description || '—'}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
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
    position: 'sticky',
    top: 0,
    zIndex: 1,
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
        maxHeight: 'calc(100vh - 260px)',
        overflowY: 'auto',
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
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');

  const searchLower = search.toLowerCase().trim();

  const filtered = advisories.filter(adv => {
    if (filter !== 'all' && adv.priority !== filter) return false;
    if (searchLower) {
      const title = (adv.title || '').toLowerCase();
      const cve   = (adv.cve_id || '').toLowerCase();
      if (!title.includes(searchLower) && !cve.includes(searchLower)) return false;
    }
    return true;
  });

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

  return (
    <div>
      {/* Filter + search bar */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 12, alignItems: 'center', flexWrap: 'wrap' }}>
        <span style={{ color: C.muted, fontSize: 10, marginRight: 4, letterSpacing: '0.08em' }}>
          FILTER
        </span>
        {['all', 'P0', 'P1', 'P2', 'P3'].map(f => (
          <button key={f} onClick={() => setFilter(f)} style={filterBtnStyle(f)}>
            {f.toUpperCase()}
          </button>
        ))}

        <input
          type="text"
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search title or CVE…"
          style={{
            marginLeft: 'auto',
            background: C.surface,
            border: `1px solid ${C.border}`,
            borderRadius: 4,
            color: C.text,
            fontSize: 11,
            padding: '5px 12px',
            width: 220,
            outline: 'none',
            transition: 'border-color 0.15s',
          }}
          onFocus={e => { e.target.style.borderColor = C.teal; }}
          onBlur={e => { e.target.style.borderColor = C.border; }}
        />

        <span style={{ color: C.muted, fontSize: 10 }}>
          {filtered.length} of {advisories.length}
        </span>
      </div>

      <div style={{ maxHeight: 'calc(100vh - 260px)', overflowY: 'auto' }}>
        {filtered.length === 0 ? (
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
            {advisories.length === 0
              ? <>No advisories yet.<br />They will appear here as events complete the full pipeline.</>
              : 'No advisories match the current filter.'
            }
          </div>
        ) : (
          filtered.map(adv => (
            <AdvisoryCard
              key={adv._uid}
              adv={adv}
              isNew={newIds.has(adv._uid)}
            />
          ))
        )}
      </div>
    </div>
  );
}

// ── Approvals View ────────────────────────────────────────────────────────────

function ApprovalsView({ approvals, onDecision }) {
  if (approvals.length === 0) {
    return (
      <div style={{
        background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6,
        padding: '52px 32px', textAlign: 'center', color: C.muted, fontSize: 12, lineHeight: 1.8,
      }}>
        No pending approvals.<br />P1/P2 advisories will appear here for human review.
      </div>
    );
  }

  return (
    <div style={{ maxHeight: 'calc(100vh - 260px)', overflowY: 'auto' }}>
      {approvals.map(a => (
        <div key={a.id} style={{
          background: C.card, border: `1px solid ${C.border}`, borderLeft: `3px solid ${C[a.priority] || C.amber}`,
          borderRadius: 6, padding: '16px 20px', marginBottom: 10,
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <PriorityPill priority={a.priority} />
              <span style={{ color: C.amber, fontSize: 12, fontWeight: 600 }}>{a.cve_id || 'CVE-UNKNOWN'}</span>
              <span style={{ color: C.muted, fontSize: 11 }}>{a.event_id}</span>
            </div>
            <span style={{ color: C.muted, fontSize: 10 }}>
              {a.requested_at ? new Date(a.requested_at).toLocaleString() : ''}
            </span>
          </div>
          <div style={{ color: C.textBright, fontSize: 14, fontWeight: 600, marginBottom: 8 }}>
            {a.title || '(no title)'}
          </div>
          {a.executive_summary && (
            <div style={{ color: C.text, fontSize: 12, lineHeight: 1.6, marginBottom: 12, padding: '8px 12px', background: 'rgba(0,212,170,0.05)', borderRadius: 4 }}>
              {a.executive_summary}
            </div>
          )}
          <div style={{ display: 'flex', gap: 16, alignItems: 'center', marginBottom: 8 }}>
            <div><span style={{ color: C.muted, fontSize: 9 }}>RISK </span><span style={{ color: C.orange, fontSize: 16, fontWeight: 700 }}>{a.risk_score ?? '—'}</span></div>
            <div><span style={{ color: C.muted, fontSize: 9 }}>SEVERITY </span><span style={{ color: C.red, fontSize: 12 }}>{(a.severity || '').toUpperCase()}</span></div>
            <div><span style={{ color: C.muted, fontSize: 9 }}>TLP </span><TlpBadge tlp={a.tlp} /></div>
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
            <button
              onClick={() => onDecision(a.id, 'approve')}
              style={{
                background: 'rgba(52,211,153,0.15)', border: `1px solid ${C.green}66`, color: C.green,
                fontSize: 11, fontWeight: 700, padding: '6px 18px', borderRadius: 4, cursor: 'pointer',
                letterSpacing: '0.06em',
              }}
            >
              APPROVE
            </button>
            <button
              onClick={() => onDecision(a.id, 'reject')}
              style={{
                background: 'rgba(255,68,85,0.12)', border: `1px solid ${C.red}55`, color: C.red,
                fontSize: 11, fontWeight: 700, padding: '6px 18px', borderRadius: 4, cursor: 'pointer',
                letterSpacing: '0.06em',
              }}
            >
              REJECT
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Settings View ─────────────────────────────────────────────────────────────

// ── Settings sub-components ───────────────────────────────────────────────────

function SettingsSlider({ label, hint, configKey, min, max, step, fmt, edits, setEdits, configMap }) {
  const current = edits[configKey] !== undefined ? edits[configKey] : (configMap[configKey] || '0');
  const numVal = parseFloat(current);
  return (
    <div style={{ marginBottom: 20 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 6 }}>
        <span style={{ color: C.textBright, fontSize: 12, fontWeight: 600 }}>{label}</span>
        <span style={{ color: C.teal, fontSize: 13, fontWeight: 700, fontVariantNumeric: 'tabular-nums' }}>
          {fmt ? fmt(numVal) : current}
        </span>
      </div>
      <input
        type="range" min={min} max={max} step={step}
        value={numVal}
        onChange={e => setEdits(prev => ({ ...prev, [configKey]: e.target.value }))}
        style={{ width: '100%', accentColor: C.teal }}
      />
      {hint && <div style={{ color: C.muted, fontSize: 10, fontStyle: 'italic', marginTop: 4, lineHeight: 1.4 }}>{hint}</div>}
    </div>
  );
}

function SettingsToggle({ label, hint, configKey, edits, setEdits, configMap }) {
  const current = edits[configKey] !== undefined ? edits[configKey] : (configMap[configKey] || 'false');
  const on = current === 'true';
  const toggle = () => setEdits(prev => ({ ...prev, [configKey]: on ? 'false' : 'true' }));
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
      <button onClick={toggle} style={{
        width: 40, height: 22, borderRadius: 11, border: 'none', cursor: 'pointer',
        background: on ? C.teal : C.border, position: 'relative', transition: 'background 0.2s', flexShrink: 0,
      }}>
        <span style={{
          position: 'absolute', top: 2, left: on ? 20 : 2,
          width: 18, height: 18, borderRadius: '50%', background: '#fff',
          transition: 'left 0.2s', boxShadow: '0 1px 3px rgba(0,0,0,0.3)',
        }} />
      </button>
      <div>
        <div style={{ color: C.text, fontSize: 11 }}>{label}</div>
        {hint && <div style={{ color: C.muted, fontSize: 10 }}>{hint}</div>}
      </div>
    </div>
  );
}

function SettingsSelect({ label, configKey, options, edits, setEdits, configMap }) {
  const current = edits[configKey] !== undefined ? edits[configKey] : (configMap[configKey] || '');
  return (
    <div style={{ marginBottom: 18 }}>
      <div style={{ color: C.textBright, fontSize: 12, fontWeight: 600, marginBottom: 6 }}>{label}</div>
      <select
        value={current}
        onChange={e => setEdits(prev => ({ ...prev, [configKey]: e.target.value }))}
        style={{
          width: '100%', background: C.surface, color: C.text, border: `1px solid ${C.border}`,
          borderRadius: 4, padding: '8px 12px', fontSize: 12, fontFamily: 'inherit', outline: 'none',
        }}
      >
        {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
    </div>
  );
}

function SettingsInput({ label, hint, configKey, edits, setEdits, configMap }) {
  const current = edits[configKey] !== undefined ? edits[configKey] : (configMap[configKey] || '');
  return (
    <div style={{ marginBottom: 18 }}>
      <div style={{ color: C.textBright, fontSize: 12, fontWeight: 600, marginBottom: 6 }}>{label}</div>
      <input
        type="text" value={current}
        onChange={e => setEdits(prev => ({ ...prev, [configKey]: e.target.value }))}
        style={{
          width: '100%', background: C.surface, color: C.text, border: `1px solid ${C.border}`,
          borderRadius: 4, padding: '8px 12px', fontSize: 12, fontFamily: 'inherit', outline: 'none',
          boxSizing: 'border-box',
        }}
      />
      {hint && <div style={{ color: C.muted, fontSize: 10, marginTop: 4 }}>{hint}</div>}
    </div>
  );
}

function AgentCard({ title, color, children }) {
  return (
    <div style={{
      background: C.card, border: `1px solid ${C.border}`, borderTop: `2px solid ${color}`,
      borderRadius: 6, padding: '20px 22px',
    }}>
      <div style={{
        color, fontSize: 12, fontWeight: 700, letterSpacing: '0.1em', marginBottom: 16,
      }}>
        {title}
      </div>
      {children}
    </div>
  );
}

// ── Settings View ─────────────────────────────────────────────────────────────

function SettingsView({ config, onConfigSave, budget, onBudgetSave, paused, onTogglePause }) {
  const [edits, setEdits] = useState({});
  const [saving, setSaving] = useState(false);

  // Build a key→value map from config array
  const configMap = {};
  for (const c of config) configMap[c.key] = c.value;

  const hasEdits = Object.keys(edits).length > 0;

  const handleSaveAll = async () => {
    setSaving(true);
    for (const [key, value] of Object.entries(edits)) {
      await onConfigSave(key, value);
    }
    setEdits({});
    setSaving(false);
  };

  const fmtPct = v => (v * 100).toFixed(0) + '%';
  const fmtDec = v => parseFloat(v).toFixed(2);
  const fmtInt = v => Number(v).toLocaleString();

  return (
    <div>
      {/* Kill Switch */}
      <div style={{
        background: C.card, border: `1px solid ${paused ? C.red + '66' : C.border}`,
        borderRadius: 6, padding: '20px 24px', marginBottom: 16,
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ color: C.textBright, fontSize: 14, fontWeight: 700, marginBottom: 4 }}>Kill Switch</div>
            <div style={{ color: C.muted, fontSize: 11 }}>
              {paused ? 'All agents are PAUSED. No events are being processed.' : 'All agents are running normally.'}
            </div>
          </div>
          <button
            onClick={onTogglePause}
            style={{
              background: paused ? 'rgba(52,211,153,0.15)' : 'rgba(255,68,85,0.15)',
              border: `1px solid ${paused ? C.green + '66' : C.red + '66'}`,
              color: paused ? C.green : C.red,
              fontSize: 12, fontWeight: 700, padding: '8px 24px', borderRadius: 4, cursor: 'pointer',
              letterSpacing: '0.06em',
            }}
          >
            {paused ? 'RESUME' : 'PAUSE ALL'}
          </button>
        </div>
      </div>

      {/* Agent cards – 3 column grid */}
      {config.length === 0 ? (
        <div style={{ color: C.muted, fontSize: 12, textAlign: 'center', padding: 40 }}>Loading configuration…</div>
      ) : (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16, marginBottom: 16 }}>
            {/* ── Triage Agent ──────────────────────────────────────────── */}
            <AgentCard title="TRIAGE AGENT" color={C.orange}>
              <SettingsSlider label="Relevance Threshold (triggers simulation)" configKey="triage_threshold"
                min={0} max={1} step={0.01} fmt={fmtDec}
                edits={edits} setEdits={setEdits} configMap={configMap}
                hint="Lower = more events simulated (higher coverage, higher cost)\nHigher = fewer events simulated (lower noise, lower cost)"
              />
              <SettingsSlider label="Infrastructure Match Weight" configKey="infra_match_weight"
                min={0} max={1} step={0.01} fmt={fmtPct}
                edits={edits} setEdits={setEdits} configMap={configMap}
              />
              <SettingsSlider label="Threat Actor History Weight" configKey="threat_actor_weight"
                min={0} max={1} step={0.01} fmt={fmtPct}
                edits={edits} setEdits={setEdits} configMap={configMap}
              />
            </AgentCard>

            {/* ── Simulation Agent ──────────────────────────────────────── */}
            <AgentCard title="SIMULATION AGENT" color={C.purple}>
              <SettingsInput label="Daily Iteration Budget" configKey="sim_daily_budget"
                hint="Maximum Monte Carlo iterations per day"
                edits={edits} setEdits={setEdits} configMap={configMap}
              />
              <SettingsSelect label="Default Polymorphic Strategy" configKey="sim_strategy"
                options={[
                  { value: 'vuln_first', label: 'Vuln-First (default)' },
                  { value: 'evasion_first', label: 'Evasion-First' },
                  { value: 'stealth', label: 'Stealth' },
                  { value: 'blitz', label: 'Blitz' },
                ]}
                edits={edits} setEdits={setEdits} configMap={configMap}
              />
              <SettingsSlider label="Monte Carlo Iterations per Event" configKey="sim_iterations"
                min={1000} max={50000} step={1000} fmt={fmtInt}
                edits={edits} setEdits={setEdits} configMap={configMap}
              />
            </AgentCard>

            {/* ── Advisory Agent ────────────────────────────────────────── */}
            <AgentCard title="ADVISORY AGENT" color={C.green}>
              <SettingsSlider label="LLM Temperature" configKey="advisory_temperature"
                min={0} max={1} step={0.05} fmt={fmtDec}
                edits={edits} setEdits={setEdits} configMap={configMap}
                hint="Lower (0.1) = consistent, conservative recommendations\nHigher (0.5) = creative threat analysis"
              />
              <div style={{ color: C.textBright, fontSize: 12, fontWeight: 600, marginBottom: 10 }}>Approval Requirements</div>
              <SettingsToggle label="Require approval for P1 advisories" configKey="approval_p1"
                edits={edits} setEdits={setEdits} configMap={configMap}
              />
              <SettingsToggle label="Require approval for P2 advisories" configKey="approval_p2"
                edits={edits} setEdits={setEdits} configMap={configMap}
              />
              <div style={{
                marginTop: 8, padding: '8px 12px', borderRadius: 4,
                background: 'rgba(0,212,170,0.06)', border: `1px solid ${C.teal}22`,
                color: C.teal, fontSize: 10, fontStyle: 'italic',
              }}>
                P0 advisories always auto-send immediately (no approval required)
              </div>
            </AgentCard>
          </div>

          {/* ── Detection Agent (full width) ─────────────────────────────── */}
          <div style={{ marginBottom: 16 }}>
            <AgentCard title="DETECTION AGENT" color={C.teal}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>
                <div>
                  <SettingsSlider label="Minimum Sigma Rule Confidence" configKey="sigma_min_confidence"
                    min={0} max={1} step={0.01} fmt={fmtDec}
                    edits={edits} setEdits={setEdits} configMap={configMap}
                    hint="Rules below this threshold require analyst review"
                  />
                </div>
                <div>
                  <div style={{ color: C.textBright, fontSize: 12, fontWeight: 600, marginBottom: 10 }}>Auto-Upgrade Coverage Status</div>
                  <SettingsToggle
                    label={'Auto-mark TTP as "detected" when rule \u2265 confidence'}
                    configKey="detection_auto_upgrade"
                    edits={edits} setEdits={setEdits} configMap={configMap}
                  />
                </div>
              </div>
            </AgentCard>
          </div>

          {/* ── Save button ──────────────────────────────────────────────── */}
          <div style={{ textAlign: 'center', marginTop: 8 }}>
            <button
              onClick={handleSaveAll}
              disabled={!hasEdits || saving}
              style={{
                background: hasEdits ? C.teal : C.border,
                border: 'none',
                color: hasEdits ? '#000' : C.muted,
                fontSize: 13, fontWeight: 700, padding: '12px 48px', borderRadius: 5,
                cursor: hasEdits ? 'pointer' : 'default',
                letterSpacing: '0.1em',
                opacity: saving ? 0.6 : 1,
                transition: 'background 0.2s, color 0.2s',
              }}
            >
              {saving ? 'SAVING…' : 'SAVE CONFIGURATION'}
            </button>
          </div>
        </>
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

function TabBar({ activeTab, onSwitch, unread, pendingApprovals }) {
  return (
    <div style={{
      display: 'flex',
      background: C.surface,
      borderBottom: `1px solid ${C.border}`,
      padding: '0 24px',
    }}>
      {[
        { id: 'ingestion',  label: 'INGESTION'  },
        { id: 'events',     label: 'EVENTS'     },
        { id: 'advisories', label: 'ADVISORIES' },
        { id: 'approvals',  label: 'APPROVALS'  },
        { id: 'attack',     label: 'ATT&CK'     },
        { id: 'settings',   label: 'SETTINGS'   },
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
            {tab.id === 'approvals' && pendingApprovals > 0 && (
              <span style={{
                background: C.amber,
                color: '#000',
                fontSize: 9,
                fontWeight: 700,
                padding: '1px 5px',
                borderRadius: 8,
                minWidth: 18,
                textAlign: 'center',
                lineHeight: '14px',
                display: 'inline-block',
              }}>
                {pendingApprovals > 99 ? '99+' : pendingApprovals}
              </span>
            )}
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

function Header({ wsStatus, paused, onTogglePause }) {
  const dotColor = { connected: C.green, disconnected: C.red, connecting: C.amber }[wsStatus] || C.muted;
  const pulse    = wsStatus === 'connected';

  return (
    <header style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 24px',
      height: 54,
      background: paused ? 'rgba(255,68,85,0.06)' : C.surface,
      borderBottom: `1px solid ${paused ? C.red + '44' : C.border}`,
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
        {paused && (
          <span style={{
            fontSize: '0.65rem', fontWeight: 700, color: C.red,
            letterSpacing: '0.12em', padding: '2px 8px',
            background: 'rgba(255,68,85,0.14)', borderRadius: 3,
            border: `1px solid ${C.red}44`,
          }}>
            PAUSED
          </span>
        )}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        <button
          onClick={onTogglePause}
          style={{
            background: paused ? 'rgba(52,211,153,0.15)' : 'rgba(255,68,85,0.10)',
            border: `1px solid ${paused ? C.green + '55' : C.red + '44'}`,
            color: paused ? C.green : C.red,
            fontSize: 10,
            fontWeight: 700,
            padding: '4px 12px',
            borderRadius: 3,
            cursor: 'pointer',
            letterSpacing: '0.06em',
          }}
        >
          {paused ? 'RESUME' : 'PAUSE'}
        </button>
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
  const [activeTab,  setActiveTab]  = useState('ingestion');
  const [unread,     setUnread]     = useState(0);
  const [events,     setEvents]     = useState([]);
  const [advisories, setAdvisories] = useState([]);
  const [inbound,    setInbound]    = useState([]);
  const [newEvIds,   setNewEvIds]   = useState(new Set());
  const [newAdvIds,  setNewAdvIds]  = useState(new Set());
  const [newInbIds,  setNewInbIds]  = useState(new Set());
  const [stats,      setStats]      = useState(null);
  const [stages,     setStages]     = useState({});       // event_id → stage
  const [paused,     setPaused]     = useState(false);
  const [approvals,  setApprovals]  = useState([]);
  const [config,     setConfig]     = useState([]);
  const [budget,     setBudget]     = useState(null);

  const wsRef        = useRef(null);
  const retryRef     = useRef(null);
  const activeTabRef = useRef(activeTab);

  useEffect(() => { activeTabRef.current = activeTab; }, [activeTab]);

  // Fetch initial HITL state
  useEffect(() => {
    fetch('/api/admin/status').then(r => r.json()).then(d => setPaused(d.paused)).catch(() => {});
    fetch('/api/approvals?status=pending').then(r => r.json()).then(d => { if (Array.isArray(d)) setApprovals(d); }).catch(() => {});
    fetch('/api/config').then(r => r.json()).then(d => { if (Array.isArray(d)) setConfig(d); }).catch(() => {});
    fetch('/api/budget').then(r => r.json()).then(d => setBudget(d)).catch(() => {});
  }, []);

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

      if (msg.type === 'ingestion') {
        const ev = { ...msg.payload, ts: msg.ts, _uid: uid() };
        setInbound(prev => {
          const eid = ev.event_id;
          if (eid && prev.some(e => e.event_id === eid)) {
            return prev.map(e => e.event_id === eid ? { ...ev, _uid: e._uid } : e);
          }
          return [ev, ...prev].slice(0, MAX_INBOUND);
        });
        flash(setNewInbIds, ev._uid);

      } else if (msg.type === 'event') {
        const ev = { ...msg.payload, ts: msg.ts, _uid: uid() };
        setEvents(prev => {
          const eid = ev.event_id;
          if (eid && prev.some(e => e.event_id === eid)) {
            return prev.map(e => e.event_id === eid ? { ...ev, _uid: e._uid } : e);
          }
          return [ev, ...prev].slice(0, MAX_EVENTS);
        });
        flash(setNewEvIds, ev._uid);

      } else if (msg.type === 'stats') {
        setStats(msg.payload);

      } else if (msg.type === 'stage_update') {
        const { event_id, stage } = msg.payload;
        if (event_id) setStages(prev => ({ ...prev, [event_id]: stage }));

      } else if (msg.type === 'stages') {
        // Bulk stage catchup on reconnect
        setStages(prev => ({ ...prev, ...msg.payload }));

      } else if (msg.type === 'system_status') {
        setPaused(msg.payload.paused);

      } else if (msg.type === 'approval_request') {
        setApprovals(prev => [msg.payload, ...prev]);

      } else if (msg.type === 'config_update') {
        setConfig(prev => prev.map(c => c.key === msg.payload.key ? { ...c, value: msg.payload.value } : c));

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

  const togglePause = async () => {
    const endpoint = paused ? '/api/admin/resume' : '/api/admin/pause';
    try {
      const res = await fetch(endpoint, { method: 'POST' });
      const data = await res.json();
      setPaused(data.paused);
    } catch { /* ignore */ }
  };

  const handleApprovalDecision = async (approvalId, action) => {
    try {
      await fetch(`/api/approvals/${approvalId}/${action}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decided_by: 'dashboard_analyst' }),
      });
      setApprovals(prev => prev.filter(a => a.id !== approvalId));
    } catch { /* ignore */ }
  };

  const handleConfigSave = async (key, value) => {
    try {
      const res = await fetch(`/api/config/${key}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value }),
      });
      const data = await res.json();
      setConfig(prev => prev.map(c => c.key === key ? { ...c, value: data.value } : c));
    } catch { /* ignore */ }
  };

  const handleBudgetSave = async (limit) => {
    try {
      await fetch('/api/budget/limit', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ limit }),
      });
      setBudget(prev => prev ? { ...prev, limit } : { used: 0, limit, date: '' });
    } catch { /* ignore */ }
  };

  return (
    <div style={{ minHeight: '100vh', background: C.bg }}>
      <Header wsStatus={wsStatus} paused={paused} onTogglePause={togglePause} />
      <TabBar activeTab={activeTab} onSwitch={handleTabSwitch} unread={unread} pendingApprovals={approvals.length} />
      <StatBar stats={stats} advisoryCount={advisories.length} />

      <div style={{ padding: '16px 24px', maxWidth: 1600, margin: '0 auto' }}>
        {activeTab === 'ingestion' && (
          <IngestionView inbound={inbound} stats={stats} newIds={newInbIds} stages={stages} />
        )}
        {activeTab === 'events' && (
          <EventsView events={events} newIds={newEvIds} />
        )}
        {activeTab === 'advisories' && (
          <AdvisoriesView advisories={advisories} newIds={newAdvIds} />
        )}
        {activeTab === 'approvals' && (
          <ApprovalsView approvals={approvals} onDecision={handleApprovalDecision} />
        )}
        {activeTab === 'attack' && (
          <AttackMatrix wsRef={wsRef} />
        )}
        {activeTab === 'settings' && (
          <SettingsView
            config={config}
            onConfigSave={handleConfigSave}
            budget={budget}
            onBudgetSave={handleBudgetSave}
            paused={paused}
            onTogglePause={togglePause}
          />
        )}
      </div>
    </div>
  );
}
