'use strict';

// ── Constants ───────────────────────────────────────────────────────────────

const STATS_INTERVAL_MS   = 10_000;  // poll /api/stats every 10 s
const FEED_MAX_ITEMS       = 80;     // max rows kept in the DOM feed
const TABLE_MAX_ROWS       = 50;     // max rows in triage table
const FLASH_MS             = 600;    // new-event highlight duration

const PRIORITY_COLORS = {
  P0: '#ff4455',
  P1: '#ff8c22',
  P2: '#f5c518',
  P3: '#4a9eff',
};

const ROUTING_COLORS = {
  triage:     '#ff8c22',
  simulation: '#a855f7',
  advisory:   '#22d3ee',
  detection:  '#34d399',
};

// ── DOM refs ────────────────────────────────────────────────────────────────

const $statusDot   = document.getElementById('status-dot');
const $statusLabel = document.getElementById('status-label');
const $statTotal   = document.getElementById('stat-total');
const $statHigh    = document.getElementById('stat-high');
const $statTriaged = document.getElementById('stat-triaged');
const $statRelev   = document.getElementById('stat-relevance');
const $qTriage     = document.getElementById('q-triage');
const $qSim        = document.getElementById('q-simulation');
const $qAdv        = document.getElementById('q-advisory');
const $feed        = document.getElementById('event-feed');
const $triageTbody = document.getElementById('triage-tbody');

// ── Chart setup ─────────────────────────────────────────────────────────────

function makeDonut(canvasId, labels, colors) {
  const ctx = document.getElementById(canvasId).getContext('2d');
  return new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{ data: labels.map(() => 0), backgroundColor: colors, borderWidth: 0 }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      cutout: '68%',
      plugins: {
        legend: {
          position: 'right',
          labels: {
            color: '#5a7294',
            font: { size: 11 },
            boxWidth: 10,
            padding: 10,
          },
        },
        tooltip: {
          callbacks: {
            label: (ctx) => ` ${ctx.label}: ${ctx.parsed.toLocaleString()}`,
          },
        },
      },
    },
  });
}

function makeBar(canvasId, labels, colors) {
  const ctx = document.getElementById(canvasId).getContext('2d');
  return new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        data: labels.map(() => 0),
        backgroundColor: colors,
        borderRadius: 4,
        borderSkipped: false,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      indexAxis: 'y',
      plugins: { legend: { display: false } },
      scales: {
        x: {
          ticks: { color: '#5a7294', font: { size: 10 } },
          grid:  { color: '#1e2d45' },
        },
        y: {
          ticks: { color: '#cdd9ec', font: { size: 11 } },
          grid:  { display: false },
        },
      },
    },
  });
}

const priorityChart = makeDonut(
  'priority-chart',
  ['P0 Critical', 'P1 High', 'P2 Medium', 'P3 Low'],
  Object.values(PRIORITY_COLORS),
);

// Routing labels / colors are dynamic; we'll initialise with known routes.
const routingChart = makeBar(
  'routing-chart',
  ['triage', 'simulation', 'advisory', 'detection'],
  ['#ff8c22', '#a855f7', '#22d3ee', '#34d399'],
);

// ── Helper: update chart data without recreating ────────────────────────────

function updateDonut(chart, valueMap) {
  const labels = chart.data.labels.map(l => l.split(' ')[0]);   // "P0 Critical" → "P0"
  chart.data.datasets[0].data = labels.map(l => valueMap[l] ?? 0);
  chart.update('none');
}

function updateBar(chart, valueMap) {
  const routeKeys = Object.keys(valueMap).sort();
  chart.data.labels = routeKeys;
  chart.data.datasets[0].data = routeKeys.map(k => valueMap[k]);
  chart.data.datasets[0].backgroundColor = routeKeys.map(k => ROUTING_COLORS[k] ?? '#8899aa');
  chart.update('none');
}

// ── Stats polling ───────────────────────────────────────────────────────────

async function fetchStats() {
  try {
    const res  = await fetch('/api/stats');
    if (!res.ok) return;
    const data = await res.json();

    $statTotal.textContent   = (data.total_ingested ?? 0).toLocaleString();
    const high = (data.by_priority?.P0 ?? 0) + (data.by_priority?.P1 ?? 0);
    $statHigh.textContent    = high.toLocaleString();
    $statTriaged.textContent = (data.triaged_count ?? 0).toLocaleString();
    $statRelev.textContent   = data.avg_relevance != null
      ? data.avg_relevance.toFixed(2)
      : '—';

    $qTriage.textContent = (data.queue_depths?.triage     ?? 0).toLocaleString();
    $qSim.textContent    = (data.queue_depths?.simulation ?? 0).toLocaleString();
    $qAdv.textContent    = (data.queue_depths?.advisory   ?? 0).toLocaleString();

    if (data.by_priority)  updateDonut(priorityChart, data.by_priority);
    if (data.by_routing)   updateBar(routingChart,    data.by_routing);

  } catch (err) {
    console.warn('Stats fetch failed:', err);
  }
}

// ── Initial event load (populate feed + table on page load) ─────────────────

async function loadInitialEvents() {
  try {
    const res    = await fetch('/api/events?limit=100');
    if (!res.ok) return;
    const events = await res.json();

    // Feed: display oldest-first so the list feels natural
    [...events].reverse().forEach(e => appendFeedItem(e, false));

    // Triage table: show only events that have been scored
    const triaged = events.filter(e => e.relevance_score != null);
    if (triaged.length) {
      $triageTbody.innerHTML = '';
      triaged.slice(0, TABLE_MAX_ROWS).forEach(e => appendTriageRow(e));
    } else {
      $triageTbody.innerHTML = '<tr><td colspan="9" class="table-empty">No triaged events yet</td></tr>';
    }
  } catch (err) {
    console.warn('Initial event load failed:', err);
  }
}

// ── Feed DOM helpers ────────────────────────────────────────────────────────

function fmtTime(isoStr) {
  if (!isoStr) return '—';
  try {
    const d = new Date(isoStr);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  } catch { return isoStr.slice(11, 19) || '—'; }
}

function priorityBadge(p) {
  const safe = ['P0','P1','P2','P3'].includes(p) ? p : 'P3';
  return `<span class="priority-badge badge-${safe}">${safe}</span>`;
}

function routeTag(r) {
  const cls = ROUTING_COLORS[r] ? `route-${r}` : 'route-advisory';
  return `<span class="route-tag ${cls}">${r ?? '—'}</span>`;
}

function appendFeedItem(event, flash = true) {
  // Remove placeholder
  const placeholder = $feed.querySelector('.feed-empty');
  if (placeholder) placeholder.remove();

  const div = document.createElement('div');
  div.className = 'feed-item' + (flash ? ' new-flash' : '');

  const label = event.cve_id || (event.event_id ? event.event_id.slice(0, 8) + '…' : '—');

  div.innerHTML = `
    <span class="feed-ts">${fmtTime(event.ingested_at)}</span>
    ${priorityBadge(event.priority)}
    <span class="source-tag">${event.source_type ?? '—'}</span>
    <span class="feed-cve" title="${event.description ?? ''}">${label}</span>
    ${routeTag(event.routing_target)}
  `;

  $feed.prepend(div);

  if (flash) {
    setTimeout(() => div.classList.remove('new-flash'), FLASH_MS);
  }

  // Trim old items
  const items = $feed.querySelectorAll('.feed-item');
  if (items.length > FEED_MAX_ITEMS) {
    items[items.length - 1].remove();
  }
}

// ── Triage table helpers ────────────────────────────────────────────────────

function scoreBar(score) {
  if (score == null) return '<span style="color:var(--text-muted)">—</span>';
  const pct  = Math.round(score * 100);
  const cls  = score >= 0.7 ? 'score-hi' : score >= 0.4 ? 'score-mid' : 'score-low';
  const width = Math.max(4, Math.round(pct * 0.8));  // max ~80px
  return `<div class="score-bar-wrap ${cls}">
    <div class="score-bar" style="width:${width}px"></div>
    <span class="score-num">${score.toFixed(2)}</span>
  </div>`;
}

function appendTriageRow(event) {
  const placeholder = $triageTbody.querySelector('.table-empty');
  if (placeholder) $triageTbody.innerHTML = '';

  const tr = document.createElement('tr');
  const label = event.cve_id || (event.event_id?.slice(0, 12) + '…') || '—';
  const p = event.priority;
  const badgeCls = ['P0','P1','P2','P3'].includes(p) ? p : 'P3';

  tr.innerHTML = `
    <td class="event-id-cell">${label}</td>
    <td><span class="source-tag">${event.source_type ?? '—'}</span></td>
    <td><span class="priority-badge badge-${badgeCls}">${p ?? '—'}</span></td>
    <td>${scoreBar(event.relevance_score)}</td>
    <td>${scoreBar(event.infrastructure_match)}</td>
    <td>${scoreBar(event.exploitability)}</td>
    <td>${scoreBar(event.temporal_urgency)}</td>
    <td>${routeTag(event.routing_target)}</td>
    <td style="color:var(--text-muted);font-size:.7rem">${fmtTime(event.ingested_at)}</td>
  `;

  $triageTbody.prepend(tr);

  // Trim
  const rows = $triageTbody.querySelectorAll('tr');
  if (rows.length > TABLE_MAX_ROWS) rows[rows.length - 1].remove();
}

// ── SSE connection ───────────────────────────────────────────────────────────

function connectSSE() {
  const es = new EventSource('/api/events/stream');

  es.onopen = () => {
    $statusDot.className   = 'status-dot live';
    $statusLabel.textContent = 'Live';
  };

  es.onmessage = (msg) => {
    try {
      const event = JSON.parse(msg.data);
      appendFeedItem(event, true);
      if (event.relevance_score != null) appendTriageRow(event);
    } catch (err) {
      console.warn('SSE parse error:', err);
    }
  };

  es.onerror = () => {
    $statusDot.className   = 'status-dot error';
    $statusLabel.textContent = 'Reconnecting…';
    es.close();
    // EventSource reconnects automatically, but we set a manual delay for UX
    setTimeout(connectSSE, 3000);
  };
}

// ── Bootstrap ───────────────────────────────────────────────────────────────

(async function init() {
  await Promise.all([fetchStats(), loadInitialEvents()]);
  setInterval(fetchStats, STATS_INTERVAL_MS);
  connectSSE();
})();
