"use strict";

const RECENT_ALERTS = 15;

const TYPE_COLORS = {
  BRUTE_FORCE: "#f85149",
  WEB_ATTACK: "#f0883e",
  PORT_SCAN: "#f0a020",
  USERNAME_ENUMERATION: "#a371f7",
  HIGH_ACTIVITY: "#58a6ff",
};
const FALLBACK_COLORS = ["#3fb950", "#db61a2", "#79c0ff", "#d29922", "#8b949e"];

const state = {
  range: 60,
  charts: {},
  seenAlerts: null,
  refresh: null,
};

function colorFor(type, index) {
  return TYPE_COLORS[type] || FALLBACK_COLORS[index % FALLBACK_COLORS.length];
}

function fmtBucket(iso, bucketMinutes, rangeMinutes) {
  const d = new Date(iso);
  const time = clock(d, false);
  if (rangeMinutes <= 1440) return time;
  const date = fmtDate(d, false);
  return bucketMinutes >= 1440 ? date : `${date} ${time}`;
}





function renderTiles(t) {
  $("t-events").textContent = fmtNum(t.events);
  $("t-events-sub").textContent = `${fmtNum(t.rejected_logs)} rejected log lines`;
  $("t-alerts").textContent = fmtNum(t.alerts);
  $("t-alerts-sub").textContent = `${fmtNum(t.open_alerts)} open / investigating`;
  $("t-high").textContent = fmtNum(t.high_alerts);
  $("t-hosts").textContent = fmtNum(t.hosts);
  $("t-hosts-sub").textContent = `${fmtNum(t.active_hosts_24h)} active in last 24 h`;
}

function renderTimeline(tl) {
  const labels = tl.buckets.map((b) => fmtBucket(b.start, tl.bucket_minutes, tl.range_minutes));
  const events = tl.buckets.map((b) => b.events);
  const alerts = tl.buckets.map((b) => b.alerts);
  const total = events.reduce((a, b) => a + b, 0);
  $("timeline-info").textContent =
    `${fmtNum(total)} events in range · 1 bar = ${tl.bucket_minutes >= 60 ? tl.bucket_minutes / 60 + " h" : tl.bucket_minutes + " min"}`;

  const chart = state.charts.timeline;
  if (chart) {
    chart.data.labels = labels;
    chart.data.datasets[0].data = events;
    chart.data.datasets[1].data = alerts;
    chart.update("none");
    return;
  }
  state.charts.timeline = new Chart($("timeline-chart"), {
    data: {
      labels,
      datasets: [
        { type: "bar", label: "Events", data: events, backgroundColor: "rgba(59,130,246,.75)",
          borderRadius: 2, yAxisID: "y", order: 2 },
        { type: "line", label: "New alerts", data: alerts, borderColor: "#f85149", backgroundColor: "#f85149",
          pointRadius: (ctx) => (ctx.raw ? 3 : 0), tension: 0.3, yAxisID: "y1", order: 1 },
      ],
    },
    options: {
      maintainAspectRatio: false,
      animation: false,
      interaction: { mode: "index", intersect: false },
      plugins: { legend: { labels: { boxWidth: 12 } } },
      scales: {
        x: { grid: { display: false }, ticks: { maxRotation: 0, autoSkipPadding: 12 } },
        y: { beginAtZero: true, ticks: { precision: 0 }, title: { display: true, text: "events" } },
        y1: { beginAtZero: true, position: "right", grid: { drawOnChartArea: false },
              ticks: { precision: 0 }, title: { display: true, text: "alerts" } },
      },
    },
  });
}

function renderTypes(byType) {
  const entries = Object.entries(byType).sort((a, b) => b[1] - a[1]);
  const total = entries.reduce((sum, [, n]) => sum + n, 0);
  $("types-empty").classList.toggle("hidden", total > 0);
  document.querySelector(".donut-wrap").classList.toggle("hidden", total === 0);

  const colors = entries.map(([type], i) => colorFor(type, i));
  $("types-legend").replaceChildren(...entries.map(([type, n], i) => {
    const swatch = el("span", "swatch");
    swatch.style.background = colors[i];
    return el("li", null, swatch, el("span", "label", prettyType(type)),
              el("span", "count", fmtNum(n)), el("span", "pct", `${Math.round((n / total) * 100)}%`));
  }));

  const chart = state.charts.types;
  const labels = entries.map(([type]) => prettyType(type));
  const data = entries.map(([, n]) => n);
  if (chart) {
    chart.data.labels = labels;
    chart.data.datasets[0].data = data;
    chart.data.datasets[0].backgroundColor = colors;
    chart.update("none");
    return;
  }
  state.charts.types = new Chart($("types-chart"), {
    type: "doughnut",
    data: { labels, datasets: [{ data, backgroundColor: colors, borderColor: "#161b22", borderWidth: 2 }] },
    options: { maintainAspectRatio: false, animation: false, cutout: "62%", plugins: { legend: { display: false } } },
  });
}

function emptyRow(colspan, text) {
  const td = el("td", "empty-row", text);
  td.colSpan = colspan;
  return el("tr", null, td);
}

function renderTopIps(rows) {
  const body = $("top-ips");
  if (!rows.length) return body.replaceChildren(emptyRow(5, "No traffic yet"));
  body.replaceChildren(...rows.map((r) => el("tr", null,
    el("td", "ip", r.ip),
    el("td", "num", fmtNum(r.event_count)),
    el("td", "num", fmtNum(r.alerts)),
    el("td", "num", r.high_alerts ? el("span", "sev-HIGH", fmtNum(r.high_alerts)) : "0"),
    el("td", "muted", fmtTime(r.last_seen)),
  )));
}

function renderAlerts(page) {
  $("alerts-info").textContent = `showing ${page.items.length} of ${fmtNum(page.total)} · click a row for details`;
  const body = $("alerts");
  if (!page.items.length) return body.replaceChildren(emptyRow(7, "No alerts yet — run a simulator to generate some"));

  const previous = state.seenAlerts;
  body.replaceChildren(...page.items.map((a) => {
    const desc = el("td", "desc", a.description);
    desc.title = a.description;
    const row = el("tr", "clickable",
      el("td", null, severityBadge(a.severity)),
      el("td", null, link(`incident.html?id=${Number(a.id)}`, "row-link", prettyType(a.type))),
      el("td", "ip", a.source_ip),
      el("td", "num", fmtNum(a.event_count)),
      el("td", null, statusLabel(a.status)),
      el("td", "muted", fmtTime(a.last_seen)),
      desc,
    );
    row.dataset.id = String(Number(a.id));
    if (previous && !previous.has(a.id)) row.classList.add("flash");
    return row;
  }));
  state.seenAlerts = new Set(page.items.map((a) => a.id));
}





async function refresh() {
  try {
    const [stats, topIps, alerts] = await Promise.all([
      getJSON(`/statistics?range_minutes=${state.range}`),
      getJSON("/top-ips?limit=10"),
      getJSON(`/alerts?limit=${RECENT_ALERTS}`),
    ]);
    renderTiles(stats.totals);
    renderTimeline(stats.timeline);
    renderTypes(stats.alerts_by_type);
    renderTopIps(topIps);
    renderAlerts(alerts);
    setStatus(true);
  } catch (err) {
    console.error(err);
    setStatus(false, err.message);
  }
}

function init() {
  Chart.defaults.color = "#8b949e";
  Chart.defaults.borderColor = "rgba(240,246,252,.08)";
  Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;

  try {
    const saved = Number(localStorage.getItem("honeysim.range"));
    if ([...$("range").options].some((o) => Number(o.value) === saved)) state.range = saved;
  } catch {}
  $("range").value = String(state.range);

  $("range").addEventListener("change", (e) => {
    state.range = Number(e.target.value);
    try { localStorage.setItem("honeysim.range", String(state.range)); } catch {}
    state.refresh();
  });

  $("alerts").addEventListener("click", (e) => {
    const row = e.target.closest("tr[data-id]");
    if (row && !e.target.closest("a")) window.location.href = `incident.html?id=${row.dataset.id}`;
  });

  state.refresh = startPolling(refresh);
}

init();
