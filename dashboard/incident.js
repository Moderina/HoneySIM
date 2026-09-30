"use strict";

const state = {
  id: null,
  alert: null,
  timelineKey: null,
  evidenceKey: null,
  openEvents: new Set(),
  rawCache: new Map(),
  refresh: null,
  busy: false,
};

function fmtDuration(fromIso, toIso) {
  let s = Math.max(0, Math.round((new Date(toIso) - new Date(fromIso)) / 1000));
  if (s < 1) return "under 1 s";

  const parts = [];
  for (const [unit, size] of [["d", 86400], ["h", 3600], ["min", 60], ["s", 1]]) {
    if (s >= size) {
      parts.push(`${Math.floor(s / size)} ${unit}`);
      s %= size;
    }
  }
  return parts.slice(0, 2).join(" ");
}

function targetSummary(events) {
  const counts = new Map();
  for (const e of events) {
    const key = e.destination_port != null ? `${e.protocol} / ${e.destination_port}` : e.protocol;
    counts.set(key, (counts.get(key) || 0) + 1);
  }

  const keys = [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([k]) => k);
  return keys.length > 5 ? `${keys.slice(0, 5).join(", ")} +${keys.length - 5} more` : keys.join(", ") || "—";
}

function describeEvent(e) {
  const d = e.details || {};
  switch (e.event_type) {

    case "LOGIN_FAILURE": {
      const pwd = e.password != null ? ` / ${e.password}` : "";
      const via = e.protocol === "HTTP" && d.path ? ` (${d.method || "POST"} ${d.path})` : "";
      return `login failed: ${e.username ?? "?"}${pwd}${via}`;
    }

    case "HTTP_REQUEST":
      return `${d.method || "?"} ${d.path_decoded ?? d.path ?? "?"} → ${d.status ?? "?"}`;
      
    case "CONNECTION":
      return `connection to ${e.protocol} port ${e.destination_port}` + (d.payload ? ` · sent: ${d.payload}` : "");
    
    case "PROTOCOL_ERROR":
      return `protocol error: ${e.message || "?"}`;

    default:
      return e.message || e.event_type;
  }
}





const ISO_DATETIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z?$/;

function renderValue(value) {
  if (typeof value === "string" && ISO_DATETIME.test(value)) {
    return el("span", null, fmtTimePrecise(value.endsWith("Z") ? value : `${value}Z`));
  }
  if (value === null || value === undefined || value === "") return el("span", "muted", "—");

  if (Array.isArray(value)) {
    if (!value.length) return el("span", "muted", "—");

    if (value.every((v) => v === null || typeof v !== "object")) {
      return el("div", "chips", ...value.map((v) => el("span", "chip", v)));
    }

    const keys = [...new Set(value.flatMap((v) => Object.keys(v || {})))];
    return el("div", "table-wrap", el("table", "mini",
      el("thead", null, el("tr", null, ...keys.map((k) => el("th", null, prettyKey(k))))),
      el("tbody", null, ...value.map((row) => el("tr", null,
        ...keys.map((k) => el("td", null, renderValue(row?.[k])))))),
    ));
  }

  if (typeof value === "object") {
    const entries = Object.entries(value);
    if (!entries.length) return el("span", "muted", "—");

    return el("table", "mini kv", el("tbody", null, ...entries.map(([k, v]) =>
      el("tr", null, el("td", "k", k), el("td", "num", renderValue(v))))));
  }
  return el("span", null, typeof value === "number" ? fmtNum(value) : value);
}

function renderEvidence(evidence) {
  const key = JSON.stringify(evidence);
  if (key === state.evidenceKey) return;

  state.evidenceKey = key;
  const entries = Object.entries(evidence || {});
  $("evidence-card").classList.toggle("hidden", !entries.length);
  $("evidence").replaceChildren(el("dl", "evidence",
    ...entries.map(([k, v]) => el("div", null, el("dt", null, prettyKey(k)), el("dd", null, renderValue(v))))));
}




async function loadRaw(eventId, pre) {
  if (!state.rawCache.has(eventId)) {
    try {
      const ev = await getJSON(`/events/${eventId}`);
      let text = ev.raw_log;
      try { text = JSON.stringify(JSON.parse(ev.raw_log), null, 2); } catch {}

      state.rawCache.set(eventId, text);
    } catch (err) {
      pre.textContent = `Could not load raw log: ${err.message}`;
      return;
    }
  }
  pre.textContent = state.rawCache.get(eventId);
}

function timelineEvent(e) {
  const pre = el("pre", "raw", "loading…");
  const details = el("details", null,
    el("summary", null,
      el("span", "tl-time", fmtTimePrecise(e.timestamp)),
      el("span", "tl-proto", e.destination_port != null ? `${e.protocol}/${e.destination_port}` : e.protocol),
      el("span", `tl-text ev-${e.event_type}`, describeEvent(e)),
    ),
    el("div", "raw-head muted", `event #${e.id} · raw log line:`),
    pre,
  );

  details.addEventListener("toggle", () => {
    if (details.open) {
      state.openEvents.add(e.id);
      loadRaw(e.id, pre);
    } else {
      state.openEvents.delete(e.id);
    }
  });
  if (state.openEvents.has(e.id)) {
    details.open = true;
  }
  return el("li", "tl-item", details);
}

function timelineMarker(iso, text) {
  return el("li", "tl-item tl-marker",
    el("div", "tl-row", el("span", "tl-time", fmtTimePrecise(iso)), el("span", "tl-proto", "SIEM"), el("span", "tl-text", text)));
}

function renderTimeline(alert) {
  const events = alert.events;
  const key = `${alert.event_count}:${events.map((e) => e.id).join(",")}:${alert.timestamp}`;
  if (key === state.timelineKey) return;

  state.timelineKey = key;
  const shown = events.length < alert.event_count ? ` (showing first ${fmtNum(events.length)})` : "";
  $("timeline-info").textContent = `${fmtNum(alert.event_count)} events${shown} · click an event for the raw log`;

  const raised = new Date(alert.timestamp);
  const items = [];
  let markerPlaced = false;
  for (const e of events) {
    if (!markerPlaced && new Date(e.timestamp) > raised) {
      items.push(timelineMarker(alert.timestamp, `detection triggered → ${alert.type} alert raised`));
      markerPlaced = true;
    }
    items.push(timelineEvent(e));
  }

  if (!markerPlaced) items.push(timelineMarker(alert.timestamp, `detection triggered → ${alert.type} alert raised`));
  $("timeline").replaceChildren(...items);
}





function renderHeader(a) {
  document.title = `Incident #${a.id} · ${prettyType(a.type)} — HoneySIM`;
  $("i-id").textContent = `#${a.id}`;
  $("i-severity").replaceChildren(severityBadge(a.severity));
  $("i-type").textContent = a.type;
  $("i-description").textContent = a.description;
  $("i-ip").textContent = a.source_ip;
  $("i-target").textContent = targetSummary(a.events);
  $("i-count").textContent = fmtNum(a.event_count);
  $("i-first").textContent = fmtTimePrecise(a.first_seen);
  $("i-last").textContent = fmtTimePrecise(a.last_seen);
  $("i-duration").textContent = fmtDuration(a.first_seen, a.last_seen);
  $("i-raised").textContent = fmtTimePrecise(a.timestamp);
  $("i-updated").textContent = fmtTimePrecise(a.updated_at);

  for (const btn of $("status-buttons").querySelectorAll("button")) {

    const active = btn.dataset.status === a.status;
    btn.classList.toggle("active", active);
    btn.classList.toggle(`st-${btn.dataset.status}`, active);
    btn.setAttribute("aria-pressed", String(active));
    btn.disabled = state.busy;
  }
}

function renderRelated(page) {
  const others = page.items.filter((a) => a.id !== state.id);
  $("related-card").classList.remove("hidden");
  $("related-info").textContent = others.length ? `${others.length} more` : "";
  if (!others.length) {
    const td = el("td", "empty-row", "No other alerts from this IP");
    td.colSpan = 5;
    return $("related").replaceChildren(el("tr", null, td));
  }

  $("related").replaceChildren(...others.map((a) => el("tr", null,
    el("td", null, severityBadge(a.severity)),
    el("td", null, link(`incident.html?id=${Number(a.id)}`, "row-link", prettyType(a.type))),
    el("td", "num", fmtNum(a.event_count)),
    el("td", null, statusLabel(a.status)),
    el("td", "muted", fmtTime(a.last_seen)),
  )));
}

function showNotFound(text) {
  $("incident").classList.add("hidden");
  for (const id of ["evidence-card", "related-card", "timeline-card"]) $(id).classList.add("hidden");

  $("not-found").classList.remove("hidden");
  $("not-found-text").textContent = text;
}

async function changeStatus(status) {
  if (state.busy || !state.alert || state.alert.status === status) return;

  state.busy = true;
  renderHeader(state.alert);
  $("status-msg").textContent = "saving…";
  try {
    const updated = await sendJSON("PATCH", `/alerts/${state.id}`, { status });
    $("status-msg").textContent = `status changed to ${updated.status.replace("_", " ")} at ${clock()}`;
  } catch (err) {
    $("status-msg").textContent = `could not change status: ${err.message}`;
  } finally {
    state.busy = false;
    await state.refresh();
  }
}





async function load() {
  try {
    const resp = await fetch(`${API}/alerts/${state.id}`, { cache: "no-store" });
    if (resp.status === 404) {
      setStatus(true);
      return showNotFound(`There is no alert with id ${state.id}.`);
    }

    if (!resp.ok) throw new Error(`/alerts/${state.id} → HTTP ${resp.status}`);

    const alert = await resp.json();
    state.alert = alert;

    $("not-found").classList.add("hidden");
    for (const id of ["incident", "timeline-card"]) $(id).classList.remove("hidden");
    renderHeader(alert);
    renderEvidence(alert.evidence);
    renderTimeline(alert);
    renderRelated(await getJSON(`/alerts?source_ip=${encodeURIComponent(alert.source_ip)}&limit=50`));
    setStatus(true);
  } catch (err) {
    console.error(err);
    setStatus(false, err.message);
  }
}

function init() {
  const id = Number(new URLSearchParams(window.location.search).get("id"));
  if (!Number.isInteger(id) || id <= 0) {
    showNotFound("Missing or invalid incident id in the URL (expected incident.html?id=<number>).");
    $("status").classList.add("hidden");
    return;
  }
  
  state.id = id;
  $("status-buttons").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-status]");
    if (btn) changeStatus(btn.dataset.status);
  });
  state.refresh = startPolling(load);
}

init();
