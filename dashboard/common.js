"use strict";

const API = "/api";
const REFRESH_MS = 5000;

const $ = (id) => document.getElementById(id);



function el(tag, className, ...children) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  node.append(...children.map((c) => (c instanceof Node ? c : String(c ?? ""))));
  return node;
}

function link(href, className, ...children) {
  const a = el("a", className, ...children);
  a.href = href;
  return a;
}

const fmtNum = (n) => Number(n ?? 0).toLocaleString();

const prettyType = (t) => String(t).toLowerCase().replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());

const prettyKey = (k) => prettyType(k);

const CLOCK_HMS = { hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" };
const CLOCK_HM = { hour: "2-digit", minute: "2-digit", hourCycle: "h23" };

function clock(d = new Date(), seconds = true) {
  return d.toLocaleTimeString([], seconds ? CLOCK_HMS : CLOCK_HM);
}

const pad2 = (n) => String(n).padStart(2, "0");

function fmtDate(d, year = true) {
  const dm = `${pad2(d.getDate())}.${pad2(d.getMonth() + 1)}`;
  return year ? `${dm}.${d.getFullYear()}` : dm;
}

function fmtTime(iso) {
  const d = new Date(iso);
  const sameDay = d.toDateString() === new Date().toDateString();
  return sameDay ? clock(d) : `${fmtDate(d)} ${clock(d)}`;
}

function fmtTimePrecise(iso) {
  const d = new Date(iso);
  const ms = String(d.getMilliseconds()).padStart(3, "0");
  return `${fmtDate(d)} ${clock(d)}.${ms}`;
}

function severityBadge(severity) {
  return el("span", `badge sev-${severity}`, severity);
}

function statusLabel(status) {
  return el("span", `st st-${status}`, status.replace("_", " "));
}

async function getJSON(path) {
  const resp = await fetch(API + path, { cache: "no-store" });
  if (!resp.ok) throw new Error(`${path} → HTTP ${resp.status}`);
  return resp.json();
}

async function sendJSON(method, path, body) {
  const resp = await fetch(API + path, {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!resp.ok) throw new Error(`${method} ${path} → HTTP ${resp.status}`);
  return resp.json();
}

function setStatus(ok, message) {
  const status = $("status");
  status.classList.toggle("live", ok);
  status.classList.toggle("down", !ok);
  $("status-text").textContent = ok ? `live · updated ${clock()}` : "API unreachable";
  $("error").classList.toggle("hidden", ok);
  if (!ok) $("error").textContent = `Cannot load data from the API (${message}). Retrying every ${REFRESH_MS / 1000} s…`;
}

function startPolling(fn) {
  let timer = null;
  async function tick() {
    clearTimeout(timer);
    await fn();
    if (document.visibilityState === "visible") timer = setTimeout(tick, REFRESH_MS);
  }
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") tick();
  });
  tick();
  return tick;
}
