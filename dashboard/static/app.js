// Sensor Shield dashboard. Polls the dashboard API and renders every tab.
"use strict";

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const icon = (name, style = "") => `<span class="material-symbols-outlined" style="${style}">${name}</span>`;
const fmtTime = (t) => (t ? new Date(t * 1000).toLocaleTimeString() : "–");
const ago = (t) => {
  if (!t) return "–";
  const s = Math.max(0, Math.round(Date.now() / 1000 - t));
  return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.round(s / 60)}m ago` : `${Math.round(s / 3600)}h ago`;
};
async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
  return r.json();
}

// Actions carry a custom header so other websites can't trigger them (see dashboard_service.py).
const ACTION = { method: "POST", headers: { "X-Dashboard-Action": "1" } };

let paused = false;

// ---------- Device selection ----------
// "auto" shows the physical board when it's live, otherwise the virtual board
// (tests/virtual_board.py) if that's running, otherwise the physical board.
let deviceChoice = "auto";
try { deviceChoice = localStorage.getItem("device") || "auto"; } catch (e) { /* storage unavailable */ }
let devices = [];
let currentDevice = null;
const KIND_LABEL = { physical: "ESP8266 board", virtual: "virtual board" };

async function refreshDevices() {
  devices = (await api("/api/devices")).devices;
  const sel = $("device-select");
  const opts = [["auto", "Auto (live board)"], ...devices.map((d) => [d.sensor_id, `${d.sensor_id} · ${KIND_LABEL[d.kind] || d.kind}`])];
  if (sel.options.length !== opts.length) {
    sel.innerHTML = opts.map(([v, t]) => `<option value="${esc(v)}">${esc(t)}</option>`).join("");
  }
  if (![...sel.options].some((o) => o.value === deviceChoice)) deviceChoice = "auto";
  sel.value = deviceChoice;
  const physical = devices.find((d) => d.kind === "physical");
  const live = devices.find((d) => d.online && d.kind === "physical") || devices.find((d) => d.online);
  const next = deviceChoice === "auto" ? (live || physical || devices[0]).sensor_id : deviceChoice;
  if (next !== currentDevice) { currentDevice = next; chart.data.labels = []; }
}
$("device-select").addEventListener("change", (e) => {
  deviceChoice = e.target.value;
  try { localStorage.setItem("device", deviceChoice); } catch (err) { /* storage unavailable */ }
  tick(true);
});
const deviceQuery = () => (currentDevice ? `device=${encodeURIComponent(currentDevice)}` : "");
let ledgerKind = "all";
let ledgerRows = [];

// ---------- Tabs ----------
const TITLES = { "tab-overview": "Main Overview", "tab-attack": "Threat Simulator", "tab-chain": "Integrity Chain", "tab-ledger": "Event Ledger", "tab-system": "System Health" };
function showTab(id) {
  document.querySelectorAll(".tab-content").forEach((t) => t.classList.toggle("active", t.id === id));
  document.querySelectorAll(".nav-item").forEach((n) => n.classList.toggle("active", n.dataset.tab === id));
  $("topbar-title").textContent = TITLES[id];
}
document.querySelectorAll(".nav-item").forEach((n) => n.addEventListener("click", () => showTab(n.dataset.tab)));
document.querySelectorAll("[data-goto]").forEach((c) => c.addEventListener("click", () => showTab(c.dataset.goto)));

// ---------- Chart ----------
const chart = new Chart($("telemetryChart"), {
  type: "line",
  data: { labels: [], datasets: [
    { label: "Temperature (°C)", data: [], borderColor: "#000000", backgroundColor: "rgba(0,0,0,.04)", borderWidth: 2, tension: 0, pointRadius: 0, fill: true, yAxisID: "y" },
    { label: "Feels like (°C)", data: [], borderColor: "#f59e0b", borderDash: [6, 4], borderWidth: 2, tension: 0, pointRadius: 0, yAxisID: "y" },
    { label: "Humidity (%)", data: [], borderColor: "#10b981", borderWidth: 2, stepped: "middle", pointRadius: 0, yAxisID: "y1" },
  ] },
  options: {
    responsive: true, maintainAspectRatio: false, animation: false,
    interaction: { mode: "index", intersect: false },
    plugins: { legend: { position: "bottom", labels: { usePointStyle: true, boxWidth: 8, font: { family: "Plus Jakarta Sans", weight: "700" }, color: "#3f3f46" } } },
    scales: {
      x: { grid: { color: "#f4f4f5" }, ticks: { color: "#52525b", maxTicksLimit: 8, font: { family: "Plus Jakarta Sans", weight: "600" } } },
      y: { position: "left", grid: { color: "#f4f4f5" }, ticks: { color: "#000000", font: { family: "Plus Jakarta Sans", weight: "700" } }, title: { display: true, text: "°C", color: "#52525b" } },
      y1: { position: "right", grid: { drawOnChartArea: false }, ticks: { color: "#10b981", font: { family: "Plus Jakarta Sans", weight: "700" } }, title: { display: true, text: "%", color: "#10b981" } },
    },
  },
});

const COMFORT = {
  comfortable: ["badge-green", "Comfortable"], caution: ["badge-amber", "Caution"],
  extreme_caution: ["badge-amber", "Extreme caution"], danger: ["badge-red", "Danger"], extreme_danger: ["badge-red", "Extreme danger"],
};
const comfortBadge = (c) => (COMFORT[c] || ["badge-gray", c || "–"]);

// ---------- Overview ----------
async function refreshOverview() {
  const o = await api(`/api/overview?${deviceQuery()}`);
  const d = o.device;
  $("kpi-validated").textContent = o.counts.validated;
  $("kpi-tamper").textContent = o.counts.tamper;
  $("kpi-recoveries").textContent = o.counts.recoveries;

  const online = d.online;
  const stream = $("kpi-stream");
  stream.className = `badge ${online ? "badge-green" : "badge-amber"}`;
  stream.innerHTML = online ? '<span class="dot dot-green animate-pulse"></span>Live' : '<span class="dot dot-amber"></span>Offline';
  $("top-device").className = `badge ${online ? "badge-green" : "badge-amber"}`;
  const kind = d.kind === "virtual" ? " (virtual)" : "";
  $("top-device").innerHTML = `<span class="dot ${online ? "dot-green animate-pulse" : "dot-amber"}"></span>${esc(d.sensor_id)}${kind} ${online ? "online" : "offline"}`;
  $("chart-live-badge").className = `badge ${online ? "badge-green" : "badge-amber"}`;
  $("chart-live-badge").innerHTML = `<span class="dot ${online ? "dot-green animate-pulse" : "dot-amber"}"></span><span>${online ? "Live" : "Waiting"}</span>`;
  $("banner-device").textContent = d.sensor_id;
  $("chart-sub").textContent = `Validated readings from ${d.sensor_id} (${KIND_LABEL[d.kind] || "device"}), latest session`;
  $("device-offline-banner").style.display = online ? "none" : "flex";
  const otherLive = devices.find((x) => x.online && x.sensor_id !== d.sensor_id);
  const hint = otherLive ? ` ${otherLive.sensor_id} is live: pick it in the device menu above.`
    : d.kind === "virtual" ? " Start it with: docker compose --profile demo up -d virtual-board"
    : " Is it powered and on the hotspot?";
  $("banner-text").textContent = (d.last_seen
    ? `Last reading from this ${KIND_LABEL[d.kind] || "device"} was ${ago(d.last_seen)}.`
    : `No readings from this ${KIND_LABEL[d.kind] || "device"} yet.`) + hint;

  const pb = $("pipeline-badge");
  if (!o.cloud_reachable) { pb.className = "badge badge-red"; pb.textContent = "Cloud unreachable"; }
  else if (o.counts.validated > 0) { pb.className = "badge badge-green"; pb.textContent = "Verified end to end"; }
  else { pb.className = "badge badge-amber"; pb.textContent = "Awaiting data"; }

  const latest = d.latest;
  const res = latest && latest.result;
  if (latest) {
    const t = latest.data.temp_centi_c / 100, h = latest.data.humidity_centi_pct / 100;
    $("kpi-latest").textContent = `${t.toFixed(1)}°C · ${Math.round(h)}%`;
    const [cls, txt] = comfortBadge(res && res.comfort);
    $("kpi-comfort").className = `badge ${cls}`; $("kpi-comfort").textContent = res ? txt : "Pending";
    $("hero-value").textContent = res ? `${res.heat_index_c.toFixed(1)}°` : "–";
    $("hero-value").style.color = cls === "badge-red" ? "#dc2626" : cls === "badge-amber" ? "#d97706" : "#10b981";
    $("hero-sub").textContent = `${t.toFixed(1)} °C · ${h.toFixed(0)}% RH${res ? ` · dew point ${res.dew_point_c.toFixed(1)} °C` : ""}`;
    $("reading-badge").className = `badge ${res ? "badge-green" : "badge-amber"}`;
    $("reading-badge").textContent = res ? "Validated" : "Processing";
    $("r-chunk").textContent = latest.chunk_id; $("r-chunk").title = latest.chunk_id;
    $("r-device").textContent = latest.sensor_id;
    $("r-counter").textContent = latest.counter;
    $("r-time").textContent = latest.timestamp ? new Date(latest.timestamp).toLocaleTimeString() : "–";
    $("kpi-latest-age").textContent = latest.timestamp
      ? `${online ? "Live" : "Last seen"} · ${ago(latest.timestamp / 1000)}` : "";
  } else {
    $("kpi-latest").textContent = "–"; $("kpi-comfort").className = "badge badge-gray"; $("kpi-comfort").textContent = "–";
    $("kpi-latest-age").textContent = "No readings yet";
    $("hero-value").textContent = "–"; $("hero-sub").textContent = "No validated reading from this device yet";
    $("reading-badge").className = "badge badge-gray"; $("reading-badge").textContent = "Waiting";
    ["r-chunk", "r-device", "r-counter", "r-time"].forEach((id) => { $(id).textContent = "–"; });
  }
  // A result only reaches final storage after passing every check below.
  const checks = [
    ["Device ECDSA signature verified", "gateway"],
    ["Timestamp within ±60 s", "gateway"],
    ["Counter fresh (no replay / delay)", "gateway, shared store"],
    ["Gateway signature + end-to-end re-verification", "fork"],
    ["Raw reading backed up before processing", "cloud"],
    ["Edge and cloud agree within 2%", "validation"],
  ];
  $("checks-list").innerHTML = checks.map(([text, where]) => `
    <li class="check-item">${icon(res ? "check_circle" : latest ? "pending" : "radio_button_unchecked",
      `color:${res ? "#10b981" : "#a1a1aa"};font-size:20px;flex-shrink:0;margin-top:1px;`)}
      <span>${text} <span style="color:#a1a1aa;font-weight:600;">· ${where}</span></span></li>`).join("");

  renderChain(o);
}

function fitAxis(axis, values, minSpan) {
  const v = values.filter((x) => typeof x === "number");
  if (!v.length) { delete axis.min; delete axis.max; return; }
  const lo = Math.min(...v), hi = Math.max(...v);
  const span = Math.max(minSpan, (hi - lo) * 1.4);
  const mid = (lo + hi) / 2;
  axis.min = Math.floor(mid - span / 2);
  axis.max = Math.ceil(mid + span / 2);
}

async function refreshReadings() {
  const r = await api(`/api/readings?limit=60&${deviceQuery()}`);
  // Only the latest session: readings within 10 minutes of the newest one, so
  // old runs from hours or days ago don't squash the live trace.
  const all = r.readings.filter((x) => x.result && x.timestamp);
  const newest = all.length ? all[all.length - 1].timestamp : 0;
  const rows = all.filter((x) => x.timestamp >= newest - 10 * 60 * 1000);
  chart.data.labels = rows.map((x) => new Date(x.timestamp).toLocaleTimeString());
  chart.data.datasets[0].data = rows.map((x) => x.result.temp_c);
  chart.data.datasets[1].data = rows.map((x) => x.result.heat_index_c);
  chart.data.datasets[2].data = rows.map((x) => x.result.humidity_pct);
  // The DHT11 reports whole units, so a tight auto-fitted axis turns a normal
  // 1-unit step into a cliff. Keep a minimum span, centred on the data, with padding.
  fitAxis(chart.options.scales.y, [...chart.data.datasets[0].data, ...chart.data.datasets[1].data], 4);
  fitAxis(chart.options.scales.y1, chart.data.datasets[2].data, 10);
  chart.update();
}

// ---------- Integrity chain ----------
const LAYERS = [
  { n: "L1", icon: "key", title: "Sensor Signature & Freshness", where: "Gateway (x2)", hop: "sensor-gateway",
    text: "Verifies each reading's ECDSA P-256 signature against the device's public key (revoked devices refused), requires a timestamp within ±60 s, then a counter higher than any seen before (shared across gateway instances).",
    stats: (o) => [["Readings accepted", o.counts.accepted, "badge-green"], ["Rejected here", o.tamper_by_hop["sensor-gateway"] || 0, "badge-red"]] },
  { n: "L2", icon: "link", title: "End-to-End Re-verification", where: "Fork", hop: "gateway-fork",
    text: "Checks the gateway's countersignature and independently re-checks the sensor's own signature, catching data altered after the gateway verified it.",
    stats: (o) => [["Rejected here", o.tamper_by_hop["gateway-fork"] || 0, "badge-red"], ["Forwarding failures", o.counts.forward_failures, "badge-gray"]] },
  { n: "L3", icon: "cloud_sync", title: "Edge-Cloud Validation", where: "Validation", hop: "edge-cloud-validation",
    text: "Edge and cloud process each reading independently; results must agree within 2% (relative) before they are accepted.",
    stats: (o) => [["Validated", o.counts.validated, "badge-green"], ["Mismatches", o.counts.mismatches, "badge-red"]] },
  { n: "L4", icon: "backup", title: "Backup, Recovery & Anomalies", where: "Cloud + Validation", hop: null,
    text: "Every raw reading is stored with the device's signature before processing. On a mismatch the backup's signature is re-verified: if valid, the result is recomputed from it; if not, the chunk is quarantined. Outliers (>3σ) are flagged.",
    stats: (o) => [["Verified recoveries", o.counts.recoveries, "badge-blue"], ["Quarantined", o.counts.quarantined, "badge-red"], ["Anomalies flagged", o.counts.anomalies, "badge-amber"]] },
];
function renderChain(o) {
  $("layer-grid").innerHTML = LAYERS.map((l) => {
    const rejected = l.hop ? (o.tamper_by_hop[l.hop] || 0) : 0;
    return `<div class="layer-card">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;">
        <div style="display:flex;align-items:center;gap:12px;">
          <div class="layer-num">${l.n}</div>
          <div class="layer-pill">${icon(l.icon, "font-size:20px;")}<span>${l.title}</span></div>
        </div>
        <span class="badge ${rejected ? "badge-red" : "badge-green"}"><span class="dot ${rejected ? "dot-red" : "dot-green"}"></span>${rejected ? "Blocking" : "Active"}</span>
      </div>
      <div style="font-size:14px;color:#52525b;line-height:1.6;">${l.text}</div>
      <div class="stat-list">
        <div class="stat-row"><span>Runs in</span><span class="mono-pill">${l.where}</span></div>
        ${l.stats(o).map(([k, v, cls]) => `<div class="stat-row"><span>${k}</span><span class="badge ${cls}">${v}</span></div>`).join("")}
      </div></div>`;
  }).join("");
  const hops = Object.entries(o.tamper_by_hop);
  $("chain-summary").textContent = hops.length ? hops.map(([h, n]) => `${h}: ${n}`).join(" · ") : "None yet";
  $("chain-ping").className = `dot ${hops.length ? "dot-red" : "dot-green"} animate-ping`;
}

// ---------- Threat simulator ----------
const CATEGORIES = [
  { title: "Cryptographic Tampering", icon: "key", badge: "Signatures", attacks: [
    { key: "corruption", name: "Packet Corruption", sub: "In transit", sev: ["badge-red", "High"], icon: "grain", red: true, desc: "Flips one bit of a sensor value in a correctly signed packet.", btn: "Inject Flip" },
    { key: "injection", name: "Packet Injection", sub: "Forged signature", sev: ["badge-red", "Fatal"], icon: "vpn_key_alert", red: true, desc: "Sends a fake reading signed with random bytes instead of the device key.", btn: "Inject Forgery" },
    { key: "gateway_tamper", name: "Gateway Tamper", sub: "After verification", sev: ["badge-red", "Severe"], icon: "edit_note", red: true, desc: "Alters data after the gateway's check and re-signs it with the gateway key.", btn: "Tamper Gateway" },
  ] },
  { title: "Freshness & Replay", icon: "hub", badge: "Counter", attacks: [
    { key: "replay", name: "Replay Attack", sub: "Captured packet", sev: ["badge-gray", "Sequence"], icon: "replay", desc: "Captures a genuine reading and resends it unchanged two seconds later.", btn: "Dispatch Replay" },
    { key: "duplication", name: "Duplication", sub: "Same packet twice", sev: ["badge-gray", "Sequence"], icon: "content_copy", desc: "Sends the same genuine reading twice in a row.", btn: "Duplicate" },
    { key: "delay", name: "Delay / Reorder", sub: "Old counter", sev: ["badge-gray", "Sequence"], icon: "swap_vert", desc: "Delivers an older reading after a newer one was already accepted.", btn: "Inject Delay" },
    { key: "stale_timestamp", name: "Delayed Delivery", sub: "Stale timestamp", sev: ["badge-gray", "Freshness"], icon: "schedule", desc: "A genuine, correctly signed reading held back 10 minutes, with a counter not yet seen.", btn: "Deliver Late" },
  ] },
  { title: "Processing & Recovery", icon: "memory", badge: "Validation", attacks: [
    { key: "node_tamper", name: "Compromised Node", sub: "Wrong edge result", sev: ["badge-red", "Severe"], icon: "dangerous", red: true, desc: "An edge node returns a doctored result. Validation must catch the disagreement and restore the true result from the signed backup.", btn: "Tamper Node" },
  ] },
  { title: "Availability", icon: "wifi_off", badge: "Tolerated", attacks: [
    { key: "dropping", name: "Packet Dropping", sub: "Lost interval", sev: ["badge-violet", "Tolerated"], icon: "call_missed", desc: "Skips one reading. Not an attack to reject: the pipeline must simply carry on. Best shown live by unplugging the board.", btn: "Drop One" },
  ] },
];
$("attack-categories").innerHTML = CATEGORIES.map((c) => `
  <div>
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
      <div style="display:flex;align-items:center;gap:10px;">
        <div class="cat-icon">${icon(c.icon, "font-size:18px;color:#ffffff;font-variation-settings:'FILL' 1;")}</div>
        <span style="font-size:18px;font-weight:800;color:#000000;">${c.title}</span>
      </div>
      <span class="badge badge-gray">${c.badge}</span>
    </div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px;">
      ${c.attacks.map((a) => `
        <div class="attack-card">
          <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px;">
            <div style="display:flex;align-items:center;gap:12px;">
              <div class="icon-box ${a.red ? "red" : "gray"}">${icon(a.icon, "font-size:24px;")}</div>
              <div><div style="font-size:16px;font-weight:800;color:#000000;">${a.name}</div><div style="font-size:13px;color:#52525b;">${a.sub}</div></div>
            </div>
            <span class="badge ${a.sev[0]}">${a.sev[1]}</span>
          </div>
          <div style="font-size:14px;color:#52525b;line-height:1.5;">${a.desc}</div>
          <div id="result-${a.key}" style="font-size:13px;font-weight:700;min-height:18px;"></div>
          <button class="attack-btn ${a.red ? "btn-primary" : "btn-ghost"}" data-attack="${a.key}" style="width:100%;justify-content:center;">${icon("bolt", "font-size:18px;")}${a.btn}</button>
        </div>`).join("")}
    </div>
  </div>`).join("");

function showAttackResult(r) {
  const el = $(`result-${r.key}`);
  if (el) el.innerHTML = `<span style="color:${r.passed ? "#059669" : "#dc2626"};">${r.passed ? "✓ Caught" : "✗ Not caught"}</span> <span style="color:#52525b;">${esc(r.detail)}</span>`;
}
async function runAttack(key, btn) {
  if (btn) btn.disabled = true;
  try { const r = await api(`/api/attacks/${key}`, ACTION); showAttackResult(r); }
  catch (e) { const el = $(`result-${key}`); if (el) el.innerHTML = `<span style="color:#dc2626;">${esc(e.message)}</span>`; }
  finally { if (btn) btn.disabled = false; await refreshAttacks(); await refreshFeed(); }
}
document.querySelectorAll(".attack-btn").forEach((b) => b.addEventListener("click", () => runAttack(b.dataset.attack, b)));

async function runAll() {
  const buttons = [$("btn-run-all"), $("btn-run-all-2"), ...document.querySelectorAll(".attack-btn")];
  buttons.forEach((b) => (b.disabled = true));
  showTab("tab-attack");
  try {
    const r = await api("/api/attacks", ACTION);
    r.results.forEach(showAttackResult);
  } finally { buttons.forEach((b) => (b.disabled = false)); await refreshAttacks(); await refreshFeed(); }
}
$("btn-run-all").addEventListener("click", runAll);
$("btn-run-all-2").addEventListener("click", runAll);

async function refreshAttacks() {
  const a = await api("/api/attacks");
  $("threat-counter").textContent = `${a.history.length} Dispatched`;
  if (a.history.length) {
    const caught = a.history.filter((r) => r.passed).length;
    $("last-attack").innerHTML = `<b style="color:#000;">${caught}/${a.history.length}</b> caught or tolerated as expected. Last: <b style="color:#000;">${esc(a.history[0].name)}</b>, ${ago(a.history[0].time)}.`;
  }
}

const HOP_ICON = { "sensor-gateway": "router", "gateway-fork": "call_split", "fork-edge": "memory", "fork-cloud": "cloud", "edge-cloud-validation": "rule" };
async function refreshFeed() {
  const events = await api("/api/events?kind=tamper&limit=30");
  $("log-feed").innerHTML = events.length ? events.map((e) => `
    <div class="log-item">
      ${icon(HOP_ICON[e.hop] || "gpp_bad", "color:#dc2626;font-size:20px;flex-shrink:0;margin-top:2px;")}
      <div style="flex:1;min-width:0;">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;">
          <span class="log-title">${esc(e.reason || "tamper")}</span><span class="log-time">${ago(e.time)}</span>
        </div>
        <div class="log-body">Caught at <b>${esc(e.hop)}</b>${e.sensor_id ? ` · ${esc(e.sensor_id)}` : ""}${e.counter != null ? ` · counter ${esc(e.counter)}` : ""}</div>
      </div>
    </div>`).join("") : `
    <div class="log-item">${icon("check_circle", "color:#10b981;font-size:20px;flex-shrink:0;margin-top:2px;")}
      <div><div class="log-title">No tampering detected</div><div class="log-body">Run an attack to see it caught here.</div></div></div>`;
}

// ---------- Ledger ----------
const EVENT_BADGE = { accepted: "badge-green", validated: "badge-green", forwarded: "badge-blue", processed: "badge-gray", final_stored: "badge-gray",
  tamper: "badge-red", anomaly: "badge-amber", validation_failed: "badge-red", forward_failed: "badge-amber",
  recovered: "badge-blue", quarantined: "badge-red", rate_limited: "badge-amber" };
function eventDetails(e) {
  const d = e.details || {};
  if (e.event === "tamper") return `${e.reason}${d.last_counter != null ? ` (last accepted ${d.last_counter})` : ""}`;
  if (e.event === "accepted" && d.data) return `${(d.data.temp_centi_c / 100).toFixed(1)} °C, ${(d.data.humidity_centi_pct / 100).toFixed(0)}% · ${d.gateway || ""}`;
  if (e.event === "processed" && d.result) return `feels like ${d.result.heat_index_c} °C · ${d.result.comfort}`;
  if (e.event === "anomaly") return `${d.metric} = ${d.value} (mean ${d.mean}, ${d.deviations}σ)`;
  if (e.event === "validation_failed") return `mismatch: ${Object.keys(d.differences || {}).join(", ")}`;
  if (e.event === "recovered") return "backup signature verified → result recomputed and restored";
  if (e.event === "quarantined") return d.reason || "backup failed verification";
  if (e.event === "rate_limited") return `client ${d.client} exceeded the rate limit`;
  if (e.event === "validated") return d.anomalies && d.anomalies.length ? `anomalies: ${d.anomalies.join(", ")}` : "edge = cloud";
  return d.error || "";
}
async function refreshLedger() {
  ledgerRows = await api(`/api/events?kind=${ledgerKind}&limit=200`);
  renderLedger();
}
function renderLedger() {
  const q = $("ledger-search").value.trim().toLowerCase();
  const rows = q ? ledgerRows.filter((e) => JSON.stringify(e).toLowerCase().includes(q)) : ledgerRows;
  $("ledger-body").innerHTML = rows.length ? rows.map((e) => `
    <tr>
      <td class="mono">${e.id}</td><td class="mono">${fmtTime(e.time)}</td>
      <td><span class="badge ${EVENT_BADGE[e.event] || "badge-gray"}">${esc(e.event)}</span></td>
      <td class="mono">${esc(e.hop)}</td><td class="mono">${esc(e.service)}</td><td class="mono">${esc(e.sensor_id || "–")}</td>
      <td class="mono">${esc(e.counter ?? "–")}</td>
      <td class="mono" title="${esc(e.chunk_id || "")}">${e.chunk_id ? esc(e.chunk_id.slice(0, 8)) + "…" : "–"}</td>
      <td style="font-size:13px;">${esc(eventDetails(e))}</td>
    </tr>`).join("") : `<tr><td colspan="9" style="text-align:center;padding:32px 16px;color:#a1a1aa;font-weight:700;">No events match.</td></tr>`;
}
document.querySelectorAll("#ledger-pills .pill").forEach((p) => p.addEventListener("click", () => {
  document.querySelectorAll("#ledger-pills .pill").forEach((x) => x.classList.toggle("active", x === p));
  ledgerKind = p.dataset.kind; refreshLedger();
}));
$("ledger-search").addEventListener("input", renderLedger);
$("btn-export").addEventListener("click", () => {
  const blob = new Blob([JSON.stringify(ledgerRows, null, 2)], { type: "application/json" });
  const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: `events-${ledgerKind}.json` });
  a.click(); URL.revokeObjectURL(a.href);
});

$("btn-verify").addEventListener("click", async () => {
  const el = $("chain-status");
  el.className = "badge badge-gray"; el.textContent = "Checking…";
  try {
    const r = await api("/api/events/verify");
    el.className = `badge ${r.ok ? "badge-green" : "badge-red"}`;
    el.innerHTML = r.ok ? `<span class="dot dot-green"></span>Intact · ${r.checked} entries`
                        : `<span class="dot dot-red"></span>Broken at #${r.first_bad_id}: ${esc(r.reason)}`;
  } catch (e) { el.className = "badge badge-red"; el.textContent = e.message; }
});

// ---------- Benchmark ----------
$("btn-benchmark").addEventListener("click", async () => {
  const btn = $("btn-benchmark");
  btn.disabled = true; $("bench-status").textContent = "Running…";
  try {
    const r = await api("/api/benchmark?genuine=30&runs=3", ACTION);
    const pct = (x) => (x == null ? "skip" : `${(x * 100).toFixed(1)}%`);
    $("bench-status").textContent = `Done in ${r.duration_s} s`;
    const tiles = [["Detection rate", pct(r.overall.detection_rate)], ["False positives", pct(r.genuine.false_positive_rate)],
                   ["F1 score", r.overall.f1.toFixed(3)], ["Latency p50", `${r.latency_ms.p50} ms`], ["Latency p95", `${r.latency_ms.p95} ms`]];
    $("bench-results").innerHTML = `
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px;">
        ${tiles.map(([k, v]) => `<div class="tile" style="text-align:center;"><div class="label" style="font-size:11px;">${k}</div><div style="font-size:22px;font-weight:800;color:#000;margin-top:4px;">${v}</div></div>`).join("")}
      </div>
      <table class="data-table"><thead><tr><th>Attack</th><th>Detected</th><th>Rate</th></tr></thead><tbody>
        ${Object.entries(r.attacks).map(([name, a]) => `<tr><td>${esc(name)}</td><td class="mono">${a.detected}/${a.runs}</td>
          <td><span class="badge ${a.detection_rate === 1 ? "badge-green" : a.detection_rate == null ? "badge-gray" : "badge-red"}">${pct(a.detection_rate)}</span></td></tr>`).join("")}
      </tbody></table>`;
  } catch (e) { $("bench-status").textContent = e.message; }
  finally { btn.disabled = false; }
});

// ---------- Health ----------
async function refreshHealth() {
  const h = await api("/api/health");
  const up = h.filter((s) => s.ok).length, all = h.length;
  const cls = up === all ? "badge-green" : up ? "badge-amber" : "badge-red";
  const dot = up === all ? "dot-green" : up ? "dot-amber" : "dot-red";
  $("top-services").className = `badge ${cls}`;
  $("top-services").innerHTML = `<span class="dot ${dot}"></span>${up}/${all} services`;
  $("health-summary").className = `badge ${cls}`;
  $("health-summary").textContent = `${up}/${all} healthy`;
  $("defense-state").style.color = up === all ? "#10b981" : "#d97706";
  $("defense-state").innerHTML = `<span class="dot ${dot}"></span>${up === all ? "Active Guard" : "Degraded"}`;
  $("service-grid").innerHTML = h.map((s) => `
    <div class="card-sm" style="display:flex;flex-direction:column;gap:10px;">
      <div style="display:flex;align-items:center;justify-content:space-between;">
        <span style="font-size:16px;font-weight:800;color:#000;">${esc(s.name)}</span>
        <span class="badge ${s.ok ? "badge-green" : "badge-red"}"><span class="dot ${s.ok ? "dot-green" : "dot-red"}"></span>${s.ok ? "Up" : "Down"}</span>
      </div>
      <div class="stat-row" style="font-size:13px;"><span>Response</span><span class="mono-pill" style="font-size:13px;">${s.ok ? s.ms + " ms" : "–"}</span></div>
      <div style="font-family:monospace;font-size:12px;color:#71717a;">${esc(s.url)}</div>
    </div>`).join("");
}

// ---------- Loop ----------
async function safe(fn) { try { await fn(); } catch (e) { console.warn(e); } }
async function tick(full) {
  if (paused && !full) return;
  await safe(refreshDevices);
  await Promise.all([safe(refreshOverview), safe(refreshReadings), safe(refreshFeed), safe(refreshLedger), safe(refreshAttacks)]);
}
$("btn-pause").addEventListener("click", () => {
  paused = !paused; $("pause-icon").textContent = paused ? "play_arrow" : "pause";
  $("btn-pause").title = paused ? "Resume live updates" : "Pause live updates";
});
$("btn-refresh").addEventListener("click", () => { tick(true); safe(refreshHealth); });
setInterval(() => { $("top-clock").textContent = new Date().toLocaleTimeString(); }, 1000);

tick(true); safe(refreshHealth);
setInterval(() => tick(false), 2500);
setInterval(() => { if (!paused) safe(refreshHealth); }, 5000);
