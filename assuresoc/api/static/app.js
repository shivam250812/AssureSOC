"use strict";

// Every value rendered here can originate from attacker-controlled logs: always go through esc().
const $ = (sel, root = document) => root.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const TACTICS = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
  "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
  "Collection", "Command and Control", "Exfiltration", "Impact"];
const TACTIC_SHORT = { "Reconnaissance": "Recon", "Resource Development": "Resource Dev", "Privilege Escalation": "Priv. Escalation",
  "Command and Control": "C2" };
const SEV_COLOR = { critical: "var(--critical)", high: "var(--high)", medium: "var(--medium)", low: "var(--low)" };
const PRIO_COLOR = { P1: "var(--p1)", P2: "var(--p2)", P3: "var(--p3)", P4: "var(--p4)" };
const VERDICT = { true_positive: "True positive", likely_true_positive: "Likely true positive",
  needs_investigation: "Needs investigation", likely_false_positive: "Likely false positive" };
const SUGGESTIONS = ["What happened, in plain English?", "What should I do in the next 30 minutes?",
  "Was any personal data exposed?", "Which accounts must be reset?", "Draft a 5-line update for the CISO."];

const state = { aiEnabled: false, incidents: [], current: null, detail: null, tab: "overview", chat: {}, done: {} };

// ---------- helpers ----------
async function api(path, opts = {}) {
  const res = await fetch(path, opts);
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).detail || msg; } catch (_) { /* not JSON */ }
    throw new Error(msg);
  }
  return res;
}

function toast(msg, err = false) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast" + (err ? " err" : "");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.add("hidden"), err ? 7000 : 4000);
}

function ist(iso, withDay = true) {
  if (!iso) return "—";
  const opts = { timeZone: "Asia/Kolkata", hour: "2-digit", minute: "2-digit", hour12: false };
  if (withDay) Object.assign(opts, { day: "2-digit", month: "short" });
  return new Date(iso).toLocaleString("en-IN", opts) + " IST";
}

function countdown(deadlineIso) {
  const ms = new Date(deadlineIso) - Date.now();
  const abs = Math.abs(ms);
  const h = Math.floor(abs / 3.6e6), m = Math.floor((abs % 3.6e6) / 6e4), s = Math.floor((abs % 6e4) / 1000);
  const t = `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  return { overdue: ms < 0, text: ms < 0 ? `OVERDUE by ${t}` : t };
}

// Escape first, then turn [al-xxxx] citations into clickable chips.
function cite(text) {
  return esc(text).replace(/\[(al-[\w-]+)\]/g, (_, id) => `<span class="chip cite" data-cite="${id}">${id}</span>`);
}

function mdToHtml(md) {
  const lines = esc(md).split("\n");
  let html = "", inList = false;
  const inline = (s) => s.replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/(^|\s)_(.+?)_(?=\s|$|[.,;:])/g, "$1<i>$2</i>");
  for (const line of lines) {
    const li = line.match(/^\s*- (.*)/);
    if (li) { if (!inList) { html += "<ul>"; inList = true; } html += `<li>${inline(li[1])}</li>`; continue; }
    if (inList) { html += "</ul>"; inList = false; }
    if (line.startsWith("## ")) html += `<h2>${inline(line.slice(3))}</h2>`;
    else if (line.startsWith("# ")) html += `<h1>${inline(line.slice(2))}</h1>`;
    else if (line.startsWith("&gt; ")) html += `<blockquote>${inline(line.slice(5))}</blockquote>`;
    else if (line.trim()) html += `<p>${inline(line)}</p>`;
  }
  return html + (inList ? "</ul>" : "");
}

// ---------- boot / ingestion ----------
async function init() {
  const [hashInc, hashTab] = location.hash.slice(1).split("/");
  if (hashInc) state.current = decodeURIComponent(hashInc);
  if (["overview", "timeline", "graph", "compliance", "ask"].includes(hashTab)) state.tab = hashTab;
  const st = await (await api("/api/status")).json();
  state.aiEnabled = st.ai_enabled;
  const badge = $("#ai-badge");
  badge.className = "badge " + (st.ai_enabled ? "ai" : "offline");
  badge.innerHTML = `<span class="dot"></span>${st.ai_enabled ? "Claude · " + esc(st.model) : "Offline analyst"}`;
  badge.title = st.ai_enabled ? "AI analysis via the Claude API" : "Set ANTHROPIC_API_KEY to enable Claude";
  if (st.workspace) await loadIncidents();
}

async function loadDemo() {
  const btn = $("#btn-demo");
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Analysing…';
  try {
    const stats = await (await api("/api/demo", { method: "POST" })).json();
    state.current = null; state.chat = {}; state.done = {};
    await loadIncidents();
    toast(`Analysed ${stats.events.toLocaleString()} events → ${stats.incidents} incidents in ${stats.elapsed_ms} ms`);
  } catch (e) { toast(e.message, true); }
  finally { btn.disabled = false; btn.textContent = "Load demo scenario"; }
}

async function uploadFiles(files) {
  if (!files.length) return;
  const fd = new FormData();
  for (const f of files) fd.append("files", f);
  toast(`Uploading ${files.length} file(s)…`);
  try {
    const stats = await (await api("/api/upload", { method: "POST", body: fd })).json();
    state.current = null; state.chat = {}; state.done = {};
    await loadIncidents();
    toast(`Parsed ${stats.events.toLocaleString()} events → ${stats.alerts} alerts → ${stats.incidents} incidents`);
  } catch (e) { toast(e.message, true); }
}

async function loadIncidents() {
  const data = await (await api("/api/incidents")).json();
  state.incidents = data.incidents;
  $("#empty").classList.add("hidden");
  $("#app").classList.remove("hidden");
  $("#funnel").classList.remove("hidden");
  $("#ws-label").textContent = data.stats.label;
  renderFunnel(data.stats);
  renderQueue();
  const keep = state.incidents.some((i) => i.id === state.current);
  if (state.incidents.length) selectIncident(keep ? state.current : state.incidents[0].id);
  else $("#detail").innerHTML = '<div class="panel">No incidents — nothing matched the detections.</div>';
}

function renderFunnel(s) {
  const p = s.by_priority;
  const chips = ["P1", "P2", "P3", "P4"].filter((k) => p[k]).map((k) => `<span class="prio ${k}">${k} · ${p[k]}</span>`).join("");
  $("#funnel").innerHTML = `
    <div class="stat"><div class="v">${s.events.toLocaleString()}</div><div class="k">events · ${Object.keys(s.sources).length} sources</div></div>
    <div class="arrow">→</div>
    <div class="stat"><div class="v">${s.alerts}</div><div class="k">alerts raised · ${s.techniques} ATT&amp;CK techniques</div></div>
    <div class="arrow">→</div>
    <div class="stat"><div class="v">${s.suppressed}</div><div class="k">suppressed (allowlist)</div></div>
    <div class="arrow">→</div>
    <div class="stat hl"><div class="v">${s.incidents}</div><div class="k">incidents</div><div class="pchips">${chips}</div></div>
    <div class="stat hl"><div class="v">${s.queue_reduction_pct}%</div><div class="k">fewer queue items</div></div>
    <div class="stat ${s.injection_events ? "warn" : ""}"><div class="v">${s.injection_events}</div><div class="k">prompt-injection payloads neutralised</div></div>
    <div class="stat"><div class="v">${s.elapsed_ms} ms</div><div class="k">end-to-end analysis</div></div>`;
}

function renderQueue() {
  $("#queue-count").textContent = `${state.incidents.length} open`;
  $("#queue-list").innerHTML = state.incidents.map((i) => `
    <div class="card ${i.priority} ${i.id === state.current ? "active" : ""}" data-id="${esc(i.id)}">
      <div class="card-top"><span class="prio ${i.priority}">${i.priority} · ${i.score}</span><span class="muted mono">${esc(i.id)}</span></div>
      <div class="card-title">${esc(i.title)}</div>
      <div class="card-meta"><span>${i.alerts} alerts</span><span>${ist(i.first_seen)}</span><span>${esc(i.status)}</span>
        ${i.certin_deadline ? `<span title="CERT-In 6-hour reporting">⏱ CERT-In</span>` : ""}
        ${i.personal_data_at_risk ? `<span title="Personal data at risk (DPDP)">🔒 DPDP</span>` : ""}
        ${i.analysis_source === "claude" ? `<span style="color:var(--accent)">✦ Claude</span>` : ""}</div>
    </div>`).join("");
}

async function selectIncident(id) {
  state.current = id;
  renderQueue();
  try {
    state.detail = await (await api(`/api/incidents/${encodeURIComponent(id)}`)).json();
    renderDetail();
  } catch (e) { toast(e.message, true); }
}

// ---------- detail ----------
function renderDetail() {
  const { incident: inc } = state.detail;
  const an = inc.analysis || {};
  const reg = inc.regulatory || {};
  const clock = reg.certin_deadline ? `
    <div class="clock" id="clock">
      <div><b>CERT-In reporting clock</b> <span class="muted">· 6 h from first indicator (${ist(reg.noticed_at)}) · ${esc((reg.certin_types || []).length)} reportable category(ies)</span></div>
      <div class="t" data-deadline="${esc(reg.certin_deadline)}"></div>
    </div>` : "";
  $("#detail").innerHTML = `
    <div class="inc-head">
      <div class="ring" style="--v:${inc.score};--ring-color:${PRIO_COLOR[inc.priority]}"><div>${inc.score}</div></div>
      <div style="min-width:0">
        <div class="inc-sub"><span class="prio ${inc.priority}">${inc.priority}</span><span class="mono">${esc(inc.id)}</span>
          <span>${ist(inc.first_seen)} → ${ist(inc.last_seen, false)}</span><span>${inc.alert_ids.length} alerts</span>
          <label>Status <select id="status">${["new", "investigating", "contained", "closed"].map((s) =>
            `<option ${s === inc.status ? "selected" : ""}>${s}</option>`).join("")}</select></label></div>
        <h1>${esc(an.title || inc.title)}</h1>
      </div>
    </div>
    ${clock}
    <nav class="tabs">${[["overview", "Overview"], ["timeline", "Timeline & evidence"], ["graph", "Entity graph"],
      ["compliance", "Compliance & reporting"], ["ask", "Ask AssureSOC"]].map(([k, l]) =>
      `<button class="tab ${state.tab === k ? "active" : ""}" data-tab="${k}">${l}</button>`).join("")}</nav>
    <div id="tab-body"></div>`;
  $("#status").onchange = async (e) => {
    await api(`/api/incidents/${inc.id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status: e.target.value }) });
    const q = state.incidents.find((i) => i.id === inc.id); if (q) q.status = e.target.value;
    inc.status = e.target.value; renderQueue(); toast(`${inc.id} marked ${e.target.value}`);
  };
  renderTab();
  tickClocks();
}

function renderTab() {
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === state.tab));
  history.replaceState(null, "", `#${state.current}/${state.tab}`);
  const body = $("#tab-body");
  ({ overview: renderOverview, timeline: renderTimeline, graph: renderGraph, compliance: renderCompliance, ask: renderAsk })[state.tab](body);
}

function renderOverview(body) {
  const { incident: inc } = state.detail;
  const an = inc.analysis || {};
  const done = state.done[inc.id] || (state.done[inc.id] = {});
  const src = inc.analysis_source === "claude"
    ? `<span class="badge ai"><span class="dot"></span>Claude${an._meta ? " · " + esc(an._meta.model) : ""}</span>`
    : `<span class="badge offline">Offline analyst</span>`;
  const aiBtn = state.aiEnabled
    ? `<button class="btn small primary" id="btn-ai">${inc.analysis_source === "claude" ? "Re-run" : "Analyse with Claude"}</button>`
    : `<span class="muted" style="text-transform:none;letter-spacing:0">Set ANTHROPIC_API_KEY for Claude</span>`;
  const actions = (an.recommended_actions || []).map((a, i) => `
    <tr class="${done[i] ? "done" : ""}"><td><input type="checkbox" class="check" data-i="${i}" ${done[i] ? "checked" : ""}></td>
    <td><span class="when ${esc(a.priority)}">${esc((a.priority || "").replace("_", " "))}</span></td>
    <td>${cite(a.action)}<div class="owner">${esc(a.owner)} · ${cite(a.rationale)}</div></td></tr>`).join("");
  const kc = TACTICS.map((t) => `<div class="kc ${inc.tactics.includes(t) ? "on" : ""}" title="${esc(t)}">${esc(TACTIC_SHORT[t] || t)}</div>`).join("");
  const entList = (obj, label) => Object.entries(obj || {}).map(([k, v]) => `<div style="margin-bottom:6px"><span class="muted">${esc(k)}s${label}</span><br>${v.slice(0, 12).map((x) => `<span class="chip">${esc(x)}</span>`).join("")}${v.length > 12 ? `<span class="muted"> +${v.length - 12}</span>` : ""}</div>`).join("");
  const ents = entList(inc.entities, "") + entList(inc.related_entities, " — targeted / context only");
  body.innerHTML = `
    <div class="panel"><h3>ATT&amp;CK kill chain — ${inc.tactics.length} of ${TACTICS.length} tactics observed</h3><div class="killchain">${kc}</div></div>
    <div class="grid2">
      <div>
        <div class="panel">
          <h3><span>AI triage ${src}</span>${aiBtn}</h3>
          <div class="summary">${cite(an.executive_summary)}</div>
          <div class="verdict"><span class="chip">${esc(VERDICT[an.verdict] || an.verdict)}</span><span class="muted">confidence: ${esc(an.confidence)}</span></div>
          ${an.injection_attempts_observed ? `<div class="alert-inj">⚠ Telemetry for this incident contained text written to manipulate AI triage. It was neutralised before analysis and is shown in red in the evidence.</div>` : ""}
          ${an.verdict_reasoning ? `<p class="muted" style="font-size:13px">${cite(an.verdict_reasoning)}</p>` : ""}
        </div>
        <div class="panel"><h3>Recommended response</h3><table class="actions">${actions || "<tr><td>No actions.</td></tr>"}</table></div>
        <div class="panel"><h3>Key findings</h3><ul class="clean">${(an.key_findings || []).map((f) => `<li>${cite(f)}</li>`).join("")}</ul></div>
        <div class="panel"><h3>Open questions for the analyst</h3><ul class="clean">${(an.investigation_questions || []).map((f) => `<li>${cite(f)}</li>`).join("")}</ul></div>
        <div class="panel"><details><summary>Technical narrative &amp; attack stage</summary>
          <p><b>Stage:</b> ${cite(an.attack_stage)}</p><div style="white-space:pre-wrap">${cite(an.technical_narrative)}</div></details></div>
      </div>
      <div>
        <div class="panel"><h3>Risk score ${inc.score}/100 · ${inc.priority}</h3>
          ${inc.factors.map((f) => `<div class="factor"><div><b>${esc(f.label)}</b><div class="muted" style="font-size:12px">${esc(f.detail)}</div></div><div class="e">${esc(f.effect)}</div></div>`).join("")}
        </div>
        <div class="panel"><h3>Business impact</h3><div>${cite(an.business_impact)}</div></div>
        <div class="panel"><h3>Techniques</h3>${inc.techniques.map((t) => `<div style="margin-bottom:4px"><span class="chip tech">${esc(t.id)}</span>${esc(t.name)}</div>`).join("")}</div>
        <div class="panel"><h3>Entities</h3>${ents}</div>
      </div>
    </div>`;
  body.querySelectorAll(".check").forEach((c) => (c.onchange = () => { done[c.dataset.i] = c.checked; c.closest("tr").classList.toggle("done", c.checked); }));
  const btn = $("#btn-ai");
  if (btn) btn.onclick = () => runClaude(btn);
}

async function runClaude(btn) {
  const id = state.detail.incident.id;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Claude is analysing…';
  try {
    const data = await (await api(`/api/incidents/${id}/analyze`, { method: "POST" })).json();
    state.detail.incident = data.incident;
    const q = state.incidents.find((i) => i.id === id);
    if (q) { q.analysis_source = "claude"; q.title = data.incident.analysis.title || q.title; }
    renderQueue();
    if (state.current === id) renderDetail();
    toast("Claude analysis complete");
  } catch (e) {
    toast(e.message, true);
    btn.disabled = false; btn.textContent = "Analyse with Claude";
  }
}

function renderEvent(ev) {
  const inj = ev.injection_fields || {};
  const keys = ["ts", "source", "action", "user", "host", "src_ip", "dst_ip", "dst_port", "country", "domain", "url",
    "status", "bytes_out", "sender", "subject", "signature", "technique", "category", "target_user", "group", "user_agent", "message"];
  return keys.filter((k) => ev[k] !== undefined).map((k) => {
    const v = k === "ts" ? ist(ev[k]) : ev[k];
    return inj[k] ? `<span class="inj">${esc(k)}: ${esc(v)}   ⚠ prompt-injection (${esc(inj[k].join(", "))})</span>` : `${esc(k)}: ${esc(v)}`;
  }).join("\n");
}

function renderTimeline(body) {
  const { alerts, evidence } = state.detail;
  const sorted = [...alerts].sort((a, b) => new Date(a.first_seen) - new Date(b.first_seen));
  body.innerHTML = `<div class="tl">${sorted.map((a) => {
    const evs = a.evidence.slice(0, 8).map((id) => evidence[id]).filter(Boolean);
    const ents = Object.entries(a.entities).flatMap(([k, v]) => v.map((x) => `<span class="chip">${esc(k)}: ${esc(x)}</span>`)).join("");
    return `<div class="tl-item" id="t-${esc(a.id)}" style="--sevc:${SEV_COLOR[a.severity]}"><div class="panel">
      <div class="tl-head"><div><span class="tl-title">${esc(a.title)}</span> <span class="chip tech">${esc(a.technique_id)}</span><span class="muted">${esc(a.tactic)}</span></div>
      <div><span class="sev ${a.severity}">${a.severity}</span> <span class="muted mono">${esc(a.id)} · ${ist(a.first_seen)}</span></div></div>
      <div class="tl-desc">${esc(a.description)}</div>
      <div>${ents}</div>
      <details><summary>Evidence: ${a.evidence.length} event(s)${a.evidence.length > 8 ? " (first 8 shown)" : ""} · confidence ${a.confidence}</summary>
        ${evs.map((e) => `<div class="ev">${renderEvent(e)}</div>`).join("")}
        ${Object.keys(a.details || {}).length ? `<div class="ev">${esc(JSON.stringify(a.details, null, 1))}</div>` : ""}
      </details></div></div>`;
  }).join("")}</div>`;
}

function renderGraph(body) {
  const { nodes, edges } = state.detail.graph;
  const W = 900, H = 520;
  const idx = new Map(nodes.map((n, i) => [n.id, i]));
  const pos = nodes.map((_, i) => ({ x: W / 2 + 200 * Math.cos((2 * Math.PI * i) / nodes.length), y: H / 2 + 160 * Math.sin((2 * Math.PI * i) / nodes.length), vx: 0, vy: 0 }));
  const k = Math.sqrt((W * H) / Math.max(nodes.length, 1)) * 0.55;
  for (let it = 0; it < 350; it++) {
    const temp = 18 * (1 - it / 350) + 0.5;
    for (let i = 0; i < pos.length; i++) {
      for (let j = i + 1; j < pos.length; j++) {
        let dx = pos[i].x - pos[j].x, dy = pos[i].y - pos[j].y;
        const d = Math.max(Math.hypot(dx, dy), 0.01), f = (k * k) / d;
        dx /= d; dy /= d;
        pos[i].vx += dx * f; pos[i].vy += dy * f; pos[j].vx -= dx * f; pos[j].vy -= dy * f;
      }
    }
    for (const e of edges) {
      const a = pos[idx.get(e.source)], b = pos[idx.get(e.target)];
      let dx = a.x - b.x, dy = a.y - b.y;
      const d = Math.max(Math.hypot(dx, dy), 0.01), f = (d * d) / k;
      dx /= d; dy /= d;
      a.vx -= dx * f; a.vy -= dy * f; b.vx += dx * f; b.vy += dy * f;
    }
    for (const p of pos) {
      p.vx += (W / 2 - p.x) * 0.02; p.vy += (H / 2 - p.y) * 0.02;
      const v = Math.hypot(p.vx, p.vy) || 1;
      p.x += (p.vx / v) * Math.min(v, temp); p.y += (p.vy / v) * Math.min(v, temp);
      p.x = Math.min(W - 60, Math.max(60, p.x)); p.y = Math.min(H - 30, Math.max(30, p.y));
      p.vx = 0; p.vy = 0;
    }
  }
  const color = (n) => n.kind === "user" ? "#5aa9ff" : n.kind === "host" ? "#2dd4a7" : n.kind === "domain" ? "#ff9f43" : n.external ? "#ff4d5e" : "#8b98a8";
  const lines = edges.map((e) => {
    const a = pos[idx.get(e.source)], b = pos[idx.get(e.target)];
    return `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="#2c3a4d" stroke-width="${1 + Math.min(e.techniques.length, 4)}"><title>${esc(e.techniques.join(", "))}</title></line>`;
  }).join("");
  const circles = nodes.map((n, i) => {
    const p = pos[i], r = 8 + Math.min(n.alerts, 8) * 1.6;
    return `<g><circle cx="${p.x}" cy="${p.y}" r="${r}" fill="${color(n)}" fill-opacity="0.85" ${n.crown_jewel ? 'stroke="#f5d547" stroke-width="3"' : ""}><title>${esc(n.kind)}: ${esc(n.label)} · ${n.alerts} alert(s)</title></circle>
      <text x="${p.x}" y="${p.y + r + 13}" text-anchor="middle" fill="#c6d0db" font-size="11.5" font-family="Inter, sans-serif">${esc(n.label)}</text></g>`;
  }).join("");
  body.innerHTML = `<div class="graph-wrap"><svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Entity relationship graph">${lines}${circles}</svg>
    <div class="legend"><span style="--c:#5aa9ff">user</span><span style="--c:#2dd4a7">host</span><span style="--c:#ff4d5e">external IP</span>
    <span style="--c:#8b98a8">internal IP</span><span style="--c:#ff9f43">domain</span><span class="cj">crown-jewel asset</span>
    <span class="muted" style="--c:transparent">edge = entities seen together in an alert (hover for techniques)</span></div></div>`;
}

function renderCompliance(body) {
  const { incident: inc } = state.detail;
  const reg = inc.regulatory || {};
  body.innerHTML = `
    <div class="grid2">
      <div>
        <div class="panel"><h3>Obligations triggered</h3>
          ${(reg.obligations || []).map((o) => `<div class="ob"><div><div class="r">${esc(o.regime)}</div><div class="muted">${esc(o.action)}</div></div>
            <div class="d">${o.deadline ? `${ist(o.deadline)}<br><span data-deadline="${esc(o.deadline)}"></span>` : "as soon as practicable"}<br><span class="chip">${esc(o.required)}</span></div></div>`).join("") || '<div class="muted">No reporting obligations identified for this incident.</div>'}
        </div>
        <div class="panel"><h3>CERT-In categories (Annexure I)</h3>
          <ul class="clean">${(reg.certin_types || []).map((t) => `<li>${esc(t)}</li>`).join("") || "<li class='muted'>None</li>"}</ul></div>
        <div class="panel"><h3>DPDP Act — personal data</h3>
          <div>${reg.personal_data_at_risk ? `<b style="color:var(--p1)">Personal data likely at risk</b> on ${esc((reg.personal_data_systems || []).join(", "))}.` : "No personal-data systems with exfiltration/impact indicators."}</div></div>
      </div>
      <div>
        <div class="panel"><h3>Drafts ready for review</h3>
          <p class="muted" style="margin-top:0">Generated from the correlated evidence${inc.analysis_source === "claude" ? " and Claude's analysis" : ""}. Verify before submission — not legal advice.</p>
          <div style="display:flex;flex-direction:column;gap:8px">
            <button class="btn" onclick="openReport('certin')">📄 CERT-In incident report</button>
            <button class="btn" onclick="openReport('insurer')">🛡 Cyber-insurance notification</button>
            <button class="btn" onclick="openIocs()">🧷 IOC export (JSON)</button>
          </div></div>
      </div>
    </div>`;
  tickClocks();
}

function renderAsk(body) {
  const id = state.detail.incident.id;
  const msgs = state.chat[id] || (state.chat[id] = []);
  body.innerHTML = `
    <div class="panel chat">
      <h3>Ask AssureSOC about ${esc(id)} <span class="muted" style="text-transform:none;letter-spacing:0">${state.aiEnabled ? "answers grounded in this incident's evidence" : "offline mode — set ANTHROPIC_API_KEY for Claude"}</span></h3>
      <div class="msgs" id="msgs">${msgs.map((m) => `<div class="msg ${m.role}">${m.role === "assistant" ? cite(m.content) : esc(m.content)}</div>`).join("")}</div>
      <div class="suggest">${SUGGESTIONS.map((s) => `<button data-q="${esc(s)}">${esc(s)}</button>`).join("")}</div>
      <form class="chat-input" id="chat-form"><input id="chat-q" placeholder="e.g. Is adm.rahul's account still compromised?" autocomplete="off"><button class="btn primary">Ask</button></form>
    </div>`;
  body.querySelectorAll(".suggest button").forEach((b) => (b.onclick = () => ask(b.dataset.q)));
  $("#chat-form").onsubmit = (e) => { e.preventDefault(); const q = $("#chat-q").value.trim(); if (q) ask(q); };
  const box = $("#msgs"); box.scrollTop = box.scrollHeight;
}

async function ask(question) {
  const id = state.detail.incident.id;
  const msgs = state.chat[id];
  const history = msgs.slice();
  msgs.push({ role: "user", content: question });
  const box = $("#msgs");
  box.insertAdjacentHTML("beforeend", `<div class="msg user">${esc(question)}</div><div class="msg assistant"><span class="spinner"></span></div>`);
  $("#chat-q").value = "";
  const out = box.lastElementChild;
  box.scrollTop = box.scrollHeight;
  let text = "";
  try {
    const res = await api(`/api/incidents/${id}/ask`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ question, history }) });
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      text += dec.decode(value, { stream: true });
      out.textContent = text;
      box.scrollTop = box.scrollHeight;
    }
    out.innerHTML = cite(text);
    msgs.push({ role: "assistant", content: text });
  } catch (e) {
    out.textContent = "Error: " + e.message;
    msgs.pop();
  }
}

// ---------- reports ----------
async function openReport(kind) {
  const id = state.detail.incident.id;
  try {
    const text = await (await api(`/api/incidents/${id}/report/${kind}`)).text();
    showModal(kind === "certin" ? `CERT-In report draft · ${id}` : `Insurer notification draft · ${id}`, mdToHtml(text), text, `${id}-${kind}.md`);
  } catch (e) { toast(e.message, true); }
}

async function openIocs() {
  const id = state.detail.incident.id;
  const data = await (await api(`/api/incidents/${id}/iocs`)).json();
  const text = JSON.stringify(data, null, 2);
  showModal(`Indicators of compromise · ${id}`, `<pre class="ev">${esc(text)}</pre>`, text, `${id}-iocs.json`);
}

function showModal(title, html, raw, filename) {
  $("#modal-title").textContent = title;
  $("#modal-body").innerHTML = html;
  $("#modal-copy").onclick = async () => { await navigator.clipboard.writeText(raw); toast("Copied to clipboard"); };
  const dl = $("#modal-download");
  URL.revokeObjectURL(dl.href);
  dl.href = URL.createObjectURL(new Blob([raw], { type: "text/plain" }));
  dl.download = filename;
  dl.textContent = "Download " + filename.split(".").pop();
  $("#modal").classList.remove("hidden");
}
function closeModal() { $("#modal").classList.add("hidden"); }

// ---------- clocks & wiring ----------
function tickClocks() {
  document.querySelectorAll("[data-deadline]").forEach((el) => {
    const c = countdown(el.dataset.deadline);
    el.textContent = el.classList.contains("t") ? (c.overdue ? c.text : `due in ${c.text}`) : (c.overdue ? c.text : `${c.text} left`);
  });
}
setInterval(tickClocks, 1000);

document.addEventListener("click", (e) => {
  const card = e.target.closest(".card[data-id]");
  if (card) { selectIncident(card.dataset.id); return; }
  const tab = e.target.closest(".tab[data-tab]");
  if (tab) { state.tab = tab.dataset.tab; renderTab(); return; }
  const c = e.target.closest("[data-cite]");
  if (c) {
    state.tab = "timeline"; renderTab();
    const el = document.getElementById("t-" + c.dataset.cite);
    if (el) { el.scrollIntoView({ behavior: "smooth", block: "center" }); el.classList.add("flash"); el.querySelector("details")?.setAttribute("open", ""); setTimeout(() => el.classList.remove("flash"), 2200); }
    return;
  }
  if (e.target.id === "modal") closeModal();
});
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModal(); });
$("#btn-demo").onclick = loadDemo;
$("#file-input").onchange = (e) => { uploadFiles(e.target.files); e.target.value = ""; };

init().catch((e) => toast(e.message, true));
