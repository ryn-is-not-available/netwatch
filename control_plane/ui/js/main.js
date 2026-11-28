import { $, esc, toast } from "./util.js";
import { api, logout, post, patch, setUnauthorizedHandler } from "./api.js";
import { initGraph, renderGraph, traced } from "./graph.js";
import { initPanels, renderPanels, handlers, selectNode, showTab } from "./panels.js";

let lastOk = 0, failing = false;
let live = true, at = null, busy = false, me = null; // me = {username, role} once signed in

function fillSelects(nodes) {
  const ids = nodes.map(n => n.node_id);
  [["src", 0], ["dst", ids.length - 1]].forEach(([id, def]) => {
    const s = $(id), prev = s.value;
    if ([...s.options].map(o => o.value).join() === ids.join()) return;
    s.innerHTML = ids.map(i => `<option>${esc(i)}</option>`).join("");
    s.value = ids.includes(prev) ? prev : ids[Math.max(def, 0)] ?? "";
  });
}
function gate() {
  const r = me?.role ?? "viewer";
  $("diagBtn").disabled = $("traceBtn").disabled = $("aiBtn").disabled = r === "viewer";
}
function showUser() {
  $("who").textContent = `${me.username} · ${me.role}`;
  $("who").hidden = $("logoutBtn").hidden = false;
}
function showLogin(message = "") {
  // Sign-in lives on its own page; nothing of the console stays visible when signed out.
  location.replace(message ? "/login?expired=1" : "/login");
}
async function startSession() {
  try {
    me = await api("/auth/me");
  } catch {
    return showLogin();
  }
  document.body.classList.add("authed");
  showUser(); gate(); await refresh();
}
async function refresh() {
  if (busy || !me) return; busy = true;
  try {
    const h = await api("/health");
    $("leader").textContent = `via ${h.instance_id} (${h.is_leader ? "leader" : "standby · writes forwarded to the leader"})`;
    // History: `at` picks the moment; "as known then" also sets known_at, showing what NetWatch
    // believed at that moment instead of today's corrected view of it (bitemporal history).
    const url = !live && at
      ? `/topology?at=${encodeURIComponent(at)}${$("knownThen").checked ? `&known_at=${encodeURIComponent(at)}` : ""}`
      : "/topology";
    const [topo, alerts, recs, audit] = await Promise.all([api(url), api("/alerts"), api("/recommendations"), api("/audit")]);
    fillSelects(topo.nodes || []); renderGraph(topo); renderSummary(topo, alerts, recs);
    lastOk = Date.now(); failing = false;
    renderPanels({
      drift: topo.drift || [], recs, alerts, audit,
      nodes: topo.nodes || [], declared: topo.declared_links || [], observed: topo.observed_links || [],
    }, me.role, me.username);
  } catch (e) {
    if (!failing) toast(`Lost contact with the control plane: ${e.message}`, true); // once, not every 3 s
    failing = true;
    $("overall").textContent = "Connection problem"; $("overall").className = "status-badge bad";
  }
  finally { busy = false; }
}
async function guard(fn, okMsg) {
  try { await fn(); if (okMsg) toast(okMsg); await refresh(); } catch (e) { toast(e.message, true); }
}
const agoLabel = mins => (mins < 90 ? `${mins} min ago` : `${Math.floor(mins / 60)} h ${mins % 60 ? `${mins % 60} min ` : ""}ago`);
function renderSummary(topo, alerts, recs) {
  const nodes = topo.nodes || [], links = topo.observed_links || [];
  const healthy = nodes.filter(n => n.health_status === "healthy").length;
  const down = nodes.filter(n => ["offline", "revoked"].includes(n.health_status)).length;
  const linksUp = links.filter(l => l.status === "up").length;
  const open = alerts.filter(a => a.status !== "resolved");
  const critical = open.filter(a => a.severity === "critical").length;
  const drift = (topo.drift || []).length, pending = recs.filter(r => r.status === "pending").length;
  const issues = (nodes.length - healthy) + (links.length - linksUp) + open.length + drift;
  const level = down || critical ? "bad" : issues ? "warn" : "ok";
  const text = level === "ok" ? "All systems normal" : `${issues} issue${issues === 1 ? " needs" : "s need"} attention`;
  $("overall").textContent = live ? text : `${text} (history)`;
  $("overall").className = `status-badge ${level}`;
  const tile = (label, value, total, state, tab, help) => {
    const tag = tab ? "button" : "div";
    return `<${tag} class="tile ${state}" ${tab ? `data-tab-target="${tab}"` : ""} title="${help}"><span class="tile-value">${value}${total === null ? "" : `<small>/${total}</small>`}</span><span class="tile-label">${label}</span></${tag}>`;
  };
  $("summary").innerHTML =
    tile("nodes healthy", healthy, nodes.length, healthy === nodes.length ? "ok" : down ? "bad" : "warn", null, "Nodes whose heartbeats arrive on time")
    + tile("links up", linksUp, links.length, linksUp === links.length ? "ok" : "warn", null, "Observed node-to-node links without packet loss")
    + tile("open alerts", open.length, null, critical ? "bad" : open.length ? "warn" : "ok", "alerts", "Alerts that are not resolved yet. Click to see them")
    + tile("drift", drift, null, drift ? "warn" : "ok", "drift", "Differences between the declared topology and what probes observe. Click to see them")
    + tile("fixes to review", pending, null, pending ? "warn" : "ok", "recs", "Suggested fixes waiting for your decision. Click to see them")
    + `<span class="updated" id="updated"></span>`;
}
function tickUpdated() {
  const el = $("updated");
  if (!el || !lastOk) return;
  const secs = Math.round((Date.now() - lastOk) / 1000);
  el.textContent = live ? (secs < 5 ? "Live · updated just now" : `Live · updated ${secs}s ago`) : "Viewing history";
  el.className = `updated${live && secs > 15 ? " stale" : ""}`;
}
function setLive(v, offset = 0) {
  $("liveBtn").hidden = v;
  live = v; at = v ? null : new Date(Date.now() + offset * 6e4).toISOString();
  $("slider").value = offset;
  $("timeLabel").textContent = v ? "Now" : agoLabel(-offset);
  $("mode").textContent = v ? "Live" : "History"; $("mode").className = "pill " + (v ? "live" : "warn");
  refresh();
}
async function trace() {
  const src = $("src").value, dst = $("dst").value, st = $("traceState"), body = $("traceBody");
  if (src === dst) return toast("Choose two different nodes.", true);
  try {
    st.textContent = "pending"; st.className = "pill warn"; body.textContent = `Tracing ${src} → ${dst}…`;
    const { trace_id } = await post("/paths/trace", { src_node_id: src, dst_node_id: dst });
    for (let i = 0; i < 16; i++) {
      await new Promise(r => setTimeout(r, 1000));
      const r = await api(`/paths/trace/${trace_id}`);
      st.textContent = r.status.toLowerCase();
      if (r.status === "DONE" || r.status === "TIMEOUT") {
        traced.clear(); let prev = src;
        (r.hops || []).forEach(h => { if (h.node_id && h.node_id !== prev) { traced.add(`${prev}->${h.node_id}`); prev = h.node_id; } });
        st.className = "pill " + (r.status === "DONE" ? "ok" : "bad");
        const path = [src, ...(r.hops || []).map(h => h.node_id).filter(Boolean)];
        body.innerHTML = `Avg RTT <b>${esc(r.avg_latency_ms ?? "n/a")} ms</b> · Loss <b>${esc(r.packet_loss_pct ?? "n/a")}%</b><div class="hops">${path.map(p => `<span>${esc(p)}</span>`).join("→")}</div>`;
        return refresh();
      }
    }
    throw new Error("Trace did not finish in 16 s.");
  } catch (e) { st.textContent = "error"; st.className = "pill bad"; body.textContent = e.message; toast(`Trace failed: ${e.message}`, true); }
}

initGraph(d => { if (d) selectNode(d.node_id); });
initPanels();
handlers.refresh = refresh;
$("traceBtn").onclick = trace;
// AI diagnosis result window: non-modal (the map stays usable), stays open until closed.
const SEV = { critical: "bad", warning: "warn", info: "" };
const ACTION_TEXT = { declare_link: a => `Declare link ${a.src} → ${a.dst}`, run_trace: a => `Run trace ${a.src} → ${a.dst}`, none: () => "No automatic action" };
function openAiWindow(meta, bodyHtml, { retry = false, fixes = false } = {}) {
  $("aiDlgMeta").textContent = meta;
  $("aiDlgBody").innerHTML = bodyHtml;
  $("aiDlgRetry").hidden = !retry;
  $("aiDlgFixes").hidden = !fixes;
  if (!$("aiDlg").open) $("aiDlg").show();
}
function renderAiResult(r, secs) {
  const items = r.items || [];
  const meta = `${r.model} · ${secs}s · ${r.recommendations_created} new fix${r.recommendations_created === 1 ? "" : "es"} added`;
  const findings = items.length ? items.map(f => `<article class="ai-finding">
      <div><span class="pill ${SEV[f.severity] ?? ""}">${esc(f.severity)}</span> <b>${esc(f.title)}</b></div>
      <p>${esc(f.explanation)}</p>
      ${f.suggested_fix ? `<p class="ai-fix"><b>Suggested fix:</b> ${esc(f.suggested_fix)}</p>` : ""}
      <p class="ai-action">${esc((ACTION_TEXT[f.action?.type] || ACTION_TEXT.none)(f.action || {}))}</p>
      <details><summary>Evidence (${f.citations.length})</summary><p class="mono">${f.citations.map(esc).join("<br>")}</p></details>
    </article>`).join("") : `<p class="ai-ok">No problems found in the current evidence.</p>`;
  const notes = r.verification_notes?.length
    ? `<details class="ai-notes"><summary>${r.verification_notes.length} finding(s) dropped or adjusted by verification</summary><ul>${r.verification_notes.map(n => `<li>${esc(n)}</li>`).join("")}</ul></details>` : "";
  openAiWindow(meta, `<p class="ai-summary">${esc(r.summary)}</p>${findings}${notes}`, { fixes: r.recommendations_created > 0 });
}
async function runAiDiagnosis() {
  const b = $("aiBtn"), started = Date.now();
  b.disabled = true; b.textContent = "Diagnosing…";
  openAiWindow("Working…", `<p class="ai-wait"><span class="spinner" aria-hidden="true"></span>Asking the model about the current network state. This usually takes a few seconds.</p>`);
  try {
    const r = await post("/ai/diagnose");
    renderAiResult(r, ((Date.now() - started) / 1000).toFixed(1));
    await refresh();
  } catch (e) {
    openAiWindow("Diagnosis failed", `<p class="ai-err">${esc(e.message)}</p>`, { retry: true });
  } finally { b.textContent = "AI diagnose"; gate(); }
}
$("aiBtn").onclick = runAiDiagnosis;
$("aiDlgRetry").onclick = runAiDiagnosis;
$("aiDlgClose").onclick = $("aiDlgOk").onclick = () => $("aiDlg").close();
$("aiDlgFixes").onclick = () => { showTab("recs"); $("aiDlg").close(); };
document.addEventListener("keydown", e => { if (e.key === "Escape" && $("aiDlg").open) $("aiDlg").close(); });
$("diagBtn").onclick = () => guard(async () => { const r = await post("/diagnose"); toast(`${r.recommendations_created} fixes generated`); });
$("slider").oninput = e => +e.target.value === 0 ? setLive(true) : setLive(false, +e.target.value);
$("histRange").onchange = e => {
  const range = +e.target.value;
  Object.assign($("slider"), { min: -range, step: Math.max(1, Math.round(range / 60)) });
  setLive(true);
};
$("knownThen").onchange = () => { if (!live) refresh(); };
$("liveBtn").onclick = () => setLive(true);
$("logoutBtn").onclick = () => { logout(); showLogin(); };
setUnauthorizedHandler(() => showLogin("Your session expired. Please sign in again."));
document.addEventListener("visibilitychange", () => { if (!document.hidden && live) refresh(); });
setInterval(() => { if (live && !document.hidden) refresh(); }, 3000);
setInterval(tickUpdated, 1000);
$("summary").onclick = e => { const t = e.target.closest("[data-tab-target]"); if (t) showTab(t.dataset.tabTarget); };
startSession();
