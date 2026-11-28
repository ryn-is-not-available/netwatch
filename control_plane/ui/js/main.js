import { $, esc, toast } from "./util.js";
import { api, login, logout, post, patch, setUnauthorizedHandler } from "./api.js";
import { initGraph, renderGraph, traced } from "./graph.js";
import { initPanels, renderPanels, handlers, selectNode } from "./panels.js";

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
  me = null;
  $("who").hidden = $("logoutBtn").hidden = true;
  $("loginErr").textContent = message;
  $("loginErr").hidden = !message;
  const dlg = $("loginDlg");
  if (!dlg.open) dlg.showModal();
  $("loginUser").focus();
}
async function startSession() {
  try {
    me = await api("/auth/me");
  } catch {
    return showLogin();
  }
  showUser(); gate(); await refresh();
}
async function refresh() {
  if (busy || !me) return; busy = true;
  try {
    const h = await api("/health");
    $("leader").textContent = `${h.instance_id} · ${h.is_leader ? "leader" : "standby"} · epoch ${h.leader_epoch}`;
    $("leader").className = "pill " + (h.is_leader ? "ok" : "warn");
    // History: `at` picks the moment; "as known then" also sets known_at, showing what NetWatch
    // believed at that moment instead of today's corrected view of it (bitemporal history).
    const url = !live && at
      ? `/topology?at=${encodeURIComponent(at)}${$("knownThen").checked ? `&known_at=${encodeURIComponent(at)}` : ""}`
      : "/topology";
    const [topo, alerts, recs, audit] = await Promise.all([api(url), api("/alerts"), api("/recommendations"), api("/audit")]);
    fillSelects(topo.nodes || []); renderGraph(topo);
    renderPanels({
      drift: topo.drift || [], recs, alerts, audit,
      nodes: topo.nodes || [], declared: topo.declared_links || [], observed: topo.observed_links || [],
    }, me.role, me.username);
  } catch (e) { toast(`Refresh failed: ${e.message}`, true); }
  finally { busy = false; }
}
async function guard(fn, okMsg) {
  try { await fn(); if (okMsg) toast(okMsg); await refresh(); } catch (e) { toast(e.message, true); }
}
const agoLabel = mins => (mins < 90 ? `${mins} min ago` : `${Math.floor(mins / 60)} h ${mins % 60 ? `${mins % 60} min ` : ""}ago`);
function setLive(v, offset = 0) {
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
$("aiBtn").onclick = async () => {
  const b = $("aiBtn");
  b.disabled = true; b.textContent = "Diagnosing…";
  try {
    const r = await post("/ai/diagnose");
    const dropped = r.verification_notes.length ? ` · ${r.verification_notes.length} dropped or adjusted by verification` : "";
    toast(`${r.summary} (${r.recommendations_created} new fix${r.recommendations_created === 1 ? "" : "es"}${dropped})`);
    document.querySelector('[data-tab="recs"]').click();
    await refresh();
  } catch (e) { toast(`AI diagnosis: ${e.message}`, true); }
  finally { b.textContent = "AI diagnose"; gate(); }
};
$("diagBtn").onclick = () => guard(async () => { const r = await post("/diagnose"); toast(`${r.recommendations_created} fixes generated`); });
$("slider").oninput = e => +e.target.value === 0 ? setLive(true) : setLive(false, +e.target.value);
$("histRange").onchange = e => {
  const range = +e.target.value;
  Object.assign($("slider"), { min: -range, step: Math.max(1, Math.round(range / 60)) });
  setLive(true);
};
$("knownThen").onchange = () => { if (!live) refresh(); };
$("liveBtn").onclick = () => setLive(true);
$("loginForm").onsubmit = async e => {
  e.preventDefault();
  try {
    await login($("loginUser").value.trim(), $("loginPass").value);
    $("loginPass").value = "";
    $("loginDlg").close();
    await startSession();
  } catch (err) { showLogin(err.message); }
};
$("loginDlg").addEventListener("cancel", e => e.preventDefault()); // signing in is required
$("logoutBtn").onclick = () => { logout(); showLogin(); };
setUnauthorizedHandler(() => showLogin("Your session expired. Please sign in again."));
document.addEventListener("visibilitychange", () => { if (!document.hidden && live) refresh(); });
setInterval(() => { if (live && !document.hidden) refresh(); }, 3000);
startSession();
