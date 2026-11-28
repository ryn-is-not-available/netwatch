import { $, esc, toast } from "./util.js";
import { api, login, post, patch } from "./api.js";
import { initGraph, renderGraph, traced, nodeCard } from "./graph.js";
import { initPanels, renderPanels, handlers } from "./panels.js";

let live = true, at = null, busy = false;

function fillSelects(nodes) {
  const ids = nodes.map(n => n.node_id);
  [["src", 0], ["dst", ids.length - 1], ["revokeSel", 0]].forEach(([id, def]) => {
    const s = $(id), prev = s.value;
    if ([...s.options].map(o => o.value).join() === ids.join()) return;
    s.innerHTML = ids.map(i => `<option>${esc(i)}</option>`).join("");
    s.value = ids.includes(prev) ? prev : ids[Math.max(def, 0)] ?? "";
  });
}
function gate() {
  const r = $("role").value;
  $("diagBtn").disabled = $("traceBtn").disabled = r === "viewer";
  $("revokeBtn").disabled = r !== "admin";
}
async function refresh() {
  if (busy) return; busy = true;
  try {
    const h = await api("/health");
    $("leader").textContent = `${h.instance_id} · ${h.is_leader ? "leader" : "standby"} · epoch ${h.leader_epoch}`;
    $("leader").className = "pill " + (h.is_leader ? "ok" : "warn");
    const url = !live && at ? `/topology?at=${encodeURIComponent(at)}&known_at=${encodeURIComponent(at)}` : "/topology";
    const [topo, alerts, recs, audit] = await Promise.all([api(url), api("/alerts"), api("/recommendations"), api("/audit")]);
    fillSelects(topo.nodes || []); renderGraph(topo);
    renderPanels({ drift: topo.drift || [], recs, alerts, audit }, $("role").value !== "viewer");
  } catch (e) { toast(`Refresh failed: ${e.message}`, true); }
  finally { busy = false; }
}
async function guard(fn, okMsg) {
  try { await fn(); if (okMsg) toast(okMsg); await refresh(); } catch (e) { toast(e.message, true); }
}
function setLive(v, offset = 0) {
  live = v; at = v ? null : new Date(Date.now() + offset * 6e4).toISOString();
  $("slider").value = offset;
  $("timeLabel").textContent = v ? "Now" : `${-offset} min ago`;
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

initGraph(d => { const i = $("inspector"); i.hidden = !d; if (d) i.innerHTML = nodeCard(d); });
initPanels();
handlers.patchRec = (id, s) => guard(() => patch(`/recommendations/${id}`, { status: s }), s === "applied" ? "Fix applied" : "Fix dismissed");
$("traceBtn").onclick = trace;
$("diagBtn").onclick = () => guard(async () => { const r = await post("/diagnose"); toast(`${r.recommendations_created} fixes generated`); });
$("revokeBtn").onclick = () => { const n = $("revokeSel").value; if (n && confirm(`Revoke ${n}? It will be cut off from the mesh.`)) guard(() => post(`/nodes/${n}/revoke`), `${n} revoked`); };
$("slider").oninput = e => +e.target.value === 0 ? setLive(true) : setLive(false, +e.target.value);
$("liveBtn").onclick = () => setLive(true);
$("role").onchange = () => guard(async () => { await login($("role").value); gate(); });
document.addEventListener("visibilitychange", () => { if (!document.hidden && live) refresh(); });
setInterval(() => { if (live && !document.hidden) refresh(); }, 3000);
(async () => { try { await login("admin"); gate(); await refresh(); } catch (e) { toast(`Login failed: ${e.message}`, true); } })();
