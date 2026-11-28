import { $, esc } from "./util.js";
export const handlers = { patchRec: null };
let data = { drift: [], recs: [], alerts: [], audit: [] }, tab = "drift", canAct = true;
const empty = t => `<div class="item muted">${t}</div>`;
const dis = () => canAct ? "" : "disabled";
const views = {
  drift: () => data.drift.length ? data.drift.map(d => `<div class="item"><b>${esc(d.src_node_id)} → ${esc(d.dst_node_id)}</b> <span class="pill bad">${esc(d.drift_type)}</span><div class="mono">${esc(d.details)}</div></div>`).join("") : empty("Observed links match the declared topology."),
  recs: () => data.recs.length ? data.recs.map(r => `<div class="item"><b>${esc(r.diagnosis)}</b><div class="muted">${esc(r.suggested_fix)}</div><div class="mono">${esc(r.status)}</div>${r.status === "pending" ? `<div class="row"><button class="primary" data-rec="${esc(r.recommendation_id)}" data-s="applied" ${dis()}>Apply fix</button><button data-rec="${esc(r.recommendation_id)}" data-s="dismissed" ${dis()}>Dismiss</button></div>` : ""}</div>`).join("") : empty("No fixes yet. Run Diagnose drift to generate them."),
  alerts: () => data.alerts.length ? data.alerts.slice(0, 20).map(a => `<div class="item"><span class="pill ${a.severity === "critical" ? "bad" : "warn"}">${esc(a.status)}</span> <b>${esc(a.affected_node_id || "mesh")}</b><div class="muted">${esc(a.message)}</div></div>`).join("") : empty("No active alerts."),
  audit: () => data.audit.length ? data.audit.slice(0, 20).map(u => `<div class="item"><b>${esc(u.action_type)}</b><div class="mono">${esc(u.actor_id)} → ${esc(u.target_entity)}</div></div>`).join("") : empty("No audit entries."),
};
export function renderPanels(d, act) {
  data = d; canAct = act;
  ["drift", "recs", "alerts"].forEach(k => $(`n-${k}`).textContent = d[k].length);
  $("panel").innerHTML = views[tab]();
}
export function initPanels() {
  document.querySelector(".tabs").onclick = e => {
    const b = e.target.closest("[data-tab]"); if (!b) return;
    tab = b.dataset.tab;
    document.querySelectorAll(".tabs button").forEach(x => x.setAttribute("aria-selected", x === b));
    $("panel").innerHTML = views[tab]();
  };
  $("panel").onclick = e => { const b = e.target.closest("[data-rec]"); if (b) handlers.patchRec(b.dataset.rec, b.dataset.s); };
}
