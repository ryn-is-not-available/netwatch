import { esc, num, $ } from "./util.js";
let cy; export const traced = new Set();
const C = { ok: "#3fb68b", warn: "#e9b44c", bad: "#ef6a5b", ink: "#e6eef5", mute: "#8ba3b8", acc: "#5ab0ff" };
const edge = (color, extra = {}) => ({ width: 2, "line-color": color, "target-arrow-color": color, "target-arrow-shape": "triangle", "curve-style": "bezier", label: "data(label)", "font-size": 9, color, "text-background-color": "#0f1b26", "text-background-opacity": .85, "text-background-padding": 2, ...extra });

export function initGraph(onSelect) {
  cy = cytoscape({
    container: $("cy"), wheelSensitivity: .3,
    style: [
      { selector: "node", style: { label: "data(id)", "text-valign": "bottom", "text-margin-y": 6, "font-size": 12, "font-weight": 500, color: C.ink, "background-color": C.ok, width: 30, height: 30, "border-width": 3, "border-color": "#0f1b26", "text-outline-width": 2, "text-outline-color": "#0f1b26" } },
      { selector: 'node[status="degraded"]', style: { "background-color": C.warn } },
      { selector: 'node[status="offline"],node[status="revoked"]', style: { "background-color": C.bad } },
      { selector: "node:selected", style: { "border-color": C.acc } },
      { selector: "edge.declared", style: edge(C.mute, { "line-style": "dashed" }) },
      { selector: "edge.observed", style: edge(C.ink, { width: 2.5 }) },
      { selector: "edge.drift", style: edge(C.bad, { width: 4, "font-weight": 600 }) },
      { selector: "edge.traced", style: { width: 5, "line-color": C.acc, "target-arrow-color": C.acc } },
    ],
  });
  cy.on("tap", "node", e => onSelect(e.target.data()));
  cy.on("tap", e => { if (e.target === cy) onSelect(null); });
  $("fit").onclick = () => cy.fit(undefined, 50);
  $("relayout").onclick = () => layout();
}
const layout = () => cy.layout({ name: cy.nodes().length > 8 ? "cose" : "circle", padding: 55, animate: false }).run();

export function renderGraph(topo) {
  const nodes = topo.nodes || [], ids = new Set(nodes.map(n => n.node_id));
  const drift = new Map((topo.drift || []).map(d => [`${d.src_node_id}->${d.dst_node_id}`, d]));
  const els = [], seen = new Set();
  nodes.forEach(n => { if (!seen.has(n.node_id)) { seen.add(n.node_id); els.push({ data: { ...n, id: n.node_id, status: n.health_status } }); } });
  const add = (id, s, t, label, cls) => { if (ids.has(s) && ids.has(t) && !seen.has(id)) { seen.add(id); els.push({ data: { id, source: s, target: t, label }, classes: cls }); } };
  const obs = new Set();
  (topo.observed_links || []).forEach(l => {
    const k = `${l.src_node_id}->${l.dst_node_id}`, d = drift.get(k); obs.add(k);
    add(`obs-${k}`, l.src_node_id, l.dst_node_id, d ? `${d.drift_type} · ${num(l.packet_loss_pct)}% loss` : `${num(l.latency_ms, 2)} ms`, (d ? "drift" : "observed") + (traced.has(k) ? " traced" : ""));
  });
  (topo.declared_links || []).forEach(l => {
    const k = `${l.src_node_id}->${l.dst_node_id}`, miss = drift.get(k)?.drift_type === "missing_declared";
    if (!obs.has(k) || miss) add(`dec-${k}`, l.src_node_id, l.dst_node_id, miss ? "missing declared" : `cost ${l.admin_cost}`, miss ? "drift" : "declared");
  });
  const pos = {}; cy.nodes().forEach(n => pos[n.id()] = { ...n.position() });
  const sel = cy.$(":selected").map(n => n.id());
  let fresh = false;
  cy.batch(() => {
    cy.elements().remove(); cy.add(els);
    cy.nodes().forEach(n => { pos[n.id()] ? n.position(pos[n.id()]) : (fresh = true); });
    sel.forEach(id => cy.getElementById(id).select());
  });
  if (fresh) layout();
  $("empty").hidden = nodes.length > 0;
}
export function nodeCard(d) {
  const rows = Object.entries(d).filter(([k, v]) => !["id", "status", "node_id", "health_status"].includes(k) && typeof v !== "object").slice(0, 6);
  return `<h3>${esc(d.id)} <span class="pill ${d.status === "healthy" ? "ok" : d.status === "degraded" ? "warn" : "bad"}">${esc(d.status)}</span></h3><dl>${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl>`;
}
