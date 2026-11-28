import { esc, num, $ } from "./util.js";

// One edge per node pair (both directions merged), coloured by the pair's worst state.
// Numbers live in a hover card instead of permanent labels, so the graph stays readable.
let cy;
export const traced = new Set(); // "a->b" keys of the last traced path
const C = { ok: "#3fb68b", warn: "#e9b44c", bad: "#ef6a5b", ink: "#e6eef5", mute: "#8ba3b8", line: "#5d7a96", acc: "#5ab0ff", panel: "#16283a" };
const STATE_LABEL = { ok: "Healthy", degraded: "Degraded", missing: "Missing (declared but not seen)", undeclared: "Not in the declared topology" };

export function initGraph(onSelect) {
  cy = cytoscape({
    container: $("cy"), wheelSensitivity: 0.3, minZoom: 0.4, maxZoom: 2.5,
    style: [
      { selector: "node", style: {
        label: "data(id)", "text-valign": "bottom", "text-margin-y": 8, "font-size": 13, "font-weight": 600,
        color: C.ink, "text-background-color": C.panel, "text-background-opacity": 0.9, "text-background-padding": 3,
        "text-background-shape": "roundrectangle", "background-color": C.ok, width: 34, height: 34,
        "border-width": 3, "border-color": "#0f1b26" } },
      { selector: 'node[status="degraded"],node[status="enrolled"]', style: { "background-color": C.warn } },
      { selector: 'node[status="offline"],node[status="revoked"]', style: { "background-color": C.bad } },
      { selector: "node:selected", style: { "border-color": C.acc, "border-width": 4 } },
      { selector: "edge", style: { width: 2, "line-color": C.line, "curve-style": "straight", opacity: 0.85 } },
      { selector: "edge.degraded", style: { "line-color": C.warn, width: 3.5, opacity: 1 } },
      { selector: "edge.missing", style: { "line-color": C.bad, "line-style": "dashed", width: 3, opacity: 1 } },
      { selector: "edge.undeclared", style: { "line-style": "dashed", "line-color": C.mute, opacity: 0.6 } },
      { selector: "edge.traced", style: { "line-color": C.acc, width: 5, opacity: 1, "z-index": 10 } },
      { selector: "edge:active, edge.hover", style: { width: 5, opacity: 1, "overlay-opacity": 0 } },
    ],
  });
  cy.on("tap", "node", e => onSelect(e.target.data()));
  cy.on("tap", e => { if (e.target === cy) onSelect(null); });
  cy.on("mouseover", "edge", e => showTip(e.target, e.renderedPosition));
  cy.on("mouseout", "edge", hideTip);
  cy.on("pan zoom", hideTip);
  cy.on("mouseover", "node", () => ($("cy").style.cursor = "pointer"));
  cy.on("mouseout", "node", () => ($("cy").style.cursor = ""));
  $("fit").onclick = () => cy.fit(undefined, 50);
  $("relayout").onclick = () => layout();
}
const layout = () => cy.layout({ name: cy.nodes().length > 8 ? "cose" : "circle", padding: 60, animate: false }).run();

function showTip(edge, pos) {
  edge.addClass("hover");
  const d = edge.data(), tip = $("edgeTip");
  const dir = (from, to, l) => l
    ? `<div class="tip-dir"><b>${esc(from)} → ${esc(to)}</b><span>${num(l.latency_ms, 2)} ms · ${num(l.packet_loss_pct)}% loss · ${esc(l.status)}</span></div>`
    : `<div class="tip-dir"><b>${esc(from)} → ${esc(to)}</b><span class="muted">not observed</span></div>`;
  tip.innerHTML = `<div class="tip-state ${d.state}">${esc(STATE_LABEL[d.state] || d.state)}</div>`
    + dir(d.a, d.b, d.ab) + dir(d.b, d.a, d.ba)
    + (d.notes.length ? `<div class="tip-notes">${d.notes.map(esc).join("<br>")}</div>` : "");
  tip.hidden = false;
  tip.style.left = `${Math.min(pos.x + 14, $("cy").clientWidth - tip.offsetWidth - 8)}px`;
  tip.style.top = `${Math.max(8, pos.y - tip.offsetHeight - 10)}px`;
}
function hideTip() { cy?.edges(".hover").removeClass("hover"); $("edgeTip").hidden = true; }

export function renderGraph(topo) {
  const nodes = topo.nodes || [], ids = new Set(nodes.map(n => n.node_id));
  const pairKey = (a, b) => (a < b ? `${a}|${b}` : `${b}|${a}`);
  const pairs = new Map();
  const pair = (a, b) => {
    const k = pairKey(a, b);
    if (!pairs.has(k)) { const [x, y] = k.split("|"); pairs.set(k, { a: x, b: y, ab: null, ba: null, declared: false, drift: [] }); }
    return pairs.get(k);
  };
  for (const l of topo.observed_links || []) {
    if (!ids.has(l.src_node_id) || !ids.has(l.dst_node_id)) continue;
    const p = pair(l.src_node_id, l.dst_node_id);
    p[l.src_node_id === p.a ? "ab" : "ba"] = l;
  }
  for (const l of topo.declared_links || []) if (ids.has(l.src_node_id) && ids.has(l.dst_node_id)) pair(l.src_node_id, l.dst_node_id).declared = true;
  for (const d of topo.drift || []) if (ids.has(d.src_node_id) && ids.has(d.dst_node_id)) pair(d.src_node_id, d.dst_node_id).drift.push(d);

  const els = nodes.map(n => ({ data: { ...n, id: n.node_id, status: n.health_status } }));
  for (const [k, p] of pairs) {
    const types = new Set(p.drift.map(d => d.drift_type));
    const degraded = [p.ab, p.ba].some(l => l && l.status === "degraded") || types.has("lossy_link");
    const state = types.has("missing_declared") ? "missing" : degraded ? "degraded" : types.has("extra_observed") && !p.declared ? "undeclared" : "ok";
    const isTraced = traced.has(`${p.a}->${p.b}`) || traced.has(`${p.b}->${p.a}`);
    els.push({ data: { id: `pair-${k}`, source: p.a, target: p.b, state, a: p.a, b: p.b, ab: p.ab, ba: p.ba,
                       notes: p.drift.map(d => d.details) }, classes: `${state}${isTraced ? " traced" : ""}` });
  }

  const pos = {}; cy.nodes().forEach(n => (pos[n.id()] = { ...n.position() }));
  const sel = cy.$(":selected").map(n => n.id());
  let fresh = false;
  cy.batch(() => {
    cy.elements().remove(); cy.add(els);
    cy.nodes().forEach(n => (pos[n.id()] ? n.position(pos[n.id()]) : (fresh = true)));
    sel.forEach(id => cy.getElementById(id).select());
  });
  if (fresh) layout();
  $("empty").hidden = nodes.length > 0;
}
