// Small dependency-free SVG line charts for node metrics.
// Specs (dataviz skill): 1px recessive gridlines, 2px lines, area wash only for a single series,
// >=8px end dots with a 2px surface ring, legend + direct end labels for 2 series, crosshair
// tooltip listing every series, keyboard-reachable, and a table view so nothing is hover-only.
const NS = "http://www.w3.org/2000/svg";
const W = 368, H = 132, M = { top: 10, right: 54, bottom: 22, left: 40 };

const el = (tag, attrs = {}, parent) => {
  const n = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  if (parent) parent.append(n);
  return n;
};
const html = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};

function niceMax(v) {
  if (!(v > 0)) return 1;
  const p = 10 ** Math.floor(Math.log10(v));
  return [1, 2, 2.5, 5, 10].map(m => m * p).find(c => c >= v);
}
const timeLabel = t => new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

/**
 * @param {HTMLElement} root   container (cleared)
 * @param {object} cfg  {title, points:[{t,...}], series:[{key,name,color}], format(v)->string, max?}
 */
export function lineChart(root, cfg) {
  root.replaceChildren();
  const fig = html("figure", "chart");
  const head = html("figcaption", "chart-head");
  head.append(html("span", "chart-title", cfg.title));
  if (cfg.series.length > 1) {
    const legend = html("span", "chart-legend");
    for (const s of cfg.series) {
      const item = html("span", "chart-key");
      const swatch = html("i");
      swatch.style.borderTopColor = s.color;
      item.append(swatch, document.createTextNode(s.name));
      legend.append(item);
    }
    head.append(legend);
  }
  fig.append(head);

  const pts = cfg.points.filter(p => cfg.series.some(s => p[s.key] != null));
  if (pts.length < 2) {
    fig.append(html("p", "chart-empty muted", "Not enough samples in this range yet."));
    root.append(fig);
    return;
  }

  const t0 = Date.parse(pts[0].t), t1 = Date.parse(pts.at(-1).t);
  const vmax = cfg.max ?? niceMax(Math.max(...pts.flatMap(p => cfg.series.map(s => p[s.key] ?? 0))));
  const x = t => M.left + ((Date.parse(t) - t0) / Math.max(1, t1 - t0)) * (W - M.left - M.right);
  const y = v => H - M.bottom - (v / vmax) * (H - M.top - M.bottom);

  const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, class: "chart-svg", role: "img", tabindex: "0",
    "aria-label": `${cfg.title}, ${pts.length} samples. Use left and right arrow keys to read values.` });

  // gridlines + y ticks (clean values: 0, half, max)
  for (const v of [0, vmax / 2, vmax]) {
    el("line", { x1: M.left, x2: W - M.right, y1: y(v), y2: y(v), class: v === 0 ? "axis" : "grid" }, svg);
    el("text", { x: M.left - 6, y: y(v) + 4, class: "tick", "text-anchor": "end" }, svg).textContent = cfg.format(v, true);
  }
  for (const p of [pts[0], pts.at(-1)]) {
    el("text", { x: x(p.t), y: H - 6, class: "tick", "text-anchor": p === pts[0] ? "start" : "end" }, svg)
      .textContent = timeLabel(p.t);
  }

  // End labels collide when series finish close together (e.g. rx == tx). Stacking them would
  // detach labels from their lines, so the legend + tooltip carry identity instead.
  const endY = cfg.series
    .map(s => [...pts].reverse().find(p => p[s.key] != null))
    .map((p, i) => (p ? y(p[cfg.series[i].key]) : null))
    .filter(v => v !== null);
  const endLabels = cfg.series.length === 1 || endY.every((a, i) => endY.every((b, j) => i === j || Math.abs(a - b) >= 12));

  // series: area wash (single series only), 2px line broken at gaps, end dot + end label
  for (const s of cfg.series) {
    const segments = [];
    let cur = [];
    for (const p of pts) {
      if (p[s.key] == null) { if (cur.length) segments.push(cur); cur = []; }
      else cur.push(p);
    }
    if (cur.length) segments.push(cur);
    for (const seg of segments) {
      const d = seg.map((p, i) => `${i ? "L" : "M"}${x(p.t).toFixed(1)},${y(p[s.key]).toFixed(1)}`).join("");
      if (cfg.series.length === 1 && seg.length > 1) {
        el("path", { d: `${d}L${x(seg.at(-1).t).toFixed(1)},${y(0)}L${x(seg[0].t).toFixed(1)},${y(0)}Z`,
          fill: s.color, "fill-opacity": "0.1", stroke: "none" }, svg);
      }
      el("path", { d, fill: "none", stroke: s.color, "stroke-width": 2, "stroke-linejoin": "round", "stroke-linecap": "round" }, svg);
    }
    const last = [...pts].reverse().find(p => p[s.key] != null);
    if (last) {
      el("circle", { cx: x(last.t), cy: y(last[s.key]), r: 4, fill: s.color, stroke: "var(--panel)", "stroke-width": 2 }, svg);
      if (endLabels) {
        el("text", { x: x(last.t) + 8, y: y(last[s.key]) + 4, class: "end-label" }, svg).textContent =
          (cfg.series.length > 1 ? `${s.name} ` : "") + cfg.format(last[s.key]);
      }
    }
  }

  // crosshair + tooltip (snaps to the nearest sample; one readout for every series)
  const cross = el("line", { y1: M.top, y2: H - M.bottom, class: "crosshair", visibility: "hidden" }, svg);
  const hit = el("rect", { x: M.left, y: 0, width: W - M.left - M.right, height: H, fill: "transparent" }, svg);
  const wrap = html("div", "chart-plot");
  const tip = html("div", "chart-tip");
  tip.hidden = true;
  wrap.append(svg, tip);
  fig.append(wrap);

  let idx = pts.length - 1;
  const show = i => {
    idx = Math.max(0, Math.min(pts.length - 1, i));
    const p = pts[idx], px = x(p.t);
    cross.setAttribute("x1", px); cross.setAttribute("x2", px); cross.setAttribute("visibility", "visible");
    tip.replaceChildren(html("div", "tip-time", timeLabel(p.t)));
    for (const s of cfg.series) {
      const row = html("div", "tip-row");
      const key = html("i"); key.style.borderTopColor = s.color;
      row.append(key, html("b", "", p[s.key] == null ? "no data" : cfg.format(p[s.key])), html("span", "muted", s.name));
      tip.append(row);
    }
    tip.hidden = false;
    const left = (px / W) * wrap.clientWidth;
    tip.style.left = `${Math.min(left + 10, wrap.clientWidth - tip.offsetWidth - 4)}px`;
  };
  const hide = () => { tip.hidden = true; cross.setAttribute("visibility", "hidden"); };
  const nearest = clientX => {
    const r = svg.getBoundingClientRect();
    const tx = t0 + (((clientX - r.left) / r.width) * W - M.left) / (W - M.left - M.right) * (t1 - t0);
    let best = 0;
    pts.forEach((p, i) => { if (Math.abs(Date.parse(p.t) - tx) < Math.abs(Date.parse(pts[best].t) - tx)) best = i; });
    return best;
  };
  hit.addEventListener("pointermove", e => show(nearest(e.clientX)));
  hit.addEventListener("pointerleave", hide);
  svg.addEventListener("focus", () => show(idx));
  svg.addEventListener("blur", hide);
  svg.addEventListener("keydown", e => {
    if (e.key === "ArrowLeft" || e.key === "ArrowRight") { e.preventDefault(); show(idx + (e.key === "ArrowRight" ? 1 : -1)); }
  });

  // table view: every value reachable without hovering
  const details = html("details", "chart-table");
  details.append(html("summary", "", "Show data table"));
  const table = html("table");
  const hr = html("tr");
  hr.append(html("th", "", "Time"), ...cfg.series.map(s => html("th", "", s.name)));
  table.append(hr);
  for (const p of pts) {
    const tr = html("tr");
    tr.append(html("td", "", timeLabel(p.t)), ...cfg.series.map(s => html("td", "", p[s.key] == null ? "—" : cfg.format(p[s.key]))));
    table.append(tr);
  }
  details.append(table);
  fig.append(details);
  root.append(fig);
}

export const fmtPct = (v, axis) => `${axis ? Math.round(v) : v.toFixed(1)}%`;
export function fmtRate(v) {
  const units = ["B/s", "KB/s", "MB/s", "GB/s"];
  let i = 0;
  while (v >= 1000 && i < units.length - 1) { v /= 1000; i++; }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}
