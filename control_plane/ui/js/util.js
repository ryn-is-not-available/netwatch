export const $ = id => document.getElementById(id);
export const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
export const num = (v, d = 1) => Number(v ?? 0).toFixed(d);
export function toast(msg, err = false) {
  const t = document.createElement("div");
  t.className = "toast" + (err ? " err" : "");
  t.textContent = msg;
  $("toasts").append(t);
  setTimeout(() => t.remove(), err ? 6000 : 3500);
}
