// Session token lives in sessionStorage: it survives reloads but not closing the tab.
const KEY = "netwatch_token";
let token = sessionStorage.getItem(KEY) || "";
let onUnauthorized = () => {};

export const setUnauthorizedHandler = fn => { onUnauthorized = fn; };

export async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(path, { ...opts, headers });
  if (res.status === 401 && path !== "/auth/token") {
    logout();
    onUnauthorized();
  }
  if (!res.ok) {
    let detail = await res.text();
    try { detail = JSON.parse(detail).detail ?? detail; } catch { /* plain text */ }
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return res.json();
}
export async function login(username, password) {
  const d = await api("/auth/token", { method: "POST", body: JSON.stringify({ username, password }) });
  token = d.access_token;
  sessionStorage.setItem(KEY, token);
  return d;
}
export function logout() {
  token = "";
  sessionStorage.removeItem(KEY);
}
export const post = (p, body) => api(p, { method: "POST", body: body && JSON.stringify(body) });
export const patch = (p, body) => api(p, { method: "PATCH", body: JSON.stringify(body) });
