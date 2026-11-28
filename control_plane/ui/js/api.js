let token = "";
export async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(path, { ...opts, headers });
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  return res.json();
}
export async function login(role) {
  const d = await api("/auth/token", { method: "POST", body: JSON.stringify({ subject: `ui-${role}`, role }) });
  token = d.access_token;
}
export const post = (p, body) => api(p, { method: "POST", body: body && JSON.stringify(body) });
export const patch = (p, body) => api(p, { method: "PATCH", body: JSON.stringify(body) });
