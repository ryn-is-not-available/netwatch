import { api, login, logout } from "./api.js";

const $ = id => document.getElementById(id);
const showError = msg => { $("loginErr").textContent = msg; $("loginErr").hidden = !msg; };

if (new URLSearchParams(location.search).has("expired")) showError("Your session expired. Please sign in again.");

// Already signed in: go straight to the console.
if (sessionStorage.getItem("netwatch_token")) {
  api("/auth/me").then(() => location.replace("/"), () => logout());
}

$("loginForm").onsubmit = async e => {
  e.preventDefault();
  const btn = e.submitter; btn.disabled = true;
  try {
    await login($("loginUser").value.trim(), $("loginPass").value);
    location.replace("/");
  } catch (err) {
    showError(err.message);
    $("loginPass").value = "";
    $("loginPass").focus();
  } finally { btn.disabled = false; }
};
