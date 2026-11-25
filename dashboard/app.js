"use strict";

// Dashboard front-end: no frameworks, no fabricated values. Every displayed
// value comes from an authenticated backend response.
const $ = (id) => document.getElementById(id);
let pollTimer = null;
let refreshSeconds = 5;
let inFlight = false;

function getCookie(name) {
  const prefix = name + "=";
  for (const part of document.cookie.split(";")) {
    const trimmed = part.trim();
    if (trimmed.startsWith(prefix)) {
      try { return decodeURIComponent(trimmed.slice(prefix.length)); }
      catch (_) { return trimmed.slice(prefix.length); }
    }
  }
  return null;
}

function setText(id, value) { $(id).textContent = value; }
function show(id) { $(id).classList.remove("hidden"); }
function hide(id) { $(id).classList.add("hidden"); }

function formatTime(iso) {
  if (!iso) return "—";
  const date = new Date(iso);
  return isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

function formatUptime(seconds) {
  if (seconds === null || seconds === undefined) return "—";
  const total = Math.max(0, Math.floor(Number(seconds)));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const secs = total % 60;
  return `${hours}h ${minutes}m ${secs}s`;
}

function setBanner(message) {
  if (!message) { hide("error-banner"); return; }
  setText("error-banner", message);
  show("error-banner");
}

async function api(path, options = {}) {
  const headers = Object.assign({}, options.headers || {});
  if (options.method && options.method !== "GET") {
    headers["X-CSRF-Token"] = getCookie("rubevpn_csrf") || "";
    headers["Content-Type"] = "application/json";
  }
  const response = await fetch(path, Object.assign({ credentials: "same-origin", headers }, options));
  if (response.status === 401 && !path.includes("/auth/login")) {
    showLogin();
    throw new Error("Authentication required");
  }
  if (!response.ok) {
    let message = "";
    try {
      const body = await response.json();
      message = body.message || (body.detail && body.detail.message) || "";
    } catch (_) { /* keep generic message */ }
    throw new Error(message || `Request failed with status ${response.status}`);
  }
  return response.json();
}

function renderStatus(data) {
  setText("app-version", `v${data.app_version || "—"}`);
  const vpn = $("vpn-status");
  vpn.textContent = data.status || "—";
  vpn.className = `status ${String(data.status || "").toLowerCase()}`;

  const session = $("session-status");
  session.textContent = data.session_status || "—";
  session.className = `status ${String(data.session_status || "").toLowerCase()}`;

  setText("uptime", formatUptime(data.uptime_seconds));
  setText("expiry", data.session_expires_at ? formatTime(data.session_expires_at) : "No active session");
  setText("clients", data.data_available
    ? (data.connected_clients === null ? "No data" : String(data.connected_clients))
    : "Unavailable (no real data)");
  setText("last-check", formatTime(data.last_health_check));

  const checks = data.diagnostics || [];
  const failed = checks.filter((check) => check.status === "FAIL").length;
  setText("diag-summary", `${failed} failed / ${checks.length} checks`);

  if (data.refresh_seconds && data.refresh_seconds !== refreshSeconds) {
    refreshSeconds = Number(data.refresh_seconds);
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = setInterval(refresh, refreshSeconds * 1000);
    }
  }
}

function appendItem(list, build) {
  const item = document.createElement("li");
  build(item);
  list.appendChild(item);
}

function renderDiagnostics(data) {
  const list = $("diagnostics");
  list.replaceChildren();
  const checks = data.checks || [];
  if (!checks.length) {
    appendItem(list, (li) => { li.textContent = "No diagnostic checks recorded."; li.className = "muted"; });
    return;
  }
  for (const check of checks) {
    appendItem(list, (li) => {
      const badge = document.createElement("span");
      badge.className = `badge ${String(check.status || "").toLowerCase()}`;
      badge.textContent = check.status || "?";
      li.appendChild(badge);
      const name = document.createElement("strong");
      name.textContent = check.name || "check";
      li.appendChild(name);
      li.appendChild(document.createTextNode(` — ${check.message || ""}`));
      if (check.recovery_action) {
        const hint = document.createElement("div");
        hint.className = "muted";
        hint.textContent = `Recovery: ${check.recovery_action}`;
        li.appendChild(hint);
      }
    });
  }
}

function renderEvents(data) {
  const list = $("events");
  list.replaceChildren();
  const events = data.events || [];
  if (!events.length) {
    appendItem(list, (li) => { li.textContent = "No events recorded yet."; li.className = "muted"; });
    return;
  }
  for (const event of events) {
    appendItem(list, (li) => {
      const badge = document.createElement("span");
      badge.className = "badge";
      badge.textContent = event.level || "INFO";
      li.appendChild(badge);
      const time = document.createElement("span");
      time.className = "muted";
      time.textContent = `${formatTime(event.timestamp)}  `;
      li.appendChild(time);
      const message = document.createElement("span");
      message.textContent = event.message || "";
      li.appendChild(message);
    });
  }
}

async function refresh() {
  if (inFlight) return;
  inFlight = true;
  const paths = ["/api/v1/status", "/api/v1/events", "/api/v1/diagnostics"];
  try {
    const results = await Promise.allSettled(paths.map((path) => api(path)));
    if (results[0].status === "fulfilled") renderStatus(results[0].value);
    if (results[1].status === "fulfilled") renderEvents(results[1].value);
    if (results[2].status === "fulfilled") renderDiagnostics(results[2].value);
    const failures = results.filter((result) => result.status === "rejected");
    setBanner(failures.length ? `Dashboard API failure: ${failures.map((f) => f.reason.message).join("; ")}` : "");
  } finally {
    inFlight = false;
  }
}

function showDashboard() {
  hide("login-screen");
  show("dashboard");
  if (pollTimer) clearInterval(pollTimer);
  refresh();
  pollTimer = setInterval(refresh, refreshSeconds * 1000);
}

function showLogin() {
  show("login-screen");
  hide("dashboard");
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  setText("login-error", "");
  const username = $("username").value;
  const password = $("password").value;
  try {
    await api("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    $("password").value = "";
    showDashboard();
  } catch (error) {
    setText("login-error", error.message || "Sign in failed");
  }
});

$("refresh-btn").addEventListener("click", () => refresh());
$("logout-btn").addEventListener("click", async () => {
  try { await api("/api/v1/auth/logout", { method: "POST", body: "{}" }); }
  catch (_) { /* local state is cleared regardless */ }
  showLogin();
});

(async function bootstrap() {
  try {
    await api("/api/v1/auth/session");
    showDashboard();
  } catch (_) {
    showLogin();
  }
})();
