// Shared front-end helpers for Alliance CRM.
const API = ''; // same origin

function saveSession(data) {
  localStorage.setItem('token', data.token);
  localStorage.setItem('user', JSON.stringify(data.user));
}
function getToken() { return localStorage.getItem('token'); }
function getUser() {
  try { return JSON.parse(localStorage.getItem('user')); } catch (e) { return null; }
}
function logout() {
  localStorage.removeItem('token');
  localStorage.removeItem('user');
  fetch('/api/auth/logout', { method: 'POST' }).finally(() => (location.href = '/portal.html'));
}

// Thin fetch wrapper that attaches the JWT.
async function api(path, opts = {}) {
  opts.headers = Object.assign(
    { 'Content-Type': 'application/json' },
    opts.headers || {}
  );
  const t = getToken();
  if (t) opts.headers['Authorization'] = 'Bearer ' + t;
  const res = await fetch(API + path, opts);
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch (e) { data = { raw: text }; }
  if (!res.ok) throw Object.assign(new Error(data.error || 'request failed'), { data, status: res.status });
  return data;
}

function requireLogin() {
  if (!getToken()) { location.href = '/portal.html'; return false; }
  return true;
}

function renderHeader(active) {
  const user = getUser();
  const el = document.getElementById('nav');
  if (!el) return;
  if (user) {
    el.innerHTML =
      '<a href="/dashboard.html">Dashboard</a>' +
      '<a href="/staff.html">Staff</a>' +
      '<a href="/profile.html">My profile</a>' +
      '<span style="margin-left:16px" class="pill">' + user.username + ' · ' + user.role + '</span>' +
      '<a href="#" onclick="logout();return false;">Log out</a>';
  } else {
    el.innerHTML = '<a href="/">Intake form</a><a href="/portal.html">Staff login</a>';
  }
}

function msg(id, text, kind) {
  const el = document.getElementById(id);
  if (!el) return;
  el.className = 'msg ' + (kind || 'ok');
  el.textContent = text;
}
