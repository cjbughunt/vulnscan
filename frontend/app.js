const $ = (id) => document.getElementById(id);
const SEV = ["critical", "high", "medium", "low", "info"];
let activeScan = null, pollTimer = null, logCursor = 0;

// ---- tool availability ----
async function loadTools() {
  try {
    const h = await (await fetch("/api/health")).json();
    const t = h.tools || {};
    $("tools").innerHTML =
      `nuclei <span class="${t.nuclei ? "on" : "off"}">${t.nuclei ? "detected" : "not found"}</span> · ` +
      `nmap <span class="${t.nmap ? "on" : "off"}">${t.nmap ? "detected" : "not found"}</span>`;
  } catch { $("tools").textContent = "api unreachable"; }
}

// ---- enable launch only when authorized + target present ----
function refreshLaunch() {
  $("launch").disabled = !($("authorized").checked && $("target").value.trim());
}
$("authorized").addEventListener("change", refreshLaunch);
$("target").addEventListener("input", refreshLaunch);

// ---- auth type toggle ----
function refreshAuth() {
  const t = $("authtype").value;
  ["header", "cookie", "form"].forEach((k) =>
    $("auth-" + k).classList.toggle("hidden", k !== t));
  $("authnote").classList.toggle("hidden", t === "none");
}
$("authtype").addEventListener("change", refreshAuth);

function buildAuth() {
  const t = $("authtype").value;
  if (t === "header")
    return { type: "header", header_name: $("a-hname").value.trim() || "Authorization",
             header_value: $("a-hval").value };
  if (t === "cookie")
    return { type: "cookie", cookie: $("a-cookie").value };
  if (t === "form")
    return {
      type: "form", login_url: $("a-login").value.trim(),
      username_field: $("a-ufield").value.trim() || "username", username: $("a-user").value,
      password_field: $("a-pfield").value.trim() || "password", password: $("a-pass").value,
      success_indicator: $("a-indicator").value.trim() || null,
    };
  return { type: "none" };
}

$("launch").addEventListener("click", async () => {
  $("err").textContent = "";
  const body = {
    target: $("target").value.trim(),
    authorized: $("authorized").checked,
    authorized_by: $("authby").value.trim() || null,
    auth: buildAuth(),
    options: {
      max_pages: +$("maxpages").value || 40,
      active_web_tests: $("active").checked,
      check_sensitive_files: $("sens").checked,
      use_nuclei: $("nuclei").checked,
      use_nmap: $("nmap").checked,
      allow_private: $("private").checked,
      subdomain_enum: $("subenum").checked,
      ssrf_callback: $("ssrfcb").value.trim() || null,
      concurrency: +$("concurrency").value || 6,
      delay: +$("delay").value || 0,
    },
  };
  const repeat = +$("repeat").value || 0;
  $("launch").disabled = true;
  try {
    if (repeat > 0) {
      body.interval_minutes = repeat;
      const res = await fetch("/api/schedules", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to create schedule");
      $("authorized").checked = false;
      refreshLaunch();
      await Promise.all([loadScans(), loadSchedules()]);
    } else {
      const res = await fetch("/api/scans", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to start scan");
      $("authorized").checked = false;
      refreshLaunch();
      await loadScans();
      openScan(data.id);
    }
  } catch (e) {
    $("err").textContent = e.message;
  } finally {
    refreshLaunch();
  }
});

// ---- schedules ----
async function loadSchedules() {
  const list = await (await fetch("/api/schedules")).json();
  const el = $("schedlist");
  if (!list.length) { el.innerHTML = '<p class="muted">No schedules.</p>'; return; }
  const every = (m) => m === 60 ? "hourly" : m === 1440 ? "daily" : m === 10080 ? "weekly" : `every ${m}m`;
  el.innerHTML = list.map((s) => `
    <div class="scan sched">
      <div class="t">
        <b>${esc(s.target)}</b>
        <small>${every(s.interval_minutes)} · next ${fmt(s.next_run)}${
          s.last_new_count != null ? ` · <span class="newc">${s.last_new_count} new last run</span>` : ""}</small>
      </div>
      <div class="sactions">
        <button class="mini" data-run="${s.id}">Run</button>
        <button class="mini" data-tog="${s.id}">${s.enabled ? "Pause" : "Resume"}</button>
        <button class="mini del" data-del="${s.id}">✕</button>
      </div>
    </div>`).join("");
  el.querySelectorAll("[data-run]").forEach((b) => b.onclick = async () => {
    await fetch(`/api/schedules/${b.dataset.run}/run`, { method: "POST" });
    setTimeout(() => { loadScans(); loadSchedules(); }, 800);
  });
  el.querySelectorAll("[data-tog]").forEach((b) => b.onclick = async () => {
    await fetch(`/api/schedules/${b.dataset.tog}/toggle`, { method: "POST" }); loadSchedules();
  });
  el.querySelectorAll("[data-del]").forEach((b) => b.onclick = async () => {
    await fetch(`/api/schedules/${b.dataset.del}`, { method: "DELETE" }); loadSchedules();
  });
}

// ---- scan list ----
async function loadScans() {
  const scans = await (await fetch("/api/scans")).json();
  const el = $("scanlist");
  if (!scans.length) { el.innerHTML = '<p class="muted">No scans yet.</p>'; return; }
  el.innerHTML = scans.map((s) => `
    <div class="scan" data-id="${s.id}">
      <div class="t"><b>${esc(s.target)}</b><small>#${s.id} · ${s.finding_count} findings · ${fmt(s.created_at)}</small></div>
      <span class="state ${s.status}">${s.status}</span>
    </div>`).join("");
  el.querySelectorAll(".scan").forEach((d) =>
    d.addEventListener("click", () => openScan(+d.dataset.id)));
}

// ---- detail view ----
function openScan(id) {
  activeScan = id; logCursor = 0;
  $("detail").classList.remove("hidden");
  $("d-html").href = `/api/scans/${id}/report?format=html`;
  $("d-json").href = `/api/scans/${id}/report?format=json`;
  $("d-logs").innerHTML = ""; $("d-findings").innerHTML = "";
  poll();
  clearInterval(pollTimer);
  pollTimer = setInterval(poll, 1500);
}
$("d-close").addEventListener("click", () => {
  $("detail").classList.add("hidden");
  clearInterval(pollTimer); activeScan = null;
});

async function poll() {
  if (!activeScan) return;
  const scan = await (await fetch(`/api/scans/${activeScan}`)).json();
  $("d-title").textContent = scan.target;
  $("d-status").innerHTML =
    `<span class="state ${scan.status}">${scan.status}</span> ` +
    `${scan.current_stage ? "· stage: " + scan.current_stage : ""} ` +
    (scan.authorized_by ? `· authorized by ${esc(scan.authorized_by)}` : "") +
    (scan.error ? ` · <span style="color:#f87171">${esc(scan.error)}</span>` : "");
  $("d-bar").style.width = (scan.progress || 0) + "%";

  const findings = await (await fetch(`/api/scans/${activeScan}/findings`)).json();
  const counts = {}; SEV.forEach((s) => counts[s] = 0);
  findings.forEach((f) => counts[f.severity] = (counts[f.severity] || 0) + 1);
  $("d-summary").innerHTML = SEV.map((s) =>
    `<span class="${s}">${s.toUpperCase()}: ${counts[s]}</span>`).join("");

  // Diff vs previous run (only meaningful once completed).
  let newKeys = new Set();
  if (scan.status === "completed") {
    try {
      const d = await (await fetch(`/api/scans/${activeScan}/diff`)).json();
      if (d.previous) {
        d.new.forEach((f) => newKeys.add(fkey(f)));
        renderDiff(d);
      } else { $("d-diff").classList.add("hidden"); }
    } catch { $("d-diff").classList.add("hidden"); }
  } else { $("d-diff").classList.add("hidden"); }

  $("d-findings").innerHTML = findings.map((f) => renderFinding(f, newKeys)).join("") ||
    '<p class="muted">No findings yet…</p>';

  const logs = await (await fetch(`/api/scans/${activeScan}/logs?after=${logCursor}`)).json();
  if (logs.length) {
    logCursor = logs[logs.length - 1].id;
    const box = $("d-logs");
    logs.forEach((l) => {
      const div = document.createElement("div");
      div.className = "l-" + l.level;
      div.textContent = `[${(l.ts || "").slice(11, 19)}] ${l.message}`;
      box.appendChild(div);
    });
    box.scrollTop = box.scrollHeight;
  }

  if (["completed", "error", "refused"].includes(scan.status)) {
    clearInterval(pollTimer);
    loadScans();
  }
}

function fkey(f) { return (f.title || "") + "\n" + (f.location || ""); }

function renderDiff(d) {
  const box = $("d-diff");
  box.classList.remove("hidden");
  const c = d.counts;
  const fixed = d.fixed.map((f) =>
    `<div class="diff-fixed"><span class="badge ${f.severity}">${f.severity.toUpperCase()}</span>
     <s>${esc(f.title)}</s> <span class="loc">${esc(f.location || "")}</span></div>`).join("");
  box.innerHTML =
    `<div class="diff-head">
       <b>Diff vs scan #${d.previous.id}</b> (${fmt(d.previous.finished_at)})
       <span class="dc new">▲ ${c.new} new</span>
       <span class="dc fixed">▼ ${c.fixed} fixed</span>
       <span class="dc same">= ${c.unchanged} unchanged</span>
     </div>
     ${c.fixed ? `<details class="diff-list"><summary>${c.fixed} fixed since last run</summary>${fixed}</details>` : ""}`;
}

function renderFinding(f, newKeys) {
  const isNew = newKeys && newKeys.has(fkey(f));
  return `<div class="finding ${f.severity}${isNew ? " isnew" : ""}">
    <h4><span class="badge ${f.severity}">${f.severity.toUpperCase()}</span>${esc(f.title)}${isNew ? ' <span class="newtag">NEW</span>' : ""}</h4>
    <div class="loc">${esc(f.location || "")}</div>
    ${f.description ? `<p>${esc(f.description)}</p>` : ""}
    ${f.evidence ? `<pre>${esc(f.evidence)}</pre>` : ""}
    ${f.remediation ? `<p><b>Fix:</b> ${esc(f.remediation)}</p>` : ""}
    <div class="loc" style="color:#64748b">${esc(f.category || "")} · ${esc(f.source || "")}</div>
  </div>`;
}

function esc(s) {
  return (s ?? "").toString().replace(/[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function fmt(iso) { return iso ? iso.slice(0, 16).replace("T", " ") : ""; }

// ---- alerts config ----
async function loadAlerts() {
  const c = await (await fetch("/api/alerts")).json();
  $("al-enabled").checked = !!c.enabled;
  $("al-sev").value = c.min_severity || "high";
  $("al-webhook").value = c.webhook_url || "";
  const e = c.email || {};
  $("al-email-on").checked = !!e.enabled;
  $("al-host").value = e.host || "";
  $("al-port").value = e.port || 587;
  $("al-user").value = e.username || "";
  $("al-pass").value = "";
  $("al-pass").placeholder = e.password === "***" ? "•••••• (saved)" : "••••••";
  $("al-from").value = e.from_addr || "";
  $("al-to").value = e.to_addr || "";
  $("al-tls").checked = e.tls !== false;
}
function alertsBody() {
  return {
    enabled: $("al-enabled").checked,
    min_severity: $("al-sev").value,
    webhook_url: $("al-webhook").value.trim(),
    email: {
      enabled: $("al-email-on").checked,
      host: $("al-host").value.trim(), port: +$("al-port").value || 587,
      username: $("al-user").value.trim(), password: $("al-pass").value,
      from_addr: $("al-from").value.trim(), to_addr: $("al-to").value.trim(),
      tls: $("al-tls").checked,
    },
  };
}
$("open-alerts").onclick = async () => { await loadAlerts(); $("alerts").classList.remove("hidden"); };
$("alerts-close").onclick = () => $("alerts").classList.add("hidden");
$("al-save").onclick = async () => {
  $("al-msg").style.color = "#86efac";
  await fetch("/api/alerts", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(alertsBody()) });
  $("al-msg").textContent = "Saved."; await loadAlerts();
};
$("al-test").onclick = async () => {
  await fetch("/api/alerts", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(alertsBody()) });
  const r = await (await fetch("/api/alerts/test", { method: "POST" })).json();
  $("al-msg").style.color = r.ok ? "#86efac" : "#f87171";
  $("al-msg").textContent = r.ok ? `Test sent via: ${r.channels.join(", ")}` : (r.error || "Test failed");
};

loadTools();
loadScans();
loadSchedules();
setInterval(() => { loadScans(); loadSchedules(); }, 5000);
