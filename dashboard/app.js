/* ═══════════════════════════════════════════════════════════════════
   Android Malware Analysis Dashboard — logic
   Data is derived from the synthetic test APKs in ../ (banker_trojan,
   sms_stealer, benign_app). All IOCs are fake: example.com + TEST-NET.
   ═══════════════════════════════════════════════════════════════════ */

"use strict";

const DANGEROUS_PERMS = new Set([
  "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_CONTACTS", "READ_CALL_LOG",
  "CAMERA", "RECORD_AUDIO", "READ_PHONE_STATE", "READ_PHONE_NUMBERS",
  "SYSTEM_ALERT_WINDOW", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
  "RECEIVE_BOOT_COMPLETED", "ACCESS_FINE_LOCATION", "BIND_ACCESSIBILITY_SERVICE",
  "BIND_DEVICE_ADMIN"
]);

/* ── Sample dataset (mirrors the real test manifests) ── */
const SAMPLES = [
  {
    id: "banker",
    name: "Bank Helper",
    pkg: "com.fake.bankhelper",
    version: "2.1",
    size: "1.8 MB",
    severity: "critical",
    score: 88,
    verdict: "MALICIOUS",
    family: "Android Banking Trojan (overlay + accessibility)",
    permissions: [
      "INTERNET", "SYSTEM_ALERT_WINDOW", "READ_SMS", "READ_PHONE_STATE",
      "ACCESS_NETWORK_STATE", "READ_CONTACTS", "READ_EXTERNAL_STORAGE", "CAMERA"
    ],
    components: [
      { type: "activity", name: ".MainActivity", note: "Exported launcher — poses as a banking utility" },
      { type: "service", name: ".BankerAccessibilityService", note: "Accessibility abuse: reads other apps' screens / auto-clicks" }
    ],
    strings: [
      { cat: "C2", level: "danger", val: "https://c2.example.com/gate.php" },
      { cat: "URL", level: "danger", val: "http://192.0.2.10/overlay/inject" },
      { cat: "overlay", level: "warn", val: "com.android.vending → fake login window" },
      { cat: "crypto", level: "warn", val: "AES/CBC/PKCS5Padding (hardcoded key)" }
    ],
    iocs: [
      { level: "critical", text: "<strong>SYSTEM_ALERT_WINDOW</strong> + accessibility service — classic overlay credential-theft pattern" },
      { level: "critical", text: "Hardcoded C2 endpoint <strong>c2.example.com/gate.php</strong>" },
      { level: "high", text: "Reads SMS alongside overlay — intercepts banking OTP codes" },
      { level: "medium", text: "Camera + contacts access unrelated to stated purpose" }
    ],
    flow: [
      "User installs app disguised as a <strong>banking helper</strong>",
      "App requests <strong>Accessibility</strong> access on first launch",
      "Detects target banking app opening, draws a <strong>fake overlay</strong> login",
      "Captures credentials + intercepts the SMS <strong>OTP</strong>",
      "Exfiltrates to <strong>C2</strong> over an AES-wrapped channel"
    ]
  },
  {
    id: "sms",
    name: "Sozlamalar",
    pkg: "uz.fake.smsstealer",
    version: "1.0",
    size: "0.9 MB",
    severity: "critical",
    score: 95,
    verdict: "MALICIOUS",
    family: "SMS Stealer / OTP interceptor (hidden icon)",
    permissions: [
      "RECEIVE_SMS", "READ_SMS", "SEND_SMS", "INTERNET", "ACCESS_NETWORK_STATE",
      "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "READ_CONTACTS",
      "RECEIVE_BOOT_COMPLETED", "SYSTEM_ALERT_WINDOW", "READ_EXTERNAL_STORAGE", "CAMERA"
    ],
    components: [
      { type: "receiver", name: ".SmsReceiver", note: "Priority 999 — intercepts SMS before the default app" },
      { type: "receiver", name: ".BootReceiver", note: "BOOT_COMPLETED persistence — survives reboot" },
      { type: "service", name: ".StealerAccessibilityService", note: "Auto-click & screen reading via accessibility" },
      { type: "receiver", name: ".AdminReceiver", note: "Device admin — resists uninstall" },
      { type: "service", name: ".ExfilService", note: "No launcher activity — app icon is hidden" }
    ],
    strings: [
      { cat: "C2", level: "danger", val: "https://exfil.example.com/sms/push" },
      { cat: "token", level: "danger", val: "bot<FAKE>:AA<redacted-test-token>" },
      { cat: "IP", level: "danger", val: "198.51.100.23" },
      { cat: "label", level: "warn", val: "Masquerades as 'Sozlamalar' (Settings)" }
    ],
    iocs: [
      { level: "critical", text: "<strong>Hidden icon</strong>: ExfilService runs with no launcher activity" },
      { level: "critical", text: "SMS receiver at <strong>priority 999</strong> — steals OTPs before the user sees them" },
      { level: "critical", text: "<strong>Device admin</strong> + boot receiver — persistence & anti-removal" },
      { level: "high", text: "Exfil endpoint <strong>exfil.example.com/sms/push</strong> with fake bot token" }
    ],
    flow: [
      "App installs as <strong>'Sozlamalar'</strong> (Settings), then hides its icon",
      "Requests <strong>Device Admin</strong> + accessibility to lock itself in",
      "<strong>SmsReceiver</strong> intercepts every incoming SMS at priority 999",
      "Extracts <strong>OTP / banking codes</strong>, reads contacts",
      "Pushes to <strong>C2</strong>; <strong>BootReceiver</strong> restarts it on reboot"
    ]
  },
  {
    id: "benign",
    name: "Calculator",
    pkg: "com.example.calculator",
    version: "1.0",
    size: "0.4 MB",
    severity: "clean",
    score: 6,
    verdict: "CLEAN",
    family: "No malicious indicators detected",
    permissions: ["INTERNET"],
    components: [
      { type: "activity", name: ".MainActivity", note: "" }
    ],
    strings: [
      { cat: "info", level: "", val: "No suspicious strings, C2, or hardcoded secrets found" }
    ],
    iocs: [
      { level: "medium", text: "Requests only <strong>INTERNET</strong> — minimal, consistent with a calculator" }
    ],
    flow: [
      "Single launcher activity, no background services",
      "No dangerous permissions requested",
      "No network exfiltration indicators",
      "Baseline <strong>benign</strong> reference sample"
    ]
  }
];

/* ── Helpers ── */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const el = (tag, cls, html) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (html != null) n.innerHTML = html;
  return n;
};

/* ═══════════════ CLOCK ═══════════════ */
function tickClock() {
  const t = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  $("#timestamp").textContent = `${pad(t.getHours())}:${pad(t.getMinutes())}:${pad(t.getSeconds())}`;
}
setInterval(tickClock, 1000);
tickClock();

/* ═══════════════ ANIMATED COUNTERS ═══════════════ */
function animateCounters() {
  $$(".stat-value").forEach((node) => {
    const target = +node.dataset.target || 0;
    const dur = 1100;
    const start = performance.now();
    const step = (now) => {
      const p = Math.min((now - start) / dur, 1);
      const eased = 1 - Math.pow(1 - p, 3);
      node.textContent = Math.round(target * eased);
      if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  });
}

/* ═══════════════ APK LIST ═══════════════ */
function renderApkList() {
  const list = $("#apkList");
  list.innerHTML = "";
  SAMPLES.forEach((s, i) => {
    const card = el("button", "apk-card");
    card.dataset.sev = s.severity;
    card.dataset.id = s.id;
    card.setAttribute("aria-pressed", i === 0 ? "true" : "false");
    const dangerCount = s.permissions.filter((p) => DANGEROUS_PERMS.has(p)).length;
    card.innerHTML = `
      <div class="apk-top">
        <span class="apk-name">${s.name}</span>
        <span class="sev-chip ${s.severity}">${s.severity}</span>
      </div>
      <span class="apk-pkg">${s.pkg}</span>
      <div class="apk-meta">
        <span>v${s.version}</span>
        <span>${s.size}</span>
        <span>${s.permissions.length} perms · ${dangerCount} risky</span>
      </div>`;
    card.addEventListener("click", () => selectApk(s.id));
    list.appendChild(card);
  });
}

/* ═══════════════ TAB PANES ═══════════════ */
function renderPermissions(s) {
  const grid = $("#permissionsGrid");
  grid.innerHTML = "";
  s.permissions.forEach((p) => {
    const dangerous = DANGEROUS_PERMS.has(p);
    const row = el("div", `perm-row ${dangerous ? "dangerous" : "normal"}`);
    row.innerHTML = `
      <span class="perm-dot"></span>
      <span class="perm-name">android.permission.${p}</span>
      <span class="perm-tag">${dangerous ? "dangerous" : "normal"}</span>`;
    grid.appendChild(row);
  });
}

function renderComponents(s) {
  const list = $("#componentsList");
  list.innerHTML = "";
  s.components.forEach((c) => {
    const row = el("div", "comp-row");
    row.innerHTML = `
      <div class="comp-head">
        <span class="comp-type">${c.type}</span>
        <span class="comp-name">${c.name}</span>
      </div>
      ${c.note ? `<span class="comp-note">${c.note}</span>` : ""}`;
    list.appendChild(row);
  });
}

function renderStrings(s) {
  const list = $("#stringsList");
  list.innerHTML = "";
  s.strings.forEach((str) => {
    const row = el("div", `string-row ${str.level}`);
    row.innerHTML = `
      <span class="string-cat">${str.cat}</span>
      <span class="string-val">${str.val}</span>`;
    list.appendChild(row);
  });
}

/* ═══════════════ THREAT GAUGE ═══════════════ */
function renderGauge(s) {
  const colorFor = (sev) =>
    sev === "critical" ? "var(--crit)" :
    sev === "high" ? "var(--high)" :
    sev === "medium" ? "var(--med)" : "var(--low)";
  const color = colorFor(s.severity);
  const R = 70, C = 2 * Math.PI * R;
  const offset = C * (1 - s.score / 100);

  $("#threatGauge").innerHTML = `
    <svg viewBox="0 0 180 180" width="180" height="180" role="img"
         aria-label="Risk score ${s.score} of 100">
      <circle cx="90" cy="90" r="${R}" fill="none" stroke="var(--border)" stroke-width="12"/>
      <circle cx="90" cy="90" r="${R}" fill="none" stroke="${color}" stroke-width="12"
        stroke-linecap="round" stroke-dasharray="${C}" stroke-dashoffset="${C}"
        transform="rotate(-90 90 90)" style="transition: stroke-dashoffset 1.2s ease">
      </circle>
      <text x="90" y="82" text-anchor="middle" fill="var(--text-0)"
        font-family="var(--mono)" font-size="34" font-weight="700">${s.score}</text>
      <text x="90" y="104" text-anchor="middle" fill="var(--text-2)"
        font-family="var(--mono)" font-size="11" letter-spacing="1">RISK / 100</text>
    </svg>`;

  // trigger the arc animation on next frame
  requestAnimationFrame(() => {
    const arc = $("#threatGauge svg circle:last-of-type");
    if (arc) arc.style.strokeDashoffset = offset;
  });

  $("#threatMeta").innerHTML = `
    <div class="threat-verdict" style="color:${color}">${s.verdict}</div>
    <div class="threat-family">${s.family}</div>`;
}

function renderIocs(s) {
  const list = $("#indicatorsList");
  list.innerHTML = "";
  const warn = `<svg class="ioc-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
  s.iocs.forEach((io) => {
    const row = el("div", `ioc-row ${io.level}`);
    row.innerHTML = `${warn}<span class="ioc-text">${io.text}</span>`;
    list.appendChild(row);
  });
}

function renderFlow(s) {
  const flow = $("#attackFlow");
  flow.innerHTML = "";
  s.flow.forEach((step, i) => {
    const node = el("div", "flow-step", step);
    node.dataset.n = i + 1;
    flow.appendChild(node);
  });
}

/* ═══════════════ TERMINAL LOG ═══════════════ */
function logLine(text, cls = "", prompt = "$") {
  const body = $("#terminalBody");
  const line = el("div", "terminal-line");
  line.innerHTML = `<span class="prompt">${prompt}</span><span class="command ${cls}">${text}</span>`;
  body.appendChild(line);
  body.scrollTop = body.scrollHeight;
}

function logAnalysis(s) {
  logLine(`analyze --pkg <span class="hl">${s.pkg}</span>`, "", "$");
  const dangerCount = s.permissions.filter((p) => DANGEROUS_PERMS.has(p)).length;
  setTimeout(() => logLine(`parsed AndroidManifest.xml → ${s.permissions.length} permissions (${dangerCount} dangerous)`, s.severity === "clean" ? "ok" : "warn"), 120);
  setTimeout(() => logLine(`enumerated ${s.components.length} components`, ""), 260);
  setTimeout(() => {
    if (s.severity === "clean") logLine(`verdict: ${s.verdict} — risk ${s.score}/100`, "ok");
    else logLine(`verdict: ${s.verdict} — ${s.family} — risk ${s.score}/100`, "err");
  }, 420);
}

/* ═══════════════ SELECTION ═══════════════ */
let current = null;
function selectApk(id) {
  const s = SAMPLES.find((x) => x.id === id);
  if (!s || s.id === current) return;
  current = s.id;

  $$(".apk-card").forEach((c) => {
    const active = c.dataset.id === id;
    c.classList.toggle("active", active);
    c.setAttribute("aria-pressed", active ? "true" : "false");
  });

  $("#selectedApkBadge").textContent = s.pkg;
  renderPermissions(s);
  renderComponents(s);
  renderStrings(s);
  renderGauge(s);
  renderIocs(s);
  renderFlow(s);
  logAnalysis(s);
}

/* ═══════════════ TABS ═══════════════ */
function wireTabs() {
  $$(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      $$(".tab-btn").forEach((b) => b.classList.remove("active"));
      $$(".tab-pane").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      const pane = $("#tab" + btn.dataset.tab.charAt(0).toUpperCase() + btn.dataset.tab.slice(1));
      if (pane) pane.classList.add("active");
    });
  });
}

/* ═══════════════ MATRIX RAIN ═══════════════ */
function startMatrix() {
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  const canvas = $("#matrixCanvas");
  const ctx = canvas.getContext("2d");
  let cols, drops;
  const chars = "01アカサタナ<>{}[]#$%&абвгде".split("");
  const font = 14;

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    cols = Math.floor(canvas.width / font);
    drops = Array(cols).fill(1);
  }
  resize();
  window.addEventListener("resize", resize);

  function draw() {
    ctx.fillStyle = "rgba(8, 11, 16, 0.08)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = "#00ff9d";
    ctx.font = `${font}px monospace`;
    for (let i = 0; i < drops.length; i++) {
      const ch = chars[Math.floor(Math.random() * chars.length)];
      ctx.fillText(ch, i * font, drops[i] * font);
      if (drops[i] * font > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    }
  }
  setInterval(draw, 55);
}

/* ═══════════════ INIT ═══════════════ */
document.addEventListener("DOMContentLoaded", () => {
  animateCounters();
  renderApkList();
  wireTabs();
  startMatrix();

  logLine("Android Malware Analyzer v1.0 — defensive lab mode", "ok");
  logLine("loaded 3 synthetic samples (example.com / TEST-NET only)", "");
  // auto-select the first sample
  setTimeout(() => selectApk(SAMPLES[0].id), 300);
});
