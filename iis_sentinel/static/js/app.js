/* IIS SENTINEL // front-end controllers (Alpine.js components + WebSocket uplink).
 * Log lines and payloads are attacker-controlled: they are only ever written with textContent / x-text. */
"use strict";

const LIST_FIELDS = {
  ad: ["servers"],
  exchange: ["alert_recipients"],
  watchers: ["log_dirs", "app_pools"],
  reports: ["recipients"],
  alerts: ["email_recipients", "http_error_codes", "watched_status_codes", "http_ignore_paths"],
};

const FIREWALLS = [
  { id: "windows", label: "Windows Firewall (on server)", desc: "netsh rule on the attacked IIS server via WinRM. Per-server bans." },
  { id: "pfsense", label: "pfSense / OPNsense", desc: "Adds the IP to a Host alias used by a block rule. Blocks for every server." },
  { id: "sonicwall", label: "SonicWall", desc: "SonicOS 7 API: address object in a deny-rule address group. Blocks for every server." },
  { id: "paloalto", label: "Palo Alto", desc: "PAN-OS User-ID tag feeding a Dynamic Address Group. No commit; blocks for every server." },
];

const START_MODES = { end: "NEW LINES ONLY", full: "WHOLE FILE" };
const SEARCH_STATUS = [
  { id: "all", label: "All Status" },
  { id: "4xx", label: "4xx Only" },
  { id: "5xx", label: "5xx Only" },
  { id: "404", label: "404 Only" },
];

let audioCtx = null;
function alertTone(severity) {
  try {
    audioCtx = audioCtx || new (window.AudioContext || window.webkitAudioContext)();
    const notes = severity === "CRITICAL" ? [880, 660, 880] : severity === "HIGH" ? [740, 554] : [620];
    notes.forEach((freq, i) => {
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      const t0 = audioCtx.currentTime + i * 0.17;
      osc.type = "square";
      osc.frequency.value = freq;
      gain.gain.setValueAtTime(0.0001, t0);
      gain.gain.exponentialRampToValueAtTime(0.06, t0 + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.0001, t0 + 0.15);
      osc.connect(gain).connect(audioCtx.destination);
      osc.start(t0);
      osc.stop(t0 + 0.16);
    });
  } catch (_) { /* audio blocked until the operator interacts with the page */ }
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    ...opts,
  });
  let body = null;
  try { body = await res.json(); } catch (_) { body = null; }
  if (res.status === 401 && !path.startsWith("/login")) {
    window.location.href = "/";
    throw new Error("Session expired");
  }
  if (!res.ok) {
    let detail = body && body.detail;
    if (detail && typeof detail === "object") {
      detail = Array.isArray(detail)
        ? detail.map((d) => d.msg || JSON.stringify(d)).join("; ")
        : Object.entries(detail).map(([k, v]) => `${k}: ${v}`).join("; ");
    }
    throw new Error(detail || `HTTP ${res.status}`);
  }
  return body;
}

const pad = (n) => String(n).padStart(2, "0");
const SEV_RANK = { INFO: 0, WARNING: 1, HIGH: 2, CRITICAL: 3 };

// Kept outside Alpine's reactive proxies: the feed is rendered imperatively for speed.
const feed = { buffer: [] };
// ip -> time it was last asked of /intel/abuseipdb/lookup (not reactive on purpose).
const abuseAsked = new Map();

const THEMES = [
  { id: "cyber", label: "Cyber", desc: "Neon on black with glow and scanlines (the original look)." },
  { id: "dark", label: "Dark", desc: "Calm dark grey, no glow or animated effects." },
  { id: "lite", label: "Lite", desc: "Light background with dark text, for bright rooms." },
  { id: "large", label: "Large Print", desc: "Bigger text and controls with high contrast." },
];
const THEME_KEY = "sentinel.theme";
const DEFAULT_THEME_KEY = "sentinel.default_theme";
function applyTheme(id) {
  const t = THEMES.some((x) => x.id === id) ? id : "cyber";
  document.documentElement.setAttribute("data-theme", t);
  return t;
}
function storedTheme() {
  try { return localStorage.getItem(THEME_KEY) || ""; } catch (_) { return ""; }
}
const termEl = () => document.getElementById("terminal");

/* =====================================================================================
 * LOGIN
 * ===================================================================================== */
function loginApp() {
  return {
    username: "",
    password: "",
    busy: false,
    error: "",
    boot: [],

    init() {
      this.$nextTick(() => this.$refs.user && this.$refs.user.focus());
      const lines = [
        "> sentinel-core v1.0 :: handshake",
        "> w3c parser ........... armed",
        "> z-score baseliner .... armed",
        "> threat matrix ........ armed",
        "> awaiting directory credentials_",
      ];
      lines.forEach((text, i) => setTimeout(() => this.boot.push({ text, ok: i > 0 && i < 4 }), 180 * (i + 1)));
    },

    async submit() {
      if (this.busy || !this.username || !this.password) return;
      this.busy = true;
      this.error = "";
      this.boot = [{ text: "> binding to active directory…", ok: false }];
      try {
        const r = await api("/login", {
          method: "POST",
          body: JSON.stringify({ username: this.username.trim(), password: this.password }),
        });
        this.boot.push({ text: `> identity verified: ${r.display_name || r.user}`, ok: true });
        this.boot.push({ text: "> initializing command center…", ok: true });
        this.password = "";
        setTimeout(() => (window.location.href = "/dashboard"), 450);
      } catch (e) {
        this.error = `ACCESS DENIED // ${e.message}`;
        this.boot.push({ text: "> bind rejected", ok: false });
        this.password = "";
        this.busy = false;
      }
    },
  };
}

/* =====================================================================================
 * DASHBOARD
 * ===================================================================================== */
function dashboardApp() {
  return {
    ARC: 2 * Math.PI * 46 * 0.75,

    // connection
    ws: null,
    connected: false,
    reconnecting: false,
    retryDelay: 1000,
    retryIn: 0,
    lastMsgAt: 0,
    serverOffset: 0,

    // identity
    user: "",
    displayName: "",
    demo: false,

    // fleet
    servers: [],
    healthBy: {},
    selected: "all",

    // data
    threats: [],
    counts: {},
    alerts: [],
    pending: [],
    bans: [],
    banBusy: {},
    centerTab: "pending",
    toasts: [],
    baseline: { current: {}, global: {} },
    pipeline: {},
    clients: 0,
    rpmHistory: [],
    clock: { time: "--:--:--", date: "" },

    // log feed
    feedMode: "all",
    paused: false,
    pendingWhilePaused: 0,
    MAX_BUFFER: 800,
    MAX_DOM: 450,

    // config drawer
    cfgOpen: false,
    cfgTab: "servers",
    form: null,
    cfgMsg: { ok: true, text: "" },
    busy: false,
    watcherStatus: [],
    nextRuns: {},
    reports: [],
    newServer: null,
    srvBusy: {},
    testResults: {},
    editingId: null,
    alertCatalog: null,
    notifPerm: "Notification" in window ? Notification.permission : "unsupported",

    FIREWALLS,
    firewall: { provider: "windows", label: "Windows Firewall (on server)", perimeter: false, target: "", error: null },
    geoStatus: null,

    // WHOIS / IP intel modal
    whois: { ip: "", data: null, intel: null },
    whoisOpen: false,

    // RESOURCE MONITOR modal (site / app pool / server metrics over WinRM)
    res: { open: false, loading: false, error: "", kind: "", name: "", label: "", serverId: null, serverName: "",
           data: null, auto: true, filter: "" },
    _resSeq: 0,
    _resTimer: null,

    // log search (left panel) — while active, live lines are buffered but not drawn
    SEARCH_STATUS,
    search: { q: "", status: "all", active: false, loading: false, page: 1, pages: 1, total: 0, capped: false,
              took: 0, error: "", mode: "", unflushed: 0, index: null },
    _searchTimer: null,
    _searchSeq: 0,

    // BAN ALL
    banAll: { open: false, busy: false, ips: 0, servers: 0, alertIds: [] },

    // BAN THREAT dialog (CIDR escalation), banned ranges, allowlist
    rangeBan: { open: false, loading: false, busy: false, ip: "", serverId: null, serverName: "", alertId: null, key: "",
                data: null, error: "", scope: "", target: "" },
    _rbSeq: 0,
    ranges: [],
    rangeBusy: {},
    rangeBanners: [],
    allow: { list: [], loading: false, error: "", ip: "", description: "", busy: {} },

    // SonicWall address groups (CONFIG > FIREWALL)
    fwGroups: { list: [], loaded: false, loading: false, error: "", name: "", description: "", busy: {} },

    // AbuseIPDB reputation (ip -> result) and UI theme
    abuse: {},
    abuseStatus: {},
    abuseTest: { busy: false, ok: null, text: "" },
    THEMES,
    theme: document.documentElement.getAttribute("data-theme") || "cyber",
    themeLocal: storedTheme(),
    defaultTheme: "cyber",

    _k: 0,

    init() {
      this.newServer = this.blankServer();
      termEl().addEventListener("click", (ev) => {
        const ip = ev.target.closest && ev.target.closest(".log-line .ip");
        if (ip) this.openWhois(ip.textContent, ip.dataset.server === "" ? null : Number(ip.dataset.server));
      });
      this.connect();
      setInterval(() => this.updateClock(), 250);
      setInterval(() => this.watchdog(), 5000);
      setInterval(() => this.syncAbuse(), 3000);
      setInterval(() => {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) this.ws.send("ping");
      }, 20000);
      this.updateClock();
    },

    /* ------------------------------------------------------------ websocket */
    connect() {
      const proto = window.location.protocol === "https:" ? "wss" : "ws";
      let ws;
      try {
        ws = new WebSocket(`${proto}://${window.location.host}/ws/dashboard`);
      } catch (e) {
        this.scheduleReconnect();
        return;
      }
      this.ws = ws;
      this.reconnecting = true;
      ws.onopen = () => {
        this.connected = true;
        this.reconnecting = false;
        this.retryDelay = 1000;
        this.retryIn = 0;
        this.lastMsgAt = Date.now();
      };
      ws.onmessage = (ev) => {
        this.lastMsgAt = Date.now();
        let msg;
        try { msg = JSON.parse(ev.data); } catch (_) { return; }
        try { this.handle(msg); } catch (e) { console.error("handler error", e, msg); }
      };
      ws.onclose = (ev) => {
        this.connected = false;
        if (ev.code === 4401) { window.location.href = "/"; return; }
        if (this.ws === ws) this.scheduleReconnect();
      };
      ws.onerror = () => { try { ws.close(); } catch (_) {} };
    },

    scheduleReconnect() {
      this.reconnecting = true;
      const delay = this.retryDelay;
      this.retryDelay = Math.min(this.retryDelay * 2, 15000);
      this.retryIn = Math.round(delay / 1000);
      const countdown = setInterval(() => { this.retryIn = Math.max(0, this.retryIn - 1); }, 1000);
      setTimeout(async () => {
        clearInterval(countdown);
        try {
          await api("/me");
        } catch (e) {
          if (String(e.message).includes("Session")) return;
        }
        this.connect();
      }, delay);
    },

    watchdog() {
      if (this.connected && Date.now() - this.lastMsgAt > 15000 && this.ws) {
        console.warn("uplink stale, cycling socket");
        try { this.ws.close(); } catch (_) {}
      }
    },

    connClass() { return this.connected ? "live" : this.reconnecting ? "wait" : "down"; },
    connLabel() { return this.connected ? "LIVE" : this.reconnecting ? "SYNC" : "OFFLINE"; },

    handle(msg) {
      switch (msg.type) {
        case "hello":
          this.setServerTime(msg.server_time);
          this.user = msg.user;
          this.displayName = msg.display_name;
          this.demo = !!msg.demo;
          this.setServers(msg.servers || []);
          this.healthBy = {};
          (msg.health || []).forEach((h) => { this.healthBy[h.server_id] = h; });
          this.threats = msg.threats || [];
          this.counts = msg.counts || {};
          this.alerts = (msg.alerts || []).map((a) => ({ ...a, _k: ++this._k }));
          if (msg.baseline) this.baseline = msg.baseline;
          this.pipeline = msg.pipeline || {};
          if (msg.firewall) this.firewall = msg.firewall;
          this.onGeneral(msg);
          feed.buffer = [];
          termEl().replaceChildren();
          this.addLogs(msg.logs || []);
          this.loadPending();
          this.loadBans();
          this.loadRanges();
          this.loadAlertHistory();
          break;
        case "servers":
          this.setServers(msg.data || []);
          break;
        case "server_status": {
          const srv = this.serverById(msg.server_id);
          if (srv) srv.status = { ...(srv.status || {}), [msg.component]: { ok: msg.ok, error: msg.error } };
          break;
        }
        case "health_removed":
          delete this.healthBy[msg.server_id];
          break;
        case "ban":
          this.onBan(msg);
          break;
        case "alert_status":
          this.setAlertStatus(msg.ids || [], msg.status);
          break;
        case "unban":
          this.bans = this.bans.filter((b) => b.id !== msg.id);
          break;
        case "range_ban_notification":
          this.onRangeBan(msg);
          break;
        case "range_unban":
          this.ranges = this.ranges.filter((r) => r.id !== msg.id);
          break;
        case "allowlist":
          if (this.cfgOpen && this.cfgTab === "allowlist") this.loadAllowlist();
          break;
        case "logs":
          this.addLogs(msg.data || []);
          break;
        case "health": {
          this.healthBy[msg.server_id] = msg.data || {};
          const srv = this.serverById(msg.server_id);
          if (srv && msg.data) {
            srv.status = { ...(srv.status || {}), health: { ok: msg.data.online !== false, error: msg.data.error || null } };
          }
          break;
        }
        case "threats":
          this.threats = msg.data || [];
          this.counts = msg.counts || this.counts;
          break;
        case "alert":
          this.addAlert(msg.data);
          break;
        case "alert_ack":
          this.alerts.forEach((a) => { if (a.id === msg.id) a.acknowledged = true; });
          break;
        case "baseline":
          this.baseline = msg.data || this.baseline;
          if (this.selId() != null) {
            this.rpmHistory.push(this.cur().live_count || this.cur().rpm || 0);
            if (this.rpmHistory.length > 90) this.rpmHistory.shift();
          }
          break;
        case "tick":
          this.setServerTime(msg.server_time);
          this.pipeline = msg.pipeline || {};
          this.clients = msg.clients || 0;
          if (this.selId() == null) {
            this.rpmHistory.push(this.pipeline.lines_per_min || 0);
            if (this.rpmHistory.length > 90) this.rpmHistory.shift();
          }
          break;
        case "firewall":
          if (msg.data) this.firewall = msg.data;
          break;
        case "general":
          this.onGeneral(msg);
          break;
        case "abuseipdb":
          Object.assign(this.abuse, msg.data || {});
          if (this.whoisOpen && msg.data && msg.data[this.whois.ip]) this.whois.abuse = msg.data[this.whois.ip];
          break;
        case "pong":
          this.setServerTime(msg.server_time);
          break;
      }
    },

    setServerTime(epoch) {
      if (typeof epoch === "number") this.serverOffset = epoch * 1000 - Date.now();
    },

    updateClock() {
      const d = new Date(Date.now() + this.serverOffset);
      this.clock.time = `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
      this.clock.date = `UTC // ${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
    },

    /* ------------------------------------------------------------ log feed */
    passes(l) {
      if (l.kind === "banner") return true;
      const sel = this.selId();
      if (sel != null && l.server_id !== sel) return false;
      if (this.feedMode === "errors") return l.status >= 400 || !!l.tags;
      if (this.feedMode === "threats") return l.level === "critical" || !!l.tags;
      return true;
    },

    renderLine(l) {
      const div = document.createElement("div");
      if (l.kind === "banner") {
        div.className = "sentinel-banner";
        div.textContent = l.text;
        div.title = `${l.ts}  ${l.text}`;
        return div;
      }
      div.className = `log-line ${l.level}`;
      const span = (cls, text) => {
        const s = document.createElement("span");
        s.className = cls;
        s.textContent = text;
        div.appendChild(s);
      };
      const t = (l.ts || "").slice(11, 19);
      span("ts", t);
      if (l.server) span("srv", `[${l.server}]`);
      if (l.site_name || l.site) span("site", l.site_name || l.site);
      span("ip", l.ip);
      div.lastChild.dataset.server = l.server_id == null ? "" : String(l.server_id);
      div.lastChild.title = "WHOIS / IP intel";
      span("m", l.method);
      span("st", String(l.status));
      div.appendChild(document.createTextNode(` ${l.uri}${l.query ? "?" + l.query : ""}`));
      span("tt", `${l.tt}ms`);
      if (l.tags) l.tags.split(",").filter(Boolean).forEach((tag) => span("tag", tag));
      div.title = `${l.server ? "[" + l.server + "]  " : ""}${l.site_name || l.site ? (l.site_name || l.site) + "  " : ""}${l.ts}  ${l.ip}  ${l.method} ${l.uri}${l.query ? "?" + l.query : ""}\nHTTP ${l.status}.${l.substatus}  ${l.tt}ms  ${l.bytes}B\n${l.ua}`;
      return div;
    },

    addLogs(lines) {
      if (!lines.length) return;
      feed.buffer.push(...lines);
      if (feed.buffer.length > this.MAX_BUFFER) feed.buffer.splice(0, feed.buffer.length - this.MAX_BUFFER);
      if (this.paused || this.search.active) { this.pendingWhilePaused += lines.length; return; }
      this.appendToTerminal(lines.filter((l) => this.passes(l)));
    },

    appendToTerminal(lines) {
      const term = termEl();
      if (!term || !lines.length) return;
      const stick = term.scrollHeight - term.scrollTop - term.clientHeight < 60;
      const frag = document.createDocumentFragment();
      lines.slice(-this.MAX_DOM).forEach((l) => frag.appendChild(this.renderLine(l)));
      term.appendChild(frag);
      while (term.childElementCount > this.MAX_DOM) term.removeChild(term.firstElementChild);
      if (stick) term.scrollTop = term.scrollHeight;
    },

    rerenderFeed() {
      if (this.search.active) { this.runSearch(1); return; }
      const term = termEl();
      term.replaceChildren();
      this.appendToTerminal(feed.buffer.filter((l) => this.passes(l)));
      term.scrollTop = term.scrollHeight;
    },

    setFeedMode(mode) { this.feedMode = mode; this.rerenderFeed(); },

    togglePause() {
      this.paused = !this.paused;
      if (!this.paused) { this.pendingWhilePaused = 0; this.rerenderFeed(); }
    },

    /* ------------------------------------------------------------ log search */
    onSearchInput() {
      clearTimeout(this._searchTimer);
      this._searchTimer = setTimeout(() => this.runSearch(1), 300);
    },

    async runSearch(page = 1) {
      clearTimeout(this._searchTimer);
      const s = this.search;
      const q = s.q.trim();
      if (!q && s.status === "all") { this.clearSearch(); return; }
      const seq = ++this._searchSeq;
      s.active = true;
      s.loading = true;
      s.error = "";
      const params = new URLSearchParams({ q, status: s.status, page: String(page), page_size: "100" });
      if (this.selId() != null) params.set("server_id", String(this.selId()));
      try {
        const r = await api(`/logs/search?${params}`);
        if (seq !== this._searchSeq || !s.active) return;
        Object.assign(s, { page: r.page, pages: r.pages, total: r.total, capped: r.total_capped, took: r.took_ms,
                           mode: r.mode, unflushed: r.unflushed || 0, index: r.index });
        const term = termEl();
        term.replaceChildren();
        const frag = document.createDocumentFragment();
        (r.results || []).forEach((l) => frag.appendChild(this.renderLine(l)));
        term.appendChild(frag);
        term.scrollTop = 0;
      } catch (e) {
        if (seq === this._searchSeq) s.error = e.message;
      } finally {
        if (seq === this._searchSeq) s.loading = false;
      }
    },

    searchPage(delta) {
      const p = this.search.page + delta;
      if (p >= 1 && p <= this.search.pages) this.runSearch(p);
    },

    searchSummary() {
      const s = this.search;
      if (s.loading) return "SEARCHING…";
      if (s.error) return s.error;
      const total = s.total.toLocaleString() + (s.capped ? "+" : "");
      return `${total} MATCH${s.total === 1 ? "" : "ES"} · PAGE ${s.page}/${s.pages} · ${s.took} ms`;
    },

    clearSearch() {
      clearTimeout(this._searchTimer);
      ++this._searchSeq;
      Object.assign(this.search, { q: "", status: "all", active: false, loading: false, page: 1, pages: 1, total: 0, error: "" });
      this.pendingWhilePaused = 0;
      this.rerenderFeed();
    },

    /* ------------------------------------------------------------ alerts */
    addAlert(a) {
      if (!a) return;
      const item = { ...a, _k: ++this._k };
      this.alerts.unshift(item);
      if (this.alerts.length > 600) this.alerts.length = 600;
      if (a.status === "Pending" && a.id && !this.pending.some((p) => p.id === a.id)) this.pending.unshift({ ...a });
      const n = a.notify;
      if (n ? (n.desktop && !n.suppressed) : (a.severity === "CRITICAL" || a.severity === "HIGH")) {
        this.toast(item, a.severity === "CRITICAL" ? 12000 : 7000);
        if (n) this.desktopNotify(a, n);
      }
    },

    desktopNotify(a, n) {
      if (n.sound) alertTone(a.severity);
      if (!("Notification" in window) || Notification.permission !== "granted") return;
      if (!document.hidden && document.hasFocus()) return;
      try {
        const pop = new Notification(`${a.severity} // ${a.server_name ? "[" + a.server_name + "] " : ""}${a.title}`, {
          body: a.message || "", tag: `sentinel-${a.id || this._k}`, requireInteraction: a.severity === "CRITICAL",
        });
        pop.onclick = () => { window.focus(); pop.close(); };
      } catch (e) { console.warn("desktop notification failed", e); }
    },

    notifStatusText() {
      switch (this.notifPerm) {
        case "granted": return "desktop pop-ups ALLOWED (shown while this tab is in the background)";
        case "denied": return "desktop pop-ups BLOCKED in browser site settings; in-page toasts still work";
        case "unsupported":
          return window.isSecureContext ? "browser has no notification support" :
            "desktop pop-ups need HTTPS or http://localhost; in-page toasts still work";
        default: return "desktop pop-ups not yet allowed";
      }
    },

    async requestNotifications() {
      if (!("Notification" in window)) return;
      try { this.notifPerm = await Notification.requestPermission(); } catch (_) { this.notifPerm = Notification.permission; }
    },

    async testAlert(desktop, email) {
      this.busy = true;
      this.cfgMsg = { ok: true, text: email ? "Sending test email via Exchange…" : "Raising test alert…" };
      try {
        if (desktop && this.notifPerm === "default") await this.requestNotifications();
        const r = await api("/alerts/test", { method: "POST", body: JSON.stringify({ desktop, email, severity: "HIGH" }) });
        if (desktop && this.notifPerm === "granted") {
          try { new Notification("IIS SENTINEL // test notification", { body: "Desktop pop-ups are working.", tag: "sentinel-test" }); } catch (_) {}
        }
        if (email) {
          const e = r.email || {};
          this.cfgMsg = e.ok ? { ok: true, text: `Test email delivered to ${(e.recipients || []).join(", ")}.` } : { ok: false, text: `Email: ${e.error || "not sent"}` };
        } else {
          this.cfgMsg = { ok: true, text: "Test alert raised: it should appear as a toast and in the alert stream." };
        }
      } catch (e) {
        this.cfgMsg = { ok: false, text: e.message };
      } finally {
        this.busy = false;
      }
    },

    toast(t, ms = 7000) {
      const item = { ...t, _k: ++this._k };
      this.toasts.push(item);
      if (this.toasts.length > 4) this.toasts.shift();
      setTimeout(() => { this.toasts = this.toasts.filter((x) => x._k !== item._k); }, ms);
    },

    async loadAlertHistory(serverId = null) {
      try {
        const q = serverId == null ? "" : `&server_id=${serverId}`;
        const r = await api(`/alerts?limit=200${q}`);
        const known = new Set(this.alerts.map((a) => a.id));
        const older = (r.alerts || []).filter((a) => !known.has(a.id)).map((a) => ({ ...a, _k: ++this._k }));
        if (!older.length) return;
        this.alerts = [...this.alerts, ...older].sort((x, y) => (y.id || 0) - (x.id || 0)).slice(0, 600);
      } catch (e) { console.error(e); }
    },

    visibleAlerts() {
      const sel = this.selId();
      return (sel == null ? this.alerts : this.alerts.filter((a) => a.server_id === sel)).slice(0, 150);
    },

    setAlertStatus(ids, status) {
      const set = new Set(ids);
      this.alerts.forEach((a) => { if (set.has(a.id)) { a.status = status; a.acknowledged = true; } });
      this.pending = this.pending.filter((p) => !set.has(p.id));
    },

    /* ------------------------------------------------------------ fleet / server scope */
    setServers(list) {
      this.servers = list;
      if (this.selected !== "all" && !list.some((s) => String(s.id) === this.selected && s.enabled)) {
        this.selected = "all";
        this.onServerChange();
      }
    },
    enabledServers() { return this.servers.filter((s) => s.enabled); },
    serverById(id) { return this.servers.find((s) => s.id === id) || null; },
    selId() { return this.selected === "all" ? null : Number(this.selected); },
    selectedName() { const s = this.serverById(this.selId()); return s ? s.server_name : "—"; },
    selectServer(id) {
      this.selected = id === "all" ? "all" : String(id);
      this.onServerChange();
    },
    onServerChange() {
      this.rpmHistory = [];
      this.rerenderFeed();
      if (this.selId() != null) this.loadAlertHistory(this.selId());
    },
    serverState(s) {
      if (!s) return "";
      const st = s.status || {};
      const h = st.health, l = st.logs;
      if ((h && h.ok === false) || (l && l.ok === false)) return "down";
      if (h && h.ok && (!s.log_unc_path && !s.local || (l && l.ok))) return "live";
      return "wait";
    },
    serverStateText(s) {
      const st = (s && s.status) || {};
      const part = (name, c) => (c == null ? `${name}: pending` : c.ok ? `${name}: OK` : `${name}: ${c.error || "DOWN"}`);
      return `${part("HEALTH", st.health)}  |  ${part("LOGS", st.logs)}`;
    },
    onlineCount() { return this.enabledServers().filter((s) => this.serverState(s) === "live").length; },
    logFeedOk() { const s = this.serverById(this.selId()); const l = s && s.status && s.status.logs; return l ? l.ok : null; },
    logFeedError() { const s = this.serverById(this.selId()); const l = s && s.status && s.status.logs; return (l && l.error) || ""; },
    activeCount() {
      const sel = this.selId();
      return sel == null ? (this.counts.active_threats || 0) : this.threats.filter((t) => t.active && t.server_id === sel).length;
    },

    /* ------------------------------------------------------------ pending threats / active defense */
    async loadPending() {
      try {
        const r = await api("/alerts?status=pending&limit=500");
        this.pending = r.alerts || [];
      } catch (e) { console.error(e); }
    },

    pendingGroups() {
      const sel = this.selId();
      const scores = {};
      this.threats.forEach((t) => { scores[t.key] = t; });
      const groups = new Map();
      for (const a of this.pending) {
        if (sel != null && a.server_id !== sel) continue;
        const key = `${a.server_id}|${a.source_ip}`;
        let g = groups.get(key);
        if (!g) {
          g = { key, server_id: a.server_id, server_name: a.server_name, ip: a.source_ip, alerts: [], top: a, cats: {}, last: a.ts };
          groups.set(key, g);
        }
        g.alerts.push(a);
        g.cats[a.category.toUpperCase()] = (g.cats[a.category.toUpperCase()] || 0) + 1;
        if ((SEV_RANK[a.severity] || 0) > (SEV_RANK[g.top.severity] || 0)) g.top = a;
        if (a.ts > g.last) g.last = a.ts;
      }
      const out = [...groups.values()].map((g) => {
        const t = scores[g.key];
        return { ...g, score: t ? t.score : null, active: !!(t && t.active), attacking: !!(t && t.attacking), geo: t ? t.geo : "" };
      });
      out.sort((a, b) => (b.active - a.active) || ((b.score || 0) - (a.score || 0)) || (b.last > a.last ? 1 : -1));
      return out;
    },

    visibleThreats() {
      const sel = this.selId();
      return sel == null ? this.threats : this.threats.filter((t) => t.server_id === sel);
    },

    banPrompt(ip, serverName) {
      const f = this.firewall;
      if (f.perimeter) {
        return `APPROVE PERIMETER BAN\n\nBlock ${ip} on ${f.label} (${f.target || "not configured"})?\n\n` +
          `This blocks the address for every server, not just ${serverName}.` + (f.error ? `\n\nWARNING: ${f.error}` : "");
      }
      return `APPROVE FIREWALL BAN\n\nBlock ${ip} on ${serverName}?\n\n` +
        `netsh advfirewall firewall add rule name="SENTINEL BAN: ${ip}" dir=in action=block remoteip=${ip}`;
    },

    async approveBan(p) {
      if (this.banBusy[p.key] || !p.ip) return;
      const rb = this.rangeBan;
      Object.assign(rb, { open: true, loading: true, busy: false, ip: p.ip, serverId: p.server_id ?? null, serverName: p.server_name || "",
                          alertId: p.top ? p.top.id : null, key: p.key, data: null, error: "", scope: "", target: "" });
      const seq = ++this._rbSeq;
      const params = new URLSearchParams({ ip: p.ip });
      if (p.server_id != null) params.set("server_id", String(p.server_id));
      try {
        const r = await api(`/intel/recommend-cidr?${params}`);
        if (seq !== this._rbSeq || !rb.open) return;
        rb.data = r;
        const opts = r.options || [];
        const rec = Math.max(0, opts.findIndex((o) => o.recommended));
        const pick = opts.slice(0, rec + 1).reverse().find((o) => !o.blocked) || opts.find((o) => !o.blocked);
        rb.scope = pick ? pick.scope : "";
        rb.target = this.rbTargetReady(r.default_target) ? r.default_target
          : ["windows", "sonicwall"].find((t) => this.rbTargetReady(t)) || r.default_target;
      } catch (e) {
        if (seq !== this._rbSeq) return;
        rb.error = `Pre-flight unavailable (${e.message}). Only a single-IP ban can be offered.`;
        rb.scope = "single";
      } finally {
        if (seq === this._rbSeq) rb.loading = false;
      }
    },

    rbOptions() {
      const rb = this.rangeBan;
      if (rb.data) return rb.data.options || [];
      if (!rb.error) return [];
      const v6 = rb.ip.includes(":");
      return [{ tier: "single", label: "Single IP", scope: "single", cidr: `${rb.ip}/${v6 ? 128 : 32}`, size: 1, recommended: true, blocked: false }];
    },

    rbScopeLabel(o) {
      return `${o.label} (${o.scope === "single" ? (this.rangeBan.ip.includes(":") ? "/128" : "/32") : o.scope})${o.recommended ? " — RECOMMENDED" : ""}`;
    },

    rbTargetReady(t) {
      const tg = this.rangeBan.data && this.rangeBan.data.targets;
      if (!tg) return t === "windows";
      if (t === "both") return tg.windows.ready && tg.sonicwall.ready;
      return !!(tg[t] && tg[t].ready);
    },

    rbTargetError(t) {
      const tg = this.rangeBan.data && this.rangeBan.data.targets;
      if (!tg || this.rbTargetReady(t)) return "";
      if (t === "both") return [tg.windows.error, tg.sonicwall.error].filter(Boolean).join("; ");
      return (tg[t] && tg[t].error) || "not available";
    },

    rbSelected() { return this.rbOptions().find((o) => o.scope === this.rangeBan.scope) || null; },

    rbCanConfirm() {
      const rb = this.rangeBan, o = this.rbSelected();
      return rb.open && !rb.loading && !rb.busy && !!o && !o.blocked && (!rb.data || this.rbTargetReady(rb.target));
    },

    closeRangeBan() {
      if (this.rangeBan.busy) return;
      this.rangeBan.open = false;
      ++this._rbSeq;
    },

    async confirmRangeBan() {
      const rb = this.rangeBan;
      if (!this.rbCanConfirm()) return;
      rb.busy = true;
      if (rb.key) this.banBusy[rb.key] = true;
      const body = { scope: rb.scope };
      if (rb.target) body.firewall_target = rb.target;
      if (rb.alertId != null) body.alert_id = rb.alertId;
      else Object.assign(body, { ip: rb.ip, server_id: rb.serverId });
      try {
        const r = await api("/defense/ban-range", { method: "POST", body: JSON.stringify(body) });
        this.setAlertStatus(r.alert_ids || [], "Approved");
        if (r.range && r.range.id && !this.ranges.some((x) => x.id === r.range.id)) this.ranges.unshift(r.range);
        rb.open = false;
        const failed = (r.results || []).filter((x) => !x.ok);
        this.toast({ severity: failed.length ? "WARNING" : "INFO", ok: !failed.length, category: "range ban",
                     title: r.already ? `${r.cidr} is already banned` : `${r.cidr} (${r.scope}) blocked`,
                     message: failed.map((x) => `${x.target}${x.server ? " " + x.server : ""}: ${x.message}`).join("\n") },
                   failed.length ? 15000 : 8000);
      } catch (e) {
        rb.error = e.message;
        this.toast({ severity: "CRITICAL", category: "range ban failed", server_name: rb.serverName, title: e.message }, 12000);
      } finally {
        rb.busy = false;
        if (rb.key) delete this.banBusy[rb.key];
      }
    },

    onRangeBan(msg) {
      this.setAlertStatus(msg.alert_ids || [], "Approved");
      const d = msg.data;
      if (d && d.id && !this.ranges.some((x) => x.id === d.id)) this.ranges.unshift(d);
      const ts = new Date(Date.now() + this.serverOffset).toISOString();
      const text = `[SENTINEL] RANGE BANNED: ${msg.cidr} (${msg.scope}) — ${msg.reason}`;
      this.addLogs([{ kind: "banner", ts, server_id: null, text }]);
      const k = ++this._k;
      this.rangeBanners = [{ k, ts, text }, ...this.rangeBanners].slice(0, 3);
      setTimeout(() => { this.rangeBanners = this.rangeBanners.filter((x) => x.k !== k); }, 120000);
    },

    async loadRanges() {
      try {
        const r = await api("/banned-ranges?active=true&page_size=200");
        this.ranges = r.ranges || [];
      } catch (e) { console.error(e); }
    },

    targetLabel(t) {
      return { windows: "WINDOWS", sonicwall: "SONICWALL", both: "WIN + SONICWALL" }[t] || (t || "").toUpperCase();
    },

    async unbanRange(r) {
      if (!window.confirm(`Lift range ban on ${r.cidr}?\n\nThe Sentinel block will be removed from ${this.targetLabel(r.firewall_target)}.`)) return;
      this.rangeBusy[r.id] = true;
      try {
        await api(`/banned-ranges/${r.id}`, { method: "DELETE" });
        this.ranges = this.ranges.filter((x) => x.id !== r.id);
      } catch (e) {
        this.toast({ severity: "CRITICAL", category: "unban failed", title: `${r.cidr}: ${e.message}` }, 12000);
      } finally {
        delete this.rangeBusy[r.id];
      }
    },

    async loadAllowlist() {
      const a = this.allow;
      a.loading = true;
      a.error = "";
      try {
        a.list = (await api("/allowlist")).entries || [];
      } catch (e) {
        a.error = e.message;
      } finally {
        a.loading = false;
      }
    },

    async addAllowlist() {
      const a = this.allow;
      const value = a.ip.trim();
      if (!value || a.busy._add) return;
      a.busy._add = true;
      try {
        const r = await api("/allowlist", { method: "POST", body: JSON.stringify({ ip_or_cidr: value, description: a.description.trim() }) });
        a.ip = "";
        a.description = "";
        const overlap = r.overlapping_bans || [];
        this.cfgMsg = overlap.length
          ? { ok: false, text: `${r.entry.ip_or_cidr} allowlisted, but it is inside active range ban(s): ${overlap.join(", ")}. UNBAN them to restore access.` }
          : { ok: true, text: `${r.entry.ip_or_cidr} added to the allowlist. It can no longer be banned.` };
        await this.loadAllowlist();
      } catch (e) {
        this.cfgMsg = { ok: false, text: e.message };
      } finally {
        delete a.busy._add;
      }
    },

    async removeAllowlist(entry) {
      if (!window.confirm(`Remove ${entry.ip_or_cidr} from the allowlist?\n\nIt will become bannable again.`)) return;
      const a = this.allow;
      a.busy[entry.id] = true;
      try {
        await api(`/allowlist/${entry.id}`, { method: "DELETE" });
        a.list = a.list.filter((x) => x.id !== entry.id);
      } catch (e) {
        this.cfgMsg = { ok: false, text: e.message };
      } finally {
        delete a.busy[entry.id];
      }
    },

    approveAlert(a) {
      const g = this.pendingGroups().find((x) => x.key === `${a.server_id}|${a.source_ip}`);
      this.approveBan(g ? { ...g, top: a } : { key: `${a.server_id}|${a.source_ip}`, ip: a.source_ip, server_name: a.server_name, top: a });
    },

    onBan(msg) {
      const ban = msg.data;
      this.setAlertStatus(msg.alert_ids || [], msg.status || "Approved");
      if (!ban) return;
      const key = `${ban.server_id}|${ban.ip_address}`;
      this.pending = this.pending.filter((p) => `${p.server_id}|${p.source_ip}` !== key);
      if (!this.bans.some((b) => b.id === ban.id)) {
        this.bans.unshift(ban);
        if (!this.banAll.busy) this.toast({ severity: "INFO", ok: true, category: "ban executed", server_name: ban.server_name, title: `${ban.ip_address} blocked by ${ban.rule_name}` });
      }
    },

    openBanAll() {
      const groups = this.pendingGroups();
      if (!groups.length) return;
      const ips = new Set(groups.map((g) => g.ip));
      const servers = new Set(groups.map((g) => g.server_id));
      this.banAll = { open: true, busy: false, ips: ips.size, servers: servers.size,
                      alertIds: groups.flatMap((g) => g.alerts.map((a) => a.id)) };
    },

    banAllText() {
      const b = this.banAll;
      return `WARNING: You are about to ban ${b.ips} IP${b.ips === 1 ? "" : "s"} across ${b.servers} server${b.servers === 1 ? "" : "s"}. Are you sure?`;
    },

    async confirmBanAll() {
      const b = this.banAll;
      if (b.busy || !b.alertIds.length) return;
      b.busy = true;
      try {
        const r = await api("/defense/ban-all", { method: "POST", body: JSON.stringify({ alert_ids: b.alertIds }) });
        const done = new Set(r.alert_ids || []);
        (r.banned || []).forEach((x) => (x.alert_ids || []).forEach((id) => done.add(id)));
        this.setAlertStatus([...done], "Approved");
        const bannedIps = new Set((r.banned || []).map((x) => x.ip));
        this.pending = this.pending.filter((p) => !(this.firewall.perimeter ? bannedIps.has(p.source_ip)
          : (r.banned || []).some((x) => x.ip === p.source_ip && x.server_id === p.server_id)));
        this.loadBans();
        b.open = false;
        this.toast({ severity: "INFO", ok: true, category: "ban all",
                     title: `${r.ip_count} IP${r.ip_count === 1 ? "" : "s"} banned across ${r.server_count} server${r.server_count === 1 ? "" : "s"}` }, 9000);
        if ((r.failed || []).length) {
          this.toast({ severity: "CRITICAL", category: "ban all", title: `${r.failed.length} ban(s) FAILED — still pending`,
                       message: r.failed.slice(0, 4).map((f) => `${f.ip}: ${f.error}`).join("\n") }, 15000);
        }
      } catch (e) {
        this.toast({ severity: "CRITICAL", category: "ban all failed", title: e.message }, 12000);
      } finally {
        b.busy = false;
      }
    },

    async dismissGroup(p) {
      this.banBusy[p.key] = true;
      try {
        for (const a of p.alerts) await api("/defense/dismiss", { method: "POST", body: JSON.stringify({ alert_id: a.id }) });
        this.setAlertStatus(p.alerts.map((a) => a.id), "Dismissed");
      } catch (e) {
        this.toast({ severity: "WARNING", category: "dismiss", title: e.message });
      } finally {
        delete this.banBusy[p.key];
      }
    },

    async loadBans() {
      try {
        const r = await api("/defense/bans");
        this.bans = r.bans || [];
      } catch (e) { console.error(e); }
    },
    visibleBans() {
      const sel = this.selId();
      return sel == null ? this.bans : this.bans.filter((b) => b.server_id === sel);
    },
    async liftBan(b) {
      if (!window.confirm(`Lift ban on ${b.ip_address} (${b.server_name})?\nThe firewall rule "${b.rule_name}" will be deleted.`)) return;
      this.banBusy["ban" + b.id] = true;
      try {
        await api(`/defense/bans/${b.id}`, { method: "DELETE" });
        this.bans = this.bans.filter((x) => x.id !== b.id);
      } catch (e) {
        this.toast({ severity: "CRITICAL", category: "unban failed", server_name: b.server_name, title: e.message }, 10000);
      } finally {
        delete this.banBusy["ban" + b.id];
      }
    },

    async ack(a) {
      try {
        await api(`/alerts/${a.id}/ack`, { method: "POST" });
        a.acknowledged = true;
      } catch (e) { console.error(e); }
    },

    /* ------------------------------------------------------------ WHOIS / IP intel */
    async openWhois(ip, serverId = null, refresh = false) {
      if (!ip) return;
      const sid = serverId == null ? this.selId() : serverId;
      const keep = this.whoisOpen && this.whois.ip === ip ? this.whois : null;
      const first = this.enabledServers().find((s) => s.id === sid) || this.enabledServers()[0];
      this.whois = {
        ip, server_id: sid, loading: true, error: "", banBusy: false,
        data: keep ? keep.data : null, intel: keep ? keep.intel : null,
        banServer: keep ? keep.banServer : (first ? String(first.id) : ""),
      };
      this.whoisOpen = true;
      // Mutate Alpine's reactive proxy, not the plain object assigned above, or the modal never re-renders.
      const state = this.whois;
      const enc = encodeURIComponent(ip);
      state.abuse = keep ? keep.abuse : (this.abuse[ip] || null);
      const [w, intel, ab] = await Promise.allSettled([
        api(`/threats/whois/${enc}${refresh ? "?refresh=true" : ""}`),
        api(`/threats/ip/${enc}`),
        this.abuseStatus.enabled ? api(`/intel/abuseipdb/${enc}${refresh ? "?refresh=true" : ""}`) : Promise.resolve(null),
      ]);
      if (this.whois !== state) return;
      if (w.status === "fulfilled") state.data = w.value;
      else state.error = `WHOIS: ${w.reason.message}`;
      if (intel.status === "fulfilled") state.intel = intel.value;
      if (ab.status === "fulfilled" && ab.value) {
        state.abuse = ab.value;
        if (ab.value.score != null) this.abuse[ip] = ab.value;
      } else if (ab.status === "rejected") {
        state.abuse = { ip, score: null, error: ab.reason.message };
      }
      state.loading = false;
    },

    /* ------------------------------------------------------------ RESOURCE MONITOR */
    openResources(kind, name, label) {
      const sid = this.selId();
      if (sid == null) return;
      clearInterval(this._resTimer);
      this.res = {
        open: true, loading: true, error: "", kind, name: name == null ? "" : String(name),
        label: label || String(name || "") || this.selectedName(), serverId: sid, serverName: this.selectedName(),
        data: null, auto: true, filter: "",
      };
      this.loadResources();
      this._resTimer = setInterval(() => {
        if (this.res.open && this.res.auto && !this.res.loading && !document.hidden) this.loadResources();
      }, 5000);
    },

    closeResources() {
      this.res.open = false;
      clearInterval(this._resTimer);
      this._resTimer = null;
      this._resSeq++;
    },

    async loadResources() {
      const r = this.res;
      const seq = ++this._resSeq;
      r.loading = true;
      const q = new URLSearchParams({ kind: r.kind, name: r.name });
      try {
        const d = await api(`/servers/${r.serverId}/resources?${q}`);
        if (seq !== this._resSeq || this.res !== r) return;
        r.data = d;
        r.error = "";
      } catch (e) {
        if (seq !== this._resSeq || this.res !== r) return;
        r.error = e.message;
      } finally {
        if (seq === this._resSeq) r.loading = false;
      }
    },

    RD() {
      return this.res.data || { headline: {}, host: {}, pools: [], processes: [], requests: [], sites: [], counter_groups: [], notes: [] };
    },

    RS() {
      return this.RD().site || { bindings: [], applications: [] };
    },

    RT() {
      return this.RD().tcp || { source: "", ports: [], by_state: [], by_port: [], top_clients: [] };
    },

    resTitle() {
      const k = { site: "IIS SITE", pool: "APP POOL", server: "SERVER" }[this.res.kind] || "";
      return `${k} RESOURCES // ${this.res.serverName}` + (this.RD().hostname ? ` (${this.RD().hostname})` : "");
    },

    fmtUnit(v, unit) {
      if (v == null || Number.isNaN(Number(v))) return "—";
      v = Number(v);
      switch (unit) {
        case "%": return `${v.toFixed(1)}%`;
        case "B": return this.fmtBytes(v);
        case "B/s": return `${this.fmtBytes(v)}/s`;
        case "MB": return this.fmtBytes(v * 1048576);
        case "ms": return `${Math.round(v).toLocaleString()} ms`;
        case "s": return v >= 120 ? this.fmtSpan(Math.round(v)) : v > 0 && v < 1 ? `${(v * 1000).toFixed(1)} ms` : `${v.toFixed(1)} s`;
        case "bit/s": return v >= 1e9 ? `${(v / 1e9).toFixed(1)} Gbit/s` : `${Math.round(v / 1e6)} Mbit/s`;
        case "/s": return `${v >= 100 ? Math.round(v).toLocaleString() : v.toFixed(1)}/s`;
        default: return Number.isInteger(v) ? v.toLocaleString() : v.toFixed(2);
      }
    },

    resTiles() {
      const h = this.RD().headline || {};
      const n = (v) => (v == null ? "—" : this.fmtNum(Math.round(v)));
      const tiles = [
        { k: "CURRENT CONNECTIONS", v: n(h.current_connections), big: true,
          sub: [h.peak_connections != null ? `peak ${n(h.peak_connections)} since IIS start` : "",
                h.server_current_connections != null ? `server total ${n(h.server_current_connections)}` : ""].filter(Boolean).join(" · ") },
        { k: "ACTIVE REQUESTS", v: n(h.active_requests), cls: h.active_requests > 50 ? "warn" : "",
          sub: h.requests_in_flight != null ? `${h.requests_in_flight} listed below` : "executing in w3wp" },
        { k: "REQUESTS / SEC", v: h.requests_per_sec == null ? "—" : this.fmtUnit(h.requests_per_sec, "/s"), sub: "all HTTP methods" },
        { k: "BANDWIDTH", v: h.bytes_per_sec == null ? "—" : this.fmtUnit(h.bytes_per_sec, "B/s"), sub: "sent + received" },
        { k: "TCP ESTABLISHED", v: n(h.tcp_established), sub: h.unique_clients != null ? `${n(h.unique_clients)} unique client IPs` : "" },
        { k: "QUEUED REQUESTS", v: n(h.http_queue), cls: h.http_queue > 0 ? "warn" : "",
          sub: `HTTP.sys queue` + (h.asp_queued != null ? ` · ASP.NET ${n(h.asp_queued)}` : "") + (h.http_rejected ? ` · ${n(h.http_rejected)} rejected` : "") },
        { k: "W3WP CPU", v: h.w3wp_cpu_percent == null ? "—" : `${h.w3wp_cpu_percent.toFixed(1)}%`, cls: h.w3wp_cpu_percent > 80 ? "bad" : h.w3wp_cpu_percent > 50 ? "warn" : "",
          sub: `${h.worker_processes || 0} worker process${h.worker_processes === 1 ? "" : "es"}` },
        { k: "W3WP MEMORY", v: h.w3wp_private_bytes == null ? "—" : this.fmtBytes(h.w3wp_private_bytes),
          sub: h.w3wp_working_set != null ? `private · ${this.fmtBytes(h.w3wp_working_set)} working set` : "private bytes" },
        { k: "CURRENT USERS", v: n(h.current_users), sub: "anonymous + authenticated" },
        { k: "RECYCLES / FAILURES", v: `${n(h.pool_recycles)} / ${n(h.worker_failures)}`, cls: h.worker_failures > 0 ? "warn" : "",
          sub: "app pool recycles / worker failures" },
      ];
      return tiles;
    },

    resGroups() {
      const f = (this.res.filter || "").trim().toLowerCase();
      const groups = this.RD().counter_groups || [];
      if (!f) return groups;
      return groups
        .map((g) => (g.title.toLowerCase().includes(f) ? g : { ...g, rows: g.rows.filter((r) => r.name.toLowerCase().includes(f)) }))
        .filter((g) => g.rows.length);
    },

    resBindings(s) {
      return (s.bindings || []).map((b) => `${b.protocol}/${b.info}`).join("  ·  ") || "—";
    },

    WH() {
      const h = this.whois.data && this.whois.data.history;
      return h || { total: 0, ip_bans: 0, range_bans: 0, active: 0, events: [] };
    },

    historyHeadline() {
      const h = this.WH();
      if (!h.total) return "Never banned by Sentinel";
      const times = `${h.total} time${h.total === 1 ? "" : "s"}`;
      const parts = [];
      if (h.ip_bans) parts.push(`${h.ip_bans} single-IP`);
      if (h.range_bans) parts.push(`${h.range_bans} range`);
      return `Banned ${times} by Sentinel (${parts.join(" + ")})` + (h.active ? ` · ${h.active} active now` : " · none active");
    },

    fmtSpan(sec) {
      if (sec == null) return "";
      if (sec < 60) return `${sec}s`;
      if (sec < 3600) return `${Math.round(sec / 60)}m`;
      if (sec < 86400) return `${(sec / 3600).toFixed(1)}h`;
      return `${(sec / 86400).toFixed(1)}d`;
    },

    /* ------------------------------------------------------------ AbuseIPDB */
    syncAbuse() {
      if (!this.abuseStatus.enabled || !this.abuseStatus.auto_lookup || !this.connected) return;
      const now = Date.now();
      const want = [];
      const add = (ip) => {
        if (!ip || this.abuse[ip]) return;
        const t = abuseAsked.get(ip);
        if (t && now - t < 120000) return;
        abuseAsked.set(ip, now);
        want.push(ip);
      };
      this.pendingGroups().forEach((g) => add(g.ip));
      this.visibleThreats().forEach((t) => add(t.ip));
      if (!want.length) return;
      api("/intel/abuseipdb/lookup", { method: "POST", body: JSON.stringify({ ips: want.slice(0, 200) }) })
        .then((r) => {
          Object.assign(this.abuse, r.results || {});
          this.abuseStatus = { ...this.abuseStatus, ...r, results: undefined };
        })
        .catch((e) => console.warn("abuseipdb lookup", e));
    },

    ipdb(ip) { return this.abuse[ip] || null; },
    ipdbText(ip) {
      const a = this.ipdb(ip);
      if (!a) return "…";
      if (a.public === false) return "LAN";
      if (a.score == null) return a.error ? "ERR" : "—";
      return `${a.score}%`;
    },
    ipdbClass(ip) {
      const a = this.ipdb(ip);
      if (!a || a.score == null) return "none";
      return a.score >= 75 ? "red" : a.score >= 25 ? "amber" : "green";
    },
    ipdbTitle(ip) {
      const a = this.ipdb(ip);
      if (!a) return "AbuseIPDB: lookup queued";
      if (a.public === false) return "AbuseIPDB: private / reserved address, not looked up";
      if (a.score == null) return `AbuseIPDB: ${a.error || "no data"}`;
      return `AbuseIPDB confidence ${a.score}% · ${this.fmtNum(a.reports || 0)} report(s) from ${this.fmtNum(a.users || 0)} user(s)` +
        (a.isp ? ` · ${a.isp}` : "") + (a.usage ? ` · ${a.usage}` : "") + (a.tor ? " · TOR EXIT" : "") +
        (a.last_reported ? ` · last reported ${a.last_reported.slice(0, 10)}` : "");
    },

    async testAbuseIPDB() {
      const t = this.abuseTest;
      t.busy = true;
      t.ok = null;
      t.text = "Contacting AbuseIPDB…";
      try {
        const key = this.form && this.form.general ? this.form.general.abuseipdb_api_key : "";
        const r = await api("/intel/abuseipdb/test", { method: "POST", body: JSON.stringify({ api_key: key || null }) });
        t.ok = r.ok;
        t.text = (r.ok ? r.message : r.error) + (r.remaining != null ? ` · ${r.remaining}/${r.limit} checks left today` : "");
      } catch (e) {
        t.ok = false;
        t.text = e.message;
      } finally {
        t.busy = false;
      }
    },

    async refreshAbuseStatus() {
      try { this.abuseStatus = await api("/intel/abuseipdb"); } catch (_) {}
    },

    abuseStatusText() {
      const s = this.abuseStatus || {};
      if (!s.configured) return "Not configured: add an API key to see AbuseIPDB scores next to Sentinel's.";
      if (!s.enabled) return "Configured but turned off.";
      const quota = s.remaining != null ? `${s.remaining} / ${s.limit} checks left today` : "quota unknown until the first lookup";
      return `ON · ${s.cached} cached · ${s.queued} queued · ${quota}` + (s.error ? ` · ${s.error}` : "");
    },

    /* ------------------------------------------------------------ themes */
    onGeneral(msg) {
      if (msg.abuseipdb) this.abuseStatus = msg.abuseipdb;
      if (msg.default_theme) {
        this.defaultTheme = msg.default_theme;
        try { localStorage.setItem(DEFAULT_THEME_KEY, msg.default_theme); } catch (_) {}
        if (!this.themeLocal) this.theme = applyTheme(msg.default_theme);
      }
    },

    setTheme(id) {
      this.themeLocal = id || "";
      try {
        if (id) localStorage.setItem(THEME_KEY, id);
        else localStorage.removeItem(THEME_KEY);
      } catch (_) {}
      this.theme = applyTheme(id || this.defaultTheme);
    },

    closeWhois() { this.whoisOpen = false; },

    W() { return (this.whois.data && this.whois.data.whois) || {}; },
    WI() { const i = this.whois.intel; return { state: (i && i.state) || null, recent: (i && i.recent) || [] }; },
    WS() { return this.WI().state || {}; },
    WB() { return (this.whois.data && this.whois.data.bans) || []; },

    whoisBanned(sid) {
      const prov = this.firewall.provider;
      const hit = (b) => (b.provider || "windows") === prov && (this.firewall.perimeter || b.server_id === sid);
      if (this.whois.data && this.whois.data.bans.some(hit)) return true;
      return this.bans.some((b) => b.ip_address === this.whois.ip && hit(b));
    },

    async whoisBan() {
      const w = this.whois;
      if (!this.whoisOpen || !w.banServer || w.banBusy) return;
      const srv = this.serverById(Number(w.banServer));
      if (!srv) return;
      if (!window.confirm(this.banPrompt(w.ip, srv.server_name))) return;
      w.banBusy = true;
      try {
        const r = await api("/defense/ban", { method: "POST", body: JSON.stringify({ server_id: srv.id, ip: w.ip }) });
        this.onBan({ data: r.ban, alert_ids: r.alert_ids, status: "Approved" });
        if (w.data && r.ban && !w.data.bans.some((b) => b.id === r.ban.id)) w.data.bans.push(r.ban);
      } catch (e) {
        this.toast({ severity: "CRITICAL", category: "ban failed", server_name: srv.server_name, title: e.message }, 10000);
      } finally {
        w.banBusy = false;
      }
    },

    async copyText(text) {
      try {
        await navigator.clipboard.writeText(text);
      } catch (_) {
        const ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand("copy"); } catch (__) {}
        ta.remove();
      }
      this.toast({ severity: "INFO", ok: true, category: "clipboard", title: `${text} copied` }, 2500);
    },

    /* ------------------------------------------------------------ threat matrix */
    scoreWidth(t) { return Math.min(100, (t.score / (t.threshold * 2)) * 100); },
    scoreClass(t) { return t.active || t.score > t.threshold ? "red" : t.score >= t.threshold * 0.5 ? "amber" : ""; },

    /* ------------------------------------------------------------ health */
    get health() {
      const sel = this.selId();
      return (sel != null && this.healthBy[sel]) || {};
    },

    fleetHealth() {
      return this.enabledServers().map((s) => ({
        app_pools: [],
        ...(this.healthBy[s.id] || {}),
        server_id: s.id, server_name: s.server_name, ip_address: s.ip_address,
      }));
    },
    lvl(v, warn, crit) { return v == null ? "ok" : v >= crit ? "crit" : v >= warn ? "warn" : "ok"; },
    cardBars(h) {
      return [
        { k: "CPU", v: h.cpu_percent || 0, level: this.lvl(h.cpu_percent, 75, 90) },
        { k: "RAM", v: h.ram_percent || 0, level: this.lvl(h.ram_percent, 80, 92) },
        { k: "DSK", v: h.disk_percent || 0, level: h.disk_free_percent < 5 ? "crit" : h.disk_free_percent < 15 ? "warn" : "ok" },
      ];
    },
    poolsUp(h) { return (h.app_pools || []).filter((p) => p.running).length; },
    poolsDown(h) { return (h.app_pools || []).some((p) => !p.running); },
    cardAlarm(h) {
      return h.online === false || this.poolsDown(h) || (h.disk_free_percent != null && h.disk_free_percent < 5) || h.cpu_percent > 90;
    },

    gauges() {
      const h = this.health || {};
      const cpuThr = 90;
      const lvl = this.lvl;
      const diskFree = h.disk_free_percent;
      return [
        { key: "cpu", label: "CPU", value: h.cpu_percent, level: lvl(h.cpu_percent, 75, cpuThr), sub: h.cpu_count ? `${h.cpu_count} CORES` : "" },
        { key: "ram", label: "RAM", value: h.ram_percent, level: lvl(h.ram_percent, 80, 92), sub: h.ram_total_gb ? `${h.ram_total_gb} GB` : "" },
        {
          key: "disk", label: "DISK", value: h.disk_percent,
          level: diskFree == null ? "ok" : diskFree < 5 ? "crit" : diskFree < 15 ? "warn" : "ok",
          sub: diskFree != null ? `${diskFree.toFixed(1)}% FREE` : "",
        },
      ];
    },

    healthAlarm() {
      const h = this.health || {};
      return h.online === false || (h.app_pools || []).some((p) => !p.running) || (h.disk_free_percent != null && h.disk_free_percent < 5) || h.cpu_percent > 90;
    },

    svcClass(s) {
      if (!s) return "muted";
      if (s === "RUNNING") return "neon-green";
      if (s === "N/A" || s === "UNKNOWN") return "muted";
      return "neon-red";
    },

    /* ------------------------------------------------------------ baseline */
    scopeBaseline() {
      const sel = this.selId();
      if (sel == null || !this.baseline) return this.baseline || {};
      return (this.baseline.per_server && this.baseline.per_server[sel]) || { current: {}, global: {} };
    },
    cur() { return this.scopeBaseline().current || {}; },
    g(metric) { const b = this.scopeBaseline(); return (b.global && b.global[metric]) || { mean: 0, std: 0 }; },
    zmeters() {
      const c = this.cur();
      return [
        { key: "rpm", label: "VOLUME DEVIATION", value: Number(c.z_rpm || 0) },
        { key: "bpm", label: "BANDWIDTH DEVIATION", value: Number(c.z_bpm || 0) },
        { key: "tt", label: "LATENCY DEVIATION", value: Number(c.z_time_taken || 0) },
      ];
    },
    zPos(z) { return Math.max(0, Math.min(100, 50 + (z / 5) * 50)); },
    zClass(z) { const a = Math.abs(z); return a > 3 ? "neon-red" : a > 2 ? "neon-amber" : "neon-cyan"; },
    zNeedle(z) { const a = Math.abs(z); return a > 3 ? "red" : a > 2 ? "amber" : ""; },

    sparkPoints() {
      const h = this.rpmHistory;
      if (h.length < 2) return [];
      const max = Math.max(...h, 1);
      const step = 300 / (h.length - 1);
      return h.map((v, i) => [(i * step).toFixed(1), (44 - (v / max) * 40).toFixed(1)]);
    },
    sparkLine() { return this.sparkPoints().map((p) => p.join(",")).join(" "); },
    sparkArea() {
      const p = this.sparkPoints();
      if (!p.length) return "";
      return `0,46 ${p.map((x) => x.join(",")).join(" ")} 300,46`;
    },

    /* ------------------------------------------------------------ formatting */
    fmtNum(n) {
      n = Number(n || 0);
      if (Math.abs(n) >= 1e6) return (n / 1e6).toFixed(1) + "M";
      if (Math.abs(n) >= 1e4) return (n / 1e3).toFixed(1) + "K";
      return Number.isInteger(n) ? n.toLocaleString() : n.toFixed(1);
    },
    fmtBytes(n) {
      n = Number(n || 0);
      const u = ["B", "KB", "MB", "GB", "TB"];
      let i = 0;
      while (Math.abs(n) >= 1024 && i < u.length - 1) { n /= 1024; i++; }
      return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
    },
    fmtTime(iso) {
      if (!iso) return "—";
      const d = new Date(iso);
      if (isNaN(d)) return iso;
      return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}Z`;
    },
    fmtDate(iso) {
      if (!iso) return "—";
      const d = new Date(iso);
      return isNaN(d) ? String(iso) : `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
    },
    fmtDuration(s) {
      if (s == null) return "—";
      s = Math.floor(s);
      const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
      return `${d}D ${pad(h)}H ${pad(m)}M`;
    },

    /* ------------------------------------------------------------ config drawer */
    async openConfig(tab) {
      if (tab) this.cfgTab = tab;
      this.cfgOpen = true;
      this.cfgMsg = { ok: true, text: "" };
      await this.loadConfig();
      this.refreshServers();
      this.loadReports();
      this.loadAlertCatalog();
      if (this.cfgTab === "allowlist") this.loadAllowlist();
      if (this.cfgTab === "general") { this.refreshAbuseStatus(); this.loadGeoStatus(); }
    },

    switchTab(t) {
      this.cfgTab = t;
      this.cfgMsg = { ok: true, text: "" };
      if (t === "alerts") this.loadAlertCatalog();
      if (t === "general") { this.refreshAbuseStatus(); this.loadGeoStatus(); }
      if (t === "allowlist") this.loadAllowlist();
      if (t === "watchers") { this.refreshServers(); this.loadGeoStatus(); }
    },

    async loadGeoStatus() {
      try { this.geoStatus = await api("/geoip"); } catch (_) { this.geoStatus = null; }
    },

    geoStatusText() {
      const g = this.geoStatus;
      if (!g) return "";
      if (g.database) return `Location source: ${g.source}${g.built ? " (built " + g.built + ")" : ""}`;
      return g.source === "rdap-country" ? "Location source: WHOIS registry country (no GeoIP database yet)" : "Location source: none";
    },

    async testFirewall() {
      const f = this.form && this.form.firewall;
      if (!f || f.provider === "windows" || this.busy) return;
      const label = (FIREWALLS.find((x) => x.id === f.provider) || {}).label || f.provider;
      this.busy = true;
      this.cfgMsg = { ok: true, text: `Testing ${label} with the settings on screen (not saved)…` };
      try {
        const r = await api("/firewall/test", { method: "POST", body: JSON.stringify({ provider: f.provider, settings: f }) });
        this.cfgMsg = { ok: r.ok, text: (r.ok ? "CONNECTION OK: " : "TEST FAILED: ") + r.message };
        this.toast({ severity: r.ok ? "INFO" : "HIGH", ok: r.ok, category: `${label} test`,
                     title: r.ok ? "Connection OK" : "Connection FAILED", message: r.message }, r.ok ? 7000 : 12000);
      } catch (e) {
        this.cfgMsg = { ok: false, text: e.message };
        this.toast({ severity: "HIGH", category: `${label} test`, title: "Connection FAILED", message: e.message }, 12000);
      } finally {
        this.busy = false;
      }
    },

    async loadFwGroups() {
      const g = this.fwGroups;
      g.loading = true;
      g.error = "";
      try {
        const r = await api("/firewall/groups");
        g.list = r.groups || [];
        g.loaded = true;
      } catch (e) {
        g.error = e.message;
      } finally {
        g.loading = false;
      }
    },

    async createFwGroup() {
      const g = this.fwGroups;
      const name = g.name.trim();
      if (!name || g.busy._create) return;
      g.busy._create = true;
      try {
        const r = await api("/firewall/groups", { method: "POST", body: JSON.stringify({ name, description: g.description.trim() }) });
        this.toast({ severity: "INFO", ok: true, category: "sonicwall", title: r.message });
        g.name = "";
        g.description = "";
        await this.loadFwGroups();
      } catch (e) {
        this.toast({ severity: "HIGH", category: "sonicwall", title: "Create group failed", message: e.message }, 12000);
      } finally {
        delete g.busy._create;
      }
    },

    async deleteFwGroup(grp) {
      const g = this.fwGroups;
      if (!window.confirm(`Delete SonicWall address group ${grp.name}?\n\nAny access rule that references it must be changed first.`)) return;
      g.busy[grp.name] = true;
      try {
        const r = await api(`/firewall/groups?name=${encodeURIComponent(grp.name)}`, { method: "DELETE" });
        this.toast({ severity: "INFO", ok: true, category: "sonicwall", title: r.message });
        await this.loadFwGroups();
      } catch (e) {
        this.toast({ severity: "HIGH", category: "sonicwall", title: "Delete group failed", message: e.message }, 12000);
      } finally {
        delete g.busy[grp.name];
      }
    },

    useFwGroup(grp) {
      if (this.form && this.form.firewall) this.form.firewall.sonicwall_group = grp.name;
      this.cfgMsg = { ok: true, text: `Default ban group set to ${grp.name}. SAVE FIREWALL to apply.` };
    },

    async loadAlertCatalog() {
      try {
        this.alertCatalog = await api("/alerts/catalog");
      } catch (e) {
        this.cfgMsg = { ok: false, text: `Failed to load alert catalog: ${e.message}` };
      }
    },

    eventsIn(gid) {
      if (!this.alertCatalog || !this.form || !this.form.alerts) return [];
      return this.alertCatalog.events.filter((e) => e.group === gid && this.form.alerts.events[e.id]);
    },

    bulkEvents(gid, field, val) {
      this.eventsIn(gid).forEach((e) => {
        const st = this.form.alerts.events[e.id];
        if (val && !st.enabled) st.enabled = true;
        st[field] = val;
      });
    },

    enabledEventCount() {
      if (!this.form || !this.form.alerts) return 0;
      return Object.values(this.form.alerts.events || {}).filter((e) => e.enabled).length;
    },

    async loadConfig() {
      try {
        const r = await api("/config");
        const form = JSON.parse(JSON.stringify(r.config));
        for (const [section, keys] of Object.entries(LIST_FIELDS)) {
          if (form[section]) keys.forEach((k) => { form[section][k] = (form[section][k] || []).join("\n"); });
        }
        if (form.alerts && !Array.isArray(form.alerts.muted_servers)) form.alerts.muted_servers = [];
        this.form = form;
        this.watcherStatus = r.watchers_status || [];
        this.nextRuns = r.report_next_runs || {};
      } catch (e) {
        this.cfgMsg = { ok: false, text: `Failed to load config: ${e.message}` };
      }
    },

    async loadReports() {
      try {
        const r = await api("/reports");
        this.reports = r.reports || [];
        this.nextRuns = r.next_runs || this.nextRuns;
      } catch (e) { console.error(e); }
    },

    async saveConfig() {
      if (!this.form) return;
      this.busy = true;
      this.cfgMsg = { ok: true, text: "" };
      const section = this.cfgTab;
      try {
        const payload = { [section]: { ...this.form[section] } };
        if (section === "general") {
          payload.watchers = { retention_days: this.form.watchers.retention_days, geoip_auto_download: this.form.watchers.geoip_auto_download };
        }
        await api("/config", { method: "POST", body: JSON.stringify(payload) });
        await this.loadConfig();
        if (section === "alerts" || section === "exchange") this.loadAlertCatalog();
        if (section === "firewall") { try { this.firewall = await api("/firewall"); } catch (_) {} }
        if (section === "watchers" || section === "general") this.loadGeoStatus();
        if (section === "general") { abuseAsked.clear(); this.refreshAbuseStatus(); }
        this.cfgMsg = { ok: true, text: `${section.toUpperCase()} configuration saved.` };
      } catch (e) {
        this.cfgMsg = { ok: false, text: e.message };
      } finally {
        this.busy = false;
      }
    },

    async testMail() {
      this.busy = true;
      this.cfgMsg = { ok: true, text: "Contacting Exchange…" };
      try {
        const r = await api("/config/test/exchange", { method: "POST", body: JSON.stringify({ recipients: [] }) });
        this.cfgMsg = r.ok ? { ok: true, text: "Test message delivered." } : { ok: false, text: `Exchange: ${r.error}` };
      } catch (e) {
        this.cfgMsg = { ok: false, text: e.message };
      } finally {
        this.busy = false;
      }
    },

    async runReport(kind, send) {
      this.busy = true;
      this.cfgMsg = { ok: true, text: `Compiling ${kind} report…` };
      try {
        const r = await api("/reports/run", { method: "POST", body: JSON.stringify({ kind, send }) });
        const ok = r.status !== "failed";
        this.cfgMsg = { ok, text: `${r.subject} — ${r.status.toUpperCase()}${r.error ? ": " + r.error : ""}` };
        await this.loadReports();
        if (!send && r.id) window.open(`/reports/${r.id}/html`, "_blank", "noopener");
      } catch (e) {
        this.cfgMsg = { ok: false, text: e.message };
      } finally {
        this.busy = false;
      }
    },

    blankServer() {
      return {
        server_name: "", ip_address: "", winrm_username: "", winrm_password: "", log_unc_path: "",
        winrm_transport: "ntlm", winrm_port: "", winrm_use_ssl: false, winrm_verify_ssl: true,
        log_start_mode: "end", log_tail_lines: 1000, enabled: true,
      };
    },

    startModeLabel(mode, lines) {
      if (mode === "tail") return `LAST ${this.fmtNum(lines || 1000)} LINES, THEN FOLLOW`;
      return START_MODES[mode] || "NEW LINES ONLY";
    },

    sitesFor(sid) {
      const w = this.watcherStatus.filter((x) => x.server_id === sid);
      return w.flatMap((x) => x.sites || []);
    },

    siteLabel(sid, folder) {
      const m = /^W3SVC(\d+)$/i.exec(folder || "");
      const sites = (this.healthBy[sid] && this.healthBy[sid].sites) || [];
      const hit = m && sites.find((s) => s.id === Number(m[1]));
      return hit && hit.name ? `${hit.name} (${folder})` : folder || "—";
    },

    editServer(s) {
      this.editingId = s.id;
      this.cfgMsg = { ok: true, text: "" };
      this.newServer = {
        server_name: s.server_name, ip_address: s.ip_address, winrm_username: s.winrm_username || "", winrm_password: "",
        log_unc_path: s.log_unc_path || "", winrm_transport: s.winrm_transport || "ntlm", winrm_port: s.winrm_port || "",
        winrm_use_ssl: !!s.winrm_use_ssl, winrm_verify_ssl: s.winrm_verify_ssl !== false,
        log_start_mode: s.log_start_mode || "end", log_tail_lines: s.log_tail_lines || 1000, enabled: !!s.enabled,
      };
      this.$nextTick(() => {
        const el = document.getElementById("server-form");
        if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    },

    cancelEdit() {
      this.editingId = null;
      this.newServer = this.blankServer();
    },

    async saveServer() {
      this.busy = true;
      this.cfgMsg = { ok: true, text: "" };
      const body = { ...this.newServer };
      body.winrm_port = body.winrm_port === "" || body.winrm_port == null ? null : Number(body.winrm_port);
      body.log_tail_lines = Number(body.log_tail_lines) || 1000;
      try {
        if (this.editingId == null) {
          const r = await api("/servers", { method: "POST", body: JSON.stringify(body) });
          this.cfgMsg = { ok: true, text: `${r.server.server_name} registered — monitoring started. Use TEST to verify WinRM and the log share.` };
        } else {
          if (!body.winrm_password) delete body.winrm_password;
          if (body.winrm_port == null) delete body.winrm_port;
          const id = this.editingId;
          const r = await api(`/servers/${id}`, { method: "PUT", body: JSON.stringify(body) });
          delete this.testResults[id];
          this.cfgMsg = { ok: true, text: `${(r.server || body).server_name} updated — monitoring restarted with the new settings.` };
        }
        this.editingId = null;
        this.newServer = this.blankServer();
        await this.refreshServers();
      } catch (e) {
        this.cfgMsg = { ok: false, text: e.message };
      } finally {
        this.busy = false;
      }
    },

    async refreshServers() {
      try {
        const r = await api("/servers");
        this.setServers(r.servers || []);
        this.watcherStatus = r.logs || this.watcherStatus;
      } catch (e) { console.error(e); }
    },

    async testServer(s) {
      this.srvBusy[s.id] = "test";
      delete this.testResults[s.id];
      try {
        const r = await api(`/servers/${s.id}/test`, { method: "POST" });
        const w = r.winrm || {}, l = r.logs || {};
        const ok = !!(w.ok && l.ok);
        const names = {};
        (w.sites || []).forEach((x) => { names[x.id] = x.name; });
        const siteTxt = (l.sites || []).map((x) => {
          const m = /^W3SVC(\d+)$/i.exec(x.site);
          return m && names[Number(m[1])] ? `${names[Number(m[1])]} (${x.site})` : x.site;
        }).join(", ");
        const wTxt = w.ok ? `WinRM OK (${w.hostname || "?"}, ${w.app_pools} pools, ${(w.sites || []).length} sites)` : `WinRM FAIL: ${w.error}`;
        const lTxt = l.ok
          ? `logs OK: ${l.layout || ""} · ${(l.sites || []).length} site folder(s)${siteTxt ? " [" + siteTxt + "]" : ""}, ${l.files} file(s), newest ${l.newest || "—"}`
          : `logs FAIL: ${l.error}`;
        this.testResults[s.id] = { ok, text: `${wTxt}  |  ${lTxt}` };
      } catch (e) {
        this.testResults[s.id] = { ok: false, text: e.message };
      } finally {
        delete this.srvBusy[s.id];
      }
    },

    async toggleServer(s) {
      this.srvBusy[s.id] = "toggle";
      try {
        await api(`/servers/${s.id}`, { method: "PUT", body: JSON.stringify({ enabled: !s.enabled }) });
        await this.refreshServers();
      } catch (e) {
        this.cfgMsg = { ok: false, text: e.message };
      } finally {
        delete this.srvBusy[s.id];
      }
    },

    async deleteServer(s) {
      if (!window.confirm(`Remove ${s.server_name} (${s.ip_address}) from Sentinel?\nMonitoring stops immediately; historical logs and alerts are kept.`)) return;
      this.srvBusy[s.id] = "delete";
      try {
        await api(`/servers/${s.id}`, { method: "DELETE" });
        if (this.editingId === s.id) this.cancelEdit();
        await this.refreshServers();
        this.cfgMsg = { ok: true, text: `${s.server_name} removed.` };
      } catch (e) {
        this.cfgMsg = { ok: false, text: e.message };
      } finally {
        delete this.srvBusy[s.id];
      }
    },

    async logout() {
      try { await api("/logout", { method: "POST" }); } catch (_) {}
      window.location.href = "/";
    },
  };
}

window.loginApp = loginApp;
window.dashboardApp = dashboardApp;
