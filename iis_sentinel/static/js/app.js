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

const START_MODES = { end: "NEW LINES ONLY", full: "WHOLE FILE" };

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

    // WHOIS / IP intel modal
    whois: null,

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
          feed.buffer = [];
          termEl().replaceChildren();
          this.addLogs(msg.logs || []);
          this.loadPending();
          this.loadBans();
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
      const sel = this.selId();
      if (sel != null && l.server_id !== sel) return false;
      if (this.feedMode === "errors") return l.status >= 400 || !!l.tags;
      if (this.feedMode === "threats") return l.level === "critical" || !!l.tags;
      return true;
    },

    renderLine(l) {
      const div = document.createElement("div");
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
      if (this.paused) { this.pendingWhilePaused += lines.length; return; }
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

    async approveBan(p) {
      if (this.banBusy[p.key]) return;
      const ok = window.confirm(
        `APPROVE FIREWALL BAN\n\nBlock ${p.ip} on ${p.server_name}?\n\n` +
        `netsh advfirewall firewall add rule name="SENTINEL BAN: ${p.ip}" dir=in action=block remoteip=${p.ip}`
      );
      if (!ok) return;
      this.banBusy[p.key] = true;
      try {
        const r = await api("/defense/ban", { method: "POST", body: JSON.stringify({ alert_id: p.top.id }) });
        this.onBan({ data: r.ban, alert_ids: r.alert_ids, status: "Approved" });
      } catch (e) {
        this.toast({ severity: "CRITICAL", category: "ban failed", server_name: p.server_name, title: e.message }, 10000);
      } finally {
        delete this.banBusy[p.key];
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
        this.toast({ severity: "INFO", ok: true, category: "ban executed", server_name: ban.server_name, title: `${ban.ip_address} blocked by ${ban.rule_name}` });
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
      const keep = this.whois && this.whois.ip === ip ? this.whois : null;
      const first = this.enabledServers().find((s) => s.id === sid) || this.enabledServers()[0];
      const state = {
        ip, server_id: sid, loading: true, error: "", banBusy: false,
        data: keep ? keep.data : null, intel: keep ? keep.intel : null,
        banServer: keep ? keep.banServer : (first ? String(first.id) : ""),
      };
      this.whois = state;
      const enc = encodeURIComponent(ip);
      const [w, intel] = await Promise.allSettled([
        api(`/threats/whois/${enc}${refresh ? "?refresh=true" : ""}`),
        api(`/threats/ip/${enc}`),
      ]);
      if (this.whois !== state) return;
      if (w.status === "fulfilled") state.data = w.value;
      else state.error = `WHOIS: ${w.reason.message}`;
      if (intel.status === "fulfilled") state.intel = intel.value;
      state.loading = false;
    },

    closeWhois() { this.whois = null; },

    W() { return (this.whois && this.whois.data && this.whois.data.whois) || {}; },

    whoisBanned(sid) {
      if (this.whois && this.whois.data && this.whois.data.bans.some((b) => b.server_id === sid)) return true;
      return !!this.whois && this.bans.some((b) => b.server_id === sid && b.ip_address === this.whois.ip);
    },

    async whoisBan() {
      const w = this.whois;
      if (!w || !w.banServer || w.banBusy) return;
      const srv = this.serverById(Number(w.banServer));
      if (!srv) return;
      if (!window.confirm(`APPROVE FIREWALL BAN\n\nBlock ${w.ip} on ${srv.server_name}?\n\n` +
        `netsh advfirewall firewall add rule name="SENTINEL BAN: ${w.ip}" dir=in action=block remoteip=${w.ip}`)) return;
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
    },

    switchTab(t) {
      this.cfgTab = t;
      this.cfgMsg = { ok: true, text: "" };
      if (t === "alerts") this.loadAlertCatalog();
      if (t === "watchers") this.refreshServers();
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
        await api("/config", { method: "POST", body: JSON.stringify(payload) });
        await this.loadConfig();
        if (section === "alerts" || section === "exchange") this.loadAlertCatalog();
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
