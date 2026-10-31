/* NetLedger console. Vanilla JS, no dependencies: live updates, command palette, network map,
   configuration time machine, filters and chart crosshairs. Pages work without it. */
(() => {
  "use strict";
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const enc = encodeURIComponent;
  const body = document.body;
  const canTrigger = body.dataset.trigger === "1";
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const icon = (name, cls = "") => `<svg class="ic ${cls}" aria-hidden="true"><use href="#i-${name}"/></svg>`;
  const getJSON = async (url) => {
    const res = await fetch(url, { headers: { Accept: "application/json" }, credentials: "same-origin" });
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.json();
  };

  /* ---------------------------------------------------------------- relative time */
  function ago(ts) {
    const s = Math.max(0, Date.now() / 1000 - ts);
    if (s < 5) return "just now";
    if (s < 60) return `${Math.floor(s)}s ago`;
    const m = Math.floor(s / 60), h = Math.floor(m / 60), d = Math.floor(h / 24);
    if (m < 60) return `${m}m ago`;
    if (h < 24) return `${h}h ${m % 60}m ago`;
    if (d < 10) return `${d}d ${h % 24}h ago`;
    return `${d}d ago`;
  }
  const tickTimes = () => $$("time[data-ts]").forEach((t) => { t.textContent = ago(+t.dataset.ts); });
  setInterval(tickTimes, 15000);

  /* ---------------------------------------------------------------- theme */
  function setTheme(theme) {
    document.documentElement.dataset.theme = theme;
    document.cookie = `nl_theme=${theme}; path=/; max-age=31536000; samesite=lax`;
  }
  function toggleTheme() {
    const current = document.documentElement.dataset.theme;
    const dark = current === "dark" || (current === "auto" && !matchMedia("(prefers-color-scheme: light)").matches);
    setTheme(dark ? "light" : "dark");
  }
  document.addEventListener("click", (ev) => { if (ev.target.closest("[data-theme-toggle]")) toggleTheme(); });

  /* ---------------------------------------------------------------- toasts */
  const TOAST_ICON = {
    config_changed: "commit", backup_failed: "database", backup_recovered: "check", health_warning: "alert", health_critical: "alert",
    health_recovered: "check", device_rebooted: "refresh", compliance_failed: "shield", compliance_passed: "check", capacity_forecast: "trend",
  };
  function toast(title, message, tone = "low", glyph = "pulse", href = null) {
    const box = $("[data-toasts]");
    if (!box) return;
    const el = document.createElement("div");
    el.className = `toast t-${tone}`;
    el.innerHTML = `${icon(glyph)}<div><b>${esc(title)}</b>${message ? `<small>${esc(message)}</small>` : ""}</div><button aria-label="Dismiss">${icon("x")}</button>`;
    el.querySelector("button").addEventListener("click", () => el.remove());
    if (href) el.addEventListener("click", (ev) => { if (!ev.target.closest("button")) location.href = href; });
    box.prepend(el);
    while (box.children.length > 4) box.lastChild.remove();
    setTimeout(() => { el.classList.add("out"); setTimeout(() => el.remove(), 320); }, 9000);
  }

  /* ---------------------------------------------------------------- run buttons */
  document.addEventListener("click", async (ev) => {
    const btn = ev.target.closest("[data-run]");
    if (!btn) return;
    ev.preventDefault();
    const job = btn.dataset.run;
    btn.disabled = true;
    try {
      const res = await fetch(`/api/run/${job}`, { method: "POST", headers: { "X-NetLedger-Request": "1" }, credentials: "same-origin" });
      if (res.status === 202) toast(job === "backup" ? "Backup started" : "Health check started", "Progress appears live in the sidebar.", "low", "play");
      else if (res.status === 409) toast("Already running", `The ${job} job is in progress.`, "warn", "clock");
      else toast("Could not start", `HTTP ${res.status}`, "crit", "alert");
      poll(true);
    } catch (err) {
      toast("Could not start", String(err), "crit", "alert");
    } finally {
      setTimeout(() => { btn.disabled = false; }, 4000);
    }
  });

  /* ---------------------------------------------------------------- live updates */
  let rev = +body.dataset.rev || 0;
  let cursor = +body.dataset.cursor || 0;
  let refreshing = false;
  let lastRefresh = 0;
  let pollTimer = null;
  const liveEl = $("[data-live-indicator]");

  async function refreshRegions() {
    if (refreshing || Date.now() - lastRefresh < 2500) return;
    refreshing = true;
    lastRefresh = Date.now();
    try {
      const res = await fetch(location.href, { credentials: "same-origin", headers: { Accept: "text/html" } });
      if (!res.ok) return;
      const doc = new DOMParser().parseFromString(await res.text(), "text/html");
      $$("[data-live]").forEach((el) => {
        const key = el.dataset.live;
        if (!key) return;
        const fresh = doc.querySelector(`[data-live="${key}"]`);
        if (!fresh) return;
        if (key === "devices") {
          const tbody = $("tbody", el), freshBody = $("tbody", fresh);
          if (tbody && freshBody) { tbody.replaceWith(freshBody); applyTable(); }
          return;
        }
        if (key === "map") {
          const data = $("[data-topo-json]", fresh);
          if (data && maps.length) { maps.forEach((m) => m.update(JSON.parse(data.textContent))); return; }
        }
        if (el.contains(document.activeElement) && document.activeElement !== body) return;
        el.replaceWith(fresh);
        init(fresh);
      });
      const freshSide = doc.querySelector(".side-foot"), side = $(".side-foot");
      if (freshSide && side) side.replaceWith(freshSide);
      ["nav"].forEach((sel) => { const f = doc.querySelector(`.${sel}`), c = $(`.${sel}`); if (f && c) c.replaceWith(f); });
      tickTimes();
    } catch (err) {
      /* network hiccup: try again on the next poll */
    } finally {
      refreshing = false;
    }
  }

  async function poll(soon = false) {
    clearTimeout(pollTimer);
    let busy = false;
    try {
      const data = await getJSON(`/api/live?cursor=${cursor}`);
      busy = Object.keys(data.progress || {}).length > 0;
      if (liveEl) {
        liveEl.className = `live ${busy ? "busy" : "ok"}`;
        liveEl.querySelector("span").textContent = busy ? "Running" : "Live";
        liveEl.title = `Live updates · checked ${new Date().toLocaleTimeString()}`;
      }
      const prog = $("[data-topprog]");
      if (prog) prog.hidden = !busy;
      (data.activity || []).slice(-3).forEach((a) => {
        const tone = a.type && a.type.endsWith("recovered") ? "ok" : a.severity === "critical" ? "crit" : a.severity === "warning" ? "warn" : "low";
        toast(a.title, a.message, tone, TOAST_ICON[a.type] || "pulse", a.device ? `/devices/${enc(a.device)}` : null);
      });
      cursor = data.cursor || cursor;
      if (data.rev !== rev) {
        rev = data.rev;
        refreshRegions();
      }
    } catch (err) {
      if (liveEl) { liveEl.className = "live err"; liveEl.querySelector("span").textContent = "Offline"; }
    }
    pollTimer = setTimeout(poll, soon ? 1200 : busy ? 2500 : 6000);
  }
  setTimeout(poll, 1500);

  /* ---------------------------------------------------------------- devices table */
  const tableState = { text: "", chip: "all", sort: null, dir: 1 };
  function applyTable() {
    const table = $("#devices");
    if (!table) return;
    const rows = $$("tbody tr", table);
    let shown = 0;
    rows.forEach((r) => {
      if (!r.dataset.search) return;
      const okText = !tableState.text || r.dataset.search.includes(tableState.text);
      const okChip = tableState.chip === "all" || r.dataset[tableState.chip] === "1";
      r.style.display = okText && okChip ? "" : "none";
      if (okText && okChip) shown += 1;
    });
    if (tableState.sort) {
      const key = `s${tableState.sort[0].toUpperCase()}${tableState.sort.slice(1)}`;
      const tbody = $("tbody", table);
      rows.sort((a, b) => {
        const x = a.dataset[key], y = b.dataset[key];
        const nx = parseFloat(x), ny = parseFloat(y);
        const cmp = !isNaN(nx) && !isNaN(ny) ? nx - ny : String(x).localeCompare(String(y));
        return cmp * tableState.dir;
      }).forEach((r) => tbody.appendChild(r));
    }
    const count = $("[data-count]");
    if (count) count.textContent = shown === rows.length ? `${rows.length} devices` : `${shown} of ${rows.length} devices`;
  }
  document.addEventListener("input", (ev) => {
    if (ev.target.matches("[data-filter]")) { tableState.text = ev.target.value.toLowerCase().trim(); applyTable(); }
    if (ev.target.matches("[data-ledger-filter]")) applyLedger();
    if (ev.target.matches("[data-code-find]")) findInConfig(ev.target);
  });
  document.addEventListener("change", (ev) => { if (ev.target.matches("[data-unplanned-filter]")) applyLedger(); });
  document.addEventListener("click", (ev) => {
    const chip = ev.target.closest("[data-chips] button");
    if (chip) {
      $$("button", chip.parentElement).forEach((b) => b.classList.toggle("on", b === chip));
      tableState.chip = chip.dataset.f;
      applyTable();
    }
    const th = ev.target.closest("th[data-sort]");
    if (th) {
      const key = th.dataset.sort;
      tableState.dir = tableState.sort === key ? -tableState.dir : (key === "name" ? 1 : -1);
      if (key === "status") tableState.dir = tableState.sort === key ? tableState.dir : 1;
      tableState.sort = key;
      $$("th[data-sort]").forEach((h) => h.classList.remove("asc", "desc"));
      th.classList.add(tableState.dir > 0 ? "asc" : "desc");
      applyTable();
    }
  });
  const params = new URLSearchParams(location.search);

  /* ---------------------------------------------------------------- change ledger filters */
  let ledgerRisk = "all";
  function applyLedger() {
    const text = ($("[data-ledger-filter]") || { value: "" }).value.toLowerCase().trim();
    const unplanned = ($("[data-unplanned-filter]") || {}).checked;
    $$(".ledger-full .entry").forEach((e) => {
      const ok = (ledgerRisk === "all" || e.dataset.risk === ledgerRisk) && (!unplanned || e.dataset.unplanned === "1") && (!text || e.dataset.search.includes(text));
      e.style.display = ok ? "" : "none";
    });
    $$(".ledger-full .day").forEach((d) => { d.style.display = $$(".entry", d).some((e) => e.style.display !== "none") ? "" : "none"; });
  }
  document.addEventListener("click", (ev) => {
    const b = ev.target.closest("[data-risk-filter] button");
    if (!b) return;
    $$("button", b.parentElement).forEach((x) => x.classList.toggle("on", x === b));
    ledgerRisk = b.dataset.r;
    applyLedger();
  });

  /* ---------------------------------------------------------------- charts */
  function bindCharts(root) {
    $$("[data-chart]", root).forEach((chart) => {
      if (chart.dataset.bound) return;
      chart.dataset.bound = "1";
      const svg = $("svg", chart), xh = $(".xh", svg), tip = $(".chart-tip", chart);
      const points = JSON.parse(chart.dataset.points || "[]");
      if (!points.length) return;
      const start = +chart.dataset.start, end = +chart.dataset.end, left = +chart.dataset.left, width = +chart.dataset.width, W = +chart.dataset.w;
      const unit = chart.dataset.unit;
      svg.addEventListener("mousemove", (ev) => {
        const rect = svg.getBoundingClientRect();
        const vx = ((ev.clientX - rect.left) / rect.width) * W;
        const t = start + ((vx - left) / width) * (end - start);
        let best = points[0];
        for (const p of points) if (Math.abs(p[0] - t) < Math.abs(best[0] - t)) best = p;
        const px = left + ((best[0] - start) / (end - start)) * width;
        xh.setAttribute("transform", `translate(${px} 0)`);
        const d = new Date(best[0] * 1000);
        tip.textContent = `${d.toLocaleDateString([], { month: "short", day: "numeric" })} ${d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })} · ${unit === "%" ? Math.round(best[1]) : best[1].toFixed(1)}${unit}`;
        tip.style.left = `${(px / W) * rect.width + 14}px`;
        chart.classList.add("hover");
      });
      svg.addEventListener("mouseleave", () => chart.classList.remove("hover"));
    });
  }

  /* ---------------------------------------------------------------- trends range */
  document.addEventListener("click", async (ev) => {
    const a = ev.target.closest("[data-range] a");
    if (!a) return;
    const panel = a.closest("[data-trends]");
    if (!panel) return;
    ev.preventDefault();
    $$("a", a.parentElement).forEach((x) => x.classList.toggle("on", x === a));
    try {
      const data = await getJSON(`/api/devices/${enc(panel.dataset.device)}/trends?range=${a.dataset.r}`);
      const target = $("[data-trends-body]", panel);
      target.innerHTML = data.html;
      bindCharts(target);
      const url = new URL(location.href);
      url.searchParams.set("range", a.dataset.r);
      history.replaceState(null, "", url.pathname + url.search + "#trends");
    } catch (err) { location.href = a.href; }
  });

  /* ---------------------------------------------------------------- configuration time machine */
  function initTimeMachine(root) {
    $$("[data-tm]", root).forEach((tm) => {
      if (tm.dataset.bound) return;
      tm.dataset.bound = "1";
      const device = tm.dataset.device;
      let from = tm.dataset.from || null, to = tm.dataset.to, view = "diff", layout = "unified", last = null;
      const diffBox = $("[data-tm-diff]", tm), configBox = $("[data-tm-config]", tm), intelBox = $("[data-tm-intel]", tm), head = $("[data-tm-head]", tm);
      const mark = () => {
        $$(".v", tm).forEach((li) => { li.classList.toggle("to", li.dataset.sha === to); li.classList.toggle("from", li.dataset.sha === from); });
        $$(".vd", tm).forEach((g) => { g.classList.toggle("to", g.dataset.sha === to); g.classList.toggle("from", g.dataset.sha === from); });
      };
      const renderDiff = () => {
        if (!last) return;
        diffBox.innerHTML = last.html[layout] || '<div class="diff-empty">This is the first version: switch to <b>Full config</b> to read it.</div>';
      };
      async function loadConfig(line) {
        const target = $("[data-code-body]", configBox);
        target.innerHTML = '<div class="empty">Loading…</div>';
        try {
          const data = await getJSON(`/api/devices/${enc(device)}/config?rev=${to}${line ? `&line=${line}` : ""}`);
          target.innerHTML = data.html;
          const count = $("[data-code-count]", configBox);
          if (count) count.textContent = `${data.lines} lines · ${data.rev.slice(0, 7)}`;
          const hit = $(".cl.hit", target);
          if (hit) setTimeout(() => hit.scrollIntoView({ block: "center" }), 60);
        } catch (err) { target.innerHTML = `<div class="empty">Could not load this version (${esc(err.message)}).</div>`; }
      }
      async function load() {
        mark();
        const download = $("[data-tm-download]", tm);
        if (download) download.href = `/api/devices/${enc(device)}/config?rev=${to}&download=1`;
        const url = new URL(location.href);
        url.searchParams.set("to", to);
        if (from) url.searchParams.set("from", from); else url.searchParams.delete("from");
        history.replaceState(null, "", url.pathname + url.search + "#timemachine");
        if (view === "config") { loadConfig(); return; }
        diffBox.style.opacity = ".55";
        try {
          last = await getJSON(`/api/devices/${enc(device)}/diff?to=${to}${from ? `&from=${from}` : ""}`);
          head.innerHTML = last.html.head;
          intelBox.innerHTML = last.html.intel;
          renderDiff();
        } catch (err) {
          diffBox.innerHTML = `<div class="diff-empty">Could not compare these versions (${esc(err.message)}).</div>`;
        } finally { diffBox.style.opacity = ""; }
      }
      const pick = (sha, prev, shift) => {
        if (shift) { if (sha !== to) from = sha; }
        else { to = sha; from = prev || null; }
        load();
      };
      tm.addEventListener("click", (ev) => {
        const li = ev.target.closest(".v");
        if (li) { pick(li.dataset.sha, li.dataset.prev, ev.shiftKey); return; }
        const dotEl = ev.target.closest(".vd");
        if (dotEl) {
          const item = $(`.v[data-sha="${dotEl.dataset.sha}"]`, tm);
          pick(dotEl.dataset.sha, item && item.dataset.prev, ev.shiftKey);
          return;
        }
        const v = ev.target.closest("[data-tm-view] button");
        if (v) {
          view = v.dataset.v;
          $$("[data-tm-view] button", tm).forEach((b) => b.classList.toggle("on", b === v));
          configBox.hidden = view !== "config";
          diffBox.hidden = view !== "diff";
          intelBox.hidden = view !== "diff";
          $("[data-tm-layout]", tm).style.visibility = view === "diff" ? "" : "hidden";
          if (view === "config") loadConfig(); else if (!last) load(); else renderDiff();
          return;
        }
        const l = ev.target.closest("[data-tm-layout] button");
        if (l) {
          layout = l.dataset.l;
          $$("[data-tm-layout] button", tm).forEach((b) => b.classList.toggle("on", b === l));
          if (!last) load(); else renderDiff();
          return;
        }
        const row = ev.target.closest(".cl.hd");
        if (row && !ev.target.closest("a")) { row.classList.toggle("folded"); refold($("[data-code-body]", tm)); return; }
        if (ev.target.closest("[data-fold-all]")) {
          const rows = $$(".cl.hd:not([data-d])", tm);
          const fold = !rows.some((r) => r.classList.contains("folded"));
          rows.forEach((r) => r.classList.toggle("folded", fold));
          refold($("[data-code-body]", tm));
        }
      });
      tm.addEventListener("keydown", (ev) => {
        const li = ev.target.closest(".v");
        if (li && (ev.key === "Enter" || ev.key === " ")) { ev.preventDefault(); pick(li.dataset.sha, li.dataset.prev, ev.shiftKey); }
      });
      if (params.get("view") === "config") {
        const btn = $('[data-tm-view] button[data-v="config"]', tm);
        if (btn) {
          view = "config";
          $$("[data-tm-view] button", tm).forEach((b) => b.classList.toggle("on", b === btn));
          configBox.hidden = false; diffBox.hidden = true; intelBox.hidden = true;
          $("[data-tm-layout]", tm).style.visibility = "hidden";
          loadConfig(params.get("line"));
          setTimeout(() => tm.scrollIntoView({ block: "start" }), 50);
        }
      }
    });
  }
  function refold(code) {
    if (!code) return;
    const rows = $$(".cl", code);
    const ranges = rows.filter((r) => r.classList.contains("folded")).map((r) => [+r.dataset.n, +r.dataset.end]);
    rows.forEach((r) => {
      const n = +r.dataset.n;
      r.classList.toggle("hidden", ranges.some(([a, b]) => n > a && n <= b));
    });
  }
  function findInConfig(input) {
    const code = input.closest("[data-tm-config]").querySelector("[data-code-body]");
    const text = input.value.toLowerCase().trim();
    let hits = 0, first = null;
    $$(".cl", code).forEach((r) => {
      const match = text && r.querySelector("code").textContent.toLowerCase().includes(text);
      r.classList.toggle("found", !!match);
      if (match) { hits += 1; first = first || r; }
    });
    const count = input.closest("[data-tm-config]").querySelector("[data-code-count]");
    if (count && text) count.textContent = `${hits} matching line${hits === 1 ? "" : "s"}`;
    if (first) {
      $$(".cl.folded", code).forEach((r) => r.classList.remove("folded"));
      refold(code);
      first.scrollIntoView({ block: "center" });
    }
  }

  /* ---------------------------------------------------------------- network map */
  const maps = [];
  const POS_KEY = "nl-topo-positions";
  const loadPos = () => { try { return JSON.parse(localStorage.getItem(POS_KEY) || "{}"); } catch (e) { return {}; } };
  const savePos = (p) => { try { localStorage.setItem(POS_KEY, JSON.stringify(p)); } catch (e) { /* private mode */ } };
  const KIND_ICON = { switch: "switch", router: "router", firewall: "shield", wireless: "wireless", host: "host" };
  const STATUS_TONE = { ok: "ok", warning: "warn", critical: "crit", unknown: "unk", external: "unk" };
  const SVGNS = "http://www.w3.org/2000/svg";
  const hue = (s) => { let h = 0; for (const c of s || "?") h = (h * 31 + c.charCodeAt(0)) % 360; return h; };

  function layoutSite(nodes, links) {
    const n = nodes.length;
    const pos = new Map();
    const order = [...nodes].sort((a, b) => (a.external - b.external) || (b.degree - a.degree) || a.id.localeCompare(b.id));
    const r0 = 26 + 22 * Math.sqrt(n);
    order.forEach((node, i) => {
      const angle = (i / Math.max(1, n)) * Math.PI * 2 + 0.6;
      const r = node.external ? r0 * 1.35 : r0 * (n > 1 ? 0.75 : 0);
      pos.set(node.id, { x: Math.cos(angle) * r, y: Math.sin(angle) * r });
    });
    const ids = new Set(nodes.map((x) => x.id));
    const local = links.filter((l) => ids.has(l.source) && ids.has(l.target));
    const iterations = n > 120 ? 140 : 320;
    for (let it = 0; it < iterations; it++) {
      const step = 18 * (1 - it / iterations) + 0.6;
      const force = new Map(nodes.map((x) => [x.id, { x: 0, y: 0 }]));
      for (let i = 0; i < n; i++) {
        for (let j = i + 1; j < n; j++) {
          const a = pos.get(nodes[i].id), b = pos.get(nodes[j].id);
          let dx = a.x - b.x, dy = a.y - b.y;
          let d2 = dx * dx + dy * dy;
          if (d2 < 0.01) { dx = 0.1 * (i - j); dy = 0.1; d2 = 0.02; }
          const f = 9500 / d2;
          const d = Math.sqrt(d2);
          const fx = (dx / d) * f, fy = (dy / d) * f;
          force.get(nodes[i].id).x += fx; force.get(nodes[i].id).y += fy;
          force.get(nodes[j].id).x -= fx; force.get(nodes[j].id).y -= fy;
        }
      }
      local.forEach((l) => {
        const a = pos.get(l.source), b = pos.get(l.target);
        const dx = b.x - a.x, dy = b.y - a.y, d = Math.sqrt(dx * dx + dy * dy) || 0.01;
        const ext = l.ext ? 88 : 128;
        const f = (d - ext) * 0.08;
        force.get(l.source).x += (dx / d) * f; force.get(l.source).y += (dy / d) * f;
        force.get(l.target).x -= (dx / d) * f; force.get(l.target).y -= (dy / d) * f;
      });
      nodes.forEach((node) => {
        const p = pos.get(node.id), f = force.get(node.id);
        f.x -= p.x * 0.016; f.y -= p.y * 0.022;
        const m = Math.sqrt(f.x * f.x + f.y * f.y);
        if (m > 0) { p.x += (f.x / m) * Math.min(step, m); p.y += (f.y / m) * Math.min(step, m); }
      });
    }
    return pos;
  }

  function layoutAll(data, aspect) {
    const bySite = new Map();
    data.nodes.forEach((n) => { if (!bySite.has(n.site)) bySite.set(n.site, []); bySite.get(n.site).push(n); });
    const linkInfo = data.links.map((l) => ({ ...l, ext: (data.nodes.find((n) => n.id === l.target) || {}).external }));
    const boxes = [];
    bySite.forEach((nodes, site) => {
      const pos = layoutSite(nodes, linkInfo);
      let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
      pos.forEach((p) => { minX = Math.min(minX, p.x); minY = Math.min(minY, p.y); maxX = Math.max(maxX, p.x); maxY = Math.max(maxY, p.y); });
      const pad = 58;
      boxes.push({ site, pos, w: maxX - minX + pad * 2, h: maxY - minY + pad * 2 + 18, ox: -minX + pad, oy: -minY + pad + 18 });
    });
    const gap = 34;
    const pack = (perRow) => {
      const placed = [];
      let x = 0, y = 0, rowH = 0, width = 0;
      boxes.forEach((box, i) => {
        if (i > 0 && i % perRow === 0) { x = 0; y += rowH + gap; rowH = 0; }
        placed.push({ box, x, y });
        x += box.w + gap;
        rowH = Math.max(rowH, box.h);
        width = Math.max(width, x - gap);
      });
      return { placed, width, height: y + rowH };
    };
    const packColumns = (count) => {
      const columns = Array.from({ length: count }, () => ({ items: [], h: 0, w: 0 }));
      [...boxes].sort((a, b) => b.h - a.h).forEach((box) => {
        const column = columns.reduce((low, c) => (c.h < low.h ? c : low), columns[0]);
        column.h += (column.items.length ? gap : 0) + box.h;
        column.w = Math.max(column.w, box.w);
        column.items.push(box);
      });
      const placed = [];
      let x = 0;
      columns.filter((c) => c.items.length).forEach((c) => {
        let y = 0;
        c.items.forEach((box) => { placed.push({ box, x: x + (c.w - box.w) / 2, y }); y += box.h + gap; });
        x += c.w + gap;
      });
      return { placed, width: x - gap, height: Math.max(...columns.map((c) => c.h)) };
    };
    let best = null;
    for (let k = 1; k <= Math.max(1, boxes.length); k++) {
      for (const p of [pack(k), packColumns(k)]) {
        const scale = Math.min(aspect / p.width, 1 / p.height);
        if (!best || scale > best.scale * 1.01) best = { ...p, scale };
      }
    }
    const out = new Map(), hulls = [];
    (best ? best.placed : []).forEach(({ box, x, y }) => {
      box.pos.forEach((p, id) => out.set(id, { x: x + box.ox + p.x, y: y + box.oy + p.y }));
      hulls.push({ site: box.site, x, y, w: box.w, h: box.h });
    });
    return { pos: out, hulls };
  }

  function createMap(container) {
    const json = $("[data-topo-json]", container);
    const mini = !!container.closest(".mini");
    const trim = (d) => {
      if (!mini) return d;
      const keep = new Set(d.nodes.filter((n) => !n.external).map((n) => n.id));
      return { ...d, nodes: d.nodes.filter((n) => keep.has(n.id)), links: d.links.filter((l) => keep.has(l.source) && keep.has(l.target)) };
    };
    let data = trim(JSON.parse(json.textContent));
    const tip = $(".topo-tip", container);
    const panel = container.closest(".topo-panel");
    let mode = "health";
    let svg = null, view = null, positions = null, hullData = [], nodeEls = new Map(), linkEls = [];
    const now = +container.dataset.now || Date.now() / 1000;

    function tone(node) { return STATUS_TONE[node.status] || "unk"; }
    function el(name, attrs = {}, parent = null) {
      const e = document.createElementNS(SVGNS, name);
      Object.entries(attrs).forEach(([k, v]) => e.setAttribute(k, v));
      if (parent) parent.appendChild(e);
      return e;
    }
    function nodeClass(node) {
      const changed = node.change_ts && now - node.change_ts < 86400;
      return `node t-${tone(node)} k-${node.kind}${node.external ? " ext" : ""}${changed ? ` changed cr-${node.change_risk || "low"}` : ""}`;
    }
    function fit() {
      let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
      hullData.forEach((h) => { minX = Math.min(minX, h.x); minY = Math.min(minY, h.y); maxX = Math.max(maxX, h.x + h.w); maxY = Math.max(maxY, h.y + h.h); });
      if (!isFinite(minX)) { minX = 0; minY = 0; maxX = 400; maxY = 300; }
      const pad = 20, band = 46;
      const rect = container.getBoundingClientRect();
      const available = Math.max(1, rect.height - band);
      let w = maxX - minX + pad * 2, h = maxY - minY + pad * 2;
      const aspect = rect.width / available;
      if (w / h < aspect) { const nw = h * aspect; minX -= (nw - w) / 2; w = nw; } else { const nh = w / aspect; minY -= (nh - h) / 2; h = nh; }
      view = { x: minX - pad, y: minY - pad, w, h: h + (h * band) / available };
      svg.setAttribute("viewBox", `${view.x} ${view.y} ${view.w} ${view.h}`);
    }
    function draw() {
      if (svg) svg.remove();
      const rect = container.getBoundingClientRect();
      const laid = layoutAll(data, Math.max(0.6, rect.width / Math.max(1, rect.height - 46)));
      positions = laid.pos;
      hullData = laid.hulls;
      const saved = loadPos();
      positions.forEach((p, id) => { if (saved[id]) { p.x = saved[id][0]; p.y = saved[id][1]; } });
      svg = el("svg", { class: "topo-svg", role: "img", "aria-label": "Network map" });
      container.prepend(svg);
      const gH = el("g", { class: "hulls" }, svg), gL = el("g", { class: "links" }, svg), gN = el("g", { class: "nodes" }, svg);
      hullData.forEach((h) => {
        el("rect", { class: "hull", x: h.x, y: h.y, width: h.w, height: h.h, rx: 22 }, gH);
        const t = el("text", { class: "hull-label", x: h.x + 18, y: h.y + 24 }, gH);
        t.textContent = h.site || "unassigned";
      });
      linkEls = data.links.map((l) => {
        const line = el("line", { class: `link ${l.status}` }, gL);
        line.__link = l;
        return line;
      });
      nodeEls = new Map();
      data.nodes.forEach((node) => {
        const g = el("g", { class: nodeClass(node) }, gN);
        const r = node.external ? 12 : 17;
        el("circle", { class: "halo", r: r + 2 }, g);
        el("circle", { class: "ring", r: r + 6 }, g);
        el("circle", { class: "bg", r }, g);
        const glyph = el("svg", { class: "ic glyph", x: -(r * 0.55), y: -(r * 0.55), width: r * 1.1, height: r * 1.1 }, g);
        el("use", { href: `#i-${KIND_ICON[node.kind] || "switch"}` }, glyph);
        const label = el("text", { class: "lbl", y: r + 15, "text-anchor": "middle" }, g);
        label.textContent = node.label;
        g.__node = node;
        if (mode === "vendor") g.style.setProperty("--tone", `hsl(${hue(node.vendor || node.platform)} 70% 62%)`);
        nodeEls.set(node.id, g);
      });
      place();
      fit();
      bind();
    }
    function place() {
      nodeEls.forEach((g, id) => { const p = positions.get(id); g.setAttribute("transform", `translate(${p.x.toFixed(1)} ${p.y.toFixed(1)})`); });
      linkEls.forEach((line) => {
        const a = positions.get(line.__link.source), b = positions.get(line.__link.target);
        if (!a || !b) return;
        line.setAttribute("x1", a.x.toFixed(1)); line.setAttribute("y1", a.y.toFixed(1));
        line.setAttribute("x2", b.x.toFixed(1)); line.setAttribute("y2", b.y.toFixed(1));
      });
    }
    function showTip(html, ev) {
      tip.innerHTML = html;
      tip.hidden = false;
      const rect = container.getBoundingClientRect();
      let x = ev.clientX - rect.left + 16, y = ev.clientY - rect.top + 14;
      if (x + 280 > rect.width) x -= 300;
      if (y + 140 > rect.height) y -= 150;
      tip.style.left = `${x}px`; tip.style.top = `${y}px`;
    }
    function highlight(id) {
      container.classList.toggle("dim", !!id);
      nodeEls.forEach((g) => g.classList.remove("hl"));
      linkEls.forEach((l) => l.classList.remove("hl"));
      if (!id) return;
      nodeEls.get(id).classList.add("hl");
      linkEls.forEach((line) => {
        const l = line.__link;
        if (l.source === id || l.target === id) {
          line.classList.add("hl");
          nodeEls.get(l.source).classList.add("hl");
          nodeEls.get(l.target).classList.add("hl");
        }
      });
    }
    function bind() {
      let drag = null, pan = null, moved = false;
      const toView = (ev) => {
        const rect = svg.getBoundingClientRect();
        return { x: view.x + ((ev.clientX - rect.left) / rect.width) * view.w, y: view.y + ((ev.clientY - rect.top) / rect.height) * view.h };
      };
      svg.addEventListener("pointerdown", (ev) => {
        moved = false;
        const g = ev.target.closest(".node");
        if (g) { drag = { id: g.__node.id, start: toView(ev) }; svg.setPointerCapture(ev.pointerId); return; }
        if (mini) return;
        pan = { x: ev.clientX, y: ev.clientY, view: { ...view } };
        svg.classList.add("panning");
        svg.setPointerCapture(ev.pointerId);
      });
      svg.addEventListener("pointermove", (ev) => {
        if (drag) {
          const p = toView(ev);
          if (Math.abs(p.x - drag.start.x) + Math.abs(p.y - drag.start.y) > 3) moved = true;
          if (moved) { positions.get(drag.id).x = p.x; positions.get(drag.id).y = p.y; place(); tip.hidden = true; }
          return;
        }
        if (pan) {
          const rect = svg.getBoundingClientRect();
          view.x = pan.view.x - ((ev.clientX - pan.x) / rect.width) * view.w;
          view.y = pan.view.y - ((ev.clientY - pan.y) / rect.height) * view.h;
          svg.setAttribute("viewBox", `${view.x} ${view.y} ${view.w} ${view.h}`);
          return;
        }
        const g = ev.target.closest(".node");
        const line = ev.target.closest(".link");
        if (g) {
          const n = g.__node;
          const links = data.links.filter((l) => l.source === n.id || l.target === n.id).length;
          const changed = n.change_ts ? `<span class="muted">changed ${ago(n.change_ts)}${n.change_risk ? ` · ${n.change_risk} risk` : ""}</span>` : "";
          showTip(`<b>${esc(n.label)}</b><span class="muted">${esc(n.platform_name)}${n.model ? ` · ${esc(n.model)}` : ""}</span>${n.host ? `<span class="muted mono">${esc(n.host)}</span>` : ""}<span class="muted">${links} link${links === 1 ? "" : "s"}${n.site ? ` · ${esc(n.site)}` : ""}</span>${changed}<span class="pill t-${tone(n)}">${esc(n.external ? "discovered via LLDP" : n.status)}</span>`, ev);
          highlight(n.id);
        } else if (line) {
          const l = line.__link;
          showTip(`<b>${esc(l.source)} ↔ ${esc(l.target.replace(/^ext:/, ""))}</b><span class="muted mono">${esc(l.source_port)} ↔ ${esc(l.target_port || "?")}</span><span class="muted">seen from ${l.seen === 2 ? "both sides" : "one side"}</span>`, ev);
        } else {
          tip.hidden = true;
          highlight(null);
        }
      });
      const end = (ev) => {
        if (drag) {
          if (moved) {
            const saved = loadPos();
            const p = positions.get(drag.id);
            saved[drag.id] = [Math.round(p.x), Math.round(p.y)];
            savePos(saved);
          } else {
            const node = nodeEls.get(drag.id).__node;
            if (!node.external) location.href = `/devices/${enc(node.id)}`;
          }
        }
        drag = null; pan = null;
        svg.classList.remove("panning");
      };
      svg.addEventListener("pointerup", end);
      svg.addEventListener("pointercancel", end);
      svg.addEventListener("pointerleave", () => { if (!drag && !pan) { tip.hidden = true; highlight(null); } });
      if (!mini) {
        svg.addEventListener("wheel", (ev) => {
          ev.preventDefault();
          const p = toView(ev);
          const k = Math.exp(ev.deltaY * 0.0012);
          const w = Math.min(Math.max(view.w * k, 120), 8000), h = (w / view.w) * view.h;
          view = { x: p.x - ((p.x - view.x) * w) / view.w, y: p.y - ((p.y - view.y) * h) / view.h, w, h };
          svg.setAttribute("viewBox", `${view.x} ${view.y} ${view.w} ${view.h}`);
        }, { passive: false });
      }
    }
    function setMode(next) {
      mode = next;
      container.classList.toggle("m-changes", mode === "changes");
      nodeEls.forEach((g) => {
        const n = g.__node;
        if (mode === "vendor") g.style.setProperty("--tone", `hsl(${hue(n.vendor || n.platform)} 70% 62%)`);
        else g.style.removeProperty("--tone");
      });
    }
    if (panel) {
      panel.addEventListener("click", (ev) => {
        const b = ev.target.closest("[data-topo-mode] button");
        if (b) { $$("[data-topo-mode] button", panel).forEach((x) => x.classList.toggle("on", x === b)); setMode(b.dataset.m); }
        if (ev.target.closest("[data-topo-fit]")) fit();
        if (ev.target.closest("[data-topo-reset]")) { savePos({}); draw(); setMode(mode); }
      });
    }
    draw();
    let resizeTimer = null;
    new ResizeObserver(() => { clearTimeout(resizeTimer); resizeTimer = setTimeout(fit, 120); }).observe(container);
    const api = {
      update(next) {
        next = trim(next);
        const same = next.nodes.length === data.nodes.length && next.links.length === data.links.length && next.nodes.every((n, i) => n.id === data.nodes[i].id);
        data = next;
        if (!same) { draw(); setMode(mode); return; }
        data.nodes.forEach((n) => { const g = nodeEls.get(n.id); if (g) { g.__node = n; g.setAttribute("class", nodeClass(n)); } });
        linkEls.forEach((line, i) => { line.__link = data.links[i]; line.setAttribute("class", `link ${data.links[i].status}`); });
      },
    };
    maps.push(api);
    return api;
  }

  /* ---------------------------------------------------------------- command palette */
  let paletteData = null;
  const PAGES = [
    { label: "Overview", href: "/", icon: "grid", hint: "g o" },
    { label: "Network map", href: "/topology", icon: "map", hint: "g m" },
    { label: "Change ledger", href: "/changes", icon: "commit", hint: "g c" },
    { label: "Where is…", href: "/search", icon: "target", hint: "g s" },
    { label: "NOC wallboard", href: "/wall", icon: "tv", hint: "g w" },
  ];
  function score(text, query) {
    text = text.toLowerCase();
    if (!query) return 1;
    const i = text.indexOf(query);
    if (i === 0) return 100 - text.length * 0.1;
    if (i > 0) return 60 - i * 0.5;
    let t = 0;
    for (const c of query) { t = text.indexOf(c, t); if (t < 0) return 0; t += 1; }
    return 20;
  }
  async function openPalette(initial = "") {
    if ($(".pal")) return;
    const pal = document.createElement("div");
    pal.className = "pal";
    pal.innerHTML = `<div class="pal-box" role="dialog" aria-label="Command palette"><div class="pal-in">${icon("search")}<input placeholder="Jump to a device, page or action - or type an IP to find it" autocomplete="off" spellcheck="false"><kbd>Esc</kbd></div><div class="pal-list"></div><div class="pal-foot"><span><kbd>↑</kbd> <kbd>↓</kbd> navigate</span><span><kbd>Enter</kbd> open</span><span><kbd>Shift</kbd>+<kbd>Enter</kbd> search configs</span></div></div>`;
    document.body.appendChild(pal);
    const input = $("input", pal), list = $(".pal-list", pal);
    input.value = initial;
    let items = [], sel = 0;
    const close = () => pal.remove();
    pal.addEventListener("click", (ev) => { if (ev.target === pal) close(); });
    if (!paletteData) { try { paletteData = await getJSON("/api/palette"); } catch (e) { paletteData = []; } }
    function render() {
      const q = input.value.toLowerCase().trim();
      const actions = [];
      if (q) actions.push({ group: "Search", label: `Where is “${input.value.trim()}”?`, icon: "target", href: `/search?q=${enc(input.value.trim())}`, s: /^[\d.:/a-f]+$/i.test(q) && /[.:]/.test(q) ? 200 : 5 });
      const devices = (paletteData || []).map((d) => ({ group: "Devices", label: d.name, sub: [d.site, d.platform, d.host].filter(Boolean).join(" · "), icon: "dot", tone: STATUS_TONE[d.status] || "unk", href: `/devices/${enc(d.name)}`, s: Math.max(score(d.name, q), score(`${d.host} ${d.site || ""} ${d.platform || ""} ${d.model || ""}`, q) * 0.6) }));
      const pages = PAGES.map((p) => ({ group: "Pages", label: p.label, sub: p.hint, icon: p.icon, href: p.href, s: score(p.label, q) }));
      const cmds = [
        ...(canTrigger ? [{ group: "Actions", label: "Run backup now", icon: "database", run: "backup", s: score("run backup now", q) }, { group: "Actions", label: "Run health check now", icon: "pulse", run: "health", s: score("run health check now", q) }] : []),
        { group: "Actions", label: "Toggle light / dark theme", icon: "sun", action: toggleTheme, s: score("toggle theme light dark", q) },
      ];
      items = [...actions, ...devices, ...pages, ...cmds].filter((i) => i.s > 0).sort((a, b) => b.s - a.s).slice(0, 14);
      sel = Math.min(sel, Math.max(0, items.length - 1));
      let group = null, html = "";
      items.forEach((item, i) => {
        if (item.group !== group) { group = item.group; html += `<div class="pal-group">${esc(group)}</div>`; }
        const glyph = item.icon === "dot" ? `<span class="dot t-${item.tone}"></span>` : icon(item.icon);
        html += `<div class="pal-item${i === sel ? " sel" : ""}" data-i="${i}">${glyph}<b>${esc(item.label)}</b>${item.sub ? `<small>${esc(item.sub)}</small>` : ""}</div>`;
      });
      list.innerHTML = html || '<div class="empty">No matches</div>';
    }
    function go(item, searchConfigs) {
      if (searchConfigs && input.value.trim()) { location.href = `/search?q=${enc(input.value.trim())}`; return; }
      if (!item) return;
      close();
      if (item.href) location.href = item.href;
      else if (item.run) { const b = document.createElement("button"); b.dataset.run = item.run; b.style.display = "none"; document.body.appendChild(b); b.click(); b.remove(); }
      else if (item.action) item.action();
    }
    input.addEventListener("input", () => { sel = 0; render(); });
    input.addEventListener("keydown", (ev) => {
      if (ev.key === "Escape") close();
      else if (ev.key === "ArrowDown") { sel = Math.min(items.length - 1, sel + 1); render(); ev.preventDefault(); }
      else if (ev.key === "ArrowUp") { sel = Math.max(0, sel - 1); render(); ev.preventDefault(); }
      else if (ev.key === "Enter") { ev.preventDefault(); go(items[sel], ev.shiftKey); }
    });
    list.addEventListener("click", (ev) => { const it = ev.target.closest(".pal-item"); if (it) go(items[+it.dataset.i]); });
    list.addEventListener("mousemove", (ev) => {
      const it = ev.target.closest(".pal-item");
      if (it && +it.dataset.i !== sel) { sel = +it.dataset.i; $$(".pal-item", list).forEach((x) => x.classList.toggle("sel", x === it)); }
    });
    render();
    input.focus();
  }
  document.addEventListener("click", (ev) => { if (ev.target.closest("[data-palette]")) openPalette(); });
  let gPressed = 0;
  document.addEventListener("keydown", (ev) => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test((document.activeElement || {}).tagName || "");
    if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "k") { ev.preventDefault(); openPalette(); return; }
    if (typing || ev.ctrlKey || ev.metaKey || ev.altKey) return;
    if (ev.key === "/") { ev.preventDefault(); const f = $("[data-filter]") || $("[data-where]"); if (f) f.focus(); else openPalette(); return; }
    if (ev.key === "g") { gPressed = Date.now(); return; }
    if (Date.now() - gPressed < 900) {
      const target = { o: "/", m: "/topology", c: "/changes", s: "/search", w: "/wall" }[ev.key];
      if (target) location.href = target;
      gPressed = 0;
    }
  });

  /* ---------------------------------------------------------------- wallboard */
  const clock = $("[data-clock]");
  if (clock) {
    const tick = () => { clock.textContent = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }); };
    tick();
    setInterval(tick, 1000);
    setInterval(() => { rev = -1; poll(true); }, 30000);
  }

  /* ---------------------------------------------------------------- init */
  function init(root = document) {
    bindCharts(root);
    initTimeMachine(root);
    $$("[data-topology]", root).forEach((c) => { if (!c.dataset.bound) { c.dataset.bound = "1"; createMap(c); } });
  }
  init();
  applyTable();
  if (location.hash === "#trends" || location.hash === "#timemachine") {
    const target = $(location.hash);
    if (target && params.get("view") !== "config") setTimeout(() => target.scrollIntoView({ block: "start" }), 30);
  }
})();
