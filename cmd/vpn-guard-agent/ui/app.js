"use strict";

// ---------- helpers ----------
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (k === "checked" || k === "disabled" || k === "value") e[k] = v;
    else e.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return e;
}
// api calls GET without a body and POST with one.
async function api(path, body) {
  const opts = body === undefined ? {} : {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  };
  const r = await fetch(path, opts);
  return r.json();
}
const clone = (o) => JSON.parse(JSON.stringify(o));

const STATE_RU = {
  ALLOWED: "Разрешено",
  BLOCKED: "Заблокировано",
  CHECKING: "Проверка сети…",
  INITIALIZING: "Запуск…",
  UNKNOWN: "Сеть не подтверждена",
  DISABLED: "Не контролируется",
  "NOT CONFIGURED": "Не настроено для этой ОС",
};
const stateRu = (s) => STATE_RU[s] || s || "—";

let regionNames = null;
try { regionNames = new Intl.DisplayNames(["ru"], { type: "region" }); } catch (_) {}
const countryName = (cc) => { try { return (regionNames && regionNames.of(cc)) || cc; } catch (_) { return cc; } };
const COUNTRIES = ("AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ " +
  "CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF " +
  "GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW " +
  "KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL " +
  "NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST " +
  "SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW").split(" ");

// ---------- state ----------
const S = {
  info: null,        // {os, admin, daemon, user, elevate_supported, picker}
  status: null,      // daemon status
  daemonError: null,
  config: null,      // working copy
  original: "",      // JSON of the saved config
  configError: null,
  problems: [],
  page: "status",
  saving: false,
};
const platformKey = () => (S.info && S.info.os === "windows" ? "windows" : "darwin");
const canEdit = () => !!(S.info && S.info.admin && S.config);
// serialize drops UI-only fields ("_own", "_warning") and treats an empty
// per-app country list as "use the default list".
function serialize(cfg) {
  return JSON.stringify(cfg, function (k, v) {
    if (k.startsWith("_")) return undefined;
    if (k === "allowed_countries" && this && this.name !== undefined && Array.isArray(v) && !v.length) return undefined;
    return v;
  });
}
const isDirty = () => S.config && serialize(S.config) !== S.original;

// ---------- loading ----------
async function loadInfo() {
  try { S.info = await api("/api/info"); } catch (e) { S.info = { os: "darwin", admin: false, daemon: false, error: String(e) }; }
}
async function loadStatus() {
  try {
    const r = await api("/api/status");
    if (r.status) { S.status = r.status; S.daemonError = null; }
    else { S.daemonError = r; }
  } catch (e) { S.daemonError = { error: String(e), daemon: false }; }
}
async function loadConfig() {
  const r = await api("/api/config");
  S.configError = r.error || null;
  if (r.config) {
    S.config = normalise(r.config);
    S.original = serialize(S.config);
  } else if (!S.config) {
    S.config = null;
  }
}
function normalise(c) {
  c.applications = c.applications || [];
  c.allowed_countries = c.allowed_countries || [];
  c.geoip = c.geoip || {};
  c.geoip.providers = c.geoip.providers || [];
  c.logging = c.logging || { level: "info" };
  delete c.application;
  return c;
}

// ---------- rendering ----------
function render() {
  renderBanners();
  renderSidebar();
  renderStatus();
  renderApps();
  renderNetwork();
  renderAdvanced();
  renderSavebar();
  $$("[data-edit]").forEach((e) => { e.disabled = !canEdit(); });
}

function renderSidebar() {
  const st = S.status ? S.status.state : "";
  $(".brand-icon").setAttribute("class", "brand-icon " + st);
  $("#brand-sub").textContent = S.status ? stateRu(st) : "служба недоступна";
  const who = $("#who");
  if (S.info && S.info.user) {
    who.textContent = S.info.user + (S.info.admin ? " · администратор" : " · только просмотр");
  } else who.textContent = "";
}

function renderBanners() {
  const box = $("#banners");
  box.replaceChildren();
  if (S.daemonError) {
    box.append(el("div", { class: "banner bad" },
      el("div", {}, el("b", {}, "Служба VPN Guard недоступна. "),
        S.daemonError.daemon === false ? "Проверьте, что служба установлена и запущена." : S.daemonError.error)));
    return;
  }
  if (S.status && S.status.config_error) {
    box.append(el("div", { class: "banner bad" },
      el("div", {}, el("b", {}, "Ошибка конфигурации — все приложения заблокированы. "), S.status.config_error)));
  }
  if (S.info && !S.info.admin) {
    const b = el("div", { class: "banner info" },
      el("div", {}, "Изменять настройки может только администратор. Сейчас доступен только просмотр."));
    if (S.info.elevate_supported) {
      b.append(el("button", { class: "btn", onclick: elevate }, "Перезапустить от имени администратора"));
    }
    box.append(b);
  }
  if (S.problems.length) {
    box.append(el("div", { class: "banner bad" },
      el("div", {}, el("b", {}, "Настройки не сохранены:"), el("ul", {}, S.problems.map((p) => el("li", {}, p))))));
  }
}

function renderStatus() {
  const st = S.status;
  const hero = $("#hero");
  hero.className = "hero " + (st ? st.state : "");
  const verified = st && (st.state === "ALLOWED" || st.state === "BLOCKED") && !st.config_error;
  const controlled = ((st && st.apps) || []).filter((a) => !a.disabled);
  const ok = controlled.filter((a) => a.state === "ALLOWED").length;
  hero.className = "hero " + (!st ? "" : verified ? (ok === controlled.length ? "ALLOWED" : ok ? "CHECKING" : "BLOCKED") : st.state);
  $("#hero-state").textContent = !st ? "Нет связи со службой"
    : verified ? "Сеть подтверждена — " + st.country.split("/").map(countryName).join(", ")
    : stateRu(st.state);
  $("#hero-reason").textContent = !st ? ""
    : verified ? (controlled.length ? `Разрешено приложений: ${ok} из ${controlled.length}` : "Нет контролируемых приложений")
    : (st.reason || "Все контролируемые приложения заблокированы до подтверждения сети");
  $("#btn-check").disabled = !st;

  const facts = $("#facts");
  facts.replaceChildren();
  const fact = (k, v) => v && facts.append(el("div", {}, el("dt", {}, k), el("dd", {}, v)));
  if (st) {
    fact("Внешний IP", st.ipv4);
    fact("IPv6", st.ipv6);
    fact("Страна", st.country ? st.country.split("/").map((c) => `${countryName(c)} (${c})`).join(", ") : "");
    fact("Сервис", st.provider);
    fact("Последняя проверка", st.checked_at && !st.checked_at.startsWith("0001") ? new Date(st.checked_at).toLocaleString("ru") : "");
  }

  const table = $("#status-apps");
  table.replaceChildren();
  const apps = (st && st.apps) || [];
  if (!apps.length) {
    table.append(el("div", { class: "empty" }, "Нет контролируемых приложений. Добавьте их на странице «Приложения»."));
    return;
  }
  table.append(el("div", { class: "trow head" }, el("div", {}, "Приложение"), el("div", {}, "Состояние"),
    el("div", {}, "Разрешено в"), el("div", {}, "Процессы")));
  for (const a of apps) {
    const row = el("div", { class: "trow" },
      el("div", {}, el("b", {}, a.name)),
      el("div", {}, el("span", { class: "badge " + a.state }, stateRu(a.state))),
      el("div", {}, (a.allowed || []).join(", ") || "—"),
      el("div", { class: "muted" }, a.disabled ? "—" : (a.pids && a.pids.length ? "запущено: " + a.pids.join(", ") : "не запущено")));
    if (a.error) row.append(el("div", { class: "err" }, a.error));
    table.append(row);
  }
}

function countriesEditor(list, onChange, disabled) {
  const box = el("div", { class: "chips" });
  for (const cc of list) {
    box.append(el("span", { class: "chip" }, el("b", {}, cc), countryName(cc),
      el("button", {
        title: "Убрать", disabled, "data-edit": true,
        onclick: () => onChange(list.filter((x) => x !== cc)),
      }, "×")));
  }
  const listId = "countries-" + Math.random().toString(36).slice(2);
  const input = el("input", {
    type: "text", placeholder: "Добавить страну: TH, Таиланд…", list: listId, disabled, "data-edit": true,
    onkeydown: (e) => { if (e.key === "Enter") { e.preventDefault(); add(); } },
    onchange: () => add(),
  });
  const dl = el("datalist", { id: listId },
    COUNTRIES.filter((c) => !list.includes(c)).map((c) => el("option", { value: `${c} — ${countryName(c)}` })));
  function add() {
    const v = input.value.trim();
    if (!v) return;
    let code = v.slice(0, 2).toUpperCase();
    if (!COUNTRIES.includes(code) || (v.length > 2 && v[2] !== " ")) {
      const byName = COUNTRIES.find((c) => countryName(c).toLowerCase() === v.toLowerCase());
      if (byName) code = byName; else if (!COUNTRIES.includes(code)) { toast("Неизвестная страна: " + v); return; }
    }
    input.value = "";
    if (!list.includes(code)) onChange([...list, code]);
  }
  box.append(input, dl);
  return box;
}

function renderApps() {
  const box = $("#apps-list");
  box.replaceChildren();
  $("#manual-add").classList.toggle("hidden", !(S.info && S.info.picker === false) || !canEdit());
  if (!S.config) {
    box.append(el("div", { class: "card empty" }, S.configError || "Конфигурация недоступна."));
    return;
  }
  const key = platformKey();
  const other = key === "darwin" ? "windows" : "darwin";
  const statusByName = {};
  ((S.status && S.status.apps) || []).forEach((a) => { statusByName[a.name] = a; });
  const ro = !canEdit();

  if (!S.config.applications.length) {
    box.append(el("div", { class: "card empty" }, "Пока нет приложений. Нажмите «Добавить приложение…»."));
  }
  S.config.applications.forEach((app, i) => {
    const sec = app[key];
    const st = statusByName[app.name];
    const card = el("div", { class: "card app-card" + (app.disabled ? " off" : ""), "data-name": app.name });

    const head = el("div", { class: "app-head" },
      el("label", { class: "switch", title: app.disabled ? "Не контролируется" : "Контролируется" },
        el("input", {
          type: "checkbox", checked: !app.disabled, disabled: ro, "data-edit": true,
          onchange: (e) => { app.disabled = !e.target.checked || undefined; if (!app.disabled) delete app.disabled; render(); },
        }), el("span")),
      el("input", {
        class: "app-name", type: "text", value: app.name, disabled: ro, "data-edit": true,
        oninput: (e) => { app.name = e.target.value; renderSavebar(); },
        onchange: () => render(),
      }),
      st ? el("span", { class: "badge " + st.state }, stateRu(st.state)) : null,
      el("button", {
        class: "btn small danger", disabled: ro, "data-edit": true,
        onclick: () => { if (confirm(`Удалить «${app.name}» из списка?`)) { S.config.applications.splice(i, 1); render(); } },
      }, "Удалить"));
    card.append(head);

    const meta = el("dl", { class: "app-meta" });
    const m = (k, v) => v && meta.append(el("dt", {}, k), el("dd", { class: "mono" }, v));
    if (sec) {
      m("Путь", sec.path);
      m("Bundle ID", sec.bundle_id);
      m("Team ID", sec.team_id);
      m("Издатель", sec.publisher);
    } else {
      meta.append(el("dt", {}, "Эта ОС"), el("dd", {}, "не настроено — приложение здесь не контролируется"));
    }
    if (app[other]) m(other === "windows" ? "Windows" : "macOS", app[other].path);
    if (st && st.pids && st.pids.length) m("Процессы", st.pids.join(", "));
    card.append(meta);
    if (st && st.error) card.append(el("p", { class: "app-warn" }, st.error));
    if (app._warning) card.append(el("p", { class: "app-warn" }, app._warning));

    const own = app._own !== undefined ? app._own : !!(app.allowed_countries && app.allowed_countries.length);
    const name = "cc-" + i;
    card.append(el("div", { class: "radio-row" },
      el("label", {}, el("input", {
        type: "radio", name, checked: !own, disabled: ro, "data-edit": true,
        onchange: () => { app._own = false; delete app.allowed_countries; render(); },
      }), `Страны по умолчанию (${S.config.allowed_countries.join(", ") || "не заданы"})`),
      el("label", {}, el("input", {
        type: "radio", name, checked: own, disabled: ro, "data-edit": true,
        onchange: () => { app._own = true; app.allowed_countries = [...S.config.allowed_countries]; render(); },
      }), "Свой список")));
    if (own) {
      card.append(countriesEditor(app.allowed_countries || [], (l) => {
        app._own = true;
        app.allowed_countries = l;
        render();
      }, ro));
      if (!(app.allowed_countries || []).length) {
        card.append(el("p", { class: "muted small" }, "Пустой список: будут использоваться страны по умолчанию."));
      }
    }
    box.append(card);
  });
}

function provider(type) { return S.config.geoip.providers.find((p) => p.type === type); }
function setProviders(useIpinfo, useCf, token) {
  const cur = S.config.geoip.providers;
  const ip = cur.find((p) => p.type === "ipinfo_lite") || { type: "ipinfo_lite", token: "" };
  const cf = cur.find((p) => p.type === "cloudflare_trace") || { type: "cloudflare_trace" };
  if (token !== undefined) ip.token = token;
  const out = [];
  if (useIpinfo) out.push(ip);
  if (useCf) out.push(cf);
  S.config.geoip.providers = out;
}

function renderNetwork() {
  const box = $("#default-countries");
  if (!S.config) { box.replaceChildren(el("span", { class: "muted" }, "—")); return; }
  box.replaceWith(Object.assign(countriesEditor(S.config.allowed_countries, (l) => {
    S.config.allowed_countries = l; render();
  }, !canEdit()), { id: "default-countries" }));

  const ip = provider("ipinfo_lite");
  const cf = provider("cloudflare_trace");
  $("#p-ipinfo").checked = !!ip;
  $("#p-cloudflare").checked = !!cf;
  const tok = $("#p-ipinfo-token");
  tok.disabled = !canEdit() || !ip;
  const masked = ip && ip.token === "********";
  tok.placeholder = masked ? "Токен сохранён — введите новый, чтобы заменить" : "Токен IPinfo (ipinfo.io → Dashboard → Token)";
  if (document.activeElement !== tok) tok.value = ip && !masked ? ip.token || "" : "";
  $("#geo-policy").value = S.config.geoip.policy || "first_success";
  $("#geo-ipv6").value = S.config.geoip.ipv6 || "auto";
}

const INTERVALS = [
  ["process_check_interval_ms", "Проверка процессов, мс", 500],
  ["network_check_interval_seconds", "Перепроверка IP, с", 30],
  ["unknown_retry_seconds", "Повтор после ошибки, с", 5],
  ["network_timeout_ms", "Таймаут запроса GeoIP, мс", 3000],
  ["network_debounce_ms", "Склейка сетевых событий, мс", 300],
  ["terminate_timeout_ms", "Ожидание перед SIGKILL, мс", 2000],
];
function renderAdvanced() {
  const box = $("#intervals");
  box.replaceChildren();
  if (S.config) {
    for (const [k, label, def] of INTERVALS) {
      box.append(el("label", { class: "field" }, label, el("input", {
        type: "number", min: 1, value: S.config[k] || def, disabled: !canEdit(), "data-edit": true,
        onchange: (e) => { S.config[k] = Math.max(1, parseInt(e.target.value, 10) || def); render(); },
      })));
    }
    $("#log-level").value = (S.config.logging && S.config.logging.level) || "info";
  }
  $("#config-path").textContent = S.status ? "Файл: " + S.status.config_path +
    (S.status.loaded_at && !S.status.loaded_at.startsWith("0001") ? " · применён " + new Date(S.status.loaded_at).toLocaleTimeString("ru") : "") : "";
}

function renderSavebar() {
  const dirty = isDirty();
  $("#savebar").classList.toggle("hidden", !dirty || !canEdit());
  $("#btn-save").disabled = S.saving;
  $("#save-msg").textContent = S.saving ? "Сохранение…" : "Есть несохранённые изменения";
}

let toastTimer;
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add("hidden"), 3500);
}

// ---------- actions ----------
async function save() {
  S.saving = true; S.problems = []; renderSavebar();
  const out = JSON.parse(serialize(S.config));
  try {
    const r = await api("/api/config", out);
    if (r.error) {
      S.problems = r.problems && r.problems.length ? r.problems : [r.error];
      toast("Не сохранено");
    } else {
      S.status = r.status || S.status;
      S.problems = [];
      await loadConfig();
      toast("Сохранено и применено");
    }
  } catch (e) {
    S.problems = [String(e)];
  }
  S.saving = false;
  render();
}

async function addAppFrom(result) {
  if (!result || result.cancelled) return;
  if (result.error) { toast(result.error); return; }
  const info = result.app;
  const key = platformKey();
  const existing = S.config.applications.find((a) => a[key] && a[key].path === info.path);
  if (existing) { toast(`«${existing.name}» уже в списке`); return; }
  let name = info.name || "Приложение";
  const names = new Set(S.config.applications.map((a) => a.name.toLowerCase()));
  for (let n = 2; names.has(name.toLowerCase()); n++) name = `${info.name} ${n}`;
  const app = { name };
  app[key] = key === "darwin"
    ? { path: info.path, bundle_id: info.bundle_id, ...(info.team_id ? { team_id: info.team_id } : {}) }
    : { path: info.path, ...(info.publisher ? { publisher: info.publisher } : {}) };
  if (info.warning) app._warning = info.warning;
  S.config.applications.push(app);
  render();
  toast(`Добавлено: ${name}. Не забудьте сохранить.`);
}

// ---------- app picker ----------
let installed = null;
async function openPicker() {
  // Windows: no installed-apps list, go straight to the file dialog.
  if (S.info && S.info.os === "windows" && S.info.picker !== false) {
    addAppFrom(await api("/api/pick-app", {}));
    return;
  }
  $("#picker-file").classList.toggle("hidden", !(S.info && S.info.picker));
  $("#picker").classList.remove("hidden");
  $("#picker-search").value = "";
  $("#picker-search").focus();
  if (!installed) {
    $("#picker-list").replaceChildren(el("div", { class: "empty" }, "Загрузка…"));
    try { installed = (await api("/api/installed")).apps || []; } catch (_) { installed = []; }
  }
  renderPicker();
}
function closePicker() { $("#picker").classList.add("hidden"); }
function renderPicker() {
  const q = $("#picker-search").value.trim().toLowerCase();
  const key = platformKey();
  const added = new Set(((S.config && S.config.applications) || []).map((a) => a[key] && a[key].path).filter(Boolean));
  const list = (installed || []).filter((a) => !q || a.name.toLowerCase().includes(q) || (a.bundle_id || "").toLowerCase().includes(q));
  const box = $("#picker-list");
  box.replaceChildren();
  if (!list.length) {
    box.append(el("div", { class: "empty" }, installed && installed.length ? "Ничего не найдено" : "Список недоступен — выберите файл"));
    return;
  }
  for (const a of list) {
    const already = added.has(a.path);
    box.append(el("button", {
      class: "picker-item", disabled: already, title: a.path,
      onclick: async () => {
        closePicker();
        addAppFrom(await api("/api/inspect", { path: a.path }));
      },
    }, el("span", {}, a.name + (already ? " — уже добавлено" : "")), el("span", { class: "sub" }, a.bundle_id + " · " + a.path)));
  }
}

async function elevate() {
  const r = await api("/api/elevate", {});
  if (r.error) toast(r.error);
}

// ---------- wiring ----------
function bind() {
  $$(".nav-item").forEach((b) => b.addEventListener("click", () => {
    S.page = b.dataset.page;
    $$(".nav-item").forEach((x) => x.classList.toggle("active", x === b));
    $$(".page").forEach((p) => p.classList.toggle("hidden", p.id !== "page-" + S.page));
  }));
  $("#btn-check").addEventListener("click", async (e) => {
    e.target.disabled = true; e.target.textContent = "Проверка…";
    const r = await api("/api/check", {});
    if (r.status) S.status = r.status; else if (r.error) toast(r.error);
    e.target.textContent = "Проверить сейчас";
    render();
  });
  $("#btn-add-app").addEventListener("click", openPicker);
  $("#picker-close").addEventListener("click", closePicker);
  $("#picker").addEventListener("click", (e) => { if (e.target.id === "picker") closePicker(); });
  $("#picker-search").addEventListener("input", renderPicker);
  $("#picker-file").addEventListener("click", async () => {
    closePicker();
    addAppFrom(await api("/api/pick-app", {}));
  });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closePicker(); });
  $("#btn-manual-add").addEventListener("click", async () => {
    const path = $("#manual-path").value.trim();
    if (!path) return;
    const r = await api("/api/inspect", { path });
    if (!r.error) $("#manual-path").value = "";
    addAppFrom(r);
  });
  $("#p-ipinfo").addEventListener("change", (e) => { setProviders(e.target.checked, !!provider("cloudflare_trace")); render(); });
  $("#p-cloudflare").addEventListener("change", (e) => { setProviders(!!provider("ipinfo_lite"), e.target.checked); render(); });
  $("#p-ipinfo-token").addEventListener("input", (e) => {
    const p = provider("ipinfo_lite");
    if (p) p.token = e.target.value || "********";
    renderSavebar();
  });
  $("#geo-policy").addEventListener("change", (e) => { S.config.geoip.policy = e.target.value; render(); });
  $("#geo-ipv6").addEventListener("change", (e) => { S.config.geoip.ipv6 = e.target.value; render(); });
  $("#log-level").addEventListener("change", (e) => { S.config.logging = { level: e.target.value }; render(); });
  $("#btn-logs").addEventListener("click", async () => { const r = await api("/api/open-logs", {}); if (r.error) toast(r.error); });
  $("#btn-reload").addEventListener("click", async () => {
    const r = await api("/api/reload", {});
    if (r.error) toast("Ошибка: " + r.error); else { S.status = r.status; await loadConfig(); toast("Конфигурация перечитана"); }
    render();
  });
  $("#btn-save").addEventListener("click", save);
  $("#btn-revert").addEventListener("click", () => { S.config = normalise(JSON.parse(S.original)); S.problems = []; render(); });
  window.addEventListener("beforeunload", (e) => { if (isDirty()) e.preventDefault(); });
}

// renderLive refreshes only status-driven parts, never the editors, so
// polling does not disturb typing or focus.
function renderLive() {
  renderBanners();
  renderSidebar();
  renderStatus();
  const byName = {};
  ((S.status && S.status.apps) || []).forEach((a) => { byName[a.name] = a; });
  $$(".app-card").forEach((card) => {
    const badge = $(".badge", card);
    const st = byName[card.dataset.name];
    if (badge && st) { badge.className = "badge " + st.state; badge.textContent = stateRu(st.state); }
  });
  $("#config-path").textContent = S.status ? "Файл: " + S.status.config_path +
    (S.status.loaded_at && !S.status.loaded_at.startsWith("0001") ? " · применён " + new Date(S.status.loaded_at).toLocaleTimeString("ru") : "") : "";
  $$("#banners [data-edit]").forEach((e) => { e.disabled = !canEdit(); });
}

async function tick() {
  const wasDown = !!S.daemonError;
  await loadStatus();
  // Pick up external changes (another admin, manual edit) when not editing.
  if (!isDirty() && S.status && (wasDown || S.lastLoaded !== S.status.loaded_at)) {
    S.lastLoaded = S.status.loaded_at;
    await loadConfig();
    render();
    return;
  }
  renderLive();
}

(async function main() {
  bind();
  await loadInfo();
  await Promise.all([loadStatus(), loadConfig().catch(() => {})]);
  S.lastLoaded = S.status && S.status.loaded_at;
  render();
  setInterval(tick, 2000);
  setInterval(loadInfo, 15000);
})();
