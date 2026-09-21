import { invoke } from "@tauri-apps/api/core";
import "./style.css";

const ui = {
  platform: document.querySelector("#platform"),
  pill: document.querySelector("#status-pill"),
  title: document.querySelector("#hero-title"),
  copy: document.querySelector("#hero-copy"),
  toggle: document.querySelector("#toggle"),
  message: document.querySelector("#action-message"),
  engine: document.querySelector("#engine-state"),
  network: document.querySelector("#network-state"),
  profile: document.querySelector("#profile-state"),
  diagnostics: document.querySelector("#diagnostics"),
  technical: document.querySelector("#technical"),
  refresh: document.querySelector("#refresh"),
  version: document.querySelector("#version"),
};

let running = false;
let busy = false;

function parseLines(text) {
  const result = {};
  for (const line of String(text || "").split(/\r?\n/)) {
    const index = line.indexOf("=");
    if (index > 0) {
      result[line.slice(0, index).trim()] = line.slice(index + 1).trim();
    }
  }
  return result;
}

function bool(value) {
  return String(value).toLowerCase() === "true";
}

function setBusy(value, label = "Выполнение…") {
  busy = value;
  ui.toggle.disabled = value;
  if (value) ui.toggle.textContent = label;
}

function renderSession(health) {
  running = bool(health.running);
  const engineAlive = bool(health.engine_alive);
  const networkAlive = bool(health.network_resource);

  ui.engine.textContent = engineAlive ? "Работает" : "Остановлен";
  ui.network.textContent = networkAlive ? "Активен" : "Не активен";

  if (running) {
    ui.pill.className = "pill online";
    ui.pill.textContent = "Включено";
    ui.title.textContent = "Защита включена";
    ui.copy.textContent =
      "Движок и принадлежащий приложению сетевой путь работают.";
    ui.toggle.textContent = "Выключить";
    ui.toggle.className = "primary danger";
  } else {
    ui.pill.className = "pill neutral";
    ui.pill.textContent = "Выключено";
    ui.title.textContent = "Защита выключена";
    ui.copy.textContent =
      "Используется встроенный проверяемый профиль. Никаких путей к файлам вводить не нужно.";
    ui.toggle.textContent = "Включить";
    ui.toggle.className = "primary";
  }

  if (!busy) ui.toggle.disabled = false;
}

function renderDiagnostics(status) {
  ui.diagnostics.replaceChildren();
  for (const item of status.diagnostics || []) {
    const row = document.createElement("div");
    row.className = "diagnostic-row";

    const text = document.createElement("div");
    const name = document.createElement("strong");
    name.textContent = item.label;
    const detail = document.createElement("span");
    detail.textContent = item.detail || item.value;
    text.append(name, detail);

    const badge = document.createElement("span");
    badge.className = `diag-badge ${item.level}`;
    badge.textContent = item.value;

    row.append(text, badge);
    ui.diagnostics.appendChild(row);
  }
}

async function loadState() {
  ui.message.textContent = "";
  try {
    const [runtimeText, backend, healthText] = await Promise.all([
      invoke("runtime_info"),
      invoke("backend_status"),
      invoke("session_health"),
    ]);
    const runtime = parseLines(runtimeText);
    const health = parseLines(healthText);

    ui.platform.textContent = runtime.platform || backend.platform || "Desktop";
    ui.profile.textContent = runtime.profile || "Balanced";
    ui.technical.textContent = [
      runtimeText,
      "",
      `backend_state=${backend.state}`,
      ...backend.diagnostics.map(
        (item) => `${item.key}=${item.value}${item.detail ? ` · ${item.detail}` : ""}`,
      ),
      "",
      healthText,
    ].join("\n");

    renderDiagnostics(backend);
    renderSession(health);
  } catch (error) {
    ui.pill.className = "pill error";
    ui.pill.textContent = "Ошибка";
    ui.title.textContent = "Нужна проверка";
    ui.copy.textContent = String(error);
    ui.toggle.disabled = true;
    ui.engine.textContent = "—";
    ui.network.textContent = "—";
    ui.technical.textContent = String(error);
  }
}

async function toggleSession() {
  if (busy) return;
  setBusy(true, running ? "Выключаем…" : "Включаем…");
  ui.message.textContent = "";

  try {
    await invoke(running ? "session_stop" : "session_start");
    ui.message.textContent = running
      ? "Сессия остановлена, сетевые изменения удалены."
      : "Сессия запущена и прошла первичную проверку.";
  } catch (error) {
    ui.message.textContent = String(error);
  } finally {
    busy = false;
    await loadState();
  }
}

ui.toggle.addEventListener("click", toggleSession);
ui.refresh.addEventListener("click", loadState);
ui.version.textContent = `v${await invoke("app_version")}`;

setBusy(true, "Проверяем…");
await loadState();
busy = false;
