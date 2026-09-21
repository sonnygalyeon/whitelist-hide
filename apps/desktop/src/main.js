import { invoke } from "@tauri-apps/api/core";
import "./style.css";

const ui = {
  state: document.querySelector("#state"),
  stateCaption: document.querySelector("#state-caption"),
  stateDetail: document.querySelector("#state-detail"),
  orb: document.querySelector("#status-orb"),
  toggle: document.querySelector("#toggle"),
  diagnostics: document.querySelector("#diagnostics"),
  refresh: document.querySelector("#refresh"),
  health: document.querySelector("#health"),
  activity: document.querySelector("#activity"),
  version: document.querySelector("#version"),
  profileName: document.querySelector("#profile-name"),
  profileState: document.querySelector("#profile-state"),
  platform: document.querySelector("#platform"),
  runtimeState: document.querySelector("#runtime-state"),
};

let running = false;
let busy = false;
let profileAvailable = false;

function addEvent(message, tone = "info") {
  const row = document.createElement("div");
  row.className = `event event-${tone}`;
  const time = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  row.innerHTML = `<span class="event-time">${time}</span><span></span>`;
  row.lastElementChild.textContent = message;
  ui.activity.prepend(row);
  while (ui.activity.children.length > 20) {
    ui.activity.lastElementChild.remove();
  }
}

function setVisualState(kind, title, detail) {
  ui.orb.dataset.state = kind;
  ui.state.textContent = title;
  ui.stateDetail.textContent = detail;
  ui.stateCaption.textContent =
    kind === "running" ? "Соединение защищено" :
    kind === "error" ? "Требуется внимание" :
    kind === "busy" ? "Выполняется операция" :
    "Защита выключена";
}

function updateToggle() {
  ui.toggle.disabled = busy || !profileAvailable;
  ui.toggle.textContent = busy ? "Выполняется…" : running ? "Отключить" : "Включить";
  ui.toggle.classList.toggle("danger", running);
}

function renderDiagnostics(status) {
  ui.diagnostics.replaceChildren();
  for (const item of status.diagnostics ?? []) {
    const row = document.createElement("div");
    row.className = "diagnostic";
    const dot = document.createElement("span");
    dot.className = `dot dot-${item.level}`;
    const copy = document.createElement("div");
    const label = document.createElement("strong");
    label.textContent = item.label;
    const value = document.createElement("span");
    value.textContent = item.value;
    copy.append(label, value);
    if (item.detail) row.title = item.detail;
    row.append(dot, copy);
    ui.diagnostics.append(row);
  }
  if (!ui.diagnostics.children.length) {
    ui.diagnostics.textContent = "Диагностические данные пока отсутствуют.";
  }
}

function parseHealth(text) {
  const values = Object.fromEntries(
    String(text)
      .split(/\r?\n/)
      .map((line) => line.split("=", 2))
      .filter((pair) => pair.length === 2),
  );
  return {
    running: values.running === "true",
    engine: values.engine_alive === "true",
    network: values.network_resource === "true",
  };
}

async function loadProfile() {
  const profile = await invoke("default_profile");
  profileAvailable = Boolean(profile.available);
  ui.profileName.textContent = profile.name;
  ui.platform.textContent = profile.platform;
  ui.profileState.textContent = profileAvailable ? "Готов" : "Не установлен";
  ui.profileState.dataset.state = profileAvailable ? "ok" : "error";
  ui.runtimeState.textContent = profileAvailable ? "Встроенный runtime найден" : "Runtime отсутствует";
  if (!profileAvailable) {
    setVisualState(
      "error",
      "Пакет неполный",
      "Встроенный runtime не найден. Установите полный desktop-пакет.",
    );
  }
  updateToggle();
}

async function refreshStatus({ log = false } = {}) {
  try {
    const status = await invoke("backend_status");
    renderDiagnostics(status);
    const healthText = await invoke("session_health");
    const health = parseHealth(healthText);
    running = health.running;
    if (running) {
      setVisualState("running", "Включено", "Движок и сетевой маршрут работают.");
    } else if (profileAvailable) {
      setVisualState("stopped", "Выключено", "Нажмите «Включить», чтобы применить стандартный профиль.");
    }
    if (log) {
      addEvent(
        running ? "Проверка: защита работает." : "Проверка: активной сессии нет.",
        running ? "ok" : "info",
      );
    }
  } catch (error) {
    running = false;
    if (profileAvailable) {
      setVisualState("error", "Ошибка проверки", String(error));
    }
    if (log) addEvent(`Ошибка проверки: ${error}`, "error");
  } finally {
    updateToggle();
  }
}

async function toggleProtection() {
  if (busy || !profileAvailable) return;
  busy = true;
  updateToggle();
  setVisualState("busy", running ? "Отключение…" : "Запуск…", "Проверяем runtime и применяем сетевые изменения.");

  try {
    if (running) {
      await invoke("session_stop");
      addEvent("Защита отключена, сетевые изменения откатаны.", "info");
    } else {
      await invoke("session_start_default");
      addEvent("Стандартный профиль успешно запущен.", "ok");
    }
    await refreshStatus();
  } catch (error) {
    setVisualState("error", "Не удалось выполнить операцию", String(error));
    addEvent(String(error), "error");
  } finally {
    busy = false;
    updateToggle();
  }
}

ui.toggle.addEventListener("click", toggleProtection);
ui.refresh.addEventListener("click", () => refreshStatus({ log: true }));
ui.health.addEventListener("click", () => refreshStatus({ log: true }));

ui.version.textContent = `v${await invoke("app_version")}`;
addEvent("Приложение запущено.");
try {
  await loadProfile();
  await refreshStatus();
} catch (error) {
  profileAvailable = false;
  setVisualState("error", "Ошибка инициализации", String(error));
  addEvent(String(error), "error");
  updateToggle();
}
