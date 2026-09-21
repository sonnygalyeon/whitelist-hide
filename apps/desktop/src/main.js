import { invoke } from "@tauri-apps/api/core";
import "./style.css";

const $ = (selector) => document.querySelector(selector);

const elements = {
  health: $("#health"),
  platform: $("#platform"),
  running: $("#running"),
  strategy: $("#strategy"),
  pid: $("#pid"),
  detail: $("#detail"),
  config: $("#config"),
  output: $("#output"),
  start: $("#start"),
  stop: $("#stop"),
  refresh: $("#refresh"),
};

function render(status) {
  elements.platform.textContent = status.platform;
  elements.running.textContent = status.running ? "Запущено" : "Остановлено";
  elements.strategy.textContent = status.strategy ?? "—";
  elements.pid.textContent = status.enginePid ?? "—";
  elements.detail.textContent = status.detail;
  elements.config.textContent = status.systemConfig;
  elements.health.textContent = status.healthy
    ? (status.running ? "Работает" : "Готово")
    : "Требует внимания";
  elements.health.dataset.state = status.healthy ? "ok" : "bad";
  elements.start.disabled = status.running;
  elements.stop.disabled = !status.running;
}

async function refresh() {
  try {
    render(await invoke("session_status"));
  } catch (error) {
    elements.output.textContent = String(error);
    elements.health.textContent = "Ошибка";
    elements.health.dataset.state = "bad";
  }
}

async function mutate(command, label) {
  elements.start.disabled = true;
  elements.stop.disabled = true;
  elements.output.textContent = label + "…";
  try {
    const status = await invoke(command);
    render(status);
    elements.output.textContent = label + ": успешно";
  } catch (error) {
    elements.output.textContent = label + ": " + String(error);
    await refresh();
  }
}

elements.start.addEventListener("click", () => mutate("session_start", "Запуск"));
elements.stop.addEventListener("click", () => mutate("session_stop", "Остановка"));
elements.refresh.addEventListener("click", refresh);

refresh();
