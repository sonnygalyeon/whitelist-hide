import { invoke } from "@tauri-apps/api/core";

const state = document.querySelector("#state");
const diagnostics = document.querySelector("#diagnostics");
const version = document.querySelector("#version");
const refresh = document.querySelector("#refresh");
const config = document.querySelector("#config");
const strategy = document.querySelector("#strategy");
const sessionOutput = document.querySelector("#session-output");

async function loadStatus() {
  state.textContent = "Проверка…";
  diagnostics.replaceChildren();

  try {
    const status = await invoke("backend_status");
    state.textContent = String(status.state);
    for (const item of status.diagnostics) {
      const row = document.createElement("p");
      row.textContent = `[${item.level}] ${item.label}: ${item.value}`;
      if (item.detail) {
        row.title = item.detail;
      }
      diagnostics.appendChild(row);
    }
  } catch (error) {
    state.textContent = "Ошибка";
    const row = document.createElement("p");
    row.textContent = String(error);
    diagnostics.appendChild(row);
  }
}

async function runSession(command, payload = {}) {
  sessionOutput.textContent = "Выполнение…";
  try {
    const result = await invoke(command, payload);
    sessionOutput.textContent =
      typeof result === "string" ? result : JSON.stringify(result, null, 2);
  } catch (error) {
    sessionOutput.textContent = String(error);
  }
  await loadStatus();
}

document.querySelector("#start").addEventListener("click", () =>
  runSession("session_start", {
    config: config.value,
    strategy: strategy.value,
  }),
);
document.querySelector("#stop").addEventListener("click", () => runSession("session_stop"));
document.querySelector("#health").addEventListener("click", () => runSession("session_health"));
refresh.addEventListener("click", loadStatus);

version.textContent = `v${await invoke("app_version")}`;
await loadStatus();
