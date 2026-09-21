import { invoke } from "@tauri-apps/api/core";

const state = document.querySelector("#state");
const diagnostics = document.querySelector("#diagnostics");
const version = document.querySelector("#version");
const refresh = document.querySelector("#refresh");

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

refresh.addEventListener("click", loadStatus);

version.textContent = `v${await invoke("app_version")}`;
await loadStatus();
