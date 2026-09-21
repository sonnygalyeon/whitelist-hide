import { invoke } from "@tauri-apps/api/core";

const platformEl = document.querySelector("#platform");
const stateEl = document.querySelector("#state");
const summaryEl = document.querySelector("#summary");
const diagnosticsEl = document.querySelector("#diagnostics");
const diagCountEl = document.querySelector("#diag-count");
const planEl = document.querySelector("#plan");
const versionEl = document.querySelector("#version");

let platform = "unsupported";

async function refresh() {
  try {
    platform = await invoke("current_platform");
    platformEl.textContent = platform;
    versionEl.textContent = `v${await invoke("app_version")}`;

    const status = await invoke("backend_status", { platform });
    stateEl.textContent = status.state;
    summaryEl.textContent = status.available
      ? "Backend доступен. Сетевые изменения выполняются только через типизированные действия."
      : "Backend для этой платформы недоступен.";

    diagnosticsEl.replaceChildren();
    diagCountEl.textContent = String(status.diagnostics.length);

    for (const item of status.diagnostics) {
      const row = document.createElement("div");
      row.className = `diag ${item.level}`;
      const title = document.createElement("strong");
      title.textContent = item.label;
      const value = document.createElement("span");
      value.textContent = item.value;
      row.append(title, value);
      if (item.detail) {
        const detail = document.createElement("small");
        detail.textContent = item.detail;
        row.append(detail);
      }
      diagnosticsEl.append(row);
    }
  } catch (error) {
    stateEl.textContent = "Ошибка";
    summaryEl.textContent = String(error);
  }
}

async function showPlan(action) {
  try {
    const result = await invoke("backend_plan", { platform, action });
    const lines = [
      result.title,
      `admin: ${result.requires_admin}`,
      `network changes: ${result.mutates_network}`,
      `executable now: ${result.executable_now}`,
      "",
      ...result.steps.map((step, index) => {
        const command = step.command_preview ? `\n   ${step.command_preview}` : "";
        return `${index + 1}. ${step.description}${command}`;
      }),
    ];
    planEl.textContent = lines.join("\n");
  } catch (error) {
    planEl.textContent = String(error);
  }
}

document.querySelector("#refresh").addEventListener("click", refresh);
for (const button of document.querySelectorAll("[data-action]")) {
  button.addEventListener("click", () => showPlan(button.dataset.action));
}

refresh();
