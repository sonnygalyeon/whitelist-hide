import { invoke } from "@tauri-apps/api/core";

const output = document.querySelector("#output");
const config = document.querySelector("#config");
const strategy = document.querySelector("#strategy");

async function call(name, args = {}) {
  output.textContent = "Working…";
  try {
    const result = await invoke(name, args);
    output.textContent = JSON.stringify(result, null, 2);
  } catch (error) {
    output.textContent = String(error);
  }
}

document.querySelector("#version").addEventListener("click", () => call("app_version"));
document.querySelector("#status").addEventListener("click", () => call("runtime_status"));
document.querySelector("#preview").addEventListener("click", () =>
  call("strategy_preview", { path: strategy.value }),
);
document.querySelector("#start").addEventListener("click", () =>
  call("session_start", {
    configPath: config.value,
    strategyPath: strategy.value,
  }),
);
document.querySelector("#stop").addEventListener("click", () => call("session_stop"));
