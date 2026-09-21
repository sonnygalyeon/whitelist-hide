import { invoke } from "@tauri-apps/api/core";

const button = document.querySelector("#version");
const output = document.querySelector("#output");

button.addEventListener("click", async () => {
  try {
    output.textContent = await invoke("app_version");
  } catch (error) {
    output.textContent = String(error);
  }
});
