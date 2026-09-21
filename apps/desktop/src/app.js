const invoke = window.__TAURI__.core.invoke;

const stateNode = document.querySelector("#state");
const summaryNode = document.querySelector("#summary");
const diagnosticsNode = document.querySelector("#diagnostics");
const platformNode = document.querySelector("#platform");
const availableNode = document.querySelector("#available");
const planNode = document.querySelector("#plan");

async function refresh() {
  try {
    platformNode.textContent = await invoke("platform");
    const status = await invoke("backend_status");
    stateNode.textContent = status.state;
    availableNode.textContent = status.available ? "available" : "unavailable";
    summaryNode.textContent = status.available
      ? "Backend diagnostics are available. Mutating actions remain guarded."
      : "This backend is not available on the current platform.";

    diagnosticsNode.replaceChildren(
      ...status.diagnostics.map((item) => {
        const card = document.createElement("article");
        card.className = "diag";
        const title = document.createElement("strong");
        title.textContent = item.label;
        const value = document.createElement("span");
        value.textContent = item.value;
        const detail = document.createElement("small");
        detail.textContent = item.detail ?? item.level;
        card.append(title, value, detail);
        return card;
      })
    );
  } catch (error) {
    stateNode.textContent = "Error";
    summaryNode.textContent = String(error);
  }
}

async function showPlan(action) {
  planNode.innerHTML = "<li>Loading plan...</li>";
  try {
    const plan = await invoke("backend_plan", { action });
    planNode.replaceChildren(
      ...plan.steps.map((step) => {
        const item = document.createElement("li");
        item.textContent = step.command_preview
          ? `${step.description} [${step.command_preview}]`
          : step.description;
        return item;
      })
    );
  } catch (error) {
    planNode.innerHTML = "";
    const item = document.createElement("li");
    item.textContent = String(error);
    planNode.append(item);
  }
}

document.querySelector("#refresh").addEventListener("click", refresh);
document.querySelectorAll("[data-action]").forEach((button) => {
  button.addEventListener("click", () => showPlan(button.dataset.action));
});

refresh();
