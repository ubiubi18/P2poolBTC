"use strict";

const csrf = document.querySelector('meta[name="pohw-csrf"]').content;
const byId = (id) => document.getElementById(id);

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    cache: "no-store",
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      "X-PoHW-CSRF": csrf,
      ...(options.headers || {}),
    },
  });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
  return payload;
}

function showError(error) {
  const box = byId("error-box");
  box.textContent = error instanceof Error ? error.message : String(error);
  box.hidden = false;
}

function clearError() { byId("error-box").hidden = true; }

function render(state) {
  byId("experiment-label").textContent = state.experiment_id;
  byId("source-state").textContent = state.source_build_verified ? "Verified" : "Blocked";
  byId("source-cid").textContent = state.source_cid_short;
  byId("launch-phase").textContent = state.launch_phase;
  byId("activation-id").textContent = state.activation_id_short;
  byId("services-state").textContent = state.services_running ? "Running" : "Stopped";
  byId("identity-status").textContent = state.identity_status;
  byId("launch-status").textContent = state.launch_status;
  byId("start-node").disabled = !state.registered || state.services_running || !byId("no-value-ack").checked;
  byId("stop-node").disabled = !state.services_running;
  byId("identity-form").querySelectorAll("input,button").forEach((item) => { item.disabled = state.registered || state.services_running; });
  if (state.explorer_url) {
    byId("explorer-link").href = state.explorer_url;
    byId("explorer-link").hidden = false;
  }
  if (state.error) showError(state.error); else clearError();
}

byId("identity-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  clearError();
  try {
    const result = await api("/api/prepare", {
      method: "POST",
      body: JSON.stringify({
        miner_id: byId("miner-id").value.trim(),
        idena_address: byId("idena-address").value.trim(),
      }),
    });
    byId("sign-web").href = result.web_sign_url;
    byId("sign-desktop").href = result.desktop_sign_url;
    byId("sign-actions").hidden = false;
    byId("identity-status").textContent = "Signing request ready. Approve it in Idena.";
  } catch (error) { showError(error); }
});

byId("no-value-ack").addEventListener("change", async () => {
  try { render(await api("/api/state")); } catch (error) { showError(error); }
});

byId("start-node").addEventListener("click", async () => {
  clearError();
  byId("start-node").disabled = true;
  byId("launch-status").textContent = "Verifying peers and starting local services...";
  try {
    const result = await api("/api/start", {
      method: "POST",
      body: JSON.stringify({ acknowledgement: "I_UNDERSTAND_NO_VALUE" }),
    });
    if (result.stratum) {
      byId("stratum-url").textContent = result.stratum.url;
      byId("stratum-worker").textContent = result.stratum.worker;
      byId("stratum-password").textContent = result.stratum.password;
    }
    render(result.state);
  } catch (error) { showError(error); }
});

byId("stop-node").addEventListener("click", async () => {
  clearError();
  try {
    const result = await api("/api/stop", { method: "POST", body: "{}" });
    byId("stratum-url").textContent = "Available after launch";
    byId("stratum-worker").textContent = "Available after launch";
    byId("stratum-password").textContent = "Shown once after launch";
    render(result.state);
  } catch (error) { showError(error); }
});

async function refresh() {
  try { render(await api("/api/state")); } catch (error) { showError(error); }
}

refresh();
globalThis.setInterval(refresh, 3000);
