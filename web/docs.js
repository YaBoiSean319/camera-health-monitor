const endpoints = document.querySelector("#endpoints");
const esc = text => String(text).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
fetch("/openapi.json").then(r => r.json()).then(spec => {
  endpoints.innerHTML = Object.entries(spec.paths).flatMap(([path, methods]) => Object.entries(methods).map(([method, operation]) => {
    const needsBody = Boolean(operation.requestBody);
    const pathParams = [...path.matchAll(/\{([^}]+)\}/g)].map(match => match[1]);
    const initial = path.endsWith("/setup/admin") || path.endsWith("/auth/login") ? '{\n  "username": "admin",\n  "password": "replace-with-your-password"\n}' : path.endsWith("/credentials") ? '{\n  "current_password": "replace-with-your-password",\n  "username": "admin",\n  "new_password": "replace-with-a-new-password"\n}' : path === "/admin/api-tokens" ? '{\n  "name": "health-check workflow",\n  "role": "operator",\n  "scopes": ["health:read", "checks:run"],\n  "expires_at": null\n}' : path === "/servers" ? '{\n  "name": "Main recorder",\n  "host": "recorder.example",\n  "username": "monitor",\n  "password": "",\n  "defaults": {"live_interval_minutes": 5, "recording_interval_minutes": 60, "recording_lookback_hours": 24}\n}' : path.endsWith("/discover") || path.endsWith("/capabilities") ? "{}" : path.includes("/servers/{") ? '{\n  "name": "Main recorder",\n  "host": "recorder.example",\n  "password": ""\n}' : "{}";
    return `<details class="endpoint"><summary><b class="verb ${method}">${method.toUpperCase()}</b><code>${esc(path)}</code><span>${esc(operation.summary)}</span></summary><div class="endpoint-body">${pathParams.map(param => `<label>${esc(param)}<input class="path-param" data-param="${esc(param)}" placeholder="${esc(param)}"></label>`).join("")}${needsBody ? `<label>JSON request body<textarea spellcheck="false">${initial}</textarea></label>` : ""}<button class="primary run-request" data-method="${method}" data-path="${esc(path)}">Try it</button><pre hidden class="api-result"></pre></div></details>`;
  })).join("");
  endpoints.addEventListener("click", async event => {
    const button = event.target.closest(".run-request"); if (!button) return;
    const card = button.closest(".endpoint-body"), output = card.querySelector(".api-result"), textarea = card.querySelector("textarea");
    let body;
    try { body = textarea ? JSON.parse(textarea.value) : undefined; }
    catch { output.hidden = false; output.textContent = "Invalid JSON request body"; return; }
    const token = document.querySelector("#docs-token").value;
    let path = button.dataset.path;
    for (const input of card.querySelectorAll(".path-param")) {
      if (!input.value.trim()) { output.hidden = false; output.textContent = `Enter ${input.dataset.param}`; return; }
      path = path.replace(`{${input.dataset.param}}`, encodeURIComponent(input.value.trim()));
    }
    const response = await fetch(`/api/v1${path}`, { method: button.dataset.method.toUpperCase(), credentials: "same-origin", headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
    const text = response.status === 204 ? "" : await response.text();
    output.hidden = false; output.textContent = `HTTP ${response.status}${text ? `\n${text}` : ""}`;
  });
}).catch(() => { endpoints.textContent = "Unable to load the API specification."; });
