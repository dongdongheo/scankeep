window.Scankeep = (() => {
  const tokenKey = "scankeepToken";
  let token = sessionStorage.getItem(tokenKey) || "";
  let messageTimer;
  let projectTargetsRequest;

  const element = id => document.getElementById(id);
  const setAuthenticated = value =>
    document.documentElement.classList.toggle("authenticated", value);

  // Decided before the body is parsed so a stored session never flashes the login card.
  setAuthenticated(Boolean(token));

  const escapeHtml = value =>
    String(value ?? "").replace(
      /[&<>"']/g,
      character =>
        ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
          character
        ],
    );

  async function api(path, options = {}) {
    const response = await fetch(`/api/scankeep${path}`, {
      ...options,
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        ...(options.headers || {}),
      },
    });
    const body =
      response.status === 204 ? null : await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(body.error || `Request failed (${response.status})`);
    }
    return body;
  }

  function loadProjectTargets() {
    if (!projectTargetsRequest) {
      projectTargetsRequest = api("/project-targets")
        .then(result => result.project_targets)
        .catch(error => {
          projectTargetsRequest = undefined;
          throw error;
        });
    }
    return projectTargetsRequest;
  }

  function message(text, error = false) {
    clearTimeout(messageTimer);
    element("message").textContent = text;
    element("message").className = `notice${error ? " error" : ""}`;
    messageTimer = setTimeout(() => element("message").classList.add("hidden"), 5000);
  }

  function status(value) {
    const normalized = String(value || "unknown").toLowerCase();
    return `<span class="status status-${escapeHtml(normalized)}">${escapeHtml(value || "Unknown")}</span>`;
  }

  function formatTime(value) {
    if (!value) return "—";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
  }

  function formatDuration(started, finished) {
    if (!started) return "—";
    const start = new Date(started).getTime();
    const end = finished ? new Date(finished).getTime() : Date.now();
    if (!Number.isFinite(start) || !Number.isFinite(end)) return "—";
    const seconds = Math.max(0, Math.round((end - start) / 1000));
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.floor(seconds / 60);
    return `${minutes}m ${seconds % 60}s`;
  }

  function cronHint() {
    const now = new Date();
    const offset = -now.getTimezoneOffset();
    const pad = value => String(Math.floor(Math.abs(value))).padStart(2, "0");
    const browser = `UTC${offset < 0 ? "-" : "+"}${pad(offset / 60)}:${pad(offset % 60)}`;
    const utc = now.toISOString().slice(0, 16).replace("T", " ");
    return (
      `Cron fields are evaluated in UTC, not on the Scankeep host or in your local time zone. ` +
      `It is now ${utc} UTC and your browser is ${browser}, so a UTC time shifts by that offset for you. ` +
      `Run times on this page are displayed in your local time.`
    );
  }

  function resultLabel(job) {
    if (!job.report) return job.status === "failed" ? "Unavailable" : "Pending";
    const gate = String(job.report.quality_gate || "Unknown").toUpperCase();
    return gate === "OK" ? "Passed" : gate === "ERROR" ? "Failed" : gate;
  }

  function resultStatus(job) {
    return status(resultLabel(job));
  }

  function jobRows(scans, emptyMessage = "No scan runs found.") {
    return scans.length
      ? scans.map(job => `
          <tr data-href="/scankeep/jobs/${encodeURIComponent(job.id)}">
            <td><strong>${escapeHtml(job.label || job.project_target_name)}</strong><div class="meta">${escapeHtml(job.project_target_name)}</div></td>
            <td>${escapeHtml(job.trigger_source)}${job.preset_name || job.schedule_name ? `<div class="meta">${escapeHtml(job.preset_name || job.schedule_name)}</div>` : ""}</td>
            <td>${escapeHtml(job.security_server_name)}<div class="meta">${escapeHtml(job.project_key)}</div></td>
            <td>${escapeHtml(job.branch)}<div class="meta">${escapeHtml(job.commit_sha ? job.commit_sha.slice(0, 12) : "not checked out yet")}</div></td>
            <td>${status(job.status)}<div class="meta">${escapeHtml(job.phase)} · ${Number(job.progress) || 0}%</div></td>
            <td>${resultStatus(job)}</td>
            <td>${escapeHtml(formatTime(job.created_at))}<div class="meta">${escapeHtml(formatDuration(job.started_at, job.finished_at))}</div></td>
          </tr>`).join("")
      : `<tr><td colspan="7" class="muted">${escapeHtml(emptyMessage)}</td></tr>`;
  }

  function createScanFilters(fixed = {}) {
    const form = element("scan-filters");

    async function load() {
      const selectedProjectKey = form.elements.project_key.value;
      const selectedProjectTarget = form.elements.project_target_id.value;
      const projectTargets = await loadProjectTargets();
      const projectKeys = [...new Set(projectTargets.map(item => item.project_key))]
        .sort((left, right) => left.localeCompare(right));
      form.elements.project_key.innerHTML =
        '<option value="">All projects</option>' +
        projectKeys.map(projectKey =>
          `<option value="${escapeHtml(projectKey)}">${escapeHtml(projectKey)}</option>`
        ).join("");
      form.elements.project_target_id.innerHTML =
        '<option value="">All targets</option>' +
        projectTargets.map(item =>
          `<option value="${escapeHtml(item.id)}">${escapeHtml(item.name)}</option>`
        ).join("");
      form.elements.project_key.value = selectedProjectKey;
      form.elements.project_target_id.value = selectedProjectTarget;
    }

    function scansPath() {
      const parameters = new URLSearchParams();
      for (const [name, value] of Object.entries(fixed)) {
        if (value) parameters.set(name, value);
      }
      for (const [name, value] of new FormData(form)) {
        const normalized = String(value).trim();
        if (normalized) parameters.set(name, normalized);
      }
      const query = parameters.toString();
      return `/scans${query ? `?${query}` : ""}`;
    }

    function bind(reload) {
      form.addEventListener("submit", async event => {
        event.preventDefault();
        event.submitter.disabled = true;
        try {
          await reload();
        } catch (error) {
          message(error.message, true);
        } finally {
          event.submitter.disabled = false;
        }
      });
      element("clear-filters").addEventListener("click", async event => {
        event.target.disabled = true;
        for (const field of form.elements) {
          if (field.name) field.value = "";
        }
        try {
          await reload();
        } catch (error) {
          message(error.message, true);
        } finally {
          event.target.disabled = false;
        }
      });
    }

    return { bind, load, scansPath };
  }

  function createSortableTable(bodyId, columns, renderRows) {
    const body = element(bodyId);
    const headers = body.closest("table").querySelectorAll("th[data-sort]");
    const collator = new Intl.Collator(undefined, {
      numeric: true,
      sensitivity: "base",
    });
    let items = [];
    let sortKey = "";
    let direction = 1;

    function render() {
      const sorted = sortKey
        ? [...items].sort((left, right) => {
            const leftValue = columns[sortKey](left);
            const rightValue = columns[sortKey](right);
            const leftEmpty = leftValue === null || leftValue === undefined || leftValue === "";
            const rightEmpty = rightValue === null || rightValue === undefined || rightValue === "";
            if (leftEmpty !== rightEmpty) return leftEmpty ? 1 : -1;
            const comparison =
              typeof leftValue === "number" && typeof rightValue === "number"
                ? leftValue - rightValue
                : collator.compare(String(leftValue ?? ""), String(rightValue ?? ""));
            return comparison * direction;
          })
        : items;
      body.innerHTML = renderRows(sorted);
    }

    for (const header of headers) {
      header.addEventListener("click", () => {
        const nextKey = header.dataset.sort;
        direction = sortKey === nextKey ? -direction : 1;
        sortKey = nextKey;
        for (const item of headers) {
          item.setAttribute(
            "aria-sort",
            item === header ? (direction === 1 ? "ascending" : "descending") : "none",
          );
        }
        render();
      });
    }

    return {
      setItems(nextItems) {
        items = nextItems;
        render();
      },
    };
  }

  function createScanSelection() {
    const state = { servers: [], projectTargets: [] };
    const selectedProjectTarget = () =>
      state.projectTargets.find(item => item.id === element("project-target-select").value);

    function renderProject() {
      const projectTarget = selectedProjectTarget();
      element("project-select").innerHTML = projectTarget
        ? `<option value="${escapeHtml(projectTarget.project_key)}">${escapeHtml(projectTarget.project_key)}</option>`
        : '<option value="">No project available</option>';
      element("branch-select").innerHTML = projectTarget
        ? "<option>Loading branches…</option>"
        : "<option>No project target available</option>";
      element("branch-select").disabled = true;
    }

    function renderProjectTargets() {
      const projectTargets = state.projectTargets.filter(
        item => item.security_server_id === element("server-select").value,
      );
      element("project-target-select").innerHTML = projectTargets.length
        ? projectTargets.map(item => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.name)}</option>`).join("")
        : '<option value="">No project targets for this server</option>';
      renderProject();
    }

    async function loadBranches(selectedBranch = "") {
      const projectTarget = selectedProjectTarget();
      if (!projectTarget) return;
      const requestedId = projectTarget.id;
      try {
        const result = await api(
          `/project-targets/${encodeURIComponent(requestedId)}/branches`,
        );
        if (selectedProjectTarget()?.id !== requestedId) return;
        element("branch-select").innerHTML = result.branches.length
          ? result.branches.map(branch =>
              `<option value="${escapeHtml(branch)}">${escapeHtml(branch)}</option>`
            ).join("")
          : "<option>No branches available</option>";
        element("branch-select").disabled = !result.branches.length;
        if (selectedBranch && result.branches.includes(selectedBranch)) {
          element("branch-select").value = selectedBranch;
        } else if (selectedBranch && result.branches.length) {
          element("branch-select").insertAdjacentHTML(
            "afterbegin",
            `<option value="" selected>${escapeHtml(selectedBranch)} (unavailable)</option>`,
          );
        }
      } catch (error) {
        if (selectedProjectTarget()?.id === requestedId) {
          element("branch-select").innerHTML = "<option>Unable to load branches</option>";
          element("branch-select").disabled = true;
          message(error.message, true);
        }
      }
    }

    async function load(initial = {}) {
      const [serverResult, projectTargets] = await Promise.all([
        api("/servers"),
        loadProjectTargets(),
      ]);
      state.servers = serverResult.servers;
      state.projectTargets = projectTargets;
      element("server-select").innerHTML = state.servers.length
        ? state.servers.map(server => `<option value="${escapeHtml(server.id)}">${escapeHtml(server.name)}</option>`).join("")
        : '<option value="">Add a security server first</option>';
      if (initial.securityServerId) {
        element("server-select").value = initial.securityServerId;
      }
      renderProjectTargets();
      if (initial.projectTargetId) {
        element("project-target-select").value = initial.projectTargetId;
        renderProject();
      }
      await loadBranches(initial.branch);
    }

    function payload(form) {
      if (element("branch-select").disabled) {
        throw new Error("Select an available branch before continuing");
      }
      return Object.fromEntries(new FormData(form).entries());
    }

    element("server-select").addEventListener("change", () => {
      renderProjectTargets();
      loadBranches();
    });
    element("project-target-select").addEventListener("change", () => {
      renderProject();
      loadBranches();
    });
    return { load, payload };
  }

  async function connect(loadPage) {
    await api("/auth", { method: "POST", body: "{}" });
    await loadPage();
    sessionStorage.setItem(tokenKey, token);
    setAuthenticated(true);
  }

  function start(loadPage = async () => {}) {
    element("login-form").addEventListener("submit", async event => {
      event.preventDefault();
      token = element("access-token").value;
      try {
        await connect(loadPage);
      } catch (error) {
        element("login-error").textContent = error.message;
        element("login-error").classList.remove("hidden");
      }
    });
    element("logout").addEventListener("click", () => {
      sessionStorage.removeItem(tokenKey);
      window.location.reload();
    });
    if (token) {
      connect(loadPage).catch(() => {
        sessionStorage.removeItem(tokenKey);
        token = "";
        setAuthenticated(false);
      });
    }
  }

  return {
    api,
    createScanFilters,
    createScanSelection,
    createSortableTable,
    cronHint,
    element,
    escapeHtml,
    formatDuration,
    formatTime,
    jobRows,
    message,
    resultLabel,
    resultStatus,
    start,
    status,
  };
})();
