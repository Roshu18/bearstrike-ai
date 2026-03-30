const toolListEl = document.getElementById("toolList");
const liveFeedEl = document.getElementById("liveFeed");
const targetInputEl = document.getElementById("targetInput");
const targetStatusEl = document.getElementById("targetStatus");
const targetFolderHintEl = document.getElementById("targetFolderHint");
const setTargetBtn = document.getElementById("setTargetBtn");
const refreshToolsBtn = document.getElementById("refreshToolsBtn");
const toolSearchEl = document.getElementById("toolSearch");
const toolStatusFilterEl = document.getElementById("toolStatusFilter");
const toolPageSizeEl = document.getElementById("toolPageSize");
const categoryFiltersEl = document.getElementById("categoryFilters");
const quickToolSelectEl = document.getElementById("quickToolSelect");
const runToolBtn = document.getElementById("runToolBtn");

const uptimeValueEl = document.getElementById("uptimeValue");
const installedValueEl = document.getElementById("installedValue");
const totalToolsValueEl = document.getElementById("totalToolsValue");
const runsValueEl = document.getElementById("runsValue");
const jobsQueuedValueEl = document.getElementById("jobsQueuedValue");
const jobsRunningValueEl = document.getElementById("jobsRunningValue");
const cacheEntriesValueEl = document.getElementById("cacheEntriesValue");
const dedupeRatioValueEl = document.getElementById("dedupeRatioValue");
const queueTotalValueEl = document.getElementById("queueTotalValue");
const queuePressureBarEl = document.getElementById("queuePressureBar");
const cacheHitBarEl = document.getElementById("cacheHitBar");
const platformMetaEl = document.getElementById("platformMeta");
const healthPillEl = document.getElementById("healthPill");
const navHealthTextEl = document.getElementById("navHealthText");

const jobsListEl = document.getElementById("jobsList");
const refreshJobsBtn = document.getElementById("refreshJobsBtn");
const jobDetailViewEl = document.getElementById("jobDetailView");
const jobTargetFilterEl = document.getElementById("jobTargetFilter");

const plannerModeEl = document.getElementById("plannerMode");
const buildPlanBtn = document.getElementById("buildPlanBtn");
const runPlanBtn = document.getElementById("runPlanBtn");
const plannerViewEl = document.getElementById("plannerView");
const endpointPriorityEl = document.getElementById("endpointPriority");
const toolsPaginationEl = document.getElementById("toolsPagination");
const purgeDaysInputEl = document.getElementById("purgeDaysInput");
const purgeIncludeResearchEl = document.getElementById("purgeIncludeResearch");
const purgeVacuumEl = document.getElementById("purgeVacuum");
const purgeNowBtnEl = document.getElementById("purgeNowBtn");
const clearAllBtnEl = document.getElementById("clearAllBtn");
const purgeStatusEl = document.getElementById("purgeStatus");
const purgeResultEl = document.getElementById("purgeResult");
const storageHintEl = document.getElementById("storageHint");
const uiTooltipEl = document.getElementById("uiTooltip");

let allTools = [];
let allJobs = [];
let activeJobTargetFilter = "";
let activeCategory = "all";
let activeStatus = "all";
let targetInFlight = false;
let dashboardErrorShown = false;
let dashboardStreamActive = false;
let lastTargetSubmission = { value: "", at: 0 };
let installingTools = new Set();
let plannerCache = null;
let toolsMeta = { page: 1, page_size: 12, total_pages: 1, total_filtered: 0, categories: [] };
let searchDebounceTimer = null;
let dashboardCurrentTarget = "";
let purgeInFlight = false;
let tooltipHost = null;

const DOMAIN_EXCLUDED_QUICK_CATEGORIES = new Set(["binary", "wireless", "forensics"]);
const DOMAIN_EXCLUDED_QUICK_NAMES = new Set([
  "angr",
  "binary_analysis",
  "binwalk",
  "checksec",
  "gdb",
  "gdb-peda",
  "ghidra",
  "radare2",
  "ropgadget",
  "ropper",
  "strings",
  "xxd",
  "aircrack-ng",
  "bettercap",
  "kismet",
  "wifi_pentest",
  "foremost",
  "steghide",
  "volatility",
  "volatility3",
]);

const FEED_DEDUPE_WINDOW_MS = 4000;
const FEED_DEDUPE_RETENTION_MS = 60000;
const feedDedupe = new Map();
const MCP_EVENT_RETENTION_MS = 10 * 60 * 1000;
const mcpEventSeen = new Map();
let mcpFeedPrimed = false;
let lastMcpEventTimestamp = 0;

function addFeed(message, type = "info") {
  const now = Date.now();
  const key = `${type}::${String(message || "").trim()}`;
  const lastSeen = Number(feedDedupe.get(key) || 0);

  if (now - lastSeen < FEED_DEDUPE_WINDOW_MS) {
    return;
  }

  feedDedupe.set(key, now);
  for (const [entryKey, seenAt] of feedDedupe.entries()) {
    if (now - Number(seenAt) > FEED_DEDUPE_RETENTION_MS) {
      feedDedupe.delete(entryKey);
    }
  }

  const line = document.createElement("p");
  line.className = `feed-line ${type}`;
  line.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
  liveFeedEl.prepend(line);

  const maxEntries = 150;
  while (liveFeedEl.children.length > maxEntries) {
    liveFeedEl.removeChild(liveFeedEl.lastChild);
  }
}

function mcpStatusToFeedType(status) {
  const value = String(status || "").trim().toLowerCase();
  if (["success", "cached", "deduped"].includes(value)) {
    return "ok";
  }
  if (["running", "queued", "busy", "progress"].includes(value)) {
    return "progress";
  }
  if (["failed", "error", "blocked", "throttled"].includes(value)) {
    return "warn";
  }
  return "info";
}

function processMcpEvents(events) {
  if (!Array.isArray(events) || !events.length) {
    return;
  }

  const normalized = events
    .map((item) => (item && typeof item === "object" ? item : null))
    .filter(Boolean)
    .sort((a, b) => Number(a.timestamp || 0) - Number(b.timestamp || 0));

  if (!normalized.length) {
    return;
  }

  const currentBatch = mcpFeedPrimed ? normalized : normalized.slice(-6);
  mcpFeedPrimed = true;
  const now = Date.now();

  for (const event of currentBatch) {
    const ts = Number(event.timestamp || 0);
    const tsMillis = ts > 0 ? Math.round(ts * 1000) : 0;
    const tool = String(event.tool || "mcp").trim() || "mcp";
    const target = String(event.target || "").trim();
    const status = String(event.status || "info").trim().toLowerCase() || "info";
    const progress = String(event.progress || "").trim();

    let detail = String(event.preview || "").trim();
    if (!detail) {
      detail = String(event.command || "").trim();
    }
    if (detail.length > 140) {
      detail = `${detail.slice(0, 137)}...`;
    }

    const signature = `${tsMillis}|${tool}|${target}|${status}|${progress}|${detail}`;
    if (mcpEventSeen.has(signature)) {
      continue;
    }
    if (lastMcpEventTimestamp > 0 && ts > 0 && ts < lastMcpEventTimestamp - 5) {
      continue;
    }
    mcpEventSeen.set(signature, now);
    if (ts > lastMcpEventTimestamp) {
      lastMcpEventTimestamp = ts;
    }

    for (const [key, seenAt] of mcpEventSeen.entries()) {
      if (now - Number(seenAt) > MCP_EVENT_RETENTION_MS) {
        mcpEventSeen.delete(key);
      }
    }

    const targetPart = target ? ` ${target}` : "";
    const progressPart = progress ? ` ${progress}` : "";
    const detailPart = detail ? ` | ${detail}` : "";
    addFeed(`MCP ${tool}${targetPart} ${status}${progressPart}${detailPart}`, mcpStatusToFeedType(status));
  }
}

function setTargetDisabled(disabled) {
  targetInFlight = disabled;
  setTargetBtn.disabled = disabled;
}

function buildCategoryFilters(categoriesInput = []) {
  const categories = ["all", ...new Set((categoriesInput || []).map((value) => String(value || "misc")))];
  categoryFiltersEl.innerHTML = "";

  categories.forEach((category) => {
    const chip = document.createElement("button");
    chip.className = `filter-chip ${activeCategory === category ? "active" : ""}`;
    chip.textContent = category;
    chip.addEventListener("click", async () => {
      activeCategory = category;
      buildCategoryFilters(toolsMeta.categories || []);
      await loadTools(false, 1);
    });
    categoryFiltersEl.appendChild(chip);
  });
}

function syncQuickToolSelect(tools) {
  const selected = quickToolSelectEl.value;
  const effectiveTarget = getEffectiveTarget();
  const domainLike = isDomainLikeTarget(effectiveTarget);
  quickToolSelectEl.innerHTML = "";

  tools.forEach((tool) => {
    if (!isQuickToolAllowedForTarget(tool, domainLike)) {
      return;
    }
    const option = document.createElement("option");
    option.value = tool.name;
    option.textContent = tool.name;
    quickToolSelectEl.appendChild(option);
  });

  if (!quickToolSelectEl.options.length) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "No installed tools";
    quickToolSelectEl.appendChild(option);
    quickToolSelectEl.disabled = true;
  } else {
    quickToolSelectEl.disabled = false;
    if (selected) {
      quickToolSelectEl.value = selected;
    }
  }
}

function isDomainLikeTarget(targetValue) {
  const raw = String(targetValue || "").trim().toLowerCase();
  if (!raw) {
    return false;
  }
  const withoutScheme = raw.replace(/^https?:\/\//, "").replace(/^wss?:\/\//, "");
  const host = withoutScheme.split("/")[0].trim();
  if (!host) {
    return false;
  }
  const ipLike = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host);
  if (ipLike) {
    return false;
  }
  return host.includes(".");
}

function isQuickToolAllowedForTarget(tool, domainLike) {
  if (!tool || String(tool.status || "").toLowerCase() !== "installed") {
    return false;
  }
  const name = String(tool.name || "").trim().toLowerCase();
  const category = String(tool.category || "").trim().toLowerCase();
  if (!name) {
    return false;
  }
  if (!domainLike) {
    return true;
  }
  if (DOMAIN_EXCLUDED_QUICK_CATEGORIES.has(category)) {
    return false;
  }
  if (DOMAIN_EXCLUDED_QUICK_NAMES.has(name)) {
    return false;
  }
  return true;
}

function renderTools() {
  const tools = allTools;
  toolListEl.innerHTML = "";

  if (!tools.length) {
    toolListEl.innerHTML = "<p class='muted'>No tools match current filter.</p>";
    return;
  }

  const grouped = tools.reduce((acc, tool) => {
    const key = String(tool.category || "misc");
    if (!acc[key]) {
      acc[key] = [];
    }
    acc[key].push(tool);
    return acc;
  }, {});

  Object.keys(grouped)
    .sort((a, b) => a.localeCompare(b))
    .forEach((category, index) => {
      const wrapper = document.createElement("details");
      wrapper.className = "tool-group";
      if (index === 0) {
        wrapper.open = true;
      }

      const summary = document.createElement("summary");
      summary.className = "tool-group-summary";
      summary.textContent = `${category.toUpperCase()} (${grouped[category].length})`;
      wrapper.appendChild(summary);

      const groupBody = document.createElement("div");
      groupBody.className = "tool-group-body";

      grouped[category].forEach((tool) => {
        const card = document.createElement("div");
        card.className = "tool-item";

        const statusClass = tool.status === "installed" ? "installed" : "not_installed";

        card.innerHTML = `
          <div class="tool-top">
            <span class="tool-name">${tool.name}</span>
            <span class="badge ${statusClass}">${tool.status}</span>
          </div>
          <div class="tool-meta">${tool.category} | ${tool.description}</div>
          <div class="actions">
            <button class="install-btn" data-action="install" data-tool="${tool.name}">Install</button>
            <button class="run-btn" data-action="run" data-tool="${tool.name}">Queue</button>
          </div>
        `;

        const installBtn = card.querySelector('[data-action="install"]');
        const runBtn = card.querySelector('[data-action="run"]');

        installBtn.disabled = installingTools.has(tool.name);
        runBtn.disabled = tool.status !== "installed";

        installBtn.addEventListener("click", () => installTool(tool.name));
        runBtn.addEventListener("click", () => queueToolRun(tool.name));

        groupBody.appendChild(card);
      });

      wrapper.appendChild(groupBody);
      toolListEl.appendChild(wrapper);
    });
}

function renderToolsPagination() {
  const page = Number(toolsMeta.page || 1);
  const totalPages = Number(toolsMeta.total_pages || 1);
  const totalFiltered = Number(toolsMeta.total_filtered || 0);

  toolsPaginationEl.innerHTML = "";
  const info = document.createElement("span");
  info.textContent = `Showing page ${page}/${totalPages} | ${totalFiltered} tools`;

  const controls = document.createElement("div");
  controls.className = "pagination-controls";

  const prevBtn = document.createElement("button");
  prevBtn.className = "ghost";
  prevBtn.textContent = "Prev";
  prevBtn.disabled = page <= 1;
  prevBtn.addEventListener("click", () => loadTools(false, page - 1));

  const nextBtn = document.createElement("button");
  nextBtn.className = "ghost";
  nextBtn.textContent = "Next";
  nextBtn.disabled = page >= totalPages;
  nextBtn.addEventListener("click", () => loadTools(false, page + 1));

  controls.appendChild(prevBtn);
  controls.appendChild(nextBtn);
  toolsPaginationEl.appendChild(info);
  toolsPaginationEl.appendChild(controls);
}

function formatDuration(seconds) {
  const value = Number(seconds || 0);
  if (value < 60) return `${Math.round(value)}s`;
  const mins = Math.floor(value / 60);
  const secs = Math.floor(value % 60);
  return `${mins}m ${secs}s`;
}

async function loadTools(showFeed = false, pageOverride = null) {
  try {
    const page = Number(pageOverride || toolsMeta.page || 1);
    const search = (toolSearchEl.value || "").trim();
    const category = activeCategory || "all";
    const status = activeStatus || "all";
    const pageSize = Number(toolPageSizeEl?.value || toolsMeta.page_size || 12);
    const refresh = showFeed ? 1 : 0;

    const qs = new URLSearchParams({
      refresh: String(refresh),
      page: String(page),
      page_size: String(pageSize),
      category,
      status,
      q: search,
    });

    const res = await fetch(`/api/tools?${qs.toString()}`);
    const data = await res.json();
    allTools = data.tools || [];
    toolsMeta = { ...toolsMeta, ...(data.meta || {}), page_size: pageSize };

    buildCategoryFilters(toolsMeta.categories || []);
    syncQuickToolSelect(allTools);
    renderTools();
    renderToolsPagination();
    if (showFeed) {
      addFeed("Tool status refreshed", "info");
    }
  } catch (err) {
    addFeed("Failed to load tool registry", "warn");
  }
}

async function setTarget() {
  const target = targetInputEl.value.trim();
  if (!target) {
    addFeed("Target is required", "warn");
    return;
  }

  if (targetInFlight) {
    addFeed("Target update already in progress", "info");
    return;
  }

  const now = Date.now();
  if (lastTargetSubmission.value === target && now - lastTargetSubmission.at < 2000) {
    addFeed("Target already submitted, waiting for response...", "info");
    return;
  }

  setTargetDisabled(true);
  lastTargetSubmission = { value: target, at: now };

  try {
    const res = await fetch("/api/target", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target }),
    });
    const data = await res.json();

    if (!res.ok) {
      addFeed(data.error || "Unable to set target", "warn");
      return;
    }

    targetStatusEl.textContent = `Current target: ${data.target} | WAF: ${data.waf_status || "Unknown"}`;
    if (data.duplicate) {
      addFeed(`Target already set: ${data.target}`, "info");
    } else {
      addFeed(`Target set: ${data.target} (WAF: ${data.waf_status || "Unknown"})`, "ok");
      const rotation = data.rotation || {};
      if (rotation.triggered) {
        addFeed(
          `Auto-cleanup applied: pruned ${Number((rotation.pruned_targets || []).length)} older target datasets`,
          "info",
        );
      }
    }
    syncQuickToolSelect(allTools || []);
  } catch (err) {
    addFeed("Target update failed", "warn");
  } finally {
    setTargetDisabled(false);
  }
}

async function installTool(toolName) {
  if (installingTools.has(toolName)) {
    addFeed(`${toolName} install already running`, "info");
    return;
  }

  installingTools.add(toolName);
  renderTools();
  addFeed(`Installing ${toolName}...`, "progress");

  try {
    const res = await fetch("/api/install", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tool: toolName }),
    });
    const data = await res.json();

    if (!res.ok || data.status === "failed") {
      addFeed(`${toolName} install failed: ${(data.output || data.error || "unknown").slice(0, 180)}`, "warn");
      return;
    }

    addFeed(`${toolName} installed successfully`, "ok");
    await loadTools(false, 1);
    await loadDashboard();
  } catch (err) {
    addFeed(`Install request failed for ${toolName}`, "warn");
  } finally {
    installingTools.delete(toolName);
    renderTools();
  }
}

function getEffectiveTarget() {
  if (dashboardCurrentTarget) {
    return dashboardCurrentTarget;
  }
  const typed = targetInputEl.value.trim();
  if (typed) {
    return typed;
  }
  return "";
}

async function queueToolRun(toolName, timeoutSeconds = 45) {
  const target = getEffectiveTarget();
  if (!target) {
    addFeed("Set a target first", "warn");
    return { ok: false, status: "missing_target", throttled: false };
  }

  try {
    const res = await fetch("/api/jobs/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tool: toolName, target, timeout_seconds: timeoutSeconds }),
    });
    const data = await res.json();

    if (!res.ok || !data.success) {
      if (String(data.status || "").toLowerCase() === "throttled") {
        addFeed(`Queue busy: ${data.error || "wait for running jobs to finish"}`, "info");
        return {
          ok: false,
          status: "throttled",
          throttled: true,
          queueSubmissionCap: Number(data.queue_submission_cap || 0),
          outstandingJobs: Number(data.outstanding_jobs || 0),
        };
      }
      addFeed(`Failed to queue ${toolName}: ${data.error || "unknown"}`, "warn");
      return { ok: false, status: "failed", throttled: false };
    }

    if (data.status === "deduped") {
      addFeed(`Dedupe merged ${toolName}: using ${data.job_id}`, "info");
    } else if (data.status === "cached") {
      addFeed(`Cache hit for ${toolName}: ${String(data.summary || "ready")}`.slice(0, 180), "ok");
    } else {
      addFeed(`Queued ${toolName} on ${target} (${data.job_id})`, "progress");
    }

    await loadJobs(false);
    await loadDashboard();
    return { ok: true, status: String(data.status || "queued").toLowerCase(), throttled: false };
  } catch (err) {
    addFeed(`Queue request failed for ${toolName}`, "warn");
    return { ok: false, status: "request_failed", throttled: false };
  }
}

async function runSelectedTool() {
  const selected = quickToolSelectEl.value;
  if (!selected) {
    addFeed("No installed tool available for quick run", "warn");
    return;
  }
  await queueToolRun(selected, 45);
}

function renderEndpointPriority(endpointPriority) {
  if (!endpointPriorityEl) {
    return;
  }

  const high = (endpointPriority && endpointPriority.high) || [];
  const medium = (endpointPriority && endpointPriority.medium) || [];
  const low = (endpointPriority && endpointPriority.low) || [];

  endpointPriorityEl.innerHTML = `
    <div class="endpoint-priority-grid">
      <div class="endpoint-priority-card"><strong>High</strong><span>${high.length}</span></div>
      <div class="endpoint-priority-card"><strong>Medium</strong><span>${medium.length}</span></div>
      <div class="endpoint-priority-card"><strong>Low</strong><span>${low.length}</span></div>
    </div>
  `;
}

function renderPlanner(planPayload) {
  const resolved = planPayload && planPayload.plan ? planPayload.plan : planPayload;
  if (!resolved || !Array.isArray(resolved.recommended_steps)) {
    plannerViewEl.textContent = "Planner not available for current target.";
    renderEndpointPriority({ high: [], medium: [], low: [] });
    return;
  }

  const plan = resolved;
  const steps = plan.recommended_steps || [];
  if (!steps.length) {
    plannerViewEl.textContent = "No recommended steps. Install core recon tools first.";
    renderEndpointPriority(plan.endpoint_priority || { high: [], medium: [], low: [] });
    return;
  }

  plannerViewEl.innerHTML = "";
  const summary = document.createElement("div");
  summary.className = "planner-step";
  summary.innerHTML = `<strong>${plan.target}</strong> | mode=${plan.mode} | token=${plan.estimated_token_cost} | waf=${plan.waf_status}`;
  plannerViewEl.appendChild(summary);

  steps.forEach((step, idx) => {
    const block = document.createElement("div");
    block.className = "planner-step";
    block.innerHTML = `
      <div><strong>${idx + 1}. ${step.tool}</strong> <span class="muted">(${step.category})</span></div>
      <div class="job-meta">timeout=${step.timeout_seconds}s | noise=${step.noise} | token=${step.token_cost}</div>
      <div>${step.reason}</div>
    `;
    plannerViewEl.appendChild(block);
  });

  renderEndpointPriority(plan.endpoint_priority || { high: [], medium: [], low: [] });

  if (Array.isArray(plan.warnings) && plan.warnings.length) {
    const warn = document.createElement("div");
    warn.className = "planner-step";
    warn.innerHTML = `<strong>Warnings</strong><div>${plan.warnings.join("<br>")}</div>`;
    plannerViewEl.appendChild(warn);
  }
}

async function buildPlan(showFeed = true) {
  const target = getEffectiveTarget();
  if (!target) {
    addFeed("Set a target first before building plan", "warn");
    return null;
  }

  const mode = plannerModeEl.value || "low_noise";
  try {
    const res = await fetch(`/api/planner?target=${encodeURIComponent(target)}&mode=${encodeURIComponent(mode)}`);
    const data = await res.json();
    if (!res.ok || data.error) {
      addFeed(data.error || "Planner failed", "warn");
      return null;
    }
    const wrapped = data.plan ? data : { success: true, plan: data };
    plannerCache = wrapped;
    renderPlanner(wrapped);
    if (showFeed) {
      addFeed(`Plan built (${mode}) for ${target}`, "info");
    }
    return data;
  } catch (err) {
    addFeed("Planner request failed", "warn");
    return null;
  }
}

async function queuePlan() {
  const payload = plannerCache || (await buildPlan(false));
  if (!payload || !payload.plan) {
    addFeed("No planner data available", "warn");
    return;
  }

  const steps = (payload.plan.recommended_steps || []).slice(0, 4);
  if (!steps.length) {
    addFeed("No runnable steps in plan", "warn");
    return;
  }

  let queuedCount = 0;
  for (const step of steps) {
    let queued = false;
    for (let attempt = 0; attempt < 10; attempt += 1) {
      const result = await queueToolRun(step.tool, Number(step.timeout_seconds || 45));
      if (result && result.ok) {
        queued = true;
        break;
      }
      if (result && result.throttled) {
        await new Promise((resolve) => setTimeout(resolve, 1200));
        continue;
      }
      break;
    }
    if (!queued) {
      addFeed(`Skipped ${step.tool}: queue limit or request failure`, "warn");
    } else {
      queuedCount += 1;
    }
  }

  addFeed(`Queued ${queuedCount}/${steps.length} planned steps`, queuedCount ? "ok" : "warn");
}

async function loadJobs(showFeed = false) {
  try {
    const qs = new URLSearchParams({ limit: "40" });
    let targetFilter = String(activeJobTargetFilter || "").trim();
    if (targetFilter === "__current__") {
      targetFilter = String(dashboardCurrentTarget || "").trim();
    }
    if (targetFilter) {
      qs.set("target", targetFilter);
    }
    const res = await fetch(`/api/jobs?${qs.toString()}`);
    const data = await res.json();
    allJobs = data.jobs || [];
    syncJobTargetFilterOptions();
    renderJobs();
    if (showFeed) {
      addFeed("Jobs refreshed", "info");
    }
  } catch (err) {
    addFeed("Failed to load jobs", "warn");
  }
}

function formatJobTime(epoch) {
  if (!epoch) {
    return "--";
  }
  const d = new Date(Number(epoch) * 1000);
  return d.toLocaleTimeString();
}

function renderJobs() {
  jobsListEl.innerHTML = "";
  if (!allJobs.length) {
    jobsListEl.innerHTML = "<p class='muted'>No jobs yet.</p>";
    return;
  }

  allJobs.forEach((job) => {
    const card = document.createElement("div");
    card.className = "job-item";

    const status = String(job.status || "queued").toLowerCase();
    const source = String(job.source || "unknown").toLowerCase();
    const canManage = source === "dashboard";
    const canRetry = canManage && ["failed", "cancelled", "canceled"].includes(status);
    const canCancel = canManage && ["queued", "running"].includes(status);

    card.innerHTML = `
      <div class="job-head">
        <div>
          <strong>${job.tool}</strong>
          <div class="job-meta">${job.target}</div>
        </div>
        <div class="job-badges">
          <span class="badge ${status}">${status}</span>
          <span class="badge job-source ${source}">${source}</span>
        </div>
      </div>
      <div class="job-meta">${job.job_id} | ${job.progress || ""}</div>
      <div class="job-meta">created=${formatJobTime(job.created_at)} | started=${formatJobTime(job.started_at)} | finished=${formatJobTime(job.finished_at)}</div>
      <div class="job-actions">
        <button class="ghost" data-action="view">View</button>
        <button class="ghost" data-action="retry" ${canRetry ? "" : "disabled"}>Retry</button>
        <button class="ghost" data-action="cancel" ${canCancel ? "" : "disabled"}>Cancel</button>
      </div>
    `;

    card.querySelector('[data-action="view"]').addEventListener("click", () => viewJob(job.job_id));
    card.querySelector('[data-action="retry"]').addEventListener("click", () => retryJob(job.job_id));
    card.querySelector('[data-action="cancel"]').addEventListener("click", () => cancelJob(job.job_id));

    jobsListEl.appendChild(card);
  });
}

function syncJobTargetFilterOptions() {
  if (!jobTargetFilterEl) {
    return;
  }
  const previous = String(jobTargetFilterEl.value || "");
  const seenTargets = [];
  const seen = new Set();
  for (const job of allJobs) {
    const target = String((job || {}).target || "").trim();
    if (!target || seen.has(target)) {
      continue;
    }
    seen.add(target);
    seenTargets.push(target);
  }
  seenTargets.sort((a, b) => a.localeCompare(b));

  jobTargetFilterEl.innerHTML = "";
  const allOpt = document.createElement("option");
  allOpt.value = "";
  allOpt.textContent = "all targets";
  jobTargetFilterEl.appendChild(allOpt);

  const currentOpt = document.createElement("option");
  currentOpt.value = "__current__";
  currentOpt.textContent = "current target";
  jobTargetFilterEl.appendChild(currentOpt);

  for (const target of seenTargets) {
    const opt = document.createElement("option");
    opt.value = target;
    opt.textContent = target;
    jobTargetFilterEl.appendChild(opt);
  }

  if ([...jobTargetFilterEl.options].some((option) => option.value === previous)) {
    jobTargetFilterEl.value = previous;
  } else if ([...jobTargetFilterEl.options].some((option) => option.value === activeJobTargetFilter)) {
    jobTargetFilterEl.value = activeJobTargetFilter;
  } else {
    jobTargetFilterEl.value = "";
  }
}

async function viewJob(jobId) {
  try {
    const res = await fetch(`/api/jobs/${encodeURIComponent(jobId)}?output=1&max_chars=12000`);
    const data = await res.json();
    if (!res.ok || !data.success) {
      addFeed(data.error || "Unable to fetch job output", "warn");
      return;
    }

    const job = data.job || {};
    const output = String(job.output || job.error || "No output");
    const block = `[${job.job_id}] ${job.status}\nTool: ${job.tool}\nTarget: ${job.target}\n\n${output}`;
    if (jobDetailViewEl) {
      jobDetailViewEl.textContent = block.slice(0, 24000);
      jobDetailViewEl.classList.remove("muted");
    }
    addFeed(`[${job.tool}] output loaded`, "info");
  } catch (err) {
    addFeed("Job output request failed", "warn");
  }
}

async function retryJob(jobId) {
  const job = allJobs.find((entry) => String(entry.job_id || "") === String(jobId));
  if (job && String(job.source || "").toLowerCase() !== "dashboard") {
    addFeed(`Retry not supported for ${job.source} jobs`, "info");
    return;
  }
  try {
    const res = await fetch(`/api/jobs/${encodeURIComponent(jobId)}/retry`, { method: "POST" });
    const data = await res.json();
    if (!res.ok || !data.success) {
      addFeed(data.error || "Retry failed", "warn");
      return;
    }
    addFeed(`Retry queued: ${data.job.job_id}`, "progress");
    await loadJobs(false);
  } catch (err) {
    addFeed("Retry request failed", "warn");
  }
}

async function cancelJob(jobId) {
  const job = allJobs.find((entry) => String(entry.job_id || "") === String(jobId));
  if (job && String(job.source || "").toLowerCase() !== "dashboard") {
    addFeed(`Cancel not supported for ${job.source} jobs`, "info");
    return;
  }
  try {
    const res = await fetch(`/api/jobs/${encodeURIComponent(jobId)}/cancel`, { method: "POST" });
    const data = await res.json();
    if (!res.ok || !data.success) {
      addFeed(data.error || "Cancel failed", "warn");
      return;
    }
    addFeed(`Cancel requested: ${jobId}`, "warn");
    await loadJobs(false);
  } catch (err) {
    addFeed("Cancel request failed", "warn");
  }
}

function refreshSummary(snapshot) {
  const uptime = Number(snapshot.uptime_seconds || 0);
  uptimeValueEl.textContent = formatDuration(uptime);
  installedValueEl.textContent = String(snapshot.installed_tools || 0);
  totalToolsValueEl.textContent = String(snapshot.total_tools || 0);
  runsValueEl.textContent = String(snapshot.runs_count || 0);
  jobsQueuedValueEl.textContent = String(snapshot.jobs_queued || 0);
  jobsRunningValueEl.textContent = String(snapshot.jobs_running || 0);

  const cacheStats = snapshot.cache_stats || {};
  const dedupeStats = snapshot.dedupe_stats || {};
  const queueStats = snapshot.queue_stats || {};

  const cacheEntries = Number(cacheStats.active_entries || 0);
  const cacheHitJobs = Number(dedupeStats.cache_hit_jobs || 0);
  const totalJobs = Math.max(0, Number(dedupeStats.total_jobs || 0));
  const dedupeRatioPct = Math.max(0, Math.min(100, Math.round(Number(dedupeStats.dedupe_ratio || 0) * 100)));
  const queueTotal = Number(queueStats.total || 0);

  cacheEntriesValueEl.textContent = String(cacheEntries);
  dedupeRatioValueEl.textContent = `${dedupeRatioPct}%`;
  queueTotalValueEl.textContent = String(queueTotal);

  const queueDepth = Math.max(0, Number(snapshot.jobs_queue_depth || 0));
  const queuePressurePct = Math.max(0, Math.min(100, Math.round((queueDepth / 25) * 100)));
  const cacheHitPct = totalJobs > 0 ? Math.max(0, Math.min(100, Math.round((cacheHitJobs / totalJobs) * 100))) : 0;

  if (queuePressureBarEl) {
    queuePressureBarEl.style.width = `${queuePressurePct}%`;
  }
  if (cacheHitBarEl) {
    cacheHitBarEl.style.width = `${cacheHitPct}%`;
  }

  const currentTarget = snapshot.current_target || "No target selected";
  const wafStatus = snapshot.waf_status || "Unknown";
  const targetOutputDir = String(snapshot.target_output_dir || "").trim();
  dashboardCurrentTarget = currentTarget && currentTarget !== "No target selected" ? String(currentTarget) : "";
  targetStatusEl.textContent = `Current target: ${currentTarget} | WAF: ${wafStatus}`;
  if (targetFolderHintEl) {
    targetFolderHintEl.textContent = `Target folder: ${targetOutputDir || "--"}`;
  }
  if (!targetInFlight && document.activeElement !== targetInputEl && !targetInputEl.value.trim() && dashboardCurrentTarget) {
    targetInputEl.value = dashboardCurrentTarget;
  }

  const platform = snapshot.platform || {};
  platformMetaEl.textContent = `${platform.platform_kind || "Unknown"} | pkg=${platform.package_manager || "manual"} | py=${platform.python_command || "python3"}`;

  const healthy = snapshot.status === "healthy";
  healthPillEl.textContent = healthy ? "HEALTHY" : "DEGRADED";
  if (navHealthTextEl) {
    navHealthTextEl.textContent = healthy ? "Healthy" : "Degraded";
  }

  const storageStats = snapshot.storage_stats || {};
  const dbSizeMb = Number(storageStats.db_size_mb || 0);
  if (storageHintEl) {
    storageHintEl.textContent = `DB: ${dbSizeMb.toFixed(2)} MB`;
  }

  processMcpEvents(snapshot.mcp_events || []);
}

async function loadDashboard() {
  try {
    const res = await fetch("/api/dashboard", { cache: "no-store" });
    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || "dashboard summary failed");
    }

    refreshSummary(data);
    dashboardErrorShown = false;
  } catch (err) {
    if (!dashboardErrorShown) {
      addFeed("Dashboard summary fetch failed", "warn");
      dashboardErrorShown = true;
    }
  }
}

function startDashboardStream() {
  if (dashboardStreamActive || typeof EventSource === "undefined") {
    return;
  }

  const source = new EventSource("/api/dashboard/stream");
  dashboardStreamActive = true;

  source.onmessage = (event) => {
    try {
      const snapshot = JSON.parse(event.data);
      refreshSummary(snapshot);
      dashboardErrorShown = false;
    } catch (_err) {
      // ignore malformed chunk
    }
  };

  source.onerror = () => {
    source.close();
    dashboardStreamActive = false;
    setTimeout(startDashboardStream, 2000);
  };
}

function startPolling() {
  setInterval(() => {
    if (!dashboardStreamActive) {
      loadDashboard();
    }
  }, 5000);
  setInterval(loadJobs, 3000);
}

function startTooltips() {
  if (!uiTooltipEl) {
    return;
  }

  const place = (x, y) => {
    const pad = 12;
    const maxX = window.innerWidth - uiTooltipEl.offsetWidth - pad;
    const maxY = window.innerHeight - uiTooltipEl.offsetHeight - pad;
    const left = Math.max(pad, Math.min(maxX, x + 16));
    const top = Math.max(pad, Math.min(maxY, y + 18));
    uiTooltipEl.style.left = `${left}px`;
    uiTooltipEl.style.top = `${top}px`;
  };

  document.addEventListener("mousemove", (event) => {
    const rawTarget = event.target;
    if (!(rawTarget instanceof Element)) {
      if (tooltipHost) {
        tooltipHost = null;
        uiTooltipEl.classList.remove("visible");
      }
      return;
    }
    const host = rawTarget.closest(".help-tip[data-tip]");
    if (!host) {
      if (tooltipHost) {
        tooltipHost = null;
        uiTooltipEl.classList.remove("visible");
      }
      return;
    }

    const tip = String(host.getAttribute("data-tip") || "").trim();
    if (!tip) {
      uiTooltipEl.classList.remove("visible");
      tooltipHost = null;
      return;
    }

    if (tooltipHost !== host || uiTooltipEl.textContent !== tip) {
      uiTooltipEl.textContent = tip;
      tooltipHost = host;
    }
    place(event.clientX, event.clientY);
    uiTooltipEl.classList.add("visible");
  });

  document.addEventListener("mouseleave", () => {
    tooltipHost = null;
    uiTooltipEl.classList.remove("visible");
  });
}

async function purgeOldData() {
  if (!purgeNowBtnEl || !clearAllBtnEl || !purgeStatusEl || !purgeResultEl || !purgeDaysInputEl || !purgeIncludeResearchEl || !purgeVacuumEl) {
    return;
  }
  if (purgeInFlight) {
    addFeed("Purge already running", "info");
    return;
  }

  const days = Math.max(1, Math.min(3650, Number(purgeDaysInputEl.value || 7)));
  const includeResearch = Boolean(purgeIncludeResearchEl.checked);
  const vacuum = Boolean(purgeVacuumEl.checked);

  purgeInFlight = true;
  purgeNowBtnEl.disabled = true;
  clearAllBtnEl.disabled = true;
  purgeStatusEl.textContent = `Running purge (${days}d)...`;
  addFeed(`Starting purge older than ${days} days`, "progress");

  try {
    const res = await fetch("/api/maintenance/purge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        days,
        include_research: includeResearch,
        vacuum,
      }),
    });
    const data = await res.json();
    if (!res.ok || !data.success) {
      purgeStatusEl.textContent = "Purge failed";
      purgeResultEl.textContent = String(data.error || "Purge request failed");
      addFeed(`Purge failed: ${data.error || "unknown error"}`, "warn");
      return;
    }

    const reclaimedMb = Number(data.reclaimed_mb || 0);
    const deleted = data.deleted || {};
    purgeStatusEl.textContent = `Done: reclaimed ~${reclaimedMb.toFixed(3)} MB`;
    purgeResultEl.textContent = [
      `Purge window: ${data.older_than_days} days`,
      `Deleted run_jobs: ${Number(deleted.run_jobs || 0)}`,
      `Deleted run_events: ${Number(deleted.run_events || 0)}`,
      `Deleted cache rows: ${Number(deleted.request_fingerprint_cache || 0)}`,
      `Deleted endpoint intel: ${Number(deleted.endpoint_intel || 0)}`,
      `Deleted research_findings: ${Number(deleted.research_findings || 0)}`,
      `Vacuum: ${data.vacuumed ? "yes" : "no"}`,
      data.vacuum_error ? `Vacuum error: ${data.vacuum_error}` : "",
      `DB size: ${Number((data.after || {}).db_size_mb || 0).toFixed(3)} MB`,
    ]
      .filter(Boolean)
      .join("\n");

    addFeed(`Purge complete: reclaimed ~${reclaimedMb.toFixed(3)} MB`, "ok");
    await loadDashboard();
  } catch (_err) {
    purgeStatusEl.textContent = "Purge failed";
    purgeResultEl.textContent = "Purge request failed due to network/backend issue.";
    addFeed("Purge request failed", "warn");
  } finally {
    purgeInFlight = false;
    purgeNowBtnEl.disabled = false;
    clearAllBtnEl.disabled = false;
  }
}

async function clearAllData() {
  if (!purgeNowBtnEl || !clearAllBtnEl || !purgeStatusEl || !purgeResultEl) {
    return;
  }
  if (purgeInFlight) {
    addFeed("Maintenance action already running", "info");
    return;
  }

  purgeInFlight = true;
  purgeNowBtnEl.disabled = true;
  clearAllBtnEl.disabled = true;
  purgeStatusEl.textContent = "Clearing all DB runtime data...";
  addFeed("Clearing all runtime DB data", "progress");

  try {
    const res = await fetch("/api/maintenance/purge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        days: 7,
        include_research: true,
        vacuum: true,
        clear_all: true,
      }),
    });
    const data = await res.json();
    if (!res.ok || !data.success) {
      purgeStatusEl.textContent = "Clear-all failed";
      purgeResultEl.textContent = String(data.error || "Clear-all request failed");
      addFeed(`Clear-all failed: ${data.error || "unknown error"}`, "warn");
      return;
    }

    const reclaimedMb = Number(data.reclaimed_mb || 0);
    const deleted = data.deleted || {};
    purgeStatusEl.textContent = `Clear-all complete (~${reclaimedMb.toFixed(3)} MB reclaimed)`;
    purgeResultEl.textContent = [
      "Clear-all mode: yes",
      `Deleted run_jobs: ${Number(deleted.run_jobs || 0)}`,
      `Deleted run_events: ${Number(deleted.run_events || 0)}`,
      `Deleted cache rows: ${Number(deleted.request_fingerprint_cache || 0)}`,
      `Deleted endpoint intel: ${Number(deleted.endpoint_intel || 0)}`,
      `Deleted research_findings: ${Number(deleted.research_findings || 0)}`,
      `Deleted install-state rows: ${Number(deleted.tool_install_state || 0)}`,
      `DB size now: ${Number((data.after || {}).db_size_mb || 0).toFixed(3)} MB`,
    ].join("\n");
    addFeed(`Clear-all completed: reclaimed ~${reclaimedMb.toFixed(3)} MB`, "ok");
    await loadDashboard();
    await loadJobs(false);
  } catch (_err) {
    purgeStatusEl.textContent = "Clear-all failed";
    purgeResultEl.textContent = "Clear-all request failed due to network/backend issue.";
    addFeed("Clear-all request failed", "warn");
  } finally {
    purgeInFlight = false;
    purgeNowBtnEl.disabled = false;
    clearAllBtnEl.disabled = false;
  }
}

setTargetBtn.addEventListener("click", setTarget);
refreshToolsBtn.addEventListener("click", () => loadTools(true, 1));
refreshJobsBtn.addEventListener("click", () => loadJobs(true));
runToolBtn.addEventListener("click", runSelectedTool);
buildPlanBtn.addEventListener("click", () => buildPlan(true));
runPlanBtn.addEventListener("click", queuePlan);
if (purgeNowBtnEl) {
  purgeNowBtnEl.addEventListener("click", purgeOldData);
}
if (clearAllBtnEl) {
  clearAllBtnEl.addEventListener("click", clearAllData);
}

toolSearchEl.addEventListener("input", () => {
  if (searchDebounceTimer) {
    clearTimeout(searchDebounceTimer);
  }
  searchDebounceTimer = setTimeout(() => loadTools(false, 1), 220);
});

if (toolStatusFilterEl) {
  toolStatusFilterEl.addEventListener("change", () => {
    activeStatus = String(toolStatusFilterEl.value || "all");
    loadTools(false, 1);
  });
}

if (toolPageSizeEl) {
  toolPageSizeEl.addEventListener("change", () => {
    toolsMeta.page_size = Number(toolPageSizeEl.value || 12);
    loadTools(false, 1);
  });
}

if (jobTargetFilterEl) {
  jobTargetFilterEl.addEventListener("change", () => {
    activeJobTargetFilter = String(jobTargetFilterEl.value || "");
    loadJobs(false);
  });
}

if (targetInputEl) {
  targetInputEl.addEventListener("input", () => {
    syncQuickToolSelect(allTools || []);
  });
}

(async () => {
  await loadTools(false, 1);
  await loadDashboard();
  await loadJobs(false);
  startDashboardStream();
  startPolling();
  startTooltips();
  addFeed("Dashboard ready", "info");
})();
