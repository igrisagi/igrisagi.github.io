const $ = (selector) => document.querySelector(selector);

const state = {
  jobId: null,
  pollTimer: null,
  report: null,
  route: null,
  liveTimer: null,
  liveBusy: false,
  animationStarted: false,
};

const canvases = {
  route: $("#routeCanvas"),
  latency: $("#latencyChart"),
  dns: $("#dnsChart"),
  http: $("#httpChart"),
};

const palette = {
  teal: "#0f9488",
  blue: "#2563eb",
  amber: "#d09221",
  rose: "#c24132",
  purple: "#7c3aed",
  ink: "#17202c",
  muted: "#667085",
  line: "#d8dee8",
};

async function api(path, options = {}) {
  const headers = options.headers || {};
  if (options.body && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }
  const response = await fetch(path, { ...options, headers });
  if (!response.ok) {
    let message = `Request failed: ${response.status}`;
    try {
      const error = await response.json();
      message = error.error || message;
    } catch {
      message = await response.text();
    }
    throw new Error(message);
  }
  return response.json();
}

function splitLines(value) {
  return value
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function value(id) {
  return $(`#${id}`).value;
}

function checked(id) {
  return $(`#${id}`).checked;
}

function numberValue(id) {
  const el = $(`#${id}`);
  return Number.parseInt(el.value, 10);
}

function collectConfig() {
  return {
    targets: splitLines(value("targets")),
    domains: splitLines(value("domains")),
    urls: splitLines(value("urls")),
    tcp_targets: splitLines(value("tcpTargets")),
    dns_servers: splitLines(value("dnsServers")),
    dns_qtypes: splitLines(value("dnsQtypes")),
    traceroute_target: value("tracerouteTarget").trim(),
    traceroute_mode: value("tracerouteMode"),
    traceroute_tcp_port: numberValue("tracerouteTcpPort"),
    mtu_target: value("mtuTarget").trim(),
    ping_count: numberValue("pingCount"),
    ping_size: numberValue("pingSize"),
    ping_timeout: numberValue("pingTimeout"),
    tcp_timeout: numberValue("tcpTimeout"),
    tcp_attempts: numberValue("tcpAttempts"),
    dns_timeout: numberValue("dnsTimeout"),
    http_timeout: numberValue("httpTimeout"),
    max_hops: numberValue("maxHops"),
    trace_timeout: numberValue("traceTimeout"),
    trace_probes: numberValue("traceProbes"),
    workers: numberValue("workers"),
    run_speedtest: checked("runSpeedtest"),
    geolocate_route: checked("geolocateRoute"),
    probe_mtu: checked("probeMtu"),
  };
}

function setDefaults(config) {
  $("#targets").value = config.targets.join("\n");
  $("#domains").value = config.domains.join("\n");
  $("#urls").value = config.urls.join("\n");
  $("#tcpTargets").value = config.tcp_targets.join("\n");
  $("#dnsServers").value = config.dns_servers.join("\n");
  $("#dnsQtypes").value = config.dns_qtypes.join("\n");
  $("#tracerouteTarget").value = config.traceroute_target;
  $("#tracerouteMode").value = config.traceroute_mode;
  $("#tracerouteTcpPort").value = config.traceroute_tcp_port;
  $("#mtuTarget").value = config.mtu_target;
  $("#maxHops").value = config.max_hops;
  $("#traceProbes").value = config.trace_probes;
  $("#traceTimeout").value = config.trace_timeout;
  $("#pingCount").value = config.ping_count;
  $("#pingSize").value = config.ping_size;
  $("#workers").value = config.workers;
  $("#pingTimeout").value = config.ping_timeout;
  $("#tcpTimeout").value = config.tcp_timeout;
  $("#tcpAttempts").value = config.tcp_attempts;
  $("#dnsTimeout").value = config.dns_timeout;
  $("#httpTimeout").value = config.http_timeout;
  $("#runSpeedtest").checked = config.run_speedtest;
  $("#geolocateRoute").checked = config.geolocate_route;
  $("#probeMtu").checked = config.probe_mtu;
  syncRangeOutputs();
}

function syncRangeOutputs() {
  $("#pingCountValue").textContent = $("#pingCount").value;
  $("#pingSizeValue").textContent = `${$("#pingSize").value} B`;
  $("#workersValue").textContent = $("#workers").value;
}

function fmtMs(value) {
  return typeof value === "number" ? `${value.toFixed(1)} ms` : "n/a";
}

function fmtMbps(value) {
  return typeof value === "number" ? `${value.toFixed(2)} Mbps` : "n/a";
}

function setStatus(stage, message, progress) {
  $("#statusStage").textContent = stage || "Idle";
  $("#statusMessage").textContent = message || "Ready";
  $("#progressBar").style.width = `${Math.max(0, Math.min(100, progress || 0))}%`;
}

function setDownloads(job) {
  const mapping = [
    ["downloadJson", "json"],
    ["downloadMarkdown", "markdown"],
    ["downloadCapabilities", "capabilities"],
    ["downloadMap", "map"],
  ];
  mapping.forEach(([id, kind]) => {
    const link = $(`#${id}`);
    if (job.status === "completed" && job.paths && job.paths[kind]) {
      link.href = `/api/jobs/${job.id}/download/${kind}`;
      link.classList.remove("disabled");
    } else {
      link.removeAttribute("href");
      link.classList.add("disabled");
    }
  });
  $("#exportMapButton").disabled = !state.route;
}

function renderSummary(summary = {}) {
  $("#kpiPublicIp").textContent = summary.public_ip || "n/a";
  $("#kpiDownload").textContent = fmtMbps(summary.download_mbps);
  $("#kpiLatency").textContent = fmtMs(summary.avg_latency_ms);
  $("#kpiLoss").textContent = typeof summary.max_loss_pct === "number" ? `${summary.max_loss_pct.toFixed(1)}%` : "n/a";
  $("#kpiDns").textContent = fmtMs(summary.avg_dns_ms);
  $("#kpiHops").textContent = typeof summary.hop_count === "number" ? summary.hop_count : "n/a";
}

function renderFindings(findings = []) {
  const list = $("#findingsList");
  list.innerHTML = "";
  if (!findings.length) {
    const li = document.createElement("li");
    li.textContent = "No findings yet.";
    list.appendChild(li);
    return;
  }
  findings.forEach((finding) => {
    const li = document.createElement("li");
    li.textContent = finding;
    list.appendChild(li);
  });
}

function renderEvents(events = []) {
  const log = $("#eventLog");
  log.innerHTML = "";
  if (!events.length) {
    log.innerHTML = '<li class="empty-state">No job timeline yet.</li>';
    return;
  }
  events.slice().reverse().forEach((event) => {
    const li = document.createElement("li");
    li.innerHTML = `<strong>${escapeHtml(event.stage)}</strong><span>${escapeHtml(event.time)} - ${escapeHtml(event.message)}</span>`;
    log.appendChild(li);
  });
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function setupCanvas(canvas) {
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  const width = Math.max(320, Math.floor(rect.width));
  const height = Math.max(220, Math.floor(rect.height));
  if (canvas.width !== width * dpr || canvas.height !== height * dpr) {
    canvas.width = width * dpr;
    canvas.height = height * dpr;
  }
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return { ctx, width, height };
}

function clearChart(canvas, title = "No data yet") {
  const { ctx, width, height } = setupCanvas(canvas);
  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = "#f8fafc";
  ctx.fillRect(0, 0, width, height);
  ctx.fillStyle = palette.muted;
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.font = "13px Inter, system-ui, sans-serif";
  ctx.fillText(title, width / 2, height / 2);
}

function drawAxes(ctx, width, height, left, bottom, top) {
  ctx.strokeStyle = "#d8dee8";
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(left, top);
  ctx.lineTo(left, height - bottom);
  ctx.lineTo(width - 14, height - bottom);
  ctx.stroke();
}

function renderLatencyChart(items = []) {
  const rows = items.filter((item) => typeof item.avg_ms === "number");
  if (!rows.length) {
    clearChart(canvases.latency, "No latency samples");
    return;
  }
  const { ctx, width, height } = setupCanvas(canvases.latency);
  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = "#fff";
  ctx.fillRect(0, 0, width, height);
  const left = 46;
  const bottom = 46;
  const top = 18;
  drawAxes(ctx, width, height, left, bottom, top);
  const maxValue = Math.max(20, ...rows.map((item) => item.p95_ms || item.max_ms || item.avg_ms));
  const chartHeight = height - top - bottom;
  const slot = (width - left - 24) / rows.length;
  rows.forEach((item, index) => {
    const barWidth = Math.max(18, Math.min(48, slot * .55));
    const x = left + index * slot + slot * .22;
    const avgH = (item.avg_ms / maxValue) * chartHeight;
    const p95H = ((item.p95_ms || item.avg_ms) / maxValue) * chartHeight;
    ctx.fillStyle = palette.teal;
    ctx.fillRect(x, height - bottom - avgH, barWidth, avgH);
    ctx.strokeStyle = palette.blue;
    ctx.lineWidth = 3;
    ctx.beginPath();
    ctx.moveTo(x - 2, height - bottom - p95H);
    ctx.lineTo(x + barWidth + 2, height - bottom - p95H);
    ctx.stroke();
    if (typeof item.packet_loss_pct === "number" && item.packet_loss_pct > 0) {
      ctx.fillStyle = palette.rose;
      ctx.beginPath();
      ctx.arc(x + barWidth / 2, top + 12, 5, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.save();
    ctx.translate(x + barWidth / 2, height - 10);
    ctx.rotate(-Math.PI / 5);
    ctx.fillStyle = palette.muted;
    ctx.font = "11px Inter, system-ui, sans-serif";
    ctx.textAlign = "right";
    ctx.fillText(String(item.target), 0, 0);
    ctx.restore();
  });
  ctx.fillStyle = palette.muted;
  ctx.textAlign = "left";
  ctx.font = "12px Inter, system-ui, sans-serif";
  ctx.fillText(`${maxValue.toFixed(0)} ms`, 8, top + 4);
}

function renderDnsChart(dns = {}) {
  const rows = [...(dns.system || []), ...(dns.direct || [])]
    .filter((item) => typeof item.duration_ms === "number")
    .slice(0, 28);
  if (!rows.length) {
    clearChart(canvases.dns, "No DNS timing data");
    return;
  }
  const { ctx, width, height } = setupCanvas(canvases.dns);
  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = "#fff";
  ctx.fillRect(0, 0, width, height);
  const left = 52;
  const bottom = 34;
  const top = 18;
  drawAxes(ctx, width, height, left, bottom, top);
  const maxValue = Math.max(20, ...rows.map((item) => item.duration_ms));
  const chartHeight = height - top - bottom;
  const slot = (width - left - 24) / rows.length;
  rows.forEach((item, index) => {
    const h = (item.duration_ms / maxValue) * chartHeight;
    const x = left + index * slot + 2;
    ctx.fillStyle = item.server ? palette.amber : palette.blue;
    ctx.fillRect(x, height - bottom - h, Math.max(4, slot - 4), h);
  });
  ctx.fillStyle = palette.muted;
  ctx.font = "12px Inter, system-ui, sans-serif";
  ctx.fillText(`${maxValue.toFixed(0)} ms`, 8, top + 4);
  ctx.fillText("system", width - 122, 18);
  ctx.fillStyle = palette.amber;
  ctx.fillRect(width - 70, 9, 14, 8);
  ctx.fillStyle = palette.blue;
  ctx.fillRect(width - 142, 9, 14, 8);
  ctx.fillStyle = palette.muted;
  ctx.fillText("direct", width - 52, 18);
}

function renderHttpChart(items = []) {
  const rows = items.filter((item) => typeof item.total_ms === "number");
  if (!rows.length) {
    clearChart(canvases.http, "No HTTP timing data");
    return;
  }
  const { ctx, width, height } = setupCanvas(canvases.http);
  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = "#fff";
  ctx.fillRect(0, 0, width, height);
  const left = 180;
  const right = 28;
  const rowHeight = Math.max(32, Math.min(48, (height - 36) / rows.length));
  const maxValue = Math.max(1, ...rows.map((item) => item.total_ms || 0));
  const colors = {
    dns_ms: palette.blue,
    tcp_connect_ms: palette.teal,
    tls_handshake_ms: palette.amber,
    ttfb_ms: palette.purple,
  };
  rows.forEach((item, index) => {
    const y = 24 + index * rowHeight;
    const label = item.host || item.url || "url";
    ctx.fillStyle = palette.muted;
    ctx.font = "12px Inter, system-ui, sans-serif";
    ctx.textAlign = "right";
    ctx.fillText(label.slice(0, 24), left - 10, y + 15);
    let x = left;
    const available = width - left - right;
    ["dns_ms", "tcp_connect_ms", "tls_handshake_ms", "ttfb_ms"].forEach((key) => {
      const value = item[key] || 0;
      const w = Math.max(value > 0 ? 2 : 0, (value / maxValue) * available);
      ctx.fillStyle = colors[key];
      ctx.fillRect(x, y, w, 18);
      x += w;
    });
    const accounted = ["dns_ms", "tcp_connect_ms", "tls_handshake_ms", "ttfb_ms"].reduce((sum, key) => sum + (item[key] || 0), 0);
    const rest = Math.max(0, (item.total_ms || 0) - accounted);
    const restWidth = (rest / maxValue) * available;
    ctx.fillStyle = "#98a2b3";
    ctx.fillRect(x, y, restWidth, 18);
    ctx.fillStyle = palette.ink;
    ctx.textAlign = "left";
    ctx.fillText(fmtMs(item.total_ms), Math.min(width - 76, x + restWidth + 8), y + 14);
  });
}

function project(lat, lon, width, height) {
  const padding = 22;
  const x = padding + ((lon + 180) / 360) * (width - padding * 2);
  const y = padding + ((90 - lat) / 180) * (height - padding * 2);
  return [x, y];
}

const landPolygons = [
  [[72,-168],[58,-138],[50,-125],[32,-117],[20,-98],[18,-82],[29,-80],[45,-74],[55,-92],[70,-112]],
  [[12,-82],[-5,-78],[-18,-70],[-35,-65],[-54,-70],[-48,-55],[-22,-42],[4,-50]],
  [[36,-10],[52,-5],[60,18],[55,45],[42,42],[34,20],[22,12],[8,18],[-28,18],[-35,30],[-20,43],[5,41],[28,34]],
  [[70,-10],[64,32],[58,80],[50,112],[36,122],[22,105],[8,78],[22,58],[38,46],[48,22]],
  [[8,75],[20,84],[22,92],[8,99],[-5,95],[-2,82]],
  [[-12,112],[-22,116],[-36,128],[-43,146],[-28,154],[-14,142]],
  [[72,-52],[60,-44],[58,-28],[70,-20],[80,-36]],
];

function routePoints(traceroute) {
  return (traceroute?.hops || [])
    .map((hop) => {
      const geo = hop.geo || {};
      const lat = Number.parseFloat(geo.lat);
      const lon = Number.parseFloat(geo.lon);
      if (!Number.isFinite(lat) || !Number.isFinite(lon)) return null;
      return { hop, lat, lon };
    })
    .filter(Boolean);
}

function renderRouteTable(traceroute) {
  const body = $("#routeTable");
  body.innerHTML = "";
  const hops = traceroute?.hops || [];
  if (!hops.length) {
    body.innerHTML = '<tr><td colspan="5">No route data yet.</td></tr>';
    return;
  }
  hops.forEach((hop) => {
    const geo = hop.geo || {};
    const place = [geo.city, geo.regionName, geo.country].filter(Boolean).join(", ") || geo.status || "n/a";
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${escapeHtml(hop.hop)}</td><td>${escapeHtml(hop.primary_ip || "n/a")}</td><td>${escapeHtml(fmtMs(hop.rtt_ms))}</td><td>${escapeHtml(place)}</td><td>${escapeHtml(geo.isp || geo.org || "n/a")}</td>`;
    body.appendChild(tr);
  });
}

function drawRouteMap(timestamp = 0) {
  const { ctx, width, height } = setupCanvas(canvases.route);
  ctx.clearRect(0, 0, width, height);
  const gradient = ctx.createLinearGradient(0, 0, width, height);
  gradient.addColorStop(0, "#111827");
  gradient.addColorStop(1, "#1f2937");
  ctx.fillStyle = gradient;
  ctx.fillRect(0, 0, width, height);

  ctx.strokeStyle = "rgba(203, 213, 225, .16)";
  ctx.lineWidth = 1;
  for (let lon = -180; lon <= 180; lon += 30) {
    const [x] = project(0, lon, width, height);
    ctx.beginPath();
    ctx.moveTo(x, 18);
    ctx.lineTo(x, height - 18);
    ctx.stroke();
  }
  for (let lat = -60; lat <= 60; lat += 30) {
    const [, y] = project(lat, 0, width, height);
    ctx.beginPath();
    ctx.moveTo(18, y);
    ctx.lineTo(width - 18, y);
    ctx.stroke();
  }

  landPolygons.forEach((poly) => {
    ctx.beginPath();
    poly.forEach(([lat, lon], index) => {
      const [x, y] = project(lat, lon, width, height);
      if (index === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.closePath();
    ctx.fillStyle = "rgba(45, 212, 191, .16)";
    ctx.fill();
    ctx.strokeStyle = "rgba(94, 234, 212, .24)";
    ctx.stroke();
  });

  const points = routePoints(state.route);
  if (!points.length) {
    ctx.fillStyle = "rgba(255,255,255,.76)";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.font = "14px Inter, system-ui, sans-serif";
    ctx.fillText("No geolocated route points yet", width / 2, height / 2);
    return;
  }

  const projected = points.map((point) => ({ ...point, xy: project(point.lat, point.lon, width, height) }));
  ctx.strokeStyle = "#5eead4";
  ctx.lineWidth = 3;
  ctx.beginPath();
  projected.forEach((point, index) => {
    if (index === 0) ctx.moveTo(point.xy[0], point.xy[1]);
    else ctx.lineTo(point.xy[0], point.xy[1]);
  });
  ctx.stroke();

  projected.forEach((point) => {
    const [x, y] = point.xy;
    ctx.fillStyle = "#f59e0b";
    ctx.beginPath();
    ctx.arc(x, y, 6, 0, Math.PI * 2);
    ctx.fill();
    ctx.strokeStyle = "#fff7ed";
    ctx.lineWidth = 2;
    ctx.stroke();
    ctx.fillStyle = "#f8fafc";
    ctx.font = "11px Inter, system-ui, sans-serif";
    ctx.textAlign = "left";
    ctx.fillText(String(point.hop.hop), x + 8, y - 8);
  });

  if (projected.length >= 2) {
    const cycle = (timestamp / 1800) % 1;
    const segment = Math.min(projected.length - 2, Math.floor(cycle * (projected.length - 1)));
    const local = (cycle * (projected.length - 1)) - segment;
    const start = projected[segment].xy;
    const end = projected[segment + 1].xy;
    const x = start[0] + (end[0] - start[0]) * local;
    const y = start[1] + (end[1] - start[1]) * local;
    ctx.fillStyle = "#38bdf8";
    ctx.shadowColor = "#38bdf8";
    ctx.shadowBlur = 14;
    ctx.beginPath();
    ctx.arc(x, y, 7, 0, Math.PI * 2);
    ctx.fill();
    ctx.shadowBlur = 0;
  }
}

function animateRoute(timestamp) {
  drawRouteMap(timestamp);
  window.requestAnimationFrame(animateRoute);
}

function renderRoute(traceroute) {
  state.route = traceroute;
  renderRouteTable(traceroute);
  drawRouteMap(0);
  $("#exportMapButton").disabled = !routePoints(traceroute).length;
}

function renderReport(report) {
  state.report = report;
  renderFindings(report.findings || []);
  renderLatencyChart(report.latency || []);
  renderDnsChart(report.dns || {});
  renderHttpChart(report.http || []);
  renderRoute(report.traceroute || null);
}

function renderJob(job) {
  state.jobId = job.id;
  setStatus(job.stage, job.message, job.progress_pct);
  renderEvents(job.events || []);
  renderSummary(job.summary || {});
  setDownloads(job);
  $("#cancelButton").disabled = !["queued", "running", "cancel_requested"].includes(job.status);
  if (job.report) {
    renderReport(job.report);
    renderSummary(job.summary || {});
  }
  if (job.status === "failed") {
    renderFindings([job.error || "Audit failed"]);
  }
}

async function startAudit() {
  try {
    $("#startButton").disabled = true;
    setStatus("Starting", "Creating audit job", 2);
    const job = await api("/api/jobs", {
      method: "POST",
      body: JSON.stringify(collectConfig()),
    });
    renderJob(job);
    startPolling(job.id);
    await refreshHistory();
  } catch (error) {
    setStatus("Error", error.message, 0);
    renderFindings([error.message]);
  } finally {
    $("#startButton").disabled = false;
  }
}

function startPolling(jobId) {
  window.clearInterval(state.pollTimer);
  const tick = async () => {
    try {
      const job = await api(`/api/jobs/${jobId}`);
      renderJob(job);
      if (!["queued", "running", "cancel_requested"].includes(job.status)) {
        window.clearInterval(state.pollTimer);
        await refreshHistory();
      }
    } catch (error) {
      setStatus("Polling Error", error.message, 0);
      window.clearInterval(state.pollTimer);
    }
  };
  tick();
  state.pollTimer = window.setInterval(tick, 1300);
}

async function cancelAudit() {
  if (!state.jobId) return;
  await api(`/api/jobs/${state.jobId}/cancel`, { method: "POST", body: "{}" });
  setStatus("Cancel Requested", "Waiting for the current network operation to return", 0);
}

async function refreshHistory() {
  const data = await api("/api/jobs");
  const list = $("#historyList");
  list.innerHTML = "";
  if (!data.jobs.length) {
    list.innerHTML = '<div class="empty-state">No completed audits yet.</div>';
    return;
  }
  data.jobs.forEach((job) => {
    const item = document.createElement("div");
    item.className = "history-item";
    const summary = job.summary || {};
    item.innerHTML = `<div><strong>${escapeHtml(job.status)} - ${escapeHtml(job.id)}</strong><span>${escapeHtml(job.created_at)} - ${escapeHtml(job.config?.traceroute_target || "")} - ${escapeHtml(summary.public_ip || "no public ip")}</span></div><button type="button">Open</button>`;
    item.querySelector("button").addEventListener("click", async () => {
      const full = await api(`/api/jobs/${job.id}`);
      renderJob(full);
    });
    list.appendChild(item);
  });
}

async function loadLatest() {
  const data = await api("/api/jobs");
  const completed = data.jobs.find((job) => job.status === "completed") || data.jobs[0];
  if (!completed) return;
  const full = await api(`/api/jobs/${completed.id}`);
  renderJob(full);
}

async function fetchLiveRoute() {
  if (state.liveBusy) return;
  state.liveBusy = true;
  $("#liveRouteButton").disabled = true;
  try {
    const config = collectConfig();
    const data = await api("/api/route-snapshot", {
      method: "POST",
      body: JSON.stringify({
        target: config.traceroute_target,
        max_hops: config.max_hops,
        trace_timeout: config.trace_timeout,
        trace_probes: config.trace_probes,
        traceroute_mode: config.traceroute_mode,
        traceroute_tcp_port: config.traceroute_tcp_port,
        geolocate_route: config.geolocate_route,
      }),
    });
    renderRoute(data.traceroute);
    setStatus("Live Route", `Updated ${data.traceroute.generated_at_utc}`, 100);
  } catch (error) {
    setStatus("Live Route Error", error.message, 0);
  } finally {
    state.liveBusy = false;
    $("#liveRouteButton").disabled = false;
  }
}

function startLiveRoute() {
  stopLiveRoute();
  const interval = Math.max(8, numberValue("liveInterval") || 20) * 1000;
  $("#stopLiveRouteButton").disabled = false;
  fetchLiveRoute();
  state.liveTimer = window.setInterval(fetchLiveRoute, interval);
}

function stopLiveRoute() {
  window.clearInterval(state.liveTimer);
  state.liveTimer = null;
  $("#stopLiveRouteButton").disabled = true;
}

function copyFindings() {
  const text = Array.from($("#findingsList").querySelectorAll("li")).map((li) => li.textContent).join("\n");
  navigator.clipboard?.writeText(text);
}

function exportMapPng() {
  canvases.route.toBlob((blob) => {
    if (!blob) return;
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `internet-route-map-${Date.now()}.png`;
    link.click();
    URL.revokeObjectURL(link.href);
  });
}

async function loadCapabilities() {
  const data = await api("/api/capabilities");
  const list = $("#capabilityList");
  list.innerHTML = "";
  data.capabilities.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    list.appendChild(li);
  });
}

async function boot() {
  $("#startButton").addEventListener("click", startAudit);
  $("#cancelButton").addEventListener("click", cancelAudit);
  $("#loadLatestButton").addEventListener("click", loadLatest);
  $("#liveRouteButton").addEventListener("click", startLiveRoute);
  $("#stopLiveRouteButton").addEventListener("click", stopLiveRoute);
  $("#copyFindingsButton").addEventListener("click", copyFindings);
  $("#exportMapButton").addEventListener("click", exportMapPng);
  $("#pingCount").addEventListener("input", syncRangeOutputs);
  $("#pingSize").addEventListener("input", syncRangeOutputs);
  $("#workers").addEventListener("input", syncRangeOutputs);
  window.addEventListener("resize", () => {
    renderLatencyChart(state.report?.latency || []);
    renderDnsChart(state.report?.dns || {});
    renderHttpChart(state.report?.http || []);
    drawRouteMap(0);
  });

  const config = await api("/api/default-config");
  setDefaults(config);
  await loadCapabilities();
  await refreshHistory();
  renderFindings([]);
  clearChart(canvases.latency);
  clearChart(canvases.dns);
  clearChart(canvases.http);
  renderRoute(null);
  if (!state.animationStarted) {
    state.animationStarted = true;
    window.requestAnimationFrame(animateRoute);
  }
}

boot().catch((error) => {
  setStatus("Startup Error", error.message, 0);
  renderFindings([error.message]);
});
