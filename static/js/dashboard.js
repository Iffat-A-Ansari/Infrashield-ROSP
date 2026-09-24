/* =========================================================
   INFRASHIELD — EXECUTIVE SECURITY DASHBOARD JAVASCRIPT
   Real-Time Data Orchestration, Dynamic Charts & Theming
   ========================================================= */

(function () {
    "use strict";

    // =========================================================
    // THEME STATE & HELPERS
    // =========================================================

    const themeToggleBtn = document.getElementById("themeToggle");
    const themeIcon = document.getElementById("themeIcon");
    const themeText = document.getElementById("themeText");

    function getTheme() {
        return document.documentElement.getAttribute("data-theme") ||
               localStorage.getItem("infrashield-theme") ||
               "dark";
    }

    function applyTheme(theme) {
        document.documentElement.setAttribute("data-theme", theme);
        localStorage.setItem("infrashield-theme", theme);

        if (themeIcon && themeText) {
            if (theme === "dark") {
                themeIcon.textContent = "☀️";
                themeText.textContent = "Light";
            } else {
                themeIcon.textContent = "🌙";
                themeText.textContent = "Dark";
            }
        }

        updateChartThemeColors();
    }

    if (themeToggleBtn) {
        themeToggleBtn.addEventListener("click", function () {
            const current = getTheme();
            const next = current === "dark" ? "light" : "dark";
            applyTheme(next);
        });
    }

    // Apply saved theme on boot
    applyTheme(getTheme());

    // =========================================================
    // CHART.JS PALETTE & INITIALIZATION
    // =========================================================

    function getChartThemeColors() {
        const isDark = getTheme() === "dark";
        return {
            text: isDark ? "#94a3b8" : "#475569",
            grid: isDark ? "rgba(148, 163, 184, 0.1)" : "rgba(15, 23, 42, 0.08)",
            legend: isDark ? "#f8fafc" : "#0f172a",
            panelBg: isDark ? "#111827" : "#ffffff",
        };
    }

    let telemetryChart = null;
    let postureChart = null;
    let portChart = null;

    function initTelemetryChart() {
        const ctx = document.getElementById("telemetryChart");
        if (!ctx) return;

        const colors = getChartThemeColors();

        telemetryChart = new Chart(ctx, {
            type: "line",
            data: {
                labels: [],
                datasets: [
                    {
                        label: "CPU Usage (%)",
                        data: [],
                        borderColor: "#38bdf8",
                        backgroundColor: "rgba(56, 189, 248, 0.1)",
                        fill: true,
                        tension: 0.35,
                        borderWidth: 2,
                        pointRadius: 2,
                        pointHoverRadius: 5
                    },
                    {
                        label: "Memory Usage (%)",
                        data: [],
                        borderColor: "#a855f7",
                        backgroundColor: "rgba(168, 85, 247, 0.08)",
                        fill: true,
                        tension: 0.35,
                        borderWidth: 2,
                        pointRadius: 2,
                        pointHoverRadius: 5
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 400 },
                plugins: {
                    legend: {
                        position: "top",
                        labels: { color: colors.legend, boxWidth: 12, font: { size: 12, family: "Inter" } }
                    },
                    tooltip: {
                        mode: "index",
                        intersect: false
                    }
                },
                scales: {
                    x: {
                        ticks: { color: colors.text, maxTicksLimit: 8, font: { size: 11 } },
                        grid: { color: colors.grid }
                    },
                    y: {
                        min: 0,
                        max: 100,
                        ticks: {
                            color: colors.text,
                            callback: function (val) { return val + "%"; },
                            font: { size: 11 }
                        },
                        grid: { color: colors.grid }
                    }
                }
            }
        });
    }

    function initPostureChart() {
        const ctx = document.getElementById("postureChart");
        if (!ctx) return;

        const colors = getChartThemeColors();

        postureChart = new Chart(ctx, {
            type: "doughnut",
            data: {
                labels: ["OS Compliance", "Network Security", "AI Anomaly Health"],
                datasets: [{
                    data: [85, 80, 90],
                    backgroundColor: [
                        "#3b82f6",
                        "#10b981",
                        "#f59e0b"
                    ],
                    borderWidth: 2,
                    borderColor: colors.panelBg
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: "68%",
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: { color: colors.legend, boxWidth: 10, font: { size: 11 } }
                    }
                }
            }
        });
    }

    function initPortChart() {
        const ctx = document.getElementById("portChart");
        if (!ctx) return;

        const colors = getChartThemeColors();

        portChart = new Chart(ctx, {
            type: "doughnut",
            data: {
                labels: ["Authorized", "Standard Services", "High Risk"],
                datasets: [{
                    data: [3, 2, 0],
                    backgroundColor: [
                        "#22c55e",
                        "#38bdf8",
                        "#ef4444"
                    ],
                    borderWidth: 2,
                    borderColor: colors.panelBg
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: "68%",
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: { color: colors.legend, boxWidth: 10, font: { size: 11 } }
                    }
                }
            }
        });
    }

    function updateChartThemeColors() {
        const colors = getChartThemeColors();

        if (telemetryChart) {
            telemetryChart.options.scales.x.ticks.color = colors.text;
            telemetryChart.options.scales.x.grid.color = colors.grid;
            telemetryChart.options.scales.y.ticks.color = colors.text;
            telemetryChart.options.scales.y.grid.color = colors.grid;
            telemetryChart.options.plugins.legend.labels.color = colors.legend;
            telemetryChart.update();
        }

        if (postureChart) {
            postureChart.data.datasets[0].borderColor = colors.panelBg;
            postureChart.options.plugins.legend.labels.color = colors.legend;
            postureChart.update();
        }

        if (portChart) {
            portChart.data.datasets[0].borderColor = colors.panelBg;
            portChart.options.plugins.legend.labels.color = colors.legend;
            portChart.update();
        }
    }

    // =========================================================
    // REAL-TIME DATA REFRESH & DOM UPDATES
    // =========================================================

    let currentAlerts = [];
    let activeAlertFilter = "all";
    let refreshTimer = null;

    function updatePostureDial(score, badgeText, badgeClass) {
        const dialText = document.getElementById("postureDialText");
        const dialProgress = document.getElementById("postureDialProgress");
        const postureBadge = document.getElementById("postureBadge");

        if (dialText) dialText.textContent = `${score}%`;

        if (dialProgress) {
            const circumference = 2 * Math.PI * 38; // radius 38
            const offset = circumference - (score / 100) * circumference;
            dialProgress.style.strokeDasharray = `${circumference} ${circumference}`;
            dialProgress.style.strokeDashoffset = offset;

            if (score >= 80) {
                dialProgress.style.stroke = "var(--success)";
            } else if (score >= 60) {
                dialProgress.style.stroke = "var(--warning)";
            } else {
                dialProgress.style.stroke = "var(--danger)";
            }
        }

        if (postureBadge) {
            postureBadge.textContent = badgeText;
            postureBadge.className = `posture-badge ${badgeClass}`;
        }
    }

    function updateKPICards(data) {
        const { vitals, compliance, network, anomaly_status } = data;

        // Compliance Card
        const compVal = document.getElementById("kpiCompVal");
        const compTag = document.getElementById("kpiCompTag");
        const compPassed = document.getElementById("kpiCompPassed");
        const compWarn = document.getElementById("kpiCompWarn");
        const compFail = document.getElementById("kpiCompFail");
        const compProgress = document.getElementById("kpiCompProgress");

        if (compVal) compVal.textContent = `${compliance.score}%`;
        if (compTag) {
            compTag.textContent = compliance.overall_status;
            compTag.className = `kpi-tag ${compliance.score >= 80 ? 'pass' : compliance.score >= 50 ? 'warning' : 'fail'}`;
        }
        if (compPassed) compPassed.textContent = compliance.passed;
        if (compWarn) compWarn.textContent = compliance.warnings;
        if (compFail) compFail.textContent = compliance.failed;
        if (compProgress) {
            compProgress.style.width = `${compliance.score}%`;
            compProgress.style.background = compliance.score >= 80 ? 'var(--success)' : compliance.score >= 50 ? 'var(--warning)' : 'var(--danger)';
        }

        // Network Card
        const netVal = document.getElementById("kpiNetVal");
        const netTag = document.getElementById("kpiNetTag");
        const netActive = document.getElementById("kpiNetActive");
        const netListening = document.getElementById("kpiNetListening");
        const netRisk = document.getElementById("kpiNetRisk");
        const netFirewall = document.getElementById("kpiNetFirewall");

        const netSummary = network.summary || {};
        const firewall = network.firewall || {};

        if (netVal) netVal.textContent = `${netSummary.listening_ports || 0} Ports`;
        if (netTag) {
            const riskLevel = netSummary.risk_level || "LOW";
            netTag.textContent = `Risk: ${riskLevel}`;
            netTag.className = `kpi-tag ${riskLevel === 'LOW' ? 'pass' : riskLevel === 'MEDIUM' ? 'warning' : 'fail'}`;
        }
        if (netActive) netActive.textContent = netSummary.active_connections || 0;
        if (netListening) netListening.textContent = netSummary.listening_ports || 0;
        if (netRisk) netRisk.textContent = netSummary.high_risk_ports || 0;
        if (netFirewall) {
            netFirewall.textContent = firewall.enabled ? "Active" : "Disabled";
            netFirewall.style.color = firewall.enabled ? "var(--success)" : "var(--danger)";
        }

        // Anomaly Card
        const anomVal = document.getElementById("kpiAnomVal");
        const anomTag = document.getElementById("kpiAnomTag");
        const anomSamples = document.getElementById("kpiAnomSamples");
        const anomCount = document.getElementById("kpiAnomCount");
        const anomProgress = document.getElementById("kpiAnomProgress");

        if (anomVal) anomVal.textContent = anomaly_status.baseline_ready ? "Model Active" : "Calibrating";
        if (anomTag) {
            anomTag.textContent = anomaly_status.baseline_ready ? "Trained" : "Baseline Prep";
            anomTag.className = `kpi-tag ${anomaly_status.baseline_ready ? 'pass' : 'info'}`;
        }
        if (anomSamples) anomSamples.textContent = `${anomaly_status.total_samples} / ${anomaly_status.baseline_needed}`;
        if (anomCount) anomCount.textContent = (data.recent_anomalies || []).length;
        if (anomProgress) {
            anomProgress.style.width = `${anomaly_status.baseline_pct}%`;
            anomProgress.style.background = anomaly_status.baseline_ready ? 'var(--success)' : 'var(--accent)';
        }

        // Host Vital Signs Card
        const sysVal = document.getElementById("kpiSysVal");
        const sysCpu = document.getElementById("kpiSysCpu");
        const sysMem = document.getElementById("kpiSysMem");
        const sysDisk = document.getElementById("kpiSysDisk");
        const sysProc = document.getElementById("kpiSysProc");

        if (sysVal) sysVal.textContent = `CPU ${vitals.cpu_percent}%`;
        if (sysCpu) sysCpu.textContent = `${vitals.cpu_percent}%`;
        if (sysMem) sysMem.textContent = `${vitals.mem_percent}% (${vitals.mem_used_gb}G/${vitals.mem_total_gb}G)`;
        if (sysDisk) sysDisk.textContent = `${vitals.disk_percent}%`;
        if (sysProc) sysProc.textContent = vitals.process_count;

        // Meta chips
        const metaHost = document.getElementById("metaHostname");
        const metaPlatform = document.getElementById("metaPlatform");
        const metaArch = document.getElementById("metaArch");
        const metaUptime = document.getElementById("metaUptime");

        if (metaHost) metaHost.textContent = vitals.hostname;
        if (metaPlatform) metaPlatform.textContent = `${vitals.system} ${vitals.release}`;
        if (metaArch) metaArch.textContent = vitals.machine;
        if (metaUptime) metaUptime.textContent = vitals.uptime;
    }

    function updateChartsData(data) {
        const { vitals, compliance, network, posture, recent_metrics } = data;

        // 1. Telemetry Chart
        if (telemetryChart) {
            let labels = [];
            let cpuData = [];
            let memData = [];

            if (recent_metrics && recent_metrics.length > 0) {
                recent_metrics.forEach(m => {
                    const timeObj = new Date(m.timestamp * 1000);
                    labels.push(timeObj.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }));
                    cpuData.push(m.cpu_percent);
                    memData.push(m.mem_percent);
                });
            } else {
                const nowLabel = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
                labels = [nowLabel];
                cpuData = [vitals.cpu_percent];
                memData = [vitals.mem_percent];
            }

            telemetryChart.data.labels = labels;
            telemetryChart.data.datasets[0].data = cpuData;
            telemetryChart.data.datasets[1].data = memData;
            telemetryChart.update();
        }

        // 2. Posture Breakdown Chart
        if (postureChart) {
            const compScore = compliance.score || 0;
            const netScore = posture.net_score || 75;
            const anomScore = posture.anomaly_score || 80;
            postureChart.data.datasets[0].data = [compScore, netScore, anomScore];
            postureChart.update();
        }

        // 3. Port Chart
        if (portChart) {
            const netSummary = network.summary || {};
            const authorized = netSummary.authorized_ports || 0;
            const highRisk = netSummary.high_risk_ports || 0;
            const other = Math.max(0, (netSummary.listening_ports || 0) - authorized - highRisk);
            portChart.data.datasets[0].data = [authorized, other, highRisk];
            portChart.update();
        }
    }

    function renderAlerts(alerts) {
        currentAlerts = alerts || [];
        const container = document.getElementById("alertsFeedContainer");
        if (!container) return;

        // Filter alerts
        let filtered = currentAlerts;
        if (activeAlertFilter === "critical") {
            filtered = currentAlerts.filter(a => a.severity === "CRITICAL");
        } else if (activeAlertFilter === "warning") {
            filtered = currentAlerts.filter(a => a.severity === "WARNING");
        } else if (activeAlertFilter === "secure") {
            filtered = currentAlerts.filter(a => a.severity === "SECURE");
        }

        // Update counts
        const allCount = document.getElementById("countAllAlerts");
        const critCount = document.getElementById("countCritAlerts");
        const warnCount = document.getElementById("countWarnAlerts");

        if (allCount) allCount.textContent = currentAlerts.length;
        if (critCount) critCount.textContent = currentAlerts.filter(a => a.severity === "CRITICAL").length;
        if (warnCount) warnCount.textContent = currentAlerts.filter(a => a.severity === "WARNING").length;

        if (filtered.length === 0) {
            container.innerHTML = `
                <div class="alert-item severity-secure">
                    <div class="alert-left-content">
                        <div class="alert-icon-pill">✓</div>
                        <div class="alert-body">
                            <div class="alert-headline-row">
                                <span class="alert-title">No alerts matching filter</span>
                                <span class="alert-source-tag">Filter</span>
                            </div>
                            <p class="alert-details">Everything looks clean under the selected category.</p>
                        </div>
                    </div>
                </div>
            `;
            return;
        }

        let html = "";
        filtered.forEach(alert => {
            const sevClass = alert.severity === "CRITICAL" ? "severity-critical" :
                             alert.severity === "WARNING" ? "severity-warning" : "severity-secure";
            const icon = alert.severity === "CRITICAL" ? "✕" :
                         alert.severity === "WARNING" ? "!" : "✓";

            html += `
                <div class="alert-item ${sevClass}">
                    <div class="alert-left-content">
                        <div class="alert-icon-pill">${icon}</div>
                        <div class="alert-body">
                            <div class="alert-headline-row">
                                <span class="alert-title">${alert.title}</span>
                                <span class="alert-source-tag">${alert.source}</span>
                            </div>
                            <p class="alert-details">${alert.details}</p>
                        </div>
                    </div>
                    <div class="alert-right-actions">
                        <span class="alert-timestamp">${alert.time}</span>
                        ${alert.link && alert.link !== '#' ? `<a href="${alert.link}" class="alert-inspect-btn">Investigate →</a>` : ''}
                    </div>
                </div>
            `;
        });

        container.innerHTML = html;
    }

    function updateSubsystemPanels(data) {
        const { compliance, network, anomaly_status } = data;

        // Subsystem 1: OS Compliance rows
        const compList = document.getElementById("subsystemCompList");
        if (compList && compliance.results) {
            let html = "";
            compliance.results.forEach(check => {
                const cls = check.status === "PASS" ? "pass" : check.status === "WARNING" ? "warning" : "fail";
                html += `
                    <div class="subsystem-row">
                        <span>${check.name}</span>
                        <span class="subsystem-badge ${cls}">${check.status}</span>
                    </div>
                `;
            });
            compList.innerHTML = html;
        }

        // Subsystem 2: Network Policy rows
        const netList = document.getElementById("subsystemNetList");
        if (netList && network) {
            const netSummary = network.summary || {};
            const fw = network.firewall || {};
            netList.innerHTML = `
                <div class="subsystem-row">
                    <span>Firewall Status (${fw.type || 'Host'})</span>
                    <span class="subsystem-badge ${fw.enabled ? 'pass' : 'fail'}">${fw.enabled ? 'Enabled' : 'Disabled'}</span>
                </div>
                <div class="subsystem-row">
                    <span>Listening Ports</span>
                    <strong>${netSummary.listening_ports || 0}</strong>
                </div>
                <div class="subsystem-row">
                    <span>High Risk Ports</span>
                    <span class="subsystem-badge ${(netSummary.high_risk_ports || 0) > 0 ? 'fail' : 'pass'}">${netSummary.high_risk_ports || 0} detected</span>
                </div>
                <div class="subsystem-row">
                    <span>Active Sockets</span>
                    <strong>${netSummary.active_connections || 0}</strong>
                </div>
            `;
        }

        // Subsystem 3: Anomaly rows
        const anomList = document.getElementById("subsystemAnomList");
        if (anomList && anomaly_status) {
            anomList.innerHTML = `
                <div class="subsystem-row">
                    <span>Algorithm</span>
                    <strong>Isolation Forest</strong>
                </div>
                <div class="subsystem-row">
                    <span>Contamination Factor</span>
                    <strong>5% (0.05)</strong>
                </div>
                <div class="subsystem-row">
                    <span>Model Status</span>
                    <span class="subsystem-badge ${anomaly_status.baseline_ready ? 'pass' : 'warning'}">${anomaly_status.baseline_ready ? 'Active' : 'Training'}</span>
                </div>
                <div class="subsystem-row">
                    <span>Telemetry Samples</span>
                    <strong>${anomaly_status.total_samples} collected</strong>
                </div>
            `;
        }
    }

    async function fetchDashboardStats(force = false) {
        try {
            const response = await fetch(`/api/dashboard-stats${force ? '?force=true' : ''}`);
            if (!response.ok) {
                throw new Error("Dashboard stats request failed");
            }

            const res = await response.json();
            if (!res.success || !res.data) {
                throw new Error("Dashboard stats payload was empty");
            }

            const d = res.data;
            updatePostureDial(d.posture.master_score, d.posture.posture_badge, d.posture.posture_class);
            updateKPICards(d);
            updateChartsData(d);
            renderAlerts(d.alerts);
            updateSubsystemPanels(d);

        } catch (error) {
            console.error("Dashboard refresh error:", error);
            throw error;
        }
    }

    // =========================================================
    // EVENT LISTENERS & SETUP
    // =========================================================

    // Full Audit Button
    const runAuditBtn = document.getElementById("runFullAuditBtn");
    if (runAuditBtn) {
        runAuditBtn.addEventListener("click", async function () {
            const origText = runAuditBtn.innerHTML;
            runAuditBtn.disabled = true;
            runAuditBtn.innerHTML = "<span>⏳</span> Scanning All Vectors...";

            try {
                await fetchDashboardStats(true);
                localStorage.setItem("infrashield-scan-trigger", Date.now().toString());
                runAuditBtn.innerHTML = "<span>✓</span> Audit Completed";
            } catch (error) {
                console.error("Full audit failed:", error);
                runAuditBtn.innerHTML = "<span>⚠️</span> Audit Failed";
            } finally {
                setTimeout(() => {
                    runAuditBtn.innerHTML = origText;
                    runAuditBtn.disabled = false;
                }, 1400);
            }
        });
    }

    // Quick Sync Button
    const quickSyncBtn = document.getElementById("quickSyncBtn");
    if (quickSyncBtn) {
        quickSyncBtn.addEventListener("click", async function () {
            const origTransform = quickSyncBtn.style.transform;
            quickSyncBtn.disabled = true;
            quickSyncBtn.style.transform = "rotate(180deg)";
            try {
                await fetchDashboardStats(false);
            } catch (error) {
                console.error("Quick sync failed:", error);
            } finally {
                setTimeout(() => {
                    quickSyncBtn.style.transform = origTransform || "none";
                    quickSyncBtn.disabled = false;
                }, 350);
            }
        });
    }

    // Alert filter buttons
    const filterButtons = document.querySelectorAll(".filter-btn");
    filterButtons.forEach(btn => {
        btn.addEventListener("click", function () {
            filterButtons.forEach(b => b.classList.remove("active"));
            this.classList.add("active");
            activeAlertFilter = this.getAttribute("data-filter") || "all";
            renderAlerts(currentAlerts);
        });
    });

    // Refresh rate selection
    const refreshSelect = document.getElementById("autoRefreshSelect");
    function setupAutoRefresh() {
        if (refreshTimer) clearInterval(refreshTimer);
        const rate = refreshSelect ? parseInt(refreshSelect.value, 10) : 5000;
        if (rate > 0) {
            refreshTimer = setInterval(() => {
                fetchDashboardStats(false).catch(() => {});
            }, rate);
        }
    }

    if (refreshSelect) {
        refreshSelect.addEventListener("change", setupAutoRefresh);
    }

    // =========================================================
    // BOOTSTRAP
    // =========================================================

    window.addEventListener("DOMContentLoaded", function () {
        initTelemetryChart();
        initPostureChart();
        initPortChart();

        // If server rendered initial payload in window.INITIAL_DASHBOARD_DATA
        if (window.INITIAL_DASHBOARD_DATA) {
            const d = window.INITIAL_DASHBOARD_DATA;
            updatePostureDial(d.posture.master_score, d.posture.posture_badge, d.posture.posture_class);
            updateKPICards(d);
            updateChartsData(d);
            renderAlerts(d.alerts);
            updateSubsystemPanels(d);
        } else {
            fetchDashboardStats(false).catch(() => {});
        }

        setupAutoRefresh();
    });

})();
