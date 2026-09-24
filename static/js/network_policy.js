// =========================================================
// InfraShield - Network Policy Scanner
// =========================================================


// =========================================================
// GLOBAL VARIABLES
// =========================================================

let riskChart = null;
let statusChart = null;

let currentPolicyData = [];


// =========================================================
// DOM ELEMENTS
// =========================================================

const scanButton =
    document.getElementById("scanButton");

const scanButtonText =
    document.getElementById("scanButtonText");

const securityScore =
    document.getElementById("securityScore");

const scoreRing =
    document.getElementById("scoreRing");

const riskBadge =
    document.getElementById("riskBadge");

const scoreDescription =
    document.getElementById("scoreDescription");

const firewallIcon =
    document.getElementById("firewallIcon");

const firewallStatus =
    document.getElementById("firewallStatus");

const firewallType =
    document.getElementById("firewallType");

const firewallRules =
    document.getElementById("firewallRules");

const activeConnections =
    document.getElementById("activeConnections");

const listeningPorts =
    document.getElementById("listeningPorts");

const highRiskPorts =
    document.getElementById("highRiskPorts");

const unauthorizedPorts =
    document.getElementById("unauthorizedPorts");

const reviewPorts =
    document.getElementById("reviewPorts");

const policyTableBody =
    document.getElementById("policyTableBody");

const policyCount =
    document.getElementById("policyCount");

const recommendationsList =
    document.getElementById("recommendationsList");

const recommendationCount =
    document.getElementById("recommendationCount");

const operatingSystem =
    document.getElementById("operatingSystem");

const firewallInfo =
    document.getElementById("firewallInfo");

const firewallRuleInfo =
    document.getElementById("firewallRuleInfo");

const scannerStatus =
    document.getElementById("scannerStatus");

const lastScan =
    document.getElementById("lastScan");


// =========================================================
// THEME ELEMENTS
// =========================================================

const themeToggle =
    document.getElementById("themeToggle");

const themeIcon =
    document.getElementById("themeIcon");

const themeText =
    document.getElementById("themeText");


// =========================================================
// THEME MANAGEMENT
// =========================================================

function applyTheme(theme) {

    document.documentElement.setAttribute("data-theme", theme);
    document.body.setAttribute("data-theme", theme);

    if (theme === "light") {

        if (themeIcon) {
            themeIcon.textContent = "🌙";
        }

        if (themeText) {
            themeText.textContent = "Dark";
        }

    }

    else {

        if (themeIcon) {
            themeIcon.textContent = "☀️";
        }

        if (themeText) {
            themeText.textContent = "Light";
        }
    }


    localStorage.setItem(
        "infrashield-theme",
        theme
    );


    /*
     * Recreate charts using the new theme colors.
     * If scan data is not available yet, nothing happens.
     */

    updateChartsTheme();
}


// =========================================================
// INITIALIZE THEME
// =========================================================

function initializeTheme() {

    const savedTheme =
        localStorage.getItem(
            "infrashield-theme"
        );


    /*
     * Dark mode is the default.
     */

    if (savedTheme === "light") {

        applyTheme("light");

    }

    else {

        applyTheme("dark");

    }
}


// =========================================================
// TOGGLE THEME
// =========================================================

function toggleTheme() {

    const currentTheme =
        document.documentElement.getAttribute("data-theme") ||
        document.body.getAttribute("data-theme") ||
        "dark";


    const newTheme =
        currentTheme === "dark"
            ? "light"
            : "dark";


    applyTheme(newTheme);
}


if (themeToggle) {

    themeToggle.addEventListener(
        "click",
        toggleTheme
    );
}


// =========================================================
// SCAN NETWORK
// =========================================================

async function scanNetwork() {

    setScanningState(true);

    try {

        const response =
            await fetch(
                "/api/network-scan"
            );


        // Check if server returned valid JSON

        let result;

        try {

            result =
                await response.json();

        }

        catch {

            throw new Error(
                "Invalid response received from the server."
            );
        }


        // Check API response

        if (
            !response.ok ||
            !result.success
        ) {

            throw new Error(
                result.error ||
                "Network scan failed."
            );
        }


        // Update dashboard

        updateDashboard(
            result.data
        );


        scannerStatus.textContent =
            "SCAN COMPLETE";


        lastScan.textContent =
            new Date().toLocaleTimeString();

    }


    catch (error) {

        console.error(
            "Network scan error:",
            error
        );


        showScanError(
            error.message ||
            "Unable to complete network scan."
        );


        scannerStatus.textContent =
            "SCAN FAILED";
    }


    finally {

        setScanningState(false);
    }
}


// =========================================================
// SCANNING STATE
// =========================================================

function setScanningState(isScanning) {

    if (isScanning) {

        scanButton.disabled = true;

        scanButton.classList.add(
            "scanning"
        );

        scanButtonText.textContent =
            "Scanning...";

        scannerStatus.textContent =
            "SCANNING";

    }

    else {

        scanButton.disabled = false;

        scanButton.classList.remove(
            "scanning"
        );

        scanButtonText.textContent =
            "Scan Network";
    }
}


// =========================================================
// UPDATE DASHBOARD
// =========================================================

function updateDashboard(data) {

    if (!data) {
        return;
    }


    /*
     * Store latest policy data.
     * This allows charts to be recreated
     * when the theme changes.
     */

    currentPolicyData =
        data.policy || [];


    const summary =
        data.summary || {};

    const firewall =
        data.firewall || {};


    updateSecurityScore(

        summary.network_score || 0,

        summary.risk_level ||
        "UNKNOWN"

    );


    updateFirewall(
        firewall
    );


    updateStatistics(
        summary
    );


    updatePolicyTable(
        data.policy || []
    );


    updateRecommendations(
        data.recommendations || []
    );


    updateSystemInformation(
        data
    );


    updateCharts(
        data.policy || []
    );
}


// =========================================================
// SECURITY SCORE
// =========================================================

function updateSecurityScore(
    score,
    riskLevel
) {

    score =
        Number(score) || 0;


    securityScore.textContent =
        score;


    riskBadge.textContent =
        riskLevel;


    const angle =
        Math.round(
            (score / 100) * 360
        );


    scoreRing.style.background =
        `conic-gradient(
            var(--blue) ${angle}deg,
            rgba(148, 163, 184, 0.08) ${angle}deg
        )`;


    // Risk description

    const descriptions = {

        LOW:
            "The network currently has a low security risk.",

        MEDIUM:
            "Some network services require security review.",

        HIGH:
            "Multiple network security issues require attention.",

        CRITICAL:
            "Critical network security risks were detected.",

        UNKNOWN:
            "Security risk could not be determined."
    };


    scoreDescription.textContent =
        descriptions[riskLevel] ||
        descriptions.UNKNOWN;


    // Risk badge class

    riskBadge.className =
        "risk-badge";


    riskBadge.classList.add(
        getRiskClass(riskLevel)
    );
}


// =========================================================
// FIREWALL
// =========================================================

function updateFirewall(firewall) {

    const enabled =
        firewall.enabled === true;

    const available =
        firewall.available === true;


    if (!available) {

        firewallIcon.textContent =
            "!";

        firewallStatus.textContent =
            "Unavailable";

        firewallType.textContent =
            firewall.type ||
            "Firewall information unavailable";

        firewallIcon.style.color =
            "var(--red)";
    }


    else if (enabled) {

        firewallIcon.textContent =
            "✓";

        firewallStatus.textContent =
            "Protected";

        firewallType.textContent =
            firewall.type ||
            "Firewall enabled";

        firewallIcon.style.color =
            "var(--green)";
    }


    else {

        firewallIcon.textContent =
            "!";

        firewallStatus.textContent =
            "Disabled";

        firewallType.textContent =
            firewall.type ||
            "Firewall disabled";

        firewallIcon.style.color =
            "var(--red)";
    }


    firewallRules.textContent =
        firewall.rules_found ?? 0;
}


// =========================================================
// STATISTICS
// =========================================================

function updateStatistics(summary) {

    activeConnections.textContent =
        summary.active_connections ?? 0;

    listeningPorts.textContent =
        summary.listening_ports ?? 0;

    highRiskPorts.textContent =
        summary.high_risk_ports ?? 0;

    unauthorizedPorts.textContent =
        summary.unauthorized_ports ?? 0;

    reviewPorts.textContent =
        summary.review_ports ?? 0;
}


// =========================================================
// POLICY TABLE
// =========================================================

function updatePolicyTable(policy) {

    policyCount.textContent =
        policy.length;


    if (!policy.length) {

        policyTableBody.innerHTML = `

            <tr>

                <td colspan="6"
                    class="empty-state">

                    <div class="empty-icon">
                        ✓
                    </div>

                    <strong>
                        No active listening ports detected
                    </strong>

                    <span>
                        The scanner did not find any ports requiring evaluation.
                    </span>

                </td>

            </tr>

        `;

        return;
    }


    policyTableBody.innerHTML =
        policy.map(item => {

            const port =
                escapeHTML(
                    item.port ?? "-"
                );


            const process =
                escapeHTML(
                    item.process ||
                    "Unknown"
                );


            const address =
                escapeHTML(
                    item.local_address ||
                    item.ip ||
                    "—"
                );


            const firewallAllowed =
                item.firewall_allowed === true;


            const status =
                String(
                    item.status ||
                    "UNKNOWN"
                ).toUpperCase();


            const risk =
                String(
                    item.risk ||
                    "UNKNOWN"
                ).toUpperCase();


            return `

                <tr>

                    <td>

                        <span class="port-number">

                            ${port}

                        </span>

                    </td>


                    <td>

                        <span class="process-name">

                            ${process}

                        </span>

                    </td>


                    <td>

                        <span class="address">

                            ${address}

                        </span>

                    </td>


                    <td>

                        <span class="badge
                            ${
                                firewallAllowed
                                    ? "badge-authorized"
                                    : "badge-unauthorized"
                            }">

                            ${
                                firewallAllowed
                                    ? "ALLOWED"
                                    : "BLOCKED"
                            }

                        </span>

                    </td>


                    <td>

                        <span class="badge
                            ${getRiskBadgeClass(risk)}">

                            ${risk}

                        </span>

                    </td>


                    <td>

                        <span class="badge
                            ${getStatusBadgeClass(status)}">

                            ${status}

                        </span>

                    </td>

                </tr>

            `;

        }).join("");
}


// =========================================================
// RECOMMENDATIONS
// =========================================================

function updateRecommendations(
    recommendations
) {

    recommendationCount.textContent =
        recommendations.length;


    if (!recommendations.length) {

        recommendationsList.innerHTML = `

            <div class="empty-recommendations">

                <div class="empty-icon">
                    ✓
                </div>

                <div>

                    <strong>
                        No security recommendations
                    </strong>

                    <p>
                        No immediate security actions were identified.
                    </p>

                </div>

            </div>

        `;

        return;
    }


    recommendationsList.innerHTML =
        recommendations.map(item => {

            const severity =
                String(
                    item.severity ||
                    "LOW"
                ).toLowerCase();


            const title =
                escapeHTML(
                    item.title ||
                    "Security Recommendation"
                );


            const description =
                escapeHTML(
                    item.message ||
                    item.description ||
                    "Review this security finding."
                );


            let icon = "!";


            if (
                severity === "medium"
            ) {

                icon = "!";
            }


            if (
                severity === "low"
            ) {

                icon = "✓";
            }


            return `

                <div class="recommendation ${severity}">

                    <div class="recommendation-icon">

                        ${icon}

                    </div>


                    <div>

                        <strong>

                            ${title}

                        </strong>


                        <p>

                            ${description}

                        </p>

                    </div>

                </div>

            `;

        }).join("");
}


// =========================================================
// SYSTEM INFORMATION
// =========================================================

function updateSystemInformation(data) {

    operatingSystem.textContent =
        data.operating_system ||
        "Unknown";


    const firewall =
        data.firewall || {};


    firewallInfo.textContent =
        firewall.type ||
        "Unknown";


    firewallRuleInfo.textContent =
        firewall.rules_found ?? 0;
}


// =========================================================
// CHART THEME
// =========================================================

function getChartTheme() {

    const theme =
        document.body.getAttribute(
            "data-theme"
        ) || "dark";


    if (theme === "light") {

        return {

            text: "#475569",

            muted: "#64748b",

            grid:
                "rgba(15, 23, 42, 0.08)"
        };
    }


    return {

        text: "#94a3b8",

        muted: "#64748b",

        grid:
            "rgba(148, 163, 184, 0.08)"
    };
}


// =========================================================
// UPDATE CHARTS AFTER THEME CHANGE
// =========================================================

function updateChartsTheme() {

    /*
     * Don't recreate charts before
     * the first network scan.
     */

    if (!currentPolicyData.length) {

        return;
    }


    updateCharts(
        currentPolicyData
    );
}


// =========================================================
// CHARTS
// =========================================================

function updateCharts(policy) {

    const riskCounts = {

        LOW: 0,

        MEDIUM: 0,

        HIGH: 0,

        CRITICAL: 0
    };


    const statusCounts = {

        AUTHORIZED: 0,

        REVIEW: 0,

        UNAUTHORIZED: 0
    };


    policy.forEach(item => {

        const risk =
            String(
                item.risk || ""
            ).toUpperCase();


        const status =
            String(
                item.status || ""
            ).toUpperCase();


        if (
            riskCounts.hasOwnProperty(
                risk
            )
        ) {

            riskCounts[risk]++;
        }


        if (
            statusCounts.hasOwnProperty(
                status
            )
        ) {

            statusCounts[status]++;
        }

    });


    createRiskChart(
        riskCounts
    );


    createStatusChart(
        statusCounts
    );
}


// =========================================================
// RISK CHART
// =========================================================

function createRiskChart(counts) {

    const canvas =
        document.getElementById(
            "riskChart"
        );


    if (!canvas) {
        return;
    }


    if (riskChart) {

        riskChart.destroy();
    }


    const chartTheme =
        getChartTheme();


    riskChart =
        new Chart(

            canvas,

            {

                type: "doughnut",


                data: {

                    labels: [

                        "Low",

                        "Medium",

                        "High",

                        "Critical"

                    ],


                    datasets: [

                        {

                            data: [

                                counts.LOW,

                                counts.MEDIUM,

                                counts.HIGH,

                                counts.CRITICAL

                            ],


                            backgroundColor: [

                                "#34d399",

                                "#fbbf24",

                                "#f87171",

                                "#dc2626"

                            ],


                            borderWidth: 0,

                            hoverOffset: 5

                        }

                    ]

                },


                options: {

                    responsive: true,

                    maintainAspectRatio: false,

                    cutout: "70%",


                    plugins: {

                        legend: {

                            position: "bottom",


                            labels: {

                                color:
                                    chartTheme.text,

                                padding: 16,


                                font: {

                                    size: 10
                                }
                            }
                        }
                    }
                }
            }
        );
}


// =========================================================
// STATUS CHART
// =========================================================

function createStatusChart(counts) {

    const canvas =
        document.getElementById(
            "statusChart"
        );


    if (!canvas) {
        return;
    }


    if (statusChart) {

        statusChart.destroy();
    }


    const chartTheme =
        getChartTheme();


    statusChart =
        new Chart(

            canvas,

            {

                type: "bar",


                data: {

                    labels: [

                        "Authorized",

                        "Review",

                        "Unauthorized"

                    ],


                    datasets: [

                        {

                            data: [

                                counts.AUTHORIZED,

                                counts.REVIEW,

                                counts.UNAUTHORIZED

                            ],


                            backgroundColor: [

                                "#34d399",

                                "#fbbf24",

                                "#f87171"

                            ],


                            borderRadius: 6,

                            borderSkipped: false

                        }

                    ]

                },


                options: {

                    responsive: true,

                    maintainAspectRatio: false,


                    scales: {

                        y: {

                            beginAtZero: true,


                            ticks: {

                                color:
                                    chartTheme.muted,

                                precision: 0

                            },


                            grid: {

                                color:
                                    chartTheme.grid

                            }

                        },


                        x: {

                            ticks: {

                                color:
                                    chartTheme.text

                            },


                            grid: {

                                display: false

                            }

                        }

                    },


                    plugins: {

                        legend: {

                            display: false

                        }

                    }

                }

            }
        );
}


// =========================================================
// ERROR DISPLAY
// =========================================================

function showScanError(message) {

    policyTableBody.innerHTML = `

        <tr>

            <td colspan="6"
                class="empty-state">

                <div class="empty-icon">
                    !
                </div>

                <strong>
                    Network scan failed
                </strong>

                <span>
                    ${escapeHTML(message)}
                </span>

            </td>

        </tr>

    `;


    securityScore.textContent =
        "--";


    riskBadge.textContent =
        "SCAN FAILED";
}


// =========================================================
// RISK CLASS
// =========================================================

function getRiskClass(risk) {

    switch (
        String(risk).toUpperCase()
    ) {

        case "LOW":

            return "badge-low";


        case "MEDIUM":

            return "badge-medium";


        case "HIGH":

            return "badge-high";


        case "CRITICAL":

            return "badge-critical";


        default:

            return "";
    }
}


function getRiskBadgeClass(risk) {

    switch (
        String(risk).toUpperCase()
    ) {

        case "LOW":

            return "badge-low";


        case "MEDIUM":

            return "badge-medium";


        case "HIGH":

            return "badge-high";


        case "CRITICAL":

            return "badge-critical";


        default:

            return "";
    }
}


// =========================================================
// STATUS CLASS
// =========================================================

function getStatusBadgeClass(status) {

    switch (
        String(status).toUpperCase()
    ) {

        case "AUTHORIZED":

            return "badge-authorized";


        case "REVIEW":

            return "badge-review";


        case "UNAUTHORIZED":

            return "badge-unauthorized";


        default:

            return "";
    }
}


// =========================================================
// HTML SAFETY
// =========================================================

function escapeHTML(value) {

    return String(value)

        .replace(
            /&/g,
            "&amp;"
        )

        .replace(
            /</g,
            "&lt;"
        )

        .replace(
            />/g,
            "&gt;"
        )

        .replace(
            /"/g,
            "&quot;"
        )

        .replace(
            /'/g,
            "&#039;"
        );
}


// =========================================================
// BUTTON EVENT
// =========================================================

if (scanButton) {
    scanButton.addEventListener(
        "click",
        scanNetwork
    );
}


// =========================================================
// INITIALIZE THEME
// =========================================================

initializeTheme();


// =========================================================
// INITIAL SCAN
// =========================================================

// Automatically scan when dashboard opens.

scanNetwork();
// Cross-tab theme sync
window.addEventListener("storage", (e) => {
    if (e.key === "infrashield-theme") {
        applyTheme(e.newValue);
    }
});

// Cross-tab scan sync
window.addEventListener("storage", (e) => {
    if (e.key === "infrashield-scan-trigger") {
        if (typeof scanNetwork === "function") {
            scanNetwork();
        }
    }
});
