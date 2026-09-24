function updateThemeButton() {
  const theme = document.documentElement.getAttribute('data-theme') || 'dark';
  const icon = document.getElementById('themeIcon');
  const label = document.getElementById('themeText') || document.getElementById('themeLabel');
  if (icon) icon.textContent = theme === 'dark' ? '☀️' : '🌙';
  if (label) label.textContent = theme === 'dark' ? 'Light' : 'Dark';
}

// CSS variables se live color values padhte hain, taaki charts current theme match karein
function getThemeColors() {
  const styles = getComputedStyle(document.documentElement);
  return {
    text: styles.getPropertyValue('--muted').trim(),
    grid: styles.getPropertyValue('--border').trim(),
    legend: styles.getPropertyValue('--text').trim(),
  };
}

function applyChartTheme() {
  const c = getThemeColors();
  [cpuMemChart, netChart].forEach(chart => {
    chart.options.scales.x.ticks.color = c.text;
    chart.options.scales.x.grid.color = c.grid;
    chart.options.scales.y.ticks.color = c.text;
    chart.options.scales.y.grid.color = c.grid;
    chart.options.plugins.legend.labels.color = c.legend;
    chart.update();
  });
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('infrashield-theme', next);
  updateThemeButton();
  applyChartTheme();
}

updateThemeButton();

const themeToggleBtn = document.getElementById('themeToggle');
if (themeToggleBtn) {
  themeToggleBtn.addEventListener('click', toggleTheme);
}

const cpuMemCtx = document.getElementById('cpuMemChart');
const netCtx = document.getElementById('netChart');
const initialColors = getThemeColors();

const cpuMemChart = new Chart(cpuMemCtx, {
  type: 'line',
  data: {
    labels: [],
    datasets: [
      { label: 'CPU %', data: [], borderColor: '#3fb950', backgroundColor: 'transparent', tension: 0.3, pointRadius: 0 },
      { label: 'Memory %', data: [], borderColor: '#58a6ff', backgroundColor: 'transparent', tension: 0.3, pointRadius: 0 },
      { label: 'Anomaly', data: [], borderColor: 'transparent', backgroundColor: '#f85149',
        pointRadius: (ctx) => ctx.raw && ctx.raw.anomaly ? 6 : 0, showLine: false }
    ]
  },
  options: {
    responsive: true,
    animation: false,
    scales: {
      x: { ticks: { color: initialColors.text }, grid: { color: initialColors.grid } },
      y: { ticks: { color: initialColors.text }, grid: { color: initialColors.grid }, min: 0, max: 100 }
    },
    plugins: { legend: { labels: { color: initialColors.legend } } }
  }
});

const netChart = new Chart(netCtx, {
  type: 'line',
  data: {
    labels: [],
    datasets: [
      { label: 'Sent B/s', data: [], borderColor: '#d29922', backgroundColor: 'transparent', tension: 0.3, pointRadius: 0 },
      { label: 'Received B/s', data: [], borderColor: '#a371f7', backgroundColor: 'transparent', tension: 0.3, pointRadius: 0 }
    ]
  },
  options: {
    responsive: true,
    animation: false,
    scales: {
      x: { ticks: { color: initialColors.text }, grid: { color: initialColors.grid } },
      y: { ticks: { color: initialColors.text }, grid: { color: initialColors.grid } }
    },
    plugins: { legend: { labels: { color: initialColors.legend } } }
  }
});

function fmtTime(ts) {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString();
}

async function refreshMetrics() {
  const res = await fetch('/api/metrics');
  const rows = await res.json();
  if (!rows.length) return;

  const labels = rows.map(r => fmtTime(r.timestamp));
  cpuMemChart.data.labels = labels;
  cpuMemChart.data.datasets[0].data = rows.map(r => r.cpu_percent);
  cpuMemChart.data.datasets[1].data = rows.map(r => r.mem_percent);
  cpuMemChart.data.datasets[2].data = rows.map(r => ({
    x: fmtTime(r.timestamp), y: r.cpu_percent, anomaly: !!r.is_anomaly
  }));
  cpuMemChart.update();

  netChart.data.labels = labels;
  netChart.data.datasets[0].data = rows.map(r => r.net_sent_rate);
  netChart.data.datasets[1].data = rows.map(r => r.net_recv_rate);
  netChart.update();

  const latest = rows[rows.length - 1];
  document.getElementById('cpuVal').textContent = latest.cpu_percent.toFixed(1) + '%';
  document.getElementById('memVal').textContent = latest.mem_percent.toFixed(1) + '%';
  document.getElementById('procVal').textContent = latest.process_count;
}

async function refreshAnomalies() {
  const res = await fetch('/api/anomalies');
  const rows = await res.json();
  const list = document.getElementById('anomalyList');
  document.getElementById('anomCount').textContent = rows.length;

  if (!rows.length) {
    list.innerHTML = '<div class="empty">No anomalies detected yet.</div>';
    return;
  }

  list.innerHTML = rows.map(r => `
    <div class="anomaly-item">
      <div class="time">${fmtTime(r.timestamp)} · score ${r.anomaly_score.toFixed(3)}</div>
      <div>CPU ${r.cpu_percent.toFixed(1)}% · Mem ${r.mem_percent.toFixed(1)}% · Procs ${r.process_count}</div>
      <div>Net ↑${Math.round(r.net_sent_rate)} B/s ↓${Math.round(r.net_recv_rate)} B/s</div>
    </div>
  `).join('');
}

async function refreshStatus() {
  const res = await fetch('/api/status');
  const s = await res.json();
  const dot = document.getElementById('statusDot');
  const text = document.getElementById('statusText');
  if (s.baseline_ready) {
    dot.classList.add('ready');
    text.textContent = `Model active — monitoring live (${s.total_samples} samples collected)`;
  } else {
    dot.classList.remove('ready');
    text.textContent = `Collecting baseline data... ${s.total_samples}/${s.baseline_needed} samples`;
  }
}

function refreshAll() {
  refreshMetrics();
  refreshAnomalies();
  refreshStatus();
}

refreshAll();
setInterval(refreshAll, 5000);
// Cross-tab theme sync
window.addEventListener("storage", (e) => {
    if (e.key === "infrashield-theme") {
        document.documentElement.setAttribute("data-theme", e.newValue);
        applyChartTheme();
    }
});
