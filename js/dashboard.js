// ---------- Clock ----------
function tickClock() {
  const el = document.getElementById('clock');
  if (el) el.textContent = new Date().toLocaleTimeString('en-GB');
}
setInterval(tickClock, 1000);
tickClock();

// ---------- Alert feed simulation ----------
const ATTACK_TYPES = [
  { label: 'Nmap SYN scan', sev: 'med', src: () => randIp(), action: 'Logged', tactic: 'Recon' },
  { label: 'Nmap service probe', sev: 'low', src: () => randIp(), action: 'Logged', tactic: 'Recon' },
  { label: 'SYN flood burst', sev: 'high', src: () => randIp(), action: 'Rate-limited', tactic: 'Impact' },
  { label: 'FTP brute-force attempt', sev: 'high', src: () => randIp(), action: 'Blocked', tactic: 'Cred. Access' },
  { label: 'Telnet login failure x5', sev: 'med', src: () => randIp(), action: 'Blocked', tactic: 'Cred. Access' },
  { label: 'Port 445 access attempt', sev: 'med', src: () => randIp(), action: 'Filtered', tactic: 'Recon' },
];

function randIp() {
  return `10.0.0.${Math.floor(Math.random() * 250) + 2}`;
}

let alertTotal = 0;
const feed = document.getElementById('alertFeed');
const countTag = document.getElementById('alertCount');

const attackCounts = { 'Nmap scans': 0, 'SYN flood': 0, 'FTP/Telnet brute': 0, 'Other': 0 };

function bucketFor(label) {
  if (label.includes('Nmap')) return 'Nmap scans';
  if (label.includes('SYN')) return 'SYN flood';
  if (label.includes('FTP') || label.includes('Telnet')) return 'FTP/Telnet brute';
  return 'Other';
}

function pushAlert() {
  const type = ATTACK_TYPES[Math.floor(Math.random() * ATTACK_TYPES.length)];
  alertTotal++;
  attackCounts[bucketFor(type.label)]++;

  const row = document.createElement('div');
  row.className = 'alert-row';
  const t = new Date().toLocaleTimeString('en-GB');
  row.innerHTML = `
    <span class="t">${t}</span>
    <span class="sev sev-${type.sev}">${type.sev.toUpperCase()}</span>
    <span class="msg">${type.label} — ${type.src()}</span>
    <span class="action">${type.action}</span>
  `;
  feed.prepend(row);
  while (feed.children.length > 60) feed.removeChild(feed.lastChild);
  countTag.textContent = `${alertTotal} alerts`;

  document.getElementById('statBlocked').textContent =
    Math.round(alertTotal * 0.82);

  updateAttackChart();
  bumpMitre(type.tactic);
}

setInterval(pushAlert, 1400);
for (let i = 0; i < 8; i++) pushAlert(); // seed the feed on load

// ---------- Firewall doughnut chart ----------
const fwCtx = document.getElementById('firewallChart');
const firewallChart = new Chart(fwCtx, {
  type: 'doughnut',
  data: {
    labels: ['Filtered', 'Open'],
    datasets: [{
      data: [98, 2],
      backgroundColor: ['#3ed9c5', '#232b38'],
      borderColor: '#12161d',
      borderWidth: 3
    }]
  },
  options: {
    cutout: '72%',
    plugins: { legend: { display: false } },
    animation: { duration: 400 }
  }
});

// ---------- Attack type bar chart ----------
const atCtx = document.getElementById('attackChart');
const attackChart = new Chart(atCtx, {
  type: 'bar',
  data: {
    labels: Object.keys(attackCounts),
    datasets: [{
      data: Object.values(attackCounts),
      backgroundColor: ['#ffb627', '#ff4d5e', '#3ed9c5', '#7c8698'],
      borderRadius: 4,
      maxBarThickness: 42
    }]
  },
  options: {
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color: '#7c8698', font: { family: 'IBM Plex Mono', size: 10 } }, grid: { display: false } },
      y: { ticks: { color: '#7c8698', font: { family: 'IBM Plex Mono', size: 10 } }, grid: { color: '#232b38' }, beginAtZero: true }
    },
    animation: { duration: 300 }
  }
});

function updateAttackChart() {
  attackChart.data.datasets[0].data = Object.values(attackCounts);
  attackChart.update();
}

// ---------- MITRE heatmap ----------
const TACTICS = ['Recon', 'Cred. Access', 'Impact', 'Exfil', 'C2', 'Persist', 'Evasion'];
const mitreGrid = document.getElementById('mitreGrid');
const mitreHits = {};
TACTICS.forEach(t => (mitreHits[t] = 0));

TACTICS.forEach(t => {
  const cell = document.createElement('div');
  cell.className = 'mitre-cell';
  cell.id = `mitre-${t}`;
  cell.textContent = t;
  mitreGrid.appendChild(cell);
});

function bumpMitre(tactic) {
  if (!(tactic in mitreHits)) return;
  mitreHits[tactic]++;
  const cell = document.getElementById(`mitre-${tactic}`);
  if (!cell) return;
  const n = mitreHits[tactic];
  cell.classList.remove('hit-low', 'hit-med', 'hit-high');
  if (n > 12) cell.classList.add('hit-high');
  else if (n > 5) cell.classList.add('hit-med');
  else if (n > 0) cell.classList.add('hit-low');
  cell.textContent = `${tactic} (${n})`;
}

// ---------- RBAC role switch ----------
const roleSelect = document.getElementById('roleSelect');
const rbacVal = document.getElementById('rbacVal');
const rbacNote = document.getElementById('rbacNote');
const roleTag = document.getElementById('roleTag');

const ROLE_COPY = {
  Analyst: {
    val: 'analyst · read-only alerts',
    note: 'Analysts can view live alerts and MITRE mappings but cannot change firewall rules. Switch role above to see access change.'
  },
  Admin: {
    val: 'admin · full control',
    note: 'Admins can view alerts, edit firewall rules, and acknowledge or escalate incidents directly from this dashboard.'
  },
  Viewer: {
    val: 'viewer · alerts hidden',
    note: 'Viewers see system status only. Alert details and MITRE mapping are hidden until elevated to Analyst or Admin.'
  }
};

roleSelect.addEventListener('change', () => {
  const role = roleSelect.value;
  const copy = ROLE_COPY[role];
  rbacVal.textContent = copy.val;
  rbacNote.textContent = copy.note;
  roleTag.textContent = `role: ${role.toLowerCase()}`;

  const feedPanel = feed.closest('.panel');
  if (role === 'Viewer') {
    feed.style.filter = 'blur(4px)';
    feed.style.pointerEvents = 'none';
  } else {
    feed.style.filter = 'none';
    feed.style.pointerEvents = 'auto';
  }
});
