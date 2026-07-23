/**
 * SOC Lab local server. Uses only Node's standard library so the project can
 * run immediately after cloning, without installing any packages.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const state = {
  metrics: { packetsInspected: 1204387, alertsGenerated: 864, incidents: 43, detectionRate: 99.8, blocked: 38, mttd: '01:42', health: 98.6 },
  agent: { risk: 76, confidence: 91, thought: 'Correlating anomalous authentication activity...', containment: 68, playbook: 'Credential Access', actions: ['Isolated source IP', 'Enriched IOC data'], approvalPending: true },
  traffic: [42,57,45,74,61,93,76],
  attackers: [{ip:'185.220.101.44',score:91,source:'TOR EXIT'},{ip:'45.83.64.102',score:77,source:'ANONYMOUS VPS'},{ip:'10.10.10.24',score:68,source:'LAB ATTACKER'}],
  alerts: []
};
const templates = [
  ['critical','SYN Flood Detected','172.16.4.28','T1499','Connection rate crossed the protected service threshold.'],
  ['high','Hydra SSH Brute Force','10.10.10.24','T1110','Repeated SSH authentication failures from a single source.'],
  ['high','Nmap Scan Detected','10.10.10.24','T1046','Horizontal port sweep detected across internal address space.'],
  ['medium','DNS Tunneling Suspected','host-client-17','T1071','High entropy DNS requests match tunnelling heuristics.'],
  ['high','PowerShell Suspicious Execution','WIN-DC01','T1059','Encoded command invoked by an unusual parent process.'],
  ['medium','RDP Login Failure','WIN-SRV02','T1021','Repeated failed remote desktop logons.']
];
function createAlert(template) {
  const [severity, name, entity, technique, analysis] = template;
  return { id: crypto.randomUUID(), severity, name, entity, technique, analysis, status: 'Open', timestamp: new Date().toISOString(), risk: severity === 'critical' ? 94 : severity === 'high' ? 82 : 64, rule: `AEGIS-${technique.replace('T','')}-DETECTION`, payload: '45 00 00 3c 1c 46 40 00 40 06 b1 e6 0a 0a 0a 18 ac 10 0a 08 00 50 01 bb' };
}
state.alerts = templates.map((t, i) => ({ ...createAlert(t), timestamp: new Date(Date.now() - i * 60000).toISOString() }));
function send(res, code, body) { res.writeHead(code, {'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'}); res.end(JSON.stringify(body)); }
function readBody(req) { return new Promise((resolve,reject) => { let raw=''; req.on('data',c=>raw+=c); req.on('end',()=>{ try { resolve(raw ? JSON.parse(raw) : {}); } catch { reject(new Error('Invalid JSON')); } }); }); }
function contentType(file) { return {'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'application/javascript; charset=utf-8','.json':'application/json'}[path.extname(file)] || 'application/octet-stream'; }
function serveStatic(res, pathname) {
  const requested = pathname === '/' ? '/index.html' : pathname;
  const file = path.resolve(ROOT, `.${requested}`);
  if (!file.startsWith(ROOT) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) { res.writeHead(404); return res.end('Not found'); }
  res.writeHead(200, {'Content-Type':contentType(file)}); fs.createReadStream(file).pipe(res);
}
const server = http.createServer(async (req,res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  try {
    if (req.method === 'GET' && url.pathname === '/api/dashboard') return send(res, 200, state);
    if (req.method === 'GET' && url.pathname === '/api/alerts') return send(res, 200, state.alerts);
    if (req.method === 'POST' && url.pathname === '/api/alerts') { const body = await readBody(req); const template = templates.find(t=>t[1]===body.name) || templates[Math.floor(Math.random()*templates.length)]; const alert = createAlert(template); state.alerts.unshift(alert); state.alerts=state.alerts.slice(0,30); state.metrics.alertsGenerated++; return send(res,201,alert); }
    if (req.method === 'POST' && /^\/api\/alerts\/[^/]+\/status$/.test(url.pathname)) { const id=url.pathname.split('/')[3], body=await readBody(req), alert=state.alerts.find(a=>a.id===id); if(!alert)return send(res,404,{error:'Alert not found'}); alert.status=body.status || 'Investigating'; return send(res,200,alert); }
    if (req.method === 'POST' && url.pathname === '/api/containment') { state.agent.containment=100; state.agent.approvalPending=false; state.agent.actions.push('Containment playbook executed'); state.agent.thought='Containment completed. Monitoring for recurrence.'; return send(res,200,{message:'Containment playbook executed successfully.',agent:state.agent}); }
    return serveStatic(res,url.pathname);
  } catch (error) { return send(res,400,{error:error.message}); }
});
setInterval(()=>{ state.metrics.packetsInspected += 480 + Math.floor(Math.random()*1800); state.traffic.shift(); state.traffic.push(38+Math.floor(Math.random()*60)); if(Math.random()>.42){ const alert=createAlert(templates[Math.floor(Math.random()*templates.length)]); state.alerts.unshift(alert); state.alerts=state.alerts.slice(0,30); state.metrics.alertsGenerated++; } },7000);
server.listen(PORT,()=>console.log(`SOC Lab running at http://localhost:${PORT}`));
