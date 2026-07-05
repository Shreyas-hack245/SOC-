// ---------- Scroll reveal ----------
const revealEls = document.querySelectorAll('.reveal');
const io = new IntersectionObserver((entries) => {
  entries.forEach(e => { if (e.isIntersecting) e.target.classList.add('in'); });
}, { threshold: 0.15 });
revealEls.forEach(el => io.observe(el));

// ---------- Signature visual: port-scan / firewall-block grid ----------
// Simulates the story: nmap scans a bank of ports, firewall filters them in real time.
const canvas = document.getElementById('portScan');
if (canvas) {
  const ctx = canvas.getContext('2d');
  const COLS = 16, ROWS = 8;
  const W = 560, H = 280;
  canvas.width = W;
  canvas.height = H;
  const cellW = W / COLS, cellH = H / ROWS;

  const ports = [];
  for (let r = 0; r < ROWS; r++) {
    for (let c = 0; c < COLS; c++) {
      ports.push({
        r, c,
        state: 'idle',      // idle -> scanning -> blocked/open
        delay: Math.random() * 4000,
        num: 1000 + Math.floor(Math.random() * 9000)
      });
    }
  }

  let sweepX = 0;
  const colors = {
    idle: '#1c222c',
    scanning: '#ffb627',
    blocked: '#2a3a3a',
    open: '#3ed9c5'
  };

  function draw(ts) {
    ctx.clearRect(0, 0, W, H);
    sweepX = (ts / 6) % (W + 120) - 60;

    ports.forEach(p => {
      const cx = p.c * cellW;
      const cy = p.r * cellH;
      const centerX = cx + cellW / 2;

      if (p.state === 'idle' && Math.abs(centerX - sweepX) < 18 && ts > p.delay) {
        p.state = 'scanning';
        p.scanStart = ts;
      }
      if (p.state === 'scanning' && ts - p.scanStart > 220) {
        p.state = Math.random() < 0.88 ? 'blocked' : 'open';
        p.resolvedAt = ts;
      }
      if (p.state !== 'idle' && p.resolvedAt && ts - p.resolvedAt > 3200) {
        p.state = 'idle';
        p.delay = ts + Math.random() * 1500;
      }

      ctx.fillStyle = colors[p.state];
      const pad = 3;
      ctx.fillRect(cx + pad, cy + pad, cellW - pad * 2, cellH - pad * 2);

      if (p.state === 'scanning') {
        ctx.strokeStyle = '#ffb627';
        ctx.lineWidth = 1;
        ctx.strokeRect(cx + pad, cy + pad, cellW - pad * 2, cellH - pad * 2);
      }
      if (p.state === 'open') {
        ctx.fillStyle = 'rgba(62,217,197,0.9)';
        ctx.font = '8px IBM Plex Mono';
        ctx.fillText(p.num, cx + 6, cy + cellH - 6);
      }
    });

    // sweep line
    const grad = ctx.createLinearGradient(sweepX - 40, 0, sweepX + 40, 0);
    grad.addColorStop(0, 'rgba(255,182,39,0)');
    grad.addColorStop(0.5, 'rgba(255,182,39,0.35)');
    grad.addColorStop(1, 'rgba(255,182,39,0)');
    ctx.fillStyle = grad;
    ctx.fillRect(sweepX - 40, 0, 80, H);

    requestAnimationFrame(draw);
  }
  requestAnimationFrame(draw);
}

// ---------- Live-feeling counters on results stat bar ----------
document.querySelectorAll('[data-count]').forEach(el => {
  const target = parseInt(el.getAttribute('data-count'), 10);
  const suffix = el.getAttribute('data-suffix') || '';
  let cur = 0;
  const step = Math.max(1, Math.round(target / 40));
  const tick = () => {
    cur = Math.min(target, cur + step);
    el.textContent = cur + suffix;
    if (cur < target) requestAnimationFrame(tick);
  };
  const obs = new IntersectionObserver((entries) => {
    if (entries[0].isIntersecting) { tick(); obs.disconnect(); }
  }, { threshold: 0.5 });
  obs.observe(el);
});
