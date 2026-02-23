/* SafePhishi — Sci-Fi OLED Dark UI · main.js */

/* ── Particle Field ─────────────────────────────────────── */
(function initParticles() {
  const canvas = document.createElement('canvas');
  canvas.id = 'particle-canvas';
  document.body.prepend(canvas);
  const ctx = canvas.getContext('2d');

  const COLORS = ['rgba(0,245,255,', 'rgba(139,43,226,', 'rgba(255,45,120,'];
  let W, H, particles = [];

  function resize() {
    W = canvas.width = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }
  resize();
  window.addEventListener('resize', resize);

  function mkParticle() {
    const c = COLORS[Math.floor(Math.random() * COLORS.length)];
    return {
      x: Math.random() * W,
      y: Math.random() * H,
      r: Math.random() * 1.2 + 0.3,
      dx: (Math.random() - 0.5) * 0.28,
      dy: (Math.random() - 0.5) * 0.28,
      alpha: Math.random() * 0.55 + 0.15,
      color: c,
      pulse: Math.random() * Math.PI * 2,
    };
  }

  for (let i = 0; i < 90; i++) particles.push(mkParticle());

  function draw() {
    ctx.clearRect(0, 0, W, H);
    particles.forEach(p => {
      p.pulse += 0.018;
      const a = p.alpha * (0.65 + 0.35 * Math.sin(p.pulse));
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = p.color + a + ')';
      ctx.fill();
      p.x += p.dx;
      p.y += p.dy;
      if (p.x < -4) p.x = W + 4;
      if (p.x > W + 4) p.x = -4;
      if (p.y < -4) p.y = H + 4;
      if (p.y > H + 4) p.y = -4;
    });

    // draw faint connection lines
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 110) {
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          const a = (1 - dist / 110) * 0.06;
          ctx.strokeStyle = `rgba(0,245,255,${a})`;
          ctx.lineWidth = 0.5;
          ctx.stroke();
        }
      }
    }
    requestAnimationFrame(draw);
  }
  draw();
})();

/* ── Cursor Glow ─────────────────────────────────────────── */
(function cursorGlow() {
  const glow = document.createElement('div');
  Object.assign(glow.style, {
    position: 'fixed',
    width: '280px',
    height: '280px',
    borderRadius: '50%',
    background: 'radial-gradient(circle, rgba(0,245,255,0.055) 0%, transparent 70%)',
    pointerEvents: 'none',
    transform: 'translate(-50%,-50%)',
    transition: 'left .12s ease, top .12s ease',
    zIndex: '0',
    mixBlendMode: 'screen',
  });
  document.body.appendChild(glow);
  window.addEventListener('mousemove', e => {
    glow.style.left = e.clientX + 'px';
    glow.style.top = e.clientY + 'px';
  });
})();

/* ── Card tilt on hover ──────────────────────────────────── */
document.querySelectorAll('.card').forEach(card => {
  card.addEventListener('mousemove', e => {
    const rect = card.getBoundingClientRect();
    const x = ((e.clientX - rect.left) / rect.width - 0.5) * 6;
    const y = ((e.clientY - rect.top) / rect.height - 0.5) * -6;
    card.style.transform = `perspective(800px) rotateX(${y}deg) rotateY(${x}deg) translateY(-2px)`;
  });
  card.addEventListener('mouseleave', () => {
    card.style.transform = '';
  });
});

/* ── Scan button pulse ring on click ─────────────────────── */
document.querySelectorAll('.btn-primary').forEach(btn => {
  btn.addEventListener('click', function () {
    this.classList.add('scanning');
    setTimeout(() => this.classList.remove('scanning'), 600);
  });
});
/* ── Apply dynamic widths from data attributes ───────────── */
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-rs-width]').forEach(el => {
    const width = el.getAttribute('data-rs-width');
    if (width) el.style.width = width + '%';
  });
});
