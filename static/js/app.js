// ── Typewriter effect ──
function typeWriter(el, text, speed = 40) {
  let i = 0;
  el.textContent = '';
  const timer = setInterval(() => {
    el.textContent += text[i++];
    if (i >= text.length) clearInterval(timer);
  }, speed);
}

// ── Animate numbers ──
function animateNumber(el, target, duration = 1000) {
  const start = 0;
  const step  = target / (duration / 16);
  let current = start;
  const timer = setInterval(() => {
    current = Math.min(current + step, target);
    el.textContent = Math.floor(current).toLocaleString();
    if (current >= target) clearInterval(timer);
  }, 16);
}

// ── Copy to clipboard ──
function copyToClipboard(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = '✓ Copied!';
    btn.style.color = '#00ff9d';
    setTimeout(() => { btn.textContent = orig; btn.style.color = ''; }, 2000);
  });
}

// ── Log line colorizer ──
function colorizeLogLines() {
  document.querySelectorAll('.log-line').forEach(line => {
    const txt = line.textContent;
    if (txt.includes('[L1-SQLI') || txt.includes('[L2-SQLI'))  line.classList.add('sqli');
    else if (txt.includes('[L3-XSS'))                           line.classList.add('xss');
    else if (txt.includes('[L4-IDOR'))                          line.classList.add('idor');
    else if (txt.includes('[L5-SSRF'))                          line.classList.add('ssrf');
    else if (txt.includes('[AUTH') || txt.includes('[L6'))      line.classList.add('auth');
    else                                                         line.classList.add('normal');
  });
}

// ── Active nav link ──
function setActiveNav() {
  const path = window.location.pathname;
  document.querySelectorAll('.nav-links a').forEach(a => {
    if (a.getAttribute('href') === path) a.classList.add('active');
  });
}

// ── Fade-in observer ──
function initFadeIn() {
  const obs = new IntersectionObserver((entries) => {
    entries.forEach(e => {
      if (e.isIntersecting) { e.target.style.opacity = '1'; e.target.style.transform = 'translateY(0)'; }
    });
  }, { threshold: 0.1 });
  document.querySelectorAll('.fade-in').forEach(el => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(20px)';
    el.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
    obs.observe(el);
  });
}

// ── Quick payload injector ──
function injectPayload(inputId, payload) {
  const el = document.getElementById(inputId);
  if (el) { el.value = payload; el.focus(); }
}

// ── Timer for SQLi time-based demo ──
let timerInterval = null;
function startTimer(displayId) {
  const el = document.getElementById(displayId);
  if (!el) return;
  let secs = 0;
  el.textContent = '0.0s';
  timerInterval = setInterval(() => {
    secs += 0.1;
    el.textContent = secs.toFixed(1) + 's';
  }, 100);
}
function stopTimer() {
  if (timerInterval) { clearInterval(timerInterval); timerInterval = null; }
}

// ── Init ──
document.addEventListener('DOMContentLoaded', () => {
  setActiveNav();
  colorizeLogLines();
  initFadeIn();

  // Animate stat numbers
  document.querySelectorAll('[data-count]').forEach(el => {
    animateNumber(el, parseInt(el.dataset.count), 1200);
  });

  // Typewriter for hero
  const tw = document.querySelector('[data-typewriter]');
  if (tw) typeWriter(tw, tw.dataset.typewriter, 50);

  // Copy buttons
  document.querySelectorAll('[data-copy]').forEach(btn => {
    btn.addEventListener('click', () => copyToClipboard(btn.dataset.copy, btn));
  });

  // ── data-payload buttons (replaces all inline onclick with &quot;) ──
  // Works for: SQLi payloads, XSS inject buttons, SSRF quick payloads
  document.querySelectorAll('.payload-btn[data-payload]').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.dataset.target;
      const payload  = btn.dataset.payload;
      const timerId  = btn.dataset.timer;

      if (targetId && payload !== undefined) {
        const el = document.getElementById(targetId);
        if (el) {
          // Decode HTML entities so the raw payload goes into the field
          const txt = document.createElement('textarea');
          txt.innerHTML = payload;
          el.value = txt.value;
          el.focus();
        }
      }

      // Start timer if button has data-timer (L2 SLEEP blind)
      if (timerId) {
        startTimer(timerId);
        // Show timer card
        const card = document.getElementById('timer-card');
        if (card) card.style.display = 'block';
      }
    });
  });

  // SQLi time-based form timer (fallback for manual typing)
  const sqlForm = document.getElementById('sqli-form');
  if (sqlForm) {
    sqlForm.addEventListener('submit', () => {
      const input = document.getElementById('id-input');
      if (input && input.value.toUpperCase().includes('SLEEP')) {
        startTimer('timer-display');
      }
    });
  }
});
