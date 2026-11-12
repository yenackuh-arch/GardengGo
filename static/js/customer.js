/* GardenGo customer site: small browser helpers. All the real checks are done by Flask on the server. */
'use strict';
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

document.addEventListener('DOMContentLoaded', () => {
  // Mobile menu
  const toggle = $('#navToggle'), menu = $('#navMenu');
  if (toggle && menu) {
    toggle.addEventListener('click', () => {
      const open = menu.classList.toggle('open');
      toggle.setAttribute('aria-expanded', open);
    });
  }

  // Show or hide the password
  const pw = $('#password'), pwBtn = $('#pwToggle');
  if (pw && pwBtn) {
    pwBtn.addEventListener('click', () => {
      const show = pw.type === 'password';
      pw.type = show ? 'text' : 'password';
      pwBtn.textContent = show ? 'Hide' : 'Show';
      pwBtn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    });
  }

  // Password strength meter (a hint only; the server checks the password again)
  const bar = $('#strengthBar'), txt = $('#strengthText');
  if (pw && bar && txt) {
    pw.addEventListener('input', () => {
      const v = pw.value;
      const score = (v.length >= 8) + (/[A-Z]/.test(v) && /[a-z]/.test(v)) + /\d/.test(v) + /[^A-Za-z0-9]/.test(v);
      const labels = ['Too short', 'Weak', 'Okay', 'Good', 'Strong'];
      bar.style.width = (v ? score * 25 : 0) + '%';
      bar.className = 'lv' + (v ? score : 0);
      txt.textContent = v ? 'Strength: ' + labels[v.length < 8 ? 0 : score] : 'Use 8 or more characters with letters and numbers.';
    });
  }

  // Quantity +/- buttons
  $$('.qty').forEach(box => {
    const input = $('input', box);
    $$('[data-step]', box).forEach(btn => btn.addEventListener('click', () => {
      const min = +input.min || 1, max = +input.max || 99;
      input.value = Math.min(max, Math.max(min, (parseInt(input.value) || min) + (+btn.dataset.step)));
      input.dispatchEvent(new Event('change', {bubbles: true}));
    }));
  });

  // Selects and number boxes that send their form when changed
  $$('[data-autosubmit]').forEach(el => el.addEventListener('change', () => el.form && el.form.submit()));

  // Ask before dangerous actions
  $$('form[data-confirm]').forEach(f => f.addEventListener('submit', e => { if (!confirm(f.dataset.confirm)) e.preventDefault(); }));

  // Stop double clicks on submit buttons (so an order is not sent twice)
  $$('form').forEach(f => f.addEventListener('submit', () => {
    const b = $('[data-once]', f);
    if (b) setTimeout(() => { b.disabled = true; }, 0);
  }));

  // Checkout: show the delivery fee as soon as the method is chosen
  const method = $('#fulfillment'), totals = $('#orderTotals');
  if (method && totals) {
    const peso = n => '\u20B1' + n.toLocaleString('en-PH', {minimumFractionDigits: 2, maximumFractionDigits: 2});
    const update = () => {
      const fee = method.value === 'delivery' ? parseFloat(totals.dataset.fee) : 0, sub = parseFloat(totals.dataset.subtotal);
      $('#feeValue').textContent = peso(fee); $('#totalValue').textContent = peso(sub + fee);
    };
    method.addEventListener('change', update); update();
  }

  // Fade-in on scroll
  const items = $$('.reveal');
  if ('IntersectionObserver' in window) {
    const io = new IntersectionObserver(es => es.forEach(e => { if (e.isIntersecting) { e.target.classList.add('visible'); io.unobserve(e.target); } }), {threshold: .12});
    items.forEach(i => io.observe(i));
  } else { items.forEach(i => i.classList.add('visible')); }
});
