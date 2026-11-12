/* GardenGo admin: small browser helpers. Flask checks everything again on the server. */
'use strict';
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

document.addEventListener('DOMContentLoaded', () => {
  // Mobile sidebar
  const toggle = $('#sidebarToggle');
  const open = on => { document.body.classList.toggle('sidebar-open', on); if (toggle) toggle.setAttribute('aria-expanded', on); };
  if (toggle) toggle.addEventListener('click', () => open(!document.body.classList.contains('sidebar-open')));
  const overlay = $('#sidebarOverlay'); if (overlay) overlay.addEventListener('click', () => open(false));
  document.addEventListener('keydown', e => { if (e.key === 'Escape') open(false); });

  // Ask before dangerous actions (delete, cancel, deactivate)
  $$('form[data-confirm]').forEach(f => f.addEventListener('submit', e => { if (!confirm(f.dataset.confirm)) e.preventDefault(); }));

  // Cancelling an order cannot be undone, so ask first
  const statusForm = $('#statusForm');
  if (statusForm) statusForm.addEventListener('submit', e => {
    if ($('#status', statusForm).value === 'Cancelled' && !confirm('Cancel this order? The plants will be returned to stock. This cannot be undone.')) e.preventDefault();
  });

  // Selects that send their form when changed
  $$('[data-autosubmit]').forEach(el => el.addEventListener('change', () => el.form && el.form.submit()));

  // Stop double clicks on submit buttons
  $$('form').forEach(f => f.addEventListener('submit', e => {
    const b = $('[data-once]', f);
    if (b && !e.defaultPrevented) setTimeout(() => { b.disabled = true; }, 0);
  }));

  // Photo preview in the plant form (preview only; the server checks the real file)
  const file = $('#image'), preview = $('#imgPreview');
  if (file && preview) file.addEventListener('change', () => {
    const f = file.files[0];
    if (f && f.type.startsWith('image/')) { preview.innerHTML = ''; const img = document.createElement('img'); img.className = 'thumb-lg'; img.alt = 'Photo preview'; img.src = URL.createObjectURL(f); preview.appendChild(img); }
  });

  // Live "new stock will be" text on the adjust page
  const adj = $('#adjustForm');
  if (adj) {
    const update = () => {
      const mode = $('input[name=mode]:checked', adj).value, n = parseInt($('#qty').value, 10), cur = +adj.dataset.current;
      const out = $('#preview');
      if (isNaN(n)) { out.textContent = ''; return; }
      const next = mode === 'restock' ? cur + n : mode === 'remove' ? cur - n : n;
      out.textContent = next < 0 ? 'That would make the stock negative.' : 'New stock will be ' + next + '.';
    };
    adj.addEventListener('input', update); update();
  }

  // Sales chart (data comes from the database through the page)
  const canvas = $('#salesChart');
  if (canvas) {
    if (typeof Chart === 'undefined') { canvas.parentElement.innerHTML = '<p class="muted p-3">The chart could not load. Please check your internet connection.</p>'; return; }
    const data = JSON.parse(canvas.dataset.chart);
    new Chart(canvas, {
      type: 'line',
      data: {labels: data.labels, datasets: [{label: 'Sales', data: data.values, borderColor: '#2E7D32', backgroundColor: 'rgba(46,125,50,.15)', fill: true, tension: .3, pointRadius: data.values.length > 8 ? 2 : 4, pointBackgroundColor: '#1B5E20'}]},
      options: {responsive: true, maintainAspectRatio: false,
        plugins: {legend: {display: false}, tooltip: {callbacks: {label: c => ' \u20B1' + c.parsed.y.toLocaleString('en-PH', {minimumFractionDigits: 2})}}},
        scales: {y: {beginAtZero: true, ticks: {callback: v => '\u20B1' + v.toLocaleString('en-PH')}}, x: {ticks: {maxTicksLimit: 8}}}}
    });
  }
});
