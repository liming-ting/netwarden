/* netwarden printable report: the dashboard's saved theme + the Print button (the
 * browser's own print dialog; "Save as PDF" never uploads anything). No other script. */
'use strict';
(function () {
  try {
    const t = localStorage.getItem('netwarden.theme');
    if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
  } catch (e) { /* private mode */ }
  const b = document.getElementById('print');
  if (b) b.addEventListener('click', () => window.print());
})();
