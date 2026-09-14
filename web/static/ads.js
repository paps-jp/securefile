// Pushes every AdSense unit on the page. Kept as an external file so the page
// needs no inline script and the CSP can stay without 'unsafe-inline' for
// scripts. Only loaded on non-secret pages (never on download pages).
'use strict';
try {
  document.querySelectorAll('ins.adsbygoogle').forEach(() => {
    (window.adsbygoogle = window.adsbygoogle || []).push({});
  });
} catch (e) { /* ads are best-effort; never break the page */ }
