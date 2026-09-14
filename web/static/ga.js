// Google Analytics 4 initialiser.
//
// The strict CSP forbids inline scripts, so the standard gtag snippet lives here
// as an external file instead. The measurement ID travels in this script tag's
// data-ga-id attribute; the loader (googletagmanager.com/gtag/js) is a separate
// tag in the page head. This file is only ever included on non-secret pages —
// never on a page whose URL or fragment can carry a share key or password.
'use strict';
(function () {
  var el = document.currentScript;
  var id = el && el.dataset ? el.dataset.gaId : '';
  if (!id) return;
  window.dataLayer = window.dataLayer || [];
  function gtag() { window.dataLayer.push(arguments); }
  window.gtag = gtag;
  gtag('js', new Date());
  gtag('config', id);
})();
