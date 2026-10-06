var state = { 
    modelFilter: new Set(), 
    selTrace: null, 
    selSpan: 0, 
    latStat: 'avg',
    auditSummary: null,
    hiddenCards: 0
};

var $ = function(id) { return document.getElementById(id); };

var ICON_PATHS = {
    security: '<path d="M12 3 20 6v5c0 5.2-3.4 9.2-8 11-4.6-1.8-8-5.8-8-11V6l8-3Z" fill="none" stroke="currentColor" stroke-width="1.7"/><path d="m8.7 12 2.1 2.1 4.5-4.6" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>',
    error: '<path d="M12 3 22 21H2L12 3Z" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/><path d="M12 9v5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/><circle cx="12" cy="17.5" r="1" fill="currentColor"/>',
    latency: '<circle cx="12" cy="12" r="8.5" fill="none" stroke="currentColor" stroke-width="1.7"/><path d="M12 7v5l3.5 2" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>',
    back: '<path d="M15 5 8 12l7 7" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>',
    refresh: '<path d="M20 11a8 8 0 0 0-14.7-3L3 11" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/><path d="M3 6v5h5" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>',
    filter: '<path d="M4 6h16M7 12h10M10 18h4" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>'
};

function renderIcons(root) {
    (root || document).querySelectorAll('.ui-icon[data-icon]').forEach(function(el) {
        var key = el.getAttribute('data-icon');
        if (ICON_PATHS[key]) el.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">' + ICON_PATHS[key] + '</svg>';
    });
}
renderIcons(document);

var esc = function(v) {
    return String(v === null || v === undefined ? '' : v).replace(/[&<>'"]/g, function(c) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[c];
    });
};

var fmt = function(n) { return Number(n || 0).toLocaleString('en-US').replace(/,/g, ' '); };
var fmtK = function(n) {
    n = Number(n || 0);
    return n >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : n >= 1e3 ? (n / 1e3).toFixed(1) + 'K' : String(Math.round(n));
};
var money = function(n) { return '$' + Number(n || 0).toFixed(4); };

var P = ['#da7751', '#fb923c', '#4cc38a', '#e0525f', '#7dbbd1', '#f5b84b', '#c4623f', '#4ade80', '#22d3ee', '#d98a9a', '#facc15', '#94a3b8', '#6ee7b7', '#fda4af', '#e6b17e'];

var CHECKS = [
    ['prompt_injection', '#da7751'],
    ['pii_detection', '#fb923c'],
    ['tool_policy', '#3ecfb2'],
    ['dangerous_params', '#e0525f'],
    ['budget_policy', '#7d9bb5']
];

function toast(m) {
    var t = $('toast');
    t.textContent = m;
    t.classList.add('show');
    clearTimeout(window._t);
    window._t = setTimeout(function() { t.classList.remove('show'); }, 2200);
}

function api(u) {
    return fetch(u, { credentials: 'include' }).then(function(r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
    });
}

function apiSend(u, method, body) {
    return fetch(u, {
        method: method,
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: body !== undefined ? JSON.stringify(body) : undefined
    }).then(function(r) {
        return r.json().catch(function() { return {}; }).then(function(data) {
            if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
            return data;
        });
    });
}


var ICON_PATHS_EXTRA = {
    slack: '<path fill="currentColor" d="M5.042 15.165a2.528 2.528 0 0 1-2.52 2.523A2.528 2.528 0 0 1 0 15.165a2.527 2.527 0 0 1 2.522-2.52h2.52v2.52zM6.313 15.165a2.527 2.527 0 0 1 2.521-2.52 2.527 2.527 0 0 1 2.521 2.52v6.313A2.528 2.528 0 0 1 8.834 24a2.528 2.528 0 0 1-2.521-2.522v-6.313zM8.834 5.042a2.528 2.528 0 0 1-2.521-2.52A2.528 2.528 0 0 1 8.834 0a2.528 2.528 0 0 1 2.521 2.522v2.52H8.834zM8.834 6.313a2.528 2.528 0 0 1 2.521 2.521 2.528 2.528 0 0 1-2.521 2.521H2.522A2.528 2.528 0 0 1 0 8.834a2.528 2.528 0 0 1 2.522-2.521h6.312zM18.956 8.834a2.528 2.528 0 0 1 2.522-2.521A2.528 2.528 0 0 1 24 8.834a2.528 2.528 0 0 1-2.522 2.521h-2.522V8.834zM17.688 8.834a2.528 2.528 0 0 1-2.523 2.521 2.527 2.527 0 0 1-2.52-2.521V2.522A2.527 2.527 0 0 1 15.165 0a2.528 2.528 0 0 1 2.523 2.522v6.312zM15.165 18.956a2.528 2.528 0 0 1 2.523 2.522A2.528 2.528 0 0 1 15.165 24a2.527 2.527 0 0 1-2.52-2.522v-2.522h2.52zM15.165 17.688a2.527 2.527 0 0 1-2.52-2.523 2.526 2.526 0 0 1 2.52-2.52h6.313A2.527 2.527 0 0 1 24 15.165a2.528 2.528 0 0 1-2.522 2.523h-6.313z"/>',
    discord: '<path fill="currentColor" d="M20.317 4.3698a19.7913 19.7913 0 00-4.8851-1.5152.0741.0741 0 00-.0785.0371c-.211.3753-.4447.8648-.6083 1.2495-1.8447-.2762-3.68-.2762-5.4868 0-.1636-.3933-.4058-.8742-.6177-1.2495a.077.077 0 00-.0785-.037 19.7363 19.7363 0 00-4.8852 1.515.0699.0699 0 00-.0321.0277C.5334 9.0458-.319 13.5799.0992 18.0578a.0824.0824 0 00.0312.0561c2.0528 1.5076 4.0413 2.4228 5.9929 3.0294a.0777.0777 0 00.0842-.0276c.4616-.6304.8731-1.2952 1.226-1.9942a.076.076 0 00-.0416-.1057c-.6528-.2476-1.2743-.5495-1.8722-.8923a.077.077 0 01-.0076-.1277c.1258-.0943.2517-.1923.3718-.2914a.0743.0743 0 01.0776-.0105c3.9278 1.7933 8.18 1.7933 12.0614 0a.0739.0739 0 01.0785.0095c.1202.099.246.1981.3728.2924a.077.077 0 01-.0066.1276 12.2986 12.2986 0 01-1.873.8914.0766.0766 0 00-.0407.1067c.3604.698.7719 1.3628 1.225 1.9932a.076.076 0 00.0842.0286c1.961-.6067 3.9495-1.5219 6.0023-3.0294a.077.077 0 00.0313-.0552c.5004-5.177-.8382-9.6739-3.5485-13.6604a.061.061 0 00-.0312-.0286zM8.02 15.3312c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9555-2.4189 2.157-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419 0 1.3332-.9555 2.4189-2.1569 2.4189zm7.9748 0c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9554-2.4189 2.1569-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419 0 1.3332-.946 2.4189-2.1568 2.4189Z"/>',
    mail: '<g fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m22 7-8.991 5.727a2 2 0 0 1-2.009 0L2 7"/><rect x="2" y="4" width="20" height="16" rx="2"/></g>',
    webhook: '<g fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 16.98h-5.99c-1.1 0-1.95.94-2.48 1.9A4 4 0 0 1 2 17c.01-.7.2-1.4.57-2"/><path d="m6 17 3.13-5.78c.53-.97.1-2.18-.5-3.1a4 4 0 1 1 6.89-4.06"/><path d="m12 6 3.13 5.73C15.66 12.7 16.9 13 18 13a4 4 0 0 1 0 8"/></g>',
    alert: '<g fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/></g>',
    check: '<g fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></g>',
    ban: '<g fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M4.929 4.929 19.07 19.071"/></g>'
};

function iconSvg(name, size) {
    var p = ICON_PATHS_EXTRA[name] || ICON_PATHS[name];
    if (!p) return '';
    var s = size || 16;
    return '<svg viewBox="0 0 24 24" width="' + s + '" height="' + s + '" aria-hidden="true" focusable="false" style="flex:none;vertical-align:-2px">' + p + '</svg>';
}
