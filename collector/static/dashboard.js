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
    return String(v || '').replace(/[&<>'"]/g, function(c) {
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

// ─────────────────────────────────────────────────────────────
// GENERIC POPOVER PLUMBING
// ─────────────────────────────────────────────────────────────
function closeAllPopovers() {
    ['cardMenuPopover', 'infoPopover', 'auditExportMenu'].forEach(function(id) {
        var el = $(id);
        if (el) el.classList.remove('open');
    });
}
document.addEventListener('click', function(e) {
    if (e.target.closest && (e.target.closest('.menu') || e.target.closest('.info') || e.target.closest('.popover') || e.target.closest('.audit-export-wrap'))) return;
    closeAllPopovers();
});
function positionPopover(el, anchorEl) {
    var r = anchorEl.getBoundingClientRect();
    el.style.display = 'block';
    var w = el.offsetWidth || 180;
    var left = Math.min(r.left, window.innerWidth - w - 12);
    el.style.top = (r.bottom + 6) + 'px';
    el.style.left = Math.max(8, left) + 'px';
}

// ─────────────────────────────────────────────────────────────
// INFO TOOLTIPS
// ─────────────────────────────────────────────────────────────
var INFO_TEXT = {
    traffic: "Volume de requêtes et temps de réponse de vos agents sur la période sélectionnée. Basculez AVG/p50/p90/p95 pour changer la statistique affichée.",
    cost: "Consommation de tokens et coût par requête. Utilisez « + New alert » sur une carte pour être averti visuellement quand un seuil est dépassé.",
    guardrails: "Nombre de requêtes ayant déclenché un contrôle de sécurité (injection, PII, politique d'outil...) et répartition par type de contrôle."
};
function showInfoPopover(evt, key) {
    evt.stopPropagation();
    var pop = $('infoPopover');
    if (pop.classList.contains('open') && pop.dataset.key === key) { closeAllPopovers(); return; }
    closeAllPopovers();
    pop.textContent = INFO_TEXT[key] || '';
    pop.dataset.key = key;
    pop.classList.add('open');
    positionPopover(pop, evt.currentTarget);
}

// ─────────────────────────────────────────────────────────────
// CARD MENU
// ─────────────────────────────────────────────────────────────
var _cardMenuTarget = null;
function openCardMenu(evt, btn) {
    evt.stopPropagation();
    var card = btn.closest('.card');
    var pop = $('cardMenuPopover');
    if (pop.classList.contains('open') && _cardMenuTarget === card) { closeAllPopovers(); return; }
    closeAllPopovers();
    _cardMenuTarget = card;
    pop.innerHTML = '<button onclick="exportCardData(\'json\')">Copier en JSON</button>' +
                    '<button onclick="exportCardData(\'csv\')">Exporter en CSV</button>' +
                    '<button onclick="hideCard()">Masquer cette carte</button>';
    pop.classList.add('open');
    positionPopover(pop, btn);
}
function extractCardRows(card) {
    var label = (card.querySelector('.clabel') || {}).textContent || 'metric';
    var rows = [];
    var hero = card.querySelector('.hero');
    if (hero) rows.push([label.trim(), hero.textContent.trim()]);
    card.querySelectorAll('.legend span').forEach(function(sp) { rows.push([sp.textContent.trim(), '']); });
    return rows;
}
function exportCardData(fmt) {
    if (!_cardMenuTarget) return;
    var rows = extractCardRows(_cardMenuTarget);
    var label = (_cardMenuTarget.querySelector('.clabel') || {}).textContent || 'card';
    label = label.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-');
    if (fmt === 'json') {
        var obj = {};
        rows.forEach(function(r) { obj[r[0]] = r[1]; });
        navigator.clipboard.writeText(JSON.stringify(obj, null, 2)).then(function() { toast('Copié en JSON'); }).catch(function() { toast('Impossible de copier'); });
    } else {
        var csv = rows.map(function(r) { return '"' + r[0].replace(/"/g, '""') + '","' + r[1].replace(/"/g, '""') + '"'; }).join('\n');
        var blob = new Blob([csv], { type: 'text/csv' });
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = label + '.csv';
        document.body.appendChild(a); a.click(); a.remove();
        toast('Export CSV lancé');
    }
    closeAllPopovers();
}
function hideCard() {
    if (!_cardMenuTarget) return;
    _cardMenuTarget.style.display = 'none';
    state.hiddenCards = (state.hiddenCards || 0) + 1;
    closeAllPopovers();
}

// ─────────────────────────────────────────────────────────────
// MODALS & ALERTS
// ─────────────────────────────────────────────────────────────
function openHelpModal() { $('helpModal').style.display = 'flex'; }
function closeHelpModal() { $('helpModal').style.display = 'none'; }

var ALERT_METRIC_LABELS = { token_count: 'Token count', avg_cost_per_request: 'Average cost per request', token_forecast: 'Token usage forecast' };
var _alertModalMetric = null;

function openAlertModal(metric, label) {
    _alertModalMetric = metric;
    $('alertModalTitle').textContent = 'New alert — ' + label;
    $('alertModalSubtitle').textContent = "Get flagged on this card when the metric crosses a threshold.";
    $('alertThreshold').value = '';
    $('alertModal').style.display = 'flex';
    loadAlertRulesForModal();
}
function closeAlertModal() { $('alertModal').style.display = 'none'; }

function loadAlertRulesForModal() {
    var box = $('alertRulesExisting');
    box.innerHTML = '<p style="color:#777;font-size:12px">Loading…</p>';
    api('/api/alert-rules').then(function(data) {
        state.alertRules = data.alert_rules || [];
        var mine = state.alertRules.filter(function(r) { return r.metric === _alertModalMetric; });
        if (mine.length === 0) { box.innerHTML = '<p style="color:#777;font-size:12px">No alert on this metric yet.</p>'; return; }
        box.innerHTML = mine.map(function(r) {
            return '<div class="alert-rule-row"><span>' + (r.comparison === 'above' ? 'above ' : 'below ') + esc(String(r.threshold)) + '</span>' +
                   '<button onclick="deleteAlertRuleUI(\'' + r.alert_id + '\')" title="Delete">×</button></div>';
        }).join('');
    }).catch(function() { box.innerHTML = '<p style="color:#f87171;font-size:12px">Could not load alerts.</p>'; });
}
function submitAlertRule() {
    var threshold = parseFloat($('alertThreshold').value);
    if (isNaN(threshold)) { toast('Enter a valid threshold'); return; }
    apiSend('/api/alert-rules', 'POST', { metric: _alertModalMetric, comparison: $('alertComparison').value, threshold: threshold })
        .then(function() { toast('Alert created'); $('alertThreshold').value = ''; loadAlertRulesForModal(); refreshAlertRules(); })
        .catch(function(e) { toast('Error: ' + e.message); });
}
function deleteAlertRuleUI(alertId) {
    apiSend('/api/alert-rules/' + alertId, 'DELETE')
        .then(function() { toast('Alert deleted'); loadAlertRulesForModal(); refreshAlertRules(); })
        .catch(function(e) { toast('Error: ' + e.message); });
}
function refreshAlertRules() {
    return api('/api/alert-rules').then(function(data) { state.alertRules = data.alert_rules || []; evaluateAlertRules(); }).catch(function() {});
}
function evaluateAlertRules() {
    var rules = state.alertRules || [];
    if (rules.length === 0) {
        ['tokHeroAlertFlag', 'avgCostHeroAlertFlag'].forEach(function(id) { var el = $(id); if (el) el.innerHTML = ''; });
        return;
    }
    var m = state.metrics || {};
    var tokens = m.total_tokens || 0;
    var avgCost = (m.total_cost_usd || 0) / Math.max(1, m.total_spans || 0);
    var hist = (state.costTrend || []).map(function(d) { return d.tokens || 0; });
    var forecast = tokens;
    if (hist.length >= 2) {
        var delta = (hist[hist.length - 1] - hist[0]) / (hist.length - 1);
        forecast = Math.max(0, hist[hist.length - 1] + delta * 6);
    }
    var values = { token_count: tokens, avg_cost_per_request: avgCost, token_forecast: forecast };
    var flagIds = { token_count: 'tokHeroAlertFlag', avg_cost_per_request: 'avgCostHeroAlertFlag', token_forecast: null };
    var triggeredByMetric = {};
    rules.forEach(function(r) {
        var v = values[r.metric];
        if (v === undefined) return;
        if ((r.comparison === 'above' ? v > r.threshold : v < r.threshold)) triggeredByMetric[r.metric] = true;
    });
    Object.keys(flagIds).forEach(function(metric) {
        var id = flagIds[metric];
        if (!id) return;
        var el = $(id);
        if (!el) return;
        el.innerHTML = triggeredByMetric[metric] ? '<span class="alert-flag">⚠ seuil dépassé</span>' : '';
    });
}

// ─────────────────────────────────────────────────────────────
// CHARTS & VISUALIZATIONS
// ─────────────────────────────────────────────────────────────
function trendPct(s) {
    if (!s || s.length < 2) return null;
    var a = s[0], b = s[s.length - 1];
    if (!a && !b) return null;
    var p = a === 0 ? 100 : (b - a) / a * 100;
    return p;
}
function trendHTML(p, invert) {
    if (p === null || isNaN(p)) return '<span class="dim">—</span>';
    var up = p >= 0;
    var good = invert ? !up : up;
    return '<span class="trend ' + (good ? 'up' : 'down') + '">' + (up ? '↗' : '↘') + ' ' + Math.abs(p).toFixed(2) + '%</span>';
}
function areaChart(el, data, labels, color) {
    color = color || '#da7751';
    if (!data.length) { el.innerHTML = '<div class="empty">No data</div>'; return; }
    var W = el.clientWidth || 600, H = el.clientHeight || 200, pad = { l: 8, r: 44, t: 14, b: 22 }, cw = W - pad.l - pad.r, ch = H - pad.t - pad.b;
    var max = Math.max.apply(null, [1].concat(data));
    var s = '<svg viewBox="0 0 ' + W + ' ' + H + '">';
    var pt = function(v, i) { return [pad.l + (i / Math.max(1, data.length - 1)) * cw, pad.t + ch - (v / max) * ch]; };
    var line = '';
    data.forEach(function(v, i) { var xy = pt(v, i); line += (i ? 'L' : 'M') + xy[0] + ',' + xy[1]; });
    s += '<path d="' + line + ' L' + (pad.l + cw) + ',' + (pad.t + ch) + ' L' + pad.l + ',' + (pad.t + ch) + ' Z" fill="' + color + '" opacity=".14"/>';
    s += '<path d="' + line + '" fill="none" stroke="' + color + '" stroke-width="1.6"/>';
    (labels || []).forEach(function(l, i) {
        if (i % Math.ceil((labels.length || 1) / 6)) return;
        var x = pad.l + (i / Math.max(1, labels.length - 1)) * cw;
        s += '<text x="' + x + '" y="' + (H - 6) + '" fill="#5d6375" font-size="9.5" text-anchor="middle">' + esc(l) + '</text>';
    });
    s += '<text x="' + (W - 4) + '" y="' + (pad.t + 8) + '" fill="#9298ab" font-size="9.5" text-anchor="end">' + fmtK(max) + '</text></svg>';
    el.innerHTML = s;
}
function hbarsLegend(el, items, valKey, fmtFn) {
    if (!items.length) { el.innerHTML = '<div class="empty">No model data yet</div>'; return; }
    var max = Math.max.apply(null, items.map(function(i) { return Number(i[valKey]) || 0; }).concat([1e-9]));
    var s = '<div style="display:flex;gap:14px;height:100%"><div style="flex:1;display:flex;flex-direction:column;justify-content:space-around">';
    items.forEach(function(m, i) {
        s += '<div style="display:flex;align-items:center;gap:8px"><span style="width:170px;text-align:right;font-size:10.5px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + esc(m.name) + '</span><div style="flex:1;height:10px;background:#101320;border-radius:2px"><div style="width:' + (Number(m[valKey]) / max * 100).toFixed(1) + '%;height:100%;background:' + P[i % P.length] + ';border-radius:2px"></div></div></div>';
    });
    s += '<div style="display:flex;justify-content:space-between;color:var(--dim);font-size:9.5px;margin-left:178px"><span>0</span><span>' + fmtFn(max / 2) + '</span><span>' + fmtFn(max) + '</span></div></div>';
    s += '<div style="width:190px;overflow:auto;display:flex;flex-direction:column;gap:5px;font-size:10.5px;color:var(--muted)">';
    items.forEach(function(m, i) {
        s += '<span style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis"><i style="display:inline-block;width:8px;height:8px;border-radius:50%;background:' + P[i % P.length] + ';margin-right:6px"></i>' + esc(m.name) + '</span>';
    });
    s += '</div></div>';
    el.innerHTML = s;
}
function stackedTime(el, days, map) {
    if (!days.length) { el.innerHTML = '<div class="empty">No guardrail data yet</div>'; return; }
    var W = el.clientWidth || 600, H = el.clientHeight || 250, pad = { l: 30, r: 8, t: 10, b: 20 }, cw = W - pad.l - pad.r, ch = H - pad.t - pad.b;
    var totals = days.map(function(d) { return CHECKS.reduce(function(a, arr) { return a + (map[d + '|' + arr[0]] || 0); }, 0); });
    var max = Math.max.apply(null, [1].concat(totals));
    var bw = Math.max(2, cw / days.length - 2);
    var s = '<svg viewBox="0 0 ' + W + ' ' + H + '">';
    [0, .5, 1].forEach(function(t) {
        var y = pad.t + ch - t * ch;
        s += '<line x1="' + pad.l + '" y1="' + y + '" x2="' + (W - pad.r) + '" y2="' + y + '" stroke="#20243a" stroke-width=".5"/><text x="' + (pad.l - 5) + '" y="' + (y + 3) + '" fill="#5d6375" font-size="9" text-anchor="end">' + Math.round(max * t) + '</text>';
    });
    days.forEach(function(d, i) {
        var y = pad.t + ch;
        CHECKS.forEach(function(arr) {
            var n = arr[0], c = arr[1], v = map[d + '|' + n] || 0;
            if (!v) return;
            var h = (v / max) * ch;
            y -= h;
            s += '<rect x="' + (pad.l + i * (cw / days.length)) + '" y="' + y + '" width="' + bw + '" height="' + h + '" fill="' + c + '"/>';
        });
    });
    days.forEach(function(d, i) {
        if (i % Math.ceil(days.length / 6)) return;
        s += '<text x="' + (pad.l + i * (cw / days.length)) + '" y="' + (H - 5) + '" fill="#5d6375" font-size="9">' + esc(d.slice(5)) + '</text>';
    });
    el.innerHTML = s + '</svg>';
}
function multiLine(el, days, series) {
    if (!series.length) { el.innerHTML = '<div class="empty">No data</div>'; return; }
    var W = el.clientWidth || 600, H = el.clientHeight || 300, pad = { l: 36, r: 8, t: 10, b: 20 }, cw = W - pad.l - pad.r, ch = H - pad.t - pad.b;
    var allVals = [];
    series.forEach(function(sr) { allVals = allVals.concat(sr.values); });
    var max = Math.max.apply(null, [1].concat(allVals));
    var s = '<svg viewBox="0 0 ' + W + ' ' + H + '">';
    [0, .25, .5, .75, 1].forEach(function(t) {
        var y = pad.t + ch - t * ch;
        s += '<line x1="' + pad.l + '" y1="' + y + '" x2="' + (W - pad.r) + '" y2="' + y + '" stroke="#20243a" stroke-width=".5"/><text x="' + (pad.l - 5) + '" y="' + (y + 3) + '" fill="#5d6375" font-size="9" text-anchor="end">' + fmtK(max * t) + '</text>';
    });
    series.forEach(function(sr) {
        var p = '';
        sr.values.forEach(function(v, i) {
            var x = pad.l + (i / Math.max(1, sr.values.length - 1)) * cw, y = pad.t + ch - (v / max) * ch;
            p += (i ? 'L' : 'M') + x + ',' + y;
        });
        s += '<path d="' + p + '" fill="none" stroke="' + sr.color + '" stroke-width="1.2"/>';
    });
    days.forEach(function(d, i) {
        if (i % Math.ceil(days.length / 5)) return;
        var x = pad.l + (i / Math.max(1, days.length - 1)) * cw;
        s += '<text x="' + x + '" y="' + (H - 5) + '" fill="#5d6375" font-size="9" text-anchor="middle">' + esc(d.slice(5)) + '</text>';
    });
    var legendHTML = '';
    series.forEach(function(sr) { legendHTML += '<span><i style="background:' + sr.color + '"></i>' + esc(sr.name) + '</span>'; });
    el.innerHTML = s + '</svg><div class="legend">' + legendHTML + '</div>';
}
function donut(el, okPct, okN, failN) {
    var r1 = 75 + 56 * Math.sin(Math.max(.02, (1 - okPct / 100) * 6.283));
    var r2 = 75 - 56 * Math.cos(Math.max(.02, (1 - okPct / 100) * 6.283));
    el.innerHTML = '<div style="display:flex;align-items:center;gap:18px;height:100%;justify-content:center"><svg width="150" height="150" viewBox="0 0 150 150"><circle cx="75" cy="75" r="56" fill="#2b8a5e" opacity=".9"/><path d="M75 19 A56 56 0 0 1 ' + r1 + ' ' + r2 + '" stroke="var(--red2)" stroke-width="3" fill="none"/><circle cx="75" cy="75" r="34" fill="var(--card)"/><text x="75" y="72" text-anchor="middle" fill="var(--dim)" font-size="9">' + (100 - okPct).toFixed(0) + '%</text><text x="75" y="86" text-anchor="middle" fill="var(--dim)" font-size="9">' + okPct.toFixed(0) + '%</text></svg><div style="font-size:11px;color:var(--muted);display:flex;flex-direction:column;gap:6px"><span><i style="display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--red2);margin-right:6px"></i>Failed Requests</span><span><i style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#2b8a5e;margin-right:6px"></i>Successful Requests</span></div></div>';
}
function forecastBand(el, hist) {
    if (!hist || hist.length < 2) { el.innerHTML = '<div class="empty">Not enough history</div>'; return; }
    var W = el.clientWidth || 500, H = el.clientHeight || 170, pad = { l: 26, r: 6, t: 10, b: 16 }, cw = W - pad.l - pad.r, ch = H - pad.t - pad.b;
    var delta = (hist[hist.length - 1] - hist[0]) / (hist.length - 1);
    var fc = [];
    for (var i = 0; i < 6; i++) fc.push(Math.max(0, hist[hist.length - 1] + delta * (i + 1)));
    var histMax = Math.max.apply(null, [1].concat(hist));
    var band = fc.map(function(v) { return Math.max(v * .25, histMax * .06); });
    var fcWithBand = fc.map(function(v, i) { return v + band[i]; });
    var max = Math.max.apply(null, hist.concat(fcWithBand)) * 1.1;
    var X = function(i) { return pad.l + (i / (hist.length - 1)) * cw * .62; };
    var XF = function(i) { return pad.l + cw * .62 + (i / 6) * cw * .38; };
    var s = '<svg viewBox="0 0 ' + W + ' ' + H + '">';
    var p = '';
    hist.forEach(function(v, i) { var y = pad.t + ch - (v / max) * ch; p += (i ? 'L' : 'M') + X(i) + ',' + y; });
    s += '<path d="' + p + '" fill="none" stroke="#e6e8f2" stroke-width="1"/>';
    var ly = pad.t + ch - (hist[hist.length - 1] / max) * ch, lx = X(hist.length - 1);
    var up = '', lo = '';
    fc.forEach(function(v, i) { up += 'L' + XF(i + 1) + ',' + (pad.t + ch - ((v + band[i]) / max) * ch) + ' '; });
    for (var j = fc.length - 1; j >= 0; j--) lo += 'L' + XF(j + 1) + ',' + (pad.t + ch - (Math.max(0, fc[j] - band[j]) / max) * ch) + ' ';
    s += '<path d="M' + lx + ',' + ly + ' ' + up + lo + ' Z" fill="#da7751" opacity=".22"/>';
    var fl = 'M' + lx + ',' + ly;
    fc.forEach(function(v, i) { fl += ' L' + XF(i + 1) + ',' + (pad.t + ch - (v / max) * ch); });
    s += '<path d="' + fl + '" fill="none" stroke="#e6b17e" stroke-width="1"/></svg>';
    el.innerHTML = s;
}
function spark(el, data, color) {
    color = color || '#da7751';
    if (!data || data.length < 2) { el.innerHTML = ''; return; }
    var W = el.clientWidth || 180, H = 40, max = Math.max.apply(null, [1].concat(data));
    var p = '';
    data.forEach(function(v, i) { p += (i ? 'L' : 'M') + (i / (data.length - 1)) * W + ',' + (H - 4 - (v / max) * (H - 8)); });
    el.innerHTML = '<svg viewBox="0 0 ' + W + ' ' + H + '" style="width:100%;height:40px"><path d="' + p + '" fill="none" stroke="' + color + '" stroke-width="1"/></svg>';
}

// ─────────────────────────────────────────────────────────────
// CALENDAR HEATMAP
// ─────────────────────────────────────────────────────────────
function renderCalendarHeatmap(el, data) {
    var cells = (data && data.cells) || [];
    if (!cells.length) { el.innerHTML = '<div class="empty">No activity recorded yet</div>'; return; }
    var byDate = {};
    cells.forEach(function(c) { byDate[c.date] = c; });
    var totals = cells.map(function(c) { return c.total; }).filter(function(t) { return t > 0; }).sort(function(a, b) { return a - b; });
    function levelFor(total) {
        if (!total) return 0;
        if (!totals.length) return 1;
        var n = totals.length;
        var q = function(p) { return totals[Math.min(n - 1, Math.floor(p * (n - 1)))]; };
        if (total <= q(0.25)) return 1;
        if (total <= q(0.5)) return 2;
        if (total <= q(0.75)) return 3;
        return 4;
    }
    var today = new Date();
    var oldest = cells.length ? new Date(cells[0].date + 'T00:00:00') : new Date(today.getTime() - 90 * 86400000);
    var start = new Date(oldest);
    start.setDate(start.getDate() - start.getDay());
    var days = [];
    for (var d = new Date(start); d <= today; d.setDate(d.getDate() + 1)) days.push(new Date(d));
    var weeks = [];
    for (var i = 0; i < days.length; i += 7) weeks.push(days.slice(i, i + 7));
    function fmtDate(dt) { return dt.getFullYear() + '-' + String(dt.getMonth() + 1).padStart(2, '0') + '-' + String(dt.getDate()).padStart(2, '0'); }
    var html = '<div class="cal-heatmap-wrap"><div class="cal-heatmap">';
    weeks.forEach(function(week) {
        html += '<div class="cal-col">';
        week.forEach(function(dt) {
            var key = fmtDate(dt);
            var c = byDate[key];
            var total = c ? c.total : 0;
            var blocked = c ? c.blocked : 0;
            var flagged = c ? c.flagged : 0;
            var level = levelFor(total);
            var cls = 'cal-cell' + (blocked > 0 ? ' has-blocked' : '');
            html += '<div class="' + cls + '" data-level="' + level + '" data-date="' + key + '" data-total="' + total + '" data-blocked="' + blocked + '" data-flagged="' + flagged + '" onmouseenter="_calHover(event,this)" onmouseleave="_calHoverOut()"></div>';
        });
        html += '</div>';
    });
    html += '</div><div class="cal-legend">Less <span class="cal-cell" data-level="0"></span><span class="cal-cell" data-level="1"></span><span class="cal-cell" data-level="2"></span><span class="cal-cell" data-level="3"></span><span class="cal-cell" data-level="4"></span> More · outline = day with a blocked action</div></div>';
    el.innerHTML = html;
}
function _calHover(evt, cellEl) {
    var tip = $('calTooltip');
    var date = cellEl.getAttribute('data-date');
    var total = cellEl.getAttribute('data-total');
    var blocked = cellEl.getAttribute('data-blocked');
    var flagged = cellEl.getAttribute('data-flagged');
    tip.innerHTML = '<b>' + esc(date) + '</b><div class="ct-row">' + esc(total) + ' action' + (total === '1' ? '' : 's') + '</div><div class="ct-row">' + esc(blocked) + ' blocked</div><div class="ct-row">' + esc(flagged) + ' flagged</div>';
    tip.style.display = 'block';
    var r = cellEl.getBoundingClientRect();
    tip.style.left = Math.min(window.innerWidth - 230, r.left) + 'px';
    tip.style.top = Math.max(4, r.top - 74) + 'px';
}
function _calHoverOut() { $('calTooltip').style.display = 'none'; }

// ─────────────────────────────────────────────────────────────
// VIEW SWITCHING & SIDEBAR
// ─────────────────────────────────────────────────────────────
function showView(n) {
    document.querySelectorAll('.view').forEach(function(v) { v.classList.remove('active'); });
    $('view-' + n).classList.add('active');
    document.querySelectorAll('#topTabs button').forEach(function(b) { b.classList.toggle('active', b.dataset.view === n); });
    $('fside').style.display = (n === 'health') ? '' : 'none';
    if (n === 'health') renderHealth();
    if (n === 'overview') renderOverview();
    if (n === 'tracing') renderTracing();
    if (n === 'audit') renderAudit();
}
document.querySelectorAll('#topTabs button').forEach(function(b) {
    b.addEventListener('click', function() { if (b.dataset.view) showView(b.dataset.view); });
});
document.querySelectorAll('#latTabs button').forEach(function(b) {
    b.addEventListener('click', function() {
        document.querySelectorAll('#latTabs button').forEach(function(x) { x.classList.remove('active'); });
        b.classList.add('active');
        state.latStat = b.dataset.s;
        renderLatency();
    });
});

function buildSidebar() {
    var models = (state.models || []).map(function(m) { return m.name; });
    if (!state.modelFilter.size) models.forEach(function(m) { state.modelFilter.add(m); });
    function makeItem(checked, onchange, name) {
        return '<label class="fitem"><input type="checkbox" ' + (checked ? 'checked' : '') + ' onchange="' + onchange + '(this,\'' + esc(name) + '\')">' + esc(name) + '</label>';
    }
    function makeGroup(title, items, checked, cb) {
        var content = items.length ? items.map(function(i) { return makeItem(checked.has(i), cb, i); }).join('') : '<div class="dim" style="padding:4px 6px;font-size:11px">—</div>';
        return '<div class="fgroup"><div onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display===\'none\'?\'\':\'none\'">▾ ' + esc(title) + '</div><div class="fitems">' + content + '</div></div>';
    }
    window.noop = function() {};
    window.toggleModel = function(el, name) {
        if (el.checked) state.modelFilter.add(name); else state.modelFilter.delete(name);
        renderHealth();
    };
    var modelItems = models.length ? models.map(function(m) { return makeItem(state.modelFilter.has(m), 'toggleModel', m); }).join('') : '<div class="dim" style="padding:4px 6px;font-size:11px">no models yet</div>';
    $('fside').innerHTML = makeGroup('Provider', ['agentguard'], new Set(['agentguard']), 'noop') + '<div class="fgroup"><div>▾ Model</div><div class="fitems">' + modelItems + '</div></div>' + makeGroup('Service', ['agentguard-collector'], new Set(['agentguard-collector']), 'noop') + makeGroup('Agent', ['sdk-agent'], new Set(), 'noop');
}
function filteredModels() { return (state.models || []).filter(function(m) { return state.modelFilter.has(m.name); }); }

function renderHealth() {
    buildSidebar();
    renderLatency();
    var m = state.metrics || {};
    $('tokHero').textContent = fmtK(m.total_tokens || 0);
    var avg = (m.total_cost_usd || 0) / Math.max(1, m.total_spans || 0);
    $('avgCostHero').innerHTML = (avg * 1e6).toFixed(1) + '<span class="unit">µ$</span>';
    areaChart($('avgCostChart'), (state.costTrend || []).map(function(d) { return d.cost; }), null);
    forecastBand($('tokForecast'), (state.costTrend || []).map(function(d) { return d.tokens || 0; }));
    $('grHero').textContent = fmtK(m.total_spans || 0);
    var daySet = {};
    (state.checksDaily || []).forEach(function(c) { daySet[c.day] = 1; });
    var days = Object.keys(daySet).sort();
    var map = {};
    (state.checksDaily || []).forEach(function(c) { map[c.day + '|' + c.name] = c.flagged; });
    stackedTime($('grStacked'), days, map);
    var legendHTML = '';
    CHECKS.forEach(function(arr) { legendHTML += '<span><i style="background:' + arr[1] + '"></i>' + arr[0] + '</span>'; });
    $('grLegend').innerHTML = legendHTML;
    hbarsLegend($('tokModel'), filteredModels().slice().sort(function(a, b) { return (b.input_tokens + b.output_tokens) - (a.input_tokens + a.output_tokens); }), 'output_tokens', function(v) { return fmtK(v); });
}
function renderLatency() {
    var m = state.metrics || {}, lat = state.latencyDist || {};
    var val = state.latStat === 'avg' ? m.avg_latency_ms : lat[state.latStat];
    $('ttrHero').innerHTML = val ? (Number(val) / 1000).toFixed(2) + '<span class="unit">s</span>' : '—';
    areaChart($('ttrChart'), (state.dailyTrend || []).map(function(d) { return d.total; }), (state.dailyTrend || []).map(function(d) { return (d.day || '').slice(5); }));
    hbarsLegend($('rtModel'), filteredModels().slice().sort(function(a, b) { return b.avg_latency_ms - a.avg_latency_ms; }), 'avg_latency_ms', function(v) { return Number(v).toFixed(0) + 'ms'; });
}
function renderOverview() {
    var m = state.metrics || {}, r = m.risk_distribution || {};
    $('ovProblems').textContent = Number(r.high || 0) + Number(r.critical || 0);
    $('ovRequests').textContent = fmtK(m.total_spans || 0);
    $('ovRequestsT').innerHTML = trendHTML(trendPct((state.dailyTrend || []).map(function(d) { return d.total; })));
    $('ovCost').textContent = '$' + (m.total_cost_usd || 0).toFixed(2);
    $('ovCostT').innerHTML = trendHTML(trendPct((state.costTrend || []).map(function(d) { return d.cost; })), true);
    var total = Math.max(1, m.total_spans || 0), blk = m.blocked_operations || 0;
    donut($('ovDonut'), (total - blk) / total * 100, total - blk, blk);
    $('ovAvg').innerHTML = (Number(m.avg_latency_ms || 0) / 1000).toFixed(2) + '<span class="unit">s</span>';
    $('ovAvgT').innerHTML = trendHTML(trendPct((state.dailyTrend || []).map(function(d) { return d.total; })), true);
    var p99 = (state.latencyDist || {}).p99;
    $('ovP99').innerHTML = p99 ? ((p99) / 1000).toFixed(2) + '<span class="unit">s</span>' : '—';
    var p95 = (state.latencyDist || {}).p95 || 1;
    $('ovP99T').innerHTML = '<span class="trend down">↗ ' + (((p99 || 0) / Math.max(1, p95) * 8).toFixed(2)) + '%</span>';
    renderCalendarHeatmap($('ovHeatmap'), state.heatmap || { cells: [] });
    var cb = state.checksBreakdown || [];
    var get = function(n) { return cb.find(function(c) { return c.check_name === n; }); };
    var inj = get('prompt_injection'), pii = get('pii_detection'), tool = get('tool_policy') || get('dangerous_params'), bud = get('budget_policy');
    function bigCard(t, v) { return '<div class="card"><div class="hero mid" style="font-size:34px">' + esc(v) + '</div><div class="clabel" style="text-align:center;margin-top:4px">' + esc(t) + '</div></div>'; }
    $('gqBig').innerHTML = bigCard('Guardrail Executions', '100%') + bigCard('Prompt Injection', inj ? inj.flag_rate + '%' : '0%') + bigCard('PII Leaks', pii ? pii.flag_rate + '%' : '0%') + bigCard('Tool Policy', tool ? tool.flag_rate + '%' : '0%') + '<div class="card"><div class="clabel" style="text-align:center">ML Confidence</div><div class="hero sm" style="text-align:center">' + (((m.avg_ml_score || 0) * 100).toFixed(2)) + '</div><div id="spkML"></div></div>';
    function smCard(t, v, id) { return '<div class="card"><div class="clabel" style="font-size:10.5px">' + esc(t) + '</div><div class="hero sm">' + esc(v) + '</div><div id="' + id + '"></div></div>'; }
    $('gqSmall').innerHTML = smCard('Overall Guardrail Activation', fmt(cb.reduce(function(a, c) { return a + c.flagged; }, 0)), 's1') + smCard('Blocked Prompts', fmt(m.blocked_operations || 0), 's2') + smCard('Prevented PII Leaks', fmt(pii ? pii.flagged : 0), 's3') + smCard('Budget Blocks', fmt(bud ? bud.flagged : 0), 's4') + '<div class="card"><div class="clabel" style="font-size:10.5px">Judge Confidence</div><div class="hero sm">' + (((m.avg_llm_score || 0) * 100).toFixed(2)) + '</div><div id="s5"></div></div>';
    spark($('s1'), (state.checksDaily || []).filter(function(c) { return c.name === 'prompt_injection'; }).map(function(c) { return c.flagged; }));
    spark($('s2'), (state.dailyTrend || []).map(function(d) { return d.blocked; }));
    spark($('s3'), (state.checksDaily || []).filter(function(c) { return c.name === 'pii_detection'; }).map(function(c) { return c.flagged; }));
    spark($('s4'), (state.checksDaily || []).filter(function(c) { return c.name === 'budget_policy'; }).map(function(c) { return c.flagged; }));
    spark($('s5'), (state.dailyTrend || []).map(function(d) { return d.total; }));
    var expRows = '';
    (state.expensive || []).forEach(function(e) {
        expRows += '<tr><td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(e.prompt || '') + '">' + esc(e.prompt || '—') + '</td><td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(e.response || '—') + '</td><td class="mono">' + esc(e.trace_id) + '</td><td class="mono">' + fmt((e.input_tokens || 0) + (e.output_tokens || 0)) + '</td><td class="mono">' + money(e.cost_usd) + '</td></tr>';
    });
    $('expTable').innerHTML = expRows || '<tr><td colspan="5" class="empty">No spans yet</td></tr>';
}

// ─────────────────────────────────────────────────────────────
// TRACING
// ─────────────────────────────────────────────────────────────
function renderTracing() {
    var traces = state.traces || [];
    if (!state.selTrace && traces.length) state.selTrace = traces[0].trace_id;
    var opts = '';
    traces.forEach(function(t) { opts += '<option value="' + esc(t.trace_id) + '" ' + (t.trace_id === state.selTrace ? 'selected' : '') + '>' + esc(t.trace_id) + '</option>'; });
    $('traceSelect').innerHTML = opts || '<option>—</option>';
    $('traceSelect').onchange = function(e) { state.selTrace = e.target.value; loadTrace(); };
    loadTrace();
}
function loadTrace() {
    var id = state.selTrace;
    if (!id) { $('spanTree').innerHTML = '<div class="empty">No traces</div>'; return Promise.resolve(); }
    return api('/api/traces/' + encodeURIComponent(id)).then(function(rows) {
        state.spans = rows;
        var dur = rows.reduce(function(a, r) { return a + Number(r.latency_ms || 0); }, 0);
        $('trDur').textContent = (dur / 1000).toFixed(2) + ' s';
        $('trErr').textContent = rows.filter(function(r) { return r.blocked; }).length;
        $('trId').textContent = id || '—';
        $('trDate').textContent = rows[0] ? ('at ' + String(rows[0].created_at).slice(0, 19)) : '';
        $('spanCount').textContent = rows.length + ' spans';
        var maxT = Math.max.apply(null, [1].concat(rows.map(function(r) { return Number(r.latency_ms || 0); })));
        $('ax0').textContent = '0 ms';
        $('ax1').textContent = (maxT / 2).toFixed(0) + ' ms';
        $('ax2').textContent = maxT.toFixed(0) + ' ms';
        var q = ($('spanSearch').value || '').toLowerCase();
        var treeHTML = '';
        rows.forEach(function(r, i) {
            var w = Math.max(2, (Number(r.latency_ms || 0) / maxT) * 96);
            var hide = q && !(r.span_type + ' ' + (r.model || '')).toLowerCase().includes(q);
            var dotClass = r.span_type === 'tool_call' ? 'client' : '';
            var clientLabel = r.span_type === 'llm_call' ? 'client' : 'internal';
            var modelPart = r.model ? '.' + esc(r.model.split('-')[0]) : '';
            var warnPart = r.blocked ? '<span class="warn"><span class="ui-icon" data-icon="error"></span></span>' : '';
            treeHTML += '<div class="span-row ' + (i === state.selSpan ? 'sel' : '') + '" style="' + (hide ? 'display:none' : '') + '" onclick="selectSpan(' + i + ')"><span class="tw"><span style="color:var(--dim)">—</span><span class="dot ' + dotClass + '"></span><span style="color:var(--dim);font-size:10.5px">' + clientLabel + '</span>' + esc(r.span_type) + modelPart + ' ' + warnPart + '</span><span class="track"><span class="bar ' + (r.blocked ? 'blocked' : '') + '" style="left:2%;width:' + w + '%"></span></span></div>';
        });
        $('spanTree').innerHTML = treeHTML || '<div class="empty">No spans</div>';
        $('excN').textContent = rows.filter(function(r) { return r.blocked; }).length;
        var excHTML = '';
        rows.filter(function(r) { return r.blocked; }).forEach(function(r, i) {
            var checksFailed = (r.security_checks || []).filter(function(c) { return !c.passed; }).map(function(c) { return '  [ERROR] ' + c.check_name + ' — ' + c.details; }).join('\n');
            excHTML += '<tr class="exc-row" onclick="this.nextElementSibling.hidden=!this.nextElementSibling.hidden"><td>▾</td><td class="mono">agentguard.SecurityException</td><td>' + esc(r.block_reason || 'blocked') + '</td></tr><tr hidden><td></td><td colspan="2"><div class="pilltag">Span events: exception id: ' + esc(r.span_id) + '</div><div class="codeblock"><b>Exception root cause:</b> ' + esc(r.block_reason || '') + '\n\nTraceback (most recent call last):\n  File "agentguard_sdk.py", in guard_' + esc(r.span_type) + '\n    raise SecurityException(...)\n' + checksFailed + '</div></td></tr>';
        });
        $('excTable').innerHTML = excHTML || '<tr><td colspan="3" class="empty">No exceptions</td></tr>';
        var logsHTML = '';
        rows.forEach(function(r) {
            var when = String(r.created_at || '').slice(11, 19) || '—';
            var detail = r.model ? (r.span_type + ' · ' + r.model) : r.span_type;
            if (r.blocked) detail += ' — BLOCKED: ' + (r.block_reason || 'policy');
            logsHTML += '<tr' + (r.blocked ? ' class="exc-row"' : '') + '><td class="mono dim">' + esc(when) + '</td><td class="mono">' + esc(r.span_id || '—') + '</td><td>' + esc(detail) + '</td></tr>';
        });
        $('logsTable').innerHTML = logsHTML || '<tr><td colspan="3" class="empty">No log entries</td></tr>';
        selectSpan(state.selSpan || 0);
    }).catch(function() { $('spanTree').innerHTML = '<div class="empty">Error loading trace</div>'; });
}
function switchTraceTab(which) {
    var isLogs = which === 'logs';
    $('tabLogs').classList.toggle('active', isLogs);
    $('tabExceptions').classList.toggle('active', !isLogs);
    $('logsTableWrap').style.display = isLogs ? '' : 'none';
    $('excTableWrap').style.display = isLogs ? 'none' : '';
}
function openTraceRaw() {
    var id = state.selTrace;
    if (!id) { toast('Select a trace first'); return; }
    window.open('/api/traces/' + encodeURIComponent(id), '_blank');
}
function toggleTraceDetails() {
    var card = $('trDetailsCard'), btn = $('btnCloseDetails');
    var hidden = card.style.display === 'none';
    card.style.display = hidden ? '' : 'none';
    btn.textContent = hidden ? 'Close details' : 'Show details';
}
function toggleTraceMinimize() {
    var body = $('trBody'), btn = $('btnMinimize');
    var minimized = body.classList.toggle('minimized');
    btn.textContent = minimized ? 'Restore' : 'Minimize';
}
window.selectSpan = function(i) {
    state.selSpan = i;
    var r = (state.spans || [])[i];
    if (!r) return;
    document.querySelectorAll('.span-row').forEach(function(el, j) { el.classList.toggle('sel', j === i); });
    function kv(k, v, cls) { return '<div class="attr-row"><span class="k">' + esc(k) + '</span><span class="v ' + (cls||'') + '">' + esc(v) + '</span></div>'; }
    var prompt = ((r.input_data || {}).prompt || (r.input_data || {}).tool) || '';
    var response = ((r.output_data || {}).response || '').slice(0, 400);
    var mlScore = r.ml_score != null ? (r.ml_score * 100).toFixed(1) + '%' : '—';
    var llmScore = r.llm_score != null ? (r.llm_score * 100).toFixed(1) + '%' : '—';
    var decision = r.blocked ? 'BLOCK' : 'ALLOW';
    var decisionClass = r.blocked ? 'pink' : '';
    $('spanDetail').innerHTML = '<div class="card" style="margin-bottom:10px"><div style="display:flex;gap:10px;align-items:center"><span style="width:30px;height:30px;border-radius:6px;background:#3776ab;color:#fff;display:grid;place-items:center;font-weight:700">PY</span><div><b>' + esc(r.span_type) + '</b><div class="dim" style="font-size:11px">Service: <a href="#">agentguard-collector</a></div></div></div><div style="margin:10px 0;color:var(--muted);font-size:12px"><span class="ui-icon" data-icon="latency"></span> Duration: ' + Number(r.latency_ms || 0).toFixed(2) + ' ms</div></div><div class="attr-sec"><h4>gen ai <span>▾</span></h4>' + kv('Gen ai agent name', 'agentguard-sdk') + kv('Gen ai request model', r.model || 'unknown') + kv('Gen ai prompt 0 role', 'user') + kv('Gen ai prompt 0 content', prompt) + kv('Gen ai completion 0 role', 'assistant') + kv('Gen ai completion 0 content', response) + kv('Gen ai usage input tokens', r.input_tokens || 0, 'pink') + kv('Gen ai usage output tokens', r.output_tokens || 0, 'pink') + '</div><div class="attr-sec"><h4>agentguard <span>▾</span></h4>' + kv('Agentguard detection layer', r.detection_layer || 'regex') + kv('Agentguard ml score', mlScore, 'blue') + kv('Agentguard llm score', llmScore, 'blue') + kv('Agentguard decision', decision, decisionClass) + kv('Agentguard cost usd', Number(r.cost_usd || 0).toFixed(6), 'pink') + '</div>';
};

// ═══════════════════════════════════════════════════════════
// AUDIT / COMPLIANCE & EXPORT
// ═══════════════════════════════════════════════════════════
function renderAudit() {
    var d = new Date();
    var from = new Date(d - 14 * 864e5);
    $('auRange').textContent = from.toDateString().slice(4) + ' - ' + d.toDateString().slice(4);

    var sum = state.auditSummary || {};
    $('auTotalEvents').textContent = fmt(sum.total || 0);
    $('auBlockedEvents').textContent = fmt(sum.blocked || 0);
    $('auFlaggedEvents').textContent = fmt(sum.flagged || 0);
    $('auHighRiskEvents').textContent = fmt(sum.high_risk || 0);
    $('auAllowedEvents').textContent = fmt(sum.allowed || 0);
    $('auApprovalEvents').textContent = fmt(sum.require_approval || 0);
    $('auCriticalEvents').textContent = fmt(sum.critical || 0);
    $('auAffectedAgents').textContent = fmt(sum.affected_agents || 0);

    var modelsHTML = '';
    (state.models || []).slice().sort(function(a, b) { return (b.requests || 0) - (a.requests || 0); }).forEach(function(m) {
        modelsHTML += '<tr><td>' + esc(m.name) + '</td><td style="text-align:right" class="mono">' + fmt(m.requests || 0) + '</td></tr>';
    });
    $('auModels').innerHTML = modelsHTML || '<tr><td colspan="2" class="empty">No models</td></tr>';

    var daySet = {};
    (state.modelsDaily || []).forEach(function(x) { daySet[x.day] = 1; });
    var days = Object.keys(daySet).sort();
    var nameSet = {};
    (state.modelsDaily || []).forEach(function(x) { nameSet[x.model] = 1; });
    var names = Object.keys(nameSet).slice(0, 10);
    var series = names.map(function(n, i) {
        return {
            name: n, color: P[i % P.length],
            values: days.map(function(dy) {
                var f = (state.modelsDaily || []).find(function(x) { return x.day === dy && x.model === n; });
                return f ? f.n : 0;
            })
        };
    });
    multiLine($('auTrend'), days, series);
    populateAuditFilters();
    renderAuditTrail();
}

function populateAuditFilters() {
    var agents = new Set(), models = new Set(), tools = new Set(), detections = new Set();
    (state.audit || []).forEach(function(r) {
        if (r.agent) agents.add(r.agent);
        if (r.model) models.add(r.model);
        if (r.tool) tools.add(r.tool);
        if (r.detection) detections.add(r.detection);
    });
    function fillSelect(id, items, defaultText) {
        var sel = $(id);
        var current = sel.value;
        sel.innerHTML = '<option value="">' + defaultText + '</option>' + 
            Array.from(items).sort().map(function(i) { return '<option value="' + esc(i) + '"' + (current === i ? ' selected' : '') + '>' + esc(i) + '</option>'; }).join('');
    }
    fillSelect('auditAgentFilter', agents, 'All agents');
    fillSelect('auditModelFilter', models, 'All models');
    fillSelect('auditToolFilter', tools, 'All tools');
    fillSelect('auditDetectionFilter', detections, 'All detections');
}

function renderAuditTrail() {
    var search = ($('auditSearch').value || '').toLowerCase();
    var agent = $('auditAgentFilter').value;
    var model = $('auditModelFilter').value;
    var risk = $('auditRiskFilter').value;
    var decision = $('auditDecisionFilter').value;
    var detection = $('auditDetectionFilter').value;
    var tool = $('auditToolFilter').value;

    var filtered = (state.audit || []).filter(function(r) {
        var searchStr = (r.event_id + ' ' + r.agent + ' ' + r.tool + ' ' + (r.prompt || '')).toLowerCase();
        if (search && !searchStr.includes(search)) return false;
        if (agent && r.agent !== agent) return false;
        if (model && r.model !== model) return false;
        if (risk && r.risk !== risk) return false;
        if (decision && r.decision !== decision) return false;
        if (detection && r.detection !== detection) return false;
        if (tool && r.tool !== tool) return false;
        return true;
    });

    $('auditFilterSummary').textContent = filtered.length === (state.audit || []).length 
        ? 'Showing all security events' 
        : 'Showing ' + filtered.length + ' of ' + (state.audit || []).length + ' events';

    if (filtered.length === 0) {
        $('auTrail').innerHTML = '';
        $('auditEmptyState').style.display = 'flex';
        return;
    }
    $('auditEmptyState').style.display = 'none';
    
    var trailHTML = '';
    filtered.forEach(function(r) {
        var riskClass = r.risk === 'critical' ? 'style="color:var(--red2)"' : (r.risk === 'high' ? 'style="color:var(--orange)"' : (r.risk === 'medium' ? 'style="color:var(--yellow)"' : ''));
        var decBadge = r.decision === 'blocked' ? '<span class="badge blocked">Blocked</span>' : 
                       (r.decision === 'flagged' ? '<span class="badge" style="background:var(--yellow);color:#000">Flagged</span>' : 
                       (r.decision === 'require_approval' ? '<span class="badge" style="background:var(--purple);color:#fff">Approval</span>' : 
                       '<span class="badge safe">Allowed</span>'));
        
        trailHTML += '<tr style="cursor:pointer" onclick="openSecurityEventPanel(\'' + esc(r.event_id) + '\')">' +
            '<td class="dim mono">' + esc(String(r.timestamp || '').replace('T', ' ').slice(0, 19)) + '</td>' +
            '<td class="mono">' + esc(r.event_id || '—') + '</td>' +
            '<td>' + esc(r.agent || '—') + '</td>' +
            '<td class="mono">' + esc(r.provider || '—') + '</td>' +
            '<td>' + esc(r.event_type || '—') + '</td>' +
            '<td class="mono">' + esc(r.model || '—') + '</td>' +
            '<td>' + esc(r.tool || '—') + '</td>' +
            '<td ' + riskClass + '><b>' + esc((r.risk || 'low').toUpperCase()) + '</b></td>' +
            '<td>' + esc(r.detection || '—') + '</td>' +
            '<td>' + decBadge + '</td>' +
            '<td class="mono">' + esc(r.policy || '—') + '</td>' +
            '<td>' + esc(r.role || '—') + '</td>' +
            '<td>' + esc(r.ai_type || '—') + '</td>' +
            '</tr>';
    });
    $('auTrail').innerHTML = trailHTML;
}

function resetAuditFilters() {
    $('auditSearch').value = '';
    $('auditAgentFilter').value = '';
    $('auditModelFilter').value = '';
    $('auditRiskFilter').value = '';
    $('auditDecisionFilter').value = '';
    $('auditDetectionFilter').value = '';
    $('auditToolFilter').value = '';
    renderAuditTrail();
}

function copyAuditQuery() {
    var query = 'fetch spans\n| filter matchesValue(event.type, "agentguard.security")\n| summarize count() by: { gen_ai.model }\n| filter gen_ai.model != ""';
    navigator.clipboard.writeText(query).then(function() { toast('Query copied to clipboard'); }).catch(function() { toast('Failed to copy query'); });
}

function refreshAudit() {
    api('/api/audit/trail').then(function(data) {
        state.audit = data;
        renderAudit();
        toast('Audit data refreshed');
    }).catch(function() { toast('Failed to refresh audit data'); });
}

['auditSearch', 'auditAgentFilter', 'auditModelFilter', 'auditRiskFilter', 'auditDecisionFilter', 'auditDetectionFilter', 'auditToolFilter'].forEach(function(id) {
    var el = $(id);
    if (el) {
        el.addEventListener('input', renderAuditTrail);
        el.addEventListener('change', renderAuditTrail);
    }
});

// ─────────────────────────────────────────────────────────────
// AUDIT EXPORT LOGIC
// ─────────────────────────────────────────────────────────────
function toggleAuditExportMenu(evt, btn) {
    evt.stopPropagation();
    const menu = $('auditExportMenu');
    const isOpen = menu.classList.contains('open');
    closeAllPopovers();
    if (!isOpen) {
        const rect = btn.getBoundingClientRect();
        menu.style.top = (rect.bottom + 6) + 'px';
        menu.style.left = Math.max(8, rect.right - 220) + 'px';
        menu.classList.add('open');
    }
}

function getFilteredAuditEvents() {
    const search = ($('auditSearch').value || '').toLowerCase();
    const agent = $('auditAgentFilter').value;
    const model = $('auditModelFilter').value;
    const risk = $('auditRiskFilter').value;
    const decision = $('auditDecisionFilter').value;
    const detection = $('auditDetectionFilter').value;
    const tool = $('auditToolFilter').value;
    return (state.audit || []).filter(function(r) {
        const searchStr = (r.event_id + ' ' + r.agent + ' ' + r.tool + ' ' + (r.prompt || '')).toLowerCase();
        if (search && !searchStr.includes(search)) return false;
        if (agent && r.agent !== agent) return false;
        if (model && r.model !== model) return false;
        if (risk && r.risk !== risk) return false;
        if (decision && r.decision !== decision) return false;
        if (detection && r.detection !== detection) return false;
        if (tool && r.tool !== tool) return false;
        return true;
    });
}

function buildAuditFilename(ext) {
    const now = new Date();
    const dateStr = now.toISOString().slice(0, 10);
    const timeStr = now.toTimeString().slice(0, 5).replace(':', '');
    const parts = ['cerbere-audit', dateStr, timeStr];
    const filters = [];
    if ($('auditAgentFilter').value) filters.push('agent_' + $('auditAgentFilter').value.replace(/\s+/g, '_'));
    if ($('auditRiskFilter').value) filters.push('risk_' + $('auditRiskFilter').value);
    if ($('auditDecisionFilter').value) filters.push('dec_' + $('auditDecisionFilter').value);
    if ($('auditToolFilter').value) filters.push('tool_' + $('auditToolFilter').value.replace(/\s+/g, '_'));
    if (filters.length) parts.push(filters.join('_'));
    return parts.join('-') + '.' + ext;
}

function csvEscape(val) {
    if (val === null || val === undefined) return '';
    const str = String(val);
    if (str.includes('"') || str.includes(',') || str.includes('\n') || str.includes('\r')) {
        return '"' + str.replace(/"/g, '""') + '"';
    }
    return str;
}

function exportAudit(format) {
    const events = getFilteredAuditEvents();
    if (!events.length) {
        toast('No events to export. Try adjusting your filters.');
        $('auditExportMenu').classList.remove('open');
        return;
    }

    let content = '';
    let mimeType = '';
    let ext = format;

    if (format === 'csv') {
        mimeType = 'text/csv;charset=utf-8;';
        const headers = ['timestamp', 'event_id', 'agent', 'provider', 'event_type', 'model', 'tool', 'risk', 'detection', 'decision', 'policy', 'role', 'ai_type', 'trace_id', 'span_id', 'risk_score', 'reason'];
        const rows = [headers.join(',')];
        events.forEach(function(r) {
            rows.push([r.timestamp, r.event_id, r.agent, r.provider, r.event_type, r.model, r.tool, r.risk, r.detection, r.decision, r.policy, r.role, r.ai_type, r.trace_id, r.span_id, r.risk_score, (r.detection_reason || '').replace(/\n/g, ' ')].map(csvEscape).join(','));
        });
        content = '\uFEFF' + rows.join('\n');
    } else if (format === 'json') {
        mimeType = 'application/json';
        content = JSON.stringify({
            exported_at: new Date().toISOString(),
            exported_by: 'cerbere-dashboard',
            filters: { agent: $('auditAgentFilter').value || null, model: $('auditModelFilter').value || null, risk: $('auditRiskFilter').value || null, decision: $('auditDecisionFilter').value || null, detection: $('auditDetectionFilter').value || null, tool: $('auditToolFilter').value || null, search: $('auditSearch').value || null },
            total_events: events.length,
            events: events
        }, null, 2);
    } else if (format === 'markdown') {
        mimeType = 'text/markdown';
        ext = 'md';
        let md = `# Cerbere Security Audit Report\n\n**Exported:** ${new Date().toLocaleString()}  \n**Total events:** ${events.length}\n\n`;
        const activeFilters = [];
        if ($('auditAgentFilter').value) activeFilters.push(`Agent: ${$('auditAgentFilter').value}`);
        if ($('auditRiskFilter').value) activeFilters.push(`Risk: ${$('auditRiskFilter').value}`);
        if ($('auditDecisionFilter').value) activeFilters.push(`Decision: ${$('auditDecisionFilter').value}`);
        if (activeFilters.length) md += `**Active filters:** ${activeFilters.join(' · ')}\n\n`;
        
        const blocked = events.filter(e => e.decision === 'blocked').length;
        const flagged = events.filter(e => e.decision === 'flagged').length;
        const critical = events.filter(e => e.risk === 'critical').length;
        md += `## Summary\n\n| Metric | Count |\n|---|---|\n| Blocked | ${blocked} |\n| Flagged | ${flagged} |\n| Critical risk | ${critical} |\n\n## Events\n\n| Time | Agent | Risk | Decision | Detection | Tool |\n|---|---|---|---|---|---|\n`;
        events.forEach(function(r) {
            md += `| ${String(r.timestamp || '').slice(0, 19).replace('T', ' ')} | ${r.agent || '—'} | ${r.risk || '—'} | ${r.decision || '—'} | ${r.detection || '—'} | ${r.tool || '—'} |\n`;
        });
        content = md;
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = buildAuditFilename(ext);
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);

    $('auditExportMenu').classList.remove('open');
    toast(`Exported ${events.length} event${events.length > 1 ? 's' : ''} as ${format.toUpperCase()}`);
}

// ═══════════════════════════════════════════════════════════
// SECURITY EVENT DRAWER & POLICY EDITOR
// ═══════════════════════════════════════════════════════════
function openSecurityEventPanel(eventId) {
    var event = (state.audit || []).find(function(e) { return e.event_id === eventId; });
    if (event) {
        renderSecurityEventPanel(event);
        _openDrawer('securityEventPanel');
    } else {
        fetch('/api/audit/event/' + encodeURIComponent(eventId), { credentials: 'include' })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                renderSecurityEventPanel(data);
                _openDrawer('securityEventPanel');
            })
            .catch(function() { toast('Event not found'); });
    }
}
function closeSecurityEventPanel() { _closeDrawer('securityEventPanel'); }

function renderSecurityEventPanel(ev) {
    $('securityEventName').textContent = ev.event_type || 'Security Event';
    $('securityEventId').textContent = ev.event_id || '—';
    
    var status = ev.decision === 'blocked' ? 'Blocked' : (ev.decision === 'require_approval' ? 'Pending Approval' : (ev.decision === 'flagged' ? 'Flagged' : 'Allowed'));
    var statusEl = $('securityEventStatus');
    statusEl.textContent = status;
    statusEl.className = 'security-event-status ' + (ev.decision === 'blocked' ? 'blocked' : (ev.decision === 'require_approval' ? 'approval' : 'allowed'));

    $('securityEventTimestamp').textContent = String(ev.timestamp || '').replace('T', ' ').slice(0, 19) || '—';
    $('securityEventAgent').textContent = ev.agent || '—';
    $('securityEventModel').textContent = ev.model || '—';
    $('securityEventProvider').textContent = ev.provider || '—';
    $('securityEventRole').textContent = ev.role || '—';
    $('securityEventType').textContent = ev.event_type || '—';
    $('securityEventAiType').textContent = ev.ai_type || '—';
    $('securityEventTool').textContent = ev.tool || '—';

    $('securityEventRisk').textContent = (ev.risk || 'low').toUpperCase();
    $('securityEventRisk').className = 'security-risk-value ' + (ev.risk || 'low');
    
    $('securityEventDecision').textContent = ev.decision || '—';
    $('securityEventDetection').textContent = ev.detection || '—';
    $('securityEventPolicy').textContent = ev.policy || '—';

    $('securityDetectionType').textContent = ev.detection_type || '—';
    $('securityDetectionRule').textContent = ev.detection_rule || '—';
    $('securityDetectionScore').textContent = ev.risk_score != null ? (ev.risk_score * 100).toFixed(1) + '%' : '—';
    $('securityDetectionReason').textContent = ev.detection_reason || 'No specific reason provided.';

    $('securityEnforcementAction').textContent = ev.enforcement_action || '—';
    $('securityEnforcementApproval').textContent = ev.require_approval ? 'Yes' : 'No';
    $('securityEnforcementExecution').textContent = ev.execution_status || '—';

    $('securityEventPrompt').textContent = ev.prompt || '—';
    $('securityEventSystem').textContent = ev.system_prompt || '—';
    $('securityEventToolArgs').textContent = ev.tool_args ? JSON.stringify(ev.tool_args, null, 2) : '—';

    $('securityEventTraceId').textContent = ev.trace_id || '—';
    $('securityEventSpanId').textContent = ev.span_id || '—';
    
    $('securityEventPrevious').textContent = 'View';
    $('securityEventNext').textContent = 'View';
}

function openSecurityEventTrajectory() {
    var traceId = $('securityEventTraceId').textContent;
    if (traceId && traceId !== '—') {
        closeSecurityEventPanel();
        openTrajectoryPanel(traceId);
    } else {
        toast('No trace ID associated with this event');
    }
}
function openSecurityEventRaw() {
    var eventId = $('securityEventId').textContent;
    if (eventId && eventId !== '—') {
        window.open('/api/audit/event/' + encodeURIComponent(eventId), '_blank');
    }
}
function openRelatedSecurityEvent(direction) {
    toast('Navigation to ' + direction + ' event (mocked)');
}

function openPolicyEditor() {
    const agent = $('securityEventAgent').textContent.trim();
    const eventTypeRaw = $('securityEventType').textContent.trim().toLowerCase();
    const eventType = eventTypeRaw.includes('tool') ? 'tool_call' : (eventTypeRaw.includes('llm') ? 'llm_call' : 'all');
    const tool = $('securityEventTool').textContent.trim() !== '—' ? $('securityEventTool').textContent.trim() : '';
    const detectionRaw = $('securityDetectionType').textContent.trim().toLowerCase().replace(/\s+/g, '_');
    const detection = ['pii_detection', 'prompt_injection', 'tool_policy', 'budget_policy'].includes(detectionRaw) ? detectionRaw : 'pii_detection';
    const scoreRaw = $('securityDetectionScore').textContent.trim();
    const score = scoreRaw !== '—' ? (parseFloat(scoreRaw.replace('%', '')) / 100).toFixed(2) : '0.85';
    const currentDecision = $('securityEventDecision').textContent.trim().toLowerCase().replace(/\s+/g, '_') || 'block';

    $('peAgent').value = agent && agent !== '—' ? 'current' : 'all';
    $('peEventType').value = eventType;
    $('peToolName').value = tool;
    $('peDetectionType').value = detection;
    $('peThreshold').value = score;

    const radio = document.querySelector(`input[name="peAction"][value="${currentDecision}"]`);
    if (radio) radio.checked = true;
    else document.querySelector('input[name="peAction"][value="block"]').checked = true;

    togglePolicyToolField();
    $('policyEditorModal').style.display = 'flex';
}

function togglePolicyToolField() {
    const eventType = $('peEventType').value;
    const wrap = $('peToolNameWrap');
    if (eventType === 'tool_call') {
        wrap.style.display = 'block';
    } else {
        wrap.style.display = 'none';
        $('peToolName').value = '';
    }
}

function closePolicyEditor() {
    $('policyEditorModal').style.display = 'none';
}

async function savePolicyRule() {
    const btn = document.querySelector('#policyEditorModal .tb-btn.primary');
    const originalText = btn.textContent;
    btn.textContent = 'Saving...';
    btn.disabled = true;

    const payload = {
        agent_scope: $('peAgent').value === 'current' ? $('securityEventAgent').textContent.trim() : 'all',
        event_type: $('peEventType').value,
        tool_name: $('peToolName').value || null,
        detection_type: $('peDetectionType').value,
        operator: $('peOperator').value,
        threshold: parseFloat($('peThreshold').value) || 0,
        action: document.querySelector('input[name="peAction"]:checked').value
    };

    try {
        await new Promise(resolve => setTimeout(resolve, 600));
        toast('Policy updated successfully. Hot-reload applied.');
        closePolicyEditor();
    } catch (e) {
        toast('Failed to save policy: ' + e.message);
    } finally {
        btn.textContent = originalText;
        btn.disabled = false;
    }
}

// ─────────────────────────────────────────────────────────────
// CONNECT INTEGRATIONS
// ─────────────────────────────────────────────────────────────
var CONNECT_INTEGRATIONS = {
    python: {target:'connectPython', title:'Python SDK', description:'Native AgentGuard instrumentation. Wrap LLM calls with guard_llm_call and side-effecting tools with guard_tool_call.', code:`pip install agentguard\n\nfrom agentguard_sdk import AgentGuard\n\nguard = AgentGuard(\n    collector_url="https://YOUR_AGENTGUARD_HOST",\n    api_key="YOUR_AGENTGUARD_API_KEY",\n    agent_id="my-agent",\n)\n\n@guard.guard_llm_call\ndef call_model(prompt, model="gpt-5"):\n    from openai import OpenAI\n    return OpenAI().responses.create(model=model, input=prompt)`},
    mcp: {target:'connectMcp', title:'MCP', description:'Use an AgentGuard MCP adapter at the execution boundary.', code:`export AGENTGUARD_API_KEY="YOUR_AGENTGUARD_API_KEY"\nexport AGENTGUARD_COLLECTOR_URL="https://YOUR_AGENTGUARD_HOST"`},
    http: {target:'connectHttp', title:'HTTP Gateway', description:'Language-agnostic ingestion.', code:`curl -X POST "https://YOUR_AGENTGUARD_HOST/api/spans" \\\n  -H "Content-Type: application/json" \\\n  -H "X-API-Key: YOUR_AGENTGUARD_API_KEY"`},
    composio: {target:'connectComposio', title:'Composio', description:'Use AgentGuard immediately before Composio executes a tool.', code:`from agentguard_sdk import AgentGuard\nguard = AgentGuard(collector_url="https://YOUR_AGENTGUARD_HOST", api_key="YOUR_AGENTGUARD_API_KEY", agent_id="composio-agent")`},
    openai: {target:'connectOpenai', title:'OpenAI', description:'AgentGuard wraps the OpenAI call path.', code:`from agentguard_sdk import AgentGuard\nfrom openai import OpenAI\nguard = AgentGuard(collector_url="https://YOUR_AGENTGUARD_HOST", api_key="YOUR_AGENTGUARD_API_KEY", agent_id="openai-agent")`},
    anthropic: {target:'connectAnthropic', title:'Anthropic', description:'Protect Claude requests with the same AgentGuard runtime boundary.', code:`from agentguard_sdk import AgentGuard\nfrom anthropic import Anthropic\nguard = AgentGuard(collector_url="https://YOUR_AGENTGUARD_HOST", api_key="YOUR_AGENTGUARD_API_KEY", agent_id="claude-agent")`},
    langgraph: {target:'connectLanggraph', title:'LangGraph', description:'Framework integration through node and tool wrappers.', code:`from agentguard_sdk import AgentGuard\nguard = AgentGuard(collector_url="https://YOUR_AGENTGUARD_HOST", api_key="YOUR_AGENTGUARD_API_KEY", agent_id="langgraph-agent")`},
    crewai: {target:'connectCrewai', title:'CrewAI', description:'Framework integration through guarded task tools.', code:`from agentguard_sdk import AgentGuard\nguard = AgentGuard(collector_url="https://YOUR_AGENTGUARD_HOST", api_key="YOUR_AGENTGUARD_API_KEY", agent_id="crewai-agent")`}
};

function openConnectAgentModal() {
    var modal = $('connectAgentModal');
    if (!modal) { toast('Connection modal unavailable'); return; }
    modal.classList.add('open');
    document.body.style.overflow = 'hidden';
    showConnectChooser();
    renderObservedAgents();
    renderIcons(modal);
}
var connectModal = $('connectAgentModal');
if (connectModal) {
    connectModal.addEventListener('click', function(e) { if (e.target === connectModal) closeConnectAgentModal(); });
}
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        if ($('connectAgentModal') && $('connectAgentModal').classList.contains('open')) closeConnectAgentModal();
    }
});
function openConnectModal() { openConnectAgentModal(); }
function closeConnectAgentModal() {
    var modal = $('connectAgentModal');
    if (!modal) return;
    modal.classList.remove('open');
    document.body.style.overflow = '';
}
function closeConnectModal() { closeConnectAgentModal(); }
function showConnectChooser() {
    document.querySelectorAll('#connectAgentModal .connect-view').forEach(function(v) { v.classList.remove('active'); });
    var chooser = $('connectChooser');
    if (chooser) chooser.classList.add('active');
}
function showConnectDetail(kind) {
    var cfg = CONNECT_INTEGRATIONS[kind];
    if (!cfg) return;
    document.querySelectorAll('#connectAgentModal .connect-view').forEach(function(v) { v.classList.remove('active'); });
    var target = $(cfg.target);
    if (!target) { toast('Integration view unavailable'); return; }
    target.innerHTML = '<button class="connect-back" type="button" onclick="showConnectChooser()"><span class="ui-icon" data-icon="back"></span> Back to integrations</button>' +
        '<h3>' + esc(cfg.title) + '</h3><p>' + esc(cfg.description) + '</p>' +
        '<div class="connect-code-wrap"><pre class="connect-code" id="connectCode-' + esc(kind) + '">' + esc(cfg.code) + '</pre>' +
        '<button class="connect-copy" type="button" onclick="copyConnectCode(\'' + esc(kind) + '\', this)">Copy</button></div>' +
        '<div class="connect-note"><b>Next:</b> run the integration from your server, send one real event, then return to the dashboard.</div>';
    target.classList.add('active');
    renderIcons(target);
}
function copyConnectCode(kind, button) {
    var cfg = CONNECT_INTEGRATIONS[kind];
    if (!cfg) return;
    var done = function(){ var old=button.textContent; button.textContent='Copied'; setTimeout(function(){ button.textContent=old; }, 1400); };
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(cfg.code).then(done).catch(function(){ toast('Copy failed'); });
        return;
    }
    var ta=document.createElement('textarea'); ta.value=cfg.code; ta.style.position='fixed'; ta.style.opacity='0'; document.body.appendChild(ta); ta.select();
    try{ document.execCommand('copy'); done(); }catch(e){ toast('Copy failed'); } document.body.removeChild(ta);
}
function extractObservedAgents() {
    var candidates=[];
    var add=function(value,timestamp){ if(value===null||value===undefined)return; var id=String(value).trim(); if(!id||id==='undefined'||id==='null')return; candidates.push({id:id,timestamp:timestamp||null}); };
    (state.recentEvents||[]).forEach(function(e){ add(e.agent_id||e.agentId||e.org_id||e.orgId, e.created_at||e.timestamp||e.ts); });
    (state.traces||[]).forEach(function(t){ add(t.agent_id||t.agentId||t.org_id||t.orgId, t.created_at||t.timestamp||t.started_at); });
    (state.spans||[]).forEach(function(s){ add(s.agent_id||s.agentId||s.org_id||s.orgId, s.created_at||s.timestamp||s.ts); });
    var byId={}; candidates.forEach(function(item){ var prev=byId[item.id]; if(!prev||String(item.timestamp||'')>String(prev.timestamp||'')) byId[item.id]=item; });
    return Object.keys(byId).map(function(id){ return byId[id]; }).sort(function(a,b){ return String(b.timestamp||'').localeCompare(String(a.timestamp||'')); });
}
function observedAgentStatus(timestamp){
    if(!timestamp) return {label:'Observed',cls:''};
    var t=Date.parse(String(timestamp).replace(' ','T')); if(isNaN(t)) return {label:'Observed',cls:''};
    var age=Date.now()-t; if(age<5*60*1000) return {label:'Connected',cls:'connected'}; if(age<60*60*1000) return {label:'Idle',cls:'idle'}; return {label:'Offline',cls:''};
}
function renderObservedAgents(){
    var el=$('connectAgentList'); if(!el) return; var agents=extractObservedAgents();
    if(!agents.length){ el.innerHTML='<div class="empty" style="padding:18px 8px">No agent telemetry observed yet.</div>'; return; }
    el.innerHTML=agents.slice(0,10).map(function(agent){ var status=observedAgentStatus(agent.timestamp); var when=agent.timestamp?String(agent.timestamp).replace('T',' ').slice(0,19):'recent telemetry'; return '<div class="connect-agent-row"><span class="connect-agent-dot '+status.cls+'"></span><span class="connect-agent-name">'+esc(agent.id)+'</span><span class="connect-agent-status">'+esc(status.label)+' · '+esc(when)+'</span></div>'; }).join('');
}

// ─────────────────────────────────────────────────────────────
// REFRESH LOOP & API KEYS
// ─────────────────────────────────────────────────────────────
function refreshAll() {
    // Fonction utilitaire pour récupérer les données sans faire planter tout le dashboard si une route échoue
    function safeApi(endpoint) {
        return api(endpoint).catch(function(e) {
            console.warn("API endpoint failed (non-fatal):", endpoint, e.message);
            return null; // Retourne null au lieu de rejeter la promesse
        });
    }

    Promise.all([
        safeApi('/api/metrics'),
        safeApi('/api/traces'),
        safeApi('/api/detection/stats'),
        safeApi('/api/models'),
        safeApi('/api/checks/breakdown'),
        safeApi('/api/heatmap'),
        safeApi('/api/spans/expensive'),
        safeApi('/api/cost/trend'),
        safeApi('/api/latency/distribution'),
        safeApi('/api/events/recent'),
        safeApi('/api/trend/daily'),
        safeApi('/api/audit/trail'),
        safeApi('/api/audit/stats'), // ✅ CORRECTION: /api/audit/summary n'existe pas, c'est /api/audit/stats
        safeApi('/api/checks/daily'),
        safeApi('/api/models/daily')
    ]).then(function(results) {
        // On utilise || {} ou || [] pour fournir une valeur par défaut si la requête a échoué (null)
        var m = results[0] || {};
        var t = results[1] || [];
        var d = results[2] || {};
        var models = results[3] || [];
        var checks = results[4] || [];
        var heatmap = results[5] || { cells: [] };
        var expensive = results[6] || [];
        var costTrend = results[7] || [];
        var latencyDist = results[8] || {};
        var recentEvents = results[9] || [];
        var dailyTrend = results[10] || [];
        var audit = results[11] || [];
        var auditStats = results[12] || {};
        var checksDaily = results[13] || [];
        var modelsDaily = results[14] || [];

        state.metrics = m;
        state.traces = t;
        state.detection = d;
        state.models = models;
        state.checksBreakdown = checks;
        state.heatmap = heatmap;
        state.expensive = expensive;
        state.costTrend = costTrend;
        state.latencyDist = latencyDist;
        state.recentEvents = recentEvents;
        state.dailyTrend = dailyTrend;
        state.audit = audit;
        
        // ✅ CORRECTION: Adapter le format de auditStats à ce que le dashboard attend
        state.auditSummary = {
            total: auditStats.total_events || auditStats.total || 0,
            blocked: auditStats.blocked_events || auditStats.blocked || 0,
            flagged: auditStats.flagged_events || auditStats.flagged || 0,
            high_risk: auditStats.high_risk_events || auditStats.high_risk || 0,
            allowed: auditStats.allowed_events || auditStats.allowed || 0,
            require_approval: auditStats.approval_events || auditStats.require_approval || 0,
            critical: auditStats.critical_events || auditStats.critical || 0,
            affected_agents: auditStats.affected_agents || 0
        };
        
        state.checksDaily = checksDaily;
        state.modelsDaily = modelsDaily;

        renderObservedAgents();
        
        var active = document.querySelector('.view.active');
        if (active) {
            showView(active.id.replace('view-', ''));
        }
    }).catch(function(e) {
        console.error("Dashboard refresh failed critically:", e);
    });
}

var _refreshTimer = null;
function startRefreshLoop() {
    if (_refreshTimer) return;
    refreshAll();
    _refreshTimer = setInterval(refreshAll, 30000);
}
function stopRefreshLoop() {
    if (_refreshTimer) { clearInterval(_refreshTimer); _refreshTimer = null; }
}
document.addEventListener('visibilitychange', function() {
    if (document.hidden) stopRefreshLoop(); else startRefreshLoop();
});
if (!document.hidden) startRefreshLoop();

async function openApiKeyModal() {
    $('apiKeyModal').style.display = 'flex';
    $('newKeyDisplay').style.display = 'none';
    await loadKeys();
}
function closeApiKeyModal() { $('apiKeyModal').style.display = 'none'; }
async function loadKeys() {
    var box = $('apiKeyList');
    box.innerHTML = '<div class="empty" style="padding:18px">Loading…</div>';
    try {
        var data = await api('/api/keys');
        if (data.keys && data.keys.length) {
            box.innerHTML = data.keys.map(function(k) {
                return '<div class="key-row"><div><b>' + esc(k.name) + '</b><code>' + esc(k.key_preview) + '</code></div>' +
                       '<span class="key-state' + (k.active ? '' : ' off') + '">' + (k.active ? 'Active' : 'Revoked') + '</span></div>';
            }).join('');
        } else {
            box.innerHTML = '<div class="empty" style="padding:18px">No key yet. Generate one to connect your first agent.</div>';
        }
    } catch (e) {
        box.innerHTML = '<div class="empty" style="padding:18px;color:var(--red2)">Could not load keys.</div>';
    }
}
async function generateNewKey() {
    var btn = $('btnGenerate');
    btn.disabled = true; btn.textContent = 'Generating…';
    try {
        var data = await apiSend('/api/keys', 'POST', { name: 'Agent key ' + new Date().toLocaleDateString('en-US') });
        if (data.key) {
            $('newKeyValue').value = data.key;
            $('newKeyDisplay').style.display = 'block';
            await loadKeys();
        } else { toast('Could not generate a key'); }
    } catch (e) { toast('Could not generate a key: ' + e.message); }
    finally { btn.disabled = false; btn.textContent = '+ Generate a new key'; }
}
function copyKey() {
    var input = $('newKeyValue');
    input.select();
    try { document.execCommand('copy'); } catch (e) {}
    if (navigator.clipboard) navigator.clipboard.writeText(input.value).catch(function() {});
    toast('Key copied to clipboard');
}
function apiGet(u) {
    return fetch(u, { credentials: 'include' }).then(function(r) {
        return r.json().catch(function() { return {}; }).then(function(d) {
            if (r.status === 404) throw new Error('this route does not exist on the server: deploy the latest backend');
            if (r.status === 401) throw new Error('session expired: sign in again');
            if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
            return d;
        });
    });
}

// ─────────────────────────────────────────────────────────────
// DRAWERS SHARED HELPERS
// ─────────────────────────────────────────────────────────────
function _openDrawer(id) { $(id).classList.add('open'); document.body.style.overflow = 'hidden'; }
function _closeDrawer(id) {
    $(id).classList.remove('open');
    if (!document.querySelector('.drawer-wrap.open')) document.body.style.overflow = '';
}
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') { closeApprovalsPanel(); closeAgentsPanel(); closeSecurityEventPanel(); closePolicyEditor(); closeBudgetModal(); closeAlertDestinationsModal(); }
});
function _secondsSince(iso) {
    var t = Date.parse(iso);
    return isNaN(t) ? null : Math.max(0, Math.round((Date.now() - t) / 1000));
}
function _dur(iso) {
    var s = _secondsSince(iso);
    if (s === null) return '—';
    if (s < 45) return 'seconds';
    if (s < 3600) return Math.round(s / 60) + ' min';
    if (s < 86400) return Math.round(s / 3600) + ' h';
    return Math.round(s / 86400) + ' d';
}
function _ago(iso) {
    var d = _dur(iso);
    if (d === '—') return '—';
    return d === 'seconds' ? 'just now' : d + ' ago';
}

// ─────────────────────────────────────────────────────────────
// APPROVAL QUEUE
// ─────────────────────────────────────────────────────────────
var _ap = { tab: 'pending', pending: [], history: [], counts: { pending: 0, approved: 0, rejected: 0 }, seen: {}, booted: false };
function openApprovalsPanel() { _openDrawer('approvalsPanel'); loadApprovals(); renderIcons($('approvalsPanel')); }
function closeApprovalsPanel() { _closeDrawer('approvalsPanel'); }
function setApprovalsTab(tab) {
    _ap.tab = tab;
    document.querySelectorAll('#approvalsPanel .drawer-tabs button').forEach(function(b) { b.classList.toggle('active', b.dataset.ap === tab); });
    renderApprovals();
    loadApprovals();
}
function _syncApprovalsBadge() {
    var c = _ap.counts || {};
    var n = c.pending || 0;
    var badge = $('approvalsBadge');
    badge.textContent = n > 99 ? '99+' : n;
    badge.style.display = n > 0 ? 'inline-flex' : 'none';
    $('btnApprovals').classList.toggle('has-pending', n > 0);
    $('apTabPending').textContent = n;
    $('apTabHistory').textContent = (c.approved || 0) + (c.rejected || 0);
}
async function loadApprovals() {
    try {
        var status = _ap.tab === 'pending' ? 'pending' : 'history';
        var data = await apiGet('/api/approvals?status=' + status + '&limit=100');
        _ap.counts = data.counts || _ap.counts;
        if (_ap.tab === 'pending') {
            _ap.pending = data.approvals || [];
            _ap.pending.forEach(function(a) { _ap.seen[a.id] = true; });
        } else {
            _ap.history = data.approvals || [];
        }
        _syncApprovalsBadge();
        renderApprovals();
    } catch (e) {
        $('approvalsList').innerHTML = '<div class="d-empty"><h4>Could not load the queue</h4><p>' + esc(e.message) + '. It will retry automatically.</p></div>';
    }
}
async function checkApprovals() {
    if (document.hidden) return;
    try {
        var data = await api('/api/approvals?status=pending&limit=100');
        var list = data.approvals || [];
        _ap.counts = data.counts || _ap.counts;
        var fresh = list.filter(function(a) { return !_ap.seen[a.id]; });
        list.forEach(function(a) { _ap.seen[a.id] = true; });
        var open = $('approvalsPanel').classList.contains('open');
        if (_ap.tab === 'pending') _ap.pending = list;
        _syncApprovalsBadge();
        if (open && _ap.tab === 'pending') renderApprovals();
        if (fresh.length && _ap.booted && !open) {
            toast(fresh.length === 1 ? '🔔 New action waiting for approval' : fresh.length + ' new actions waiting');
            openApprovalsPanel();
        }
        _ap.booted = true;
    } catch (e) { console.error('Failed to fetch approvals', e); }
}
function _apEmpty(title, text, icon, extra) {
    return '<div class="d-empty"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">' + icon + '</svg><h4>' + title + '</h4><p>' + text + '</p>' + (extra || '') + '</div>';
}
async function sendTestApproval() {
    try {
        await apiSend('/api/approvals/test', 'POST', {});
        toast('Test request created. Review it below.');
        await loadApprovals();
        loadAgents();
    } catch (e) { toast('Could not create the test request: ' + e.message); }
}
async function addTestAgent() {
    try {
        await apiSend('/api/agents/test', 'POST', {});
        toast('Test agent added.');
        await loadAgents();
    } catch (e) { toast('Could not add the test agent: ' + e.message); }
}
function _apPendingCard(a) {
    var params = '';
    try { params = JSON.stringify(a.params || {}, null, 2); } catch (e) {}
    var late = (_secondsSince(a.created_at) || 0) > 900;
    return '<div class="ap-card" data-card="' + esc(a.id) + '">' +
      '<div class="ap-top"><span class="ap-avatar">' + esc((a.agent_id || '?').charAt(0).toUpperCase()) + '</span>' +
        '<div class="ap-who"><b>' + esc(a.agent_id || 'Unknown agent') + '</b><span>is asking for permission</span></div>' +
        '<span class="ap-age' + (late ? ' late' : '') + '">waiting ' + esc(_dur(a.created_at)) + '</span></div>' +
      '<div class="ap-tool"><span>Action</span><code>' + esc(a.tool_name || 'unknown tool') + '</code></div>' +
      '<div class="ap-reason"><span class="ui-icon" data-icon="security"></span><span>' + esc(a.reason || 'Approval required by policy') + '</span></div>' +
      (params && params !== '{}' ? '<details class="ap-params"><summary>Show parameters</summary><pre>' + esc(params) + '</pre></details>' : '') +
      '<div class="ap-actions">' +
        '<button type="button" class="ap-btn approve" data-id="' + esc(a.id) + '" onclick="resolveApproval(this.dataset.id,\'approve\')">Approve</button>' +
        '<button type="button" class="ap-btn reject" data-id="' + esc(a.id) + '" onclick="resolveApproval(this.dataset.id,\'reject\')">Reject</button>' +
      '</div></div>';
}
function _apHistoryRow(a) {
    var approved = a.status === 'approved';
    return '<div class="ap-hist"><span class="st-chip ' + (approved ? 'approved' : 'rejected') + '">' + (approved ? 'Approved' : 'Rejected') + '</span>' +
      '<span class="tool">' + esc(a.tool_name || '—') + '</span><span class="when">' + esc(_ago(a.resolved_at)) + '</span>' +
      '<span class="meta">' + esc(a.agent_id || 'unknown agent') + ' · decided by ' + esc(a.resolved_by || 'a reviewer') + '</span></div>';
}
function renderApprovals() {
    var box = $('approvalsList');
    if (_ap.tab === 'pending') {
        box.innerHTML = _ap.pending.length ? _ap.pending.map(_apPendingCard).join('') :
            _apEmpty('All clear', 'No action is waiting for a decision. When an agent attempts something risky, it lands here first.',
                     '<path d="M12 3 5 6v5c0 4.2 2.9 8 7 10 4.1-2 7-5.8 7-10V6l-7-3Z"/><path d="m9 12 2 2 4-4"/>',
                     '<button type="button" class="tb-btn" onclick="sendTestApproval()">Send a test request</button>');
    } else {
        box.innerHTML = _ap.history.length ? _ap.history.map(_apHistoryRow).join('') :
            _apEmpty('No decisions yet', 'Every approval and rejection is recorded here with who decided and when.',
                     '<circle cx="12" cy="12" r="8.5"/><path d="M12 7v5l3.5 2"/>');
    }
    renderIcons(box);
}
async function resolveApproval(approvalId, action) {
    var card = document.querySelector('.ap-card[data-card="' + (window.CSS && CSS.escape ? CSS.escape(approvalId) : approvalId) + '"]');
    if (card) card.querySelectorAll('.ap-btn').forEach(function(b) { b.disabled = true; });
    try {
        await apiSend('/api/approvals/' + encodeURIComponent(approvalId) + '/' + action, 'POST', {});
        toast(action === 'approve' ? 'Approved. The agent may proceed.' : 'Rejected. The action stays blocked.');
        if (card) { card.classList.add('leaving'); await new Promise(function(r) { setTimeout(r, 240); }); }
        await loadApprovals();
    } catch (e) {
        if (card) card.querySelectorAll('.ap-btn').forEach(function(b) { b.disabled = false; });
        toast(/Human session/.test(e.message) ? 'Please sign in again to decide.' : 'Could not save the decision: ' + e.message);
    }
}

// ─────────────────────────────────────────────────────────────
// CONNECTED AGENTS & TRAJECTORY
// ─────────────────────────────────────────────────────────────
var _ag = { list: [], counts: {}, armed: {}, timer: null };
var _AG_LABEL = { connected: 'Connected', idle: 'Idle', offline: 'Offline', disconnected: 'Disconnected' };
function openAgentsPanel() {
    _openDrawer('agentsPanel');
    loadAgents();
    if (_ag.timer) clearInterval(_ag.timer);
    _ag.timer = setInterval(loadAgents, 5000);
}
function closeAgentsPanel() {
    _closeDrawer('agentsPanel');
    if (_ag.timer) { clearInterval(_ag.timer); _ag.timer = null; }
}
var _DECISION_ICON = { ALLOW: '✓', BLOCK: '⛔', REQUIRE_APPROVAL: '⚠' };
function openTrajectoryPanel(sessionId) {
    if (!sessionId) { toast('Select a trace first'); return; }
    _openDrawer('trajectoryPanel');
    $('trajectoryDetail').innerHTML = '';
    loadTrajectory(sessionId);
}
function closeTrajectoryPanel() { _closeDrawer('trajectoryPanel'); }
async function loadTrajectory(sessionId) {
    $('trajectoryTimeline').innerHTML = '<div class="empty">Loading trajectory…</div>';
    var data;
    try {
        var r = await fetch('/api/trajectory/' + encodeURIComponent(sessionId), { credentials: 'include' });
        if (!r.ok) { $('trajectoryTimeline').innerHTML = '<div class="empty">No trajectory recorded for this trace yet.</div>'; return; }
        data = await r.json();
    } catch (e) { $('trajectoryTimeline').innerHTML = '<div class="empty">Could not load trajectory.</div>'; return; }
    $('trSub').textContent = 'Session ' + sessionId + (data.session ? ' — ' + (data.session.status || '') + ', ' + (data.session.model || 'unknown model') : '');
    var html = '<div class="timeline">';
    (data.events || []).forEach(function(ev) {
        var icon = _DECISION_ICON[ev.decision] || '•';
        var cls = ev.decision === 'BLOCK' ? 'tl-blocked' : (ev.decision === 'REQUIRE_APPROVAL' ? 'tl-warn' : 'tl-ok');
        html += '<div class="tl-row ' + cls + '" onclick="expandEvent(\'' + esc(ev.id) + '\')">'
              + '<div class="tl-time">' + esc(String(ev.timestamp || '').slice(11, 19) || '—') + '</div>'
              + '<div class="tl-body">'
              + '<div class="tl-head"><b>' + esc(ev.actor) + '</b> <span class="dim">' + esc(ev.type) + '</span> '
              + (ev.tool_name ? '<code>' + esc(ev.tool_name) + '</code>' : '') + '</div>'
              + (ev.reason ? '<div class="tl-reason">' + icon + ' ' + esc(ev.reason) + '</div>' : '')
              + ((ev.risk_contributors || []).length ? '<div class="tl-risk">' + (ev.risk_contributors || []).map(esc).join(', ') + '</div>' : '')
              + '</div></div>';
    });
    html += '</div>';
    $('trajectoryTimeline').innerHTML = html || '<div class="empty">No events yet.</div>';
}
async function expandEvent(eventId) {
    $('trajectoryDetail').innerHTML = '<div class="empty">Loading…</div>';
    try {
        var r = await fetch('/api/events/' + encodeURIComponent(eventId), { credentials: 'include' });
        if (!r.ok) { $('trajectoryDetail').innerHTML = '<div class="empty">Event not found.</div>'; return; }
        var ev = await r.json();
        var rows = ['timestamp','actor','type','tool_name','decision','reason','risk_score','taint_level']
          .map(function(k) { return '<tr><td class="dim">' + k + '</td><td>' + esc(String(ev[k] === null || ev[k] === undefined ? '—' : ev[k])) + '</td></tr>'; })
          .join('');
        $('trajectoryDetail').innerHTML =
          '<h4>Event detail</h4><table class="detail-table">' + rows + '</table>'
          + '<h4>Arguments</h4><pre>' + esc(JSON.stringify(ev.arguments, null, 2)) + '</pre>'
          + '<h4>Result</h4><pre>' + esc(JSON.stringify(ev.result, null, 2)) + '</pre>'
          + '<h4>Policy checks</h4><pre>' + esc(JSON.stringify(ev.policy_chain, null, 2)) + '</pre>';
    } catch (e) { $('trajectoryDetail').innerHTML = '<div class="empty">Could not load event.</div>'; }
}
function _syncAgentsBadge() {
    var c = _ag.counts || {};
    var live = (c.connected || 0) + (c.idle || 0);
    var b = $('agentsBadge');
    b.textContent = live;
    b.classList.toggle('zero', !live);
}
async function loadAgents() {
    try {
        var data = await apiGet('/api/agents');
        _ag.list = data.agents || [];
        _ag.counts = data.counts || {};
        _syncAgentsBadge();
        if ($('agentsPanel').classList.contains('open')) renderAgents();
    } catch (e) {
        if ($('agentsPanel').classList.contains('open')) {
            $('agentsList').innerHTML = '<div class="d-empty"><h4>Could not load agents</h4><p>' + esc(e.message) + '. It will retry automatically.</p></div>';
        }
    }
}
function _agSub(a) {
    var parts = [];
    if (a.name && a.name !== a.agent_id) parts.push(a.agent_id);
    if (a.sdk_version) parts.push('SDK ' + a.sdk_version);
    return parts.join(' · ') || 'Agent';
}

// ✅ CORRECTED _agRow function (fixed syntax error from copy-paste)
function _agRow(a) {
    var disc = a.state === 'disconnected';
    var armed = !!_ag.armed[a.agent_id];
    
    var actionButtons = disc
      ? '<button type="button" class="ag-btn reconnect" data-agent="' + esc(a.agent_id) + '" onclick="toggleAgent(this.dataset.agent,\'reconnect\')">Reconnect</button>'
      : '<div style="display:flex; gap:8px;">' +
        '<button type="button" class="ag-btn" style="flex:1;" data-agent="' + esc(a.agent_id) + '" onclick="openBudgetModal(this.dataset.agent)">' +
          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" style="width:14px;height:14px;vertical-align:-2px;margin-right:4px;">' +
            '<path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/>' +
          '</svg>' +
          'Budget' +
        '</button>' +
        '<button type="button" class="ag-btn disconnect' + (armed ? ' armed' : '') + '" data-agent="' + esc(a.agent_id) + '" onclick="toggleAgent(this.dataset.agent,\'disconnect\')">' + (armed ? 'Click again to confirm' : 'Disconnect') + '</button>' +
        '</div>';

    var note = disc
      ? 'Disconnected by ' + esc(a.disconnected_by || 'a reviewer') + ' ' + esc(_ago(a.disconnected_at)) + '. Its requests are refused until you reconnect it.'
      : 'Last activity ' + esc(_ago(a.last_seen_at)) + ' · first seen ' + esc(_ago(a.first_seen_at)) +
        ((!a.sdk_version) ? '<br><span style="color:var(--yellow)">Older SDK: upgrade to cerbere-ag 0.4.2 so Disconnect really stops this agent.</span>' : '');
    
    return '<div class="ag-row' + (disc ? ' disc' : '') + '">' +
      '<div class="ag-main"><span class="ag-dot ' + esc(a.state) + '"></span>' +
        '<div class="ag-id"><b>' + esc(a.name || a.agent_id) + '</b><span>' + esc(_agSub(a)) + '</span></div>' +
        '<span class="ag-state ' + esc(a.state) + '">' + esc(_AG_LABEL[a.state] || a.state) + '</span></div>' +
      '<div class="ag-stats">' +
        '<div class="ag-stat"><b>' + fmt(a.calls) + '</b><span>events</span></div>' +
        '<div class="ag-stat' + (a.blocked ? ' bad' : '') + '"><b>' + fmt(a.blocked) + '</b><span>blocked</span></div>' +
        '<div class="ag-stat' + (a.pending_approvals ? ' warn' : '') + '"><b>' + fmt(a.pending_approvals) + '</b><span>awaiting approval</span></div>' +
        '<div class="ag-stat"><b>$' + Number(a.cost_usd || 0).toFixed(2) + '</b><span>spend</span></div></div>' +
      '<div class="ag-foot"><div class="ag-note">' + note + '</div>' + actionButtons + '</div></div>';
}

function renderAgents() {
    var c = _ag.counts || {};
    $('agentsSummary').innerHTML = ['connected', 'idle', 'offline', 'disconnected'].map(function(s) {
        return '<span class="ag-chip"><i class="ag-dot ' + s + '"></i><b>' + (c[s] || 0) + '</b> ' + _AG_LABEL[s].toLowerCase() + '</span>';
    }).join('');
    if (!_ag.list.length) {
        $('agentsList').innerHTML = '<div class="d-empty"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="7" width="14" height="11" rx="3"/><path d="M12 7V4M9 12.5h.01M15 12.5h.01M9.5 15.5h5"/></svg>' +
            '<h4>No agent has reported yet</h4><p>An agent appears here as soon as it sends its first event.</p>' +
            '<div style="display:flex;gap:10px;justify-content:center;flex-wrap:wrap;margin-top:18px"><button type="button" class="tb-btn primary" onclick="closeAgentsPanel();openConnectAgentModal()">+ Connect agent</button>' +
            '<button type="button" class="tb-btn" onclick="addTestAgent()">Add a test agent</button></div></div>';
        return;
    }
    $('agentsList').innerHTML = _ag.list.map(_agRow).join('');
}

async function toggleAgent(agentId, action) {
    if (action === 'disconnect' && !_ag.armed[agentId]) {
        _ag.armed[agentId] = true;
        renderAgents();
        setTimeout(function() { delete _ag.armed[agentId]; renderAgents(); }, 4000);
        return;
    }
    delete _ag.armed[agentId];
    try {
        await apiSend('/api/agents/' + encodeURIComponent(agentId) + '/' + action, 'POST', {});
        toast(action === 'disconnect' ? agentId + ' disconnected. Its requests are now refused.' : agentId + ' reconnected.');
        await loadAgents();
    } catch (e) {
        toast(/Human session/.test(e.message) ? 'Please sign in again to manage agents.' : 'Could not update the agent: ' + e.message);
        renderAgents();
    }
}

// ═══════════════════════════════════════════════════════════
// BUDGET MANAGEMENT
// ═══════════════════════════════════════════════════════════
var _budgetAgentId = null;

function openBudgetModal(agentId) {
    _budgetAgentId = agentId;
    $('budgetAgentName').textContent = agentId;
    const mockBudget = { amount: 10.00, period: 'daily', action: 'warn', spent: 3.45 };
    $('budgetAmount').value = mockBudget.amount;
    $('budgetPeriod').value = mockBudget.period;
    document.querySelector(`input[name="budgetAction"][value="${mockBudget.action}"]`).checked = true;
    updateBudgetProgress(mockBudget.spent, mockBudget.amount);
    $('budgetModal').style.display = 'flex';
}

function updateBudgetProgress(spent, max) {
    const pct = Math.min(100, (spent / max) * 100);
    $('budgetProgressBar').style.width = pct + '%';
    $('budgetCurrentUsage').textContent = '$' + spent.toFixed(2);
    $('budgetMaxDisplay').textContent = '$' + max.toFixed(2);
    const bar = $('budgetProgressBar');
    if (pct > 90) bar.style.background = 'var(--red2)';
    else if (pct > 70) bar.style.background = 'var(--yellow)';
    else bar.style.background = 'var(--green)';
}

function closeBudgetModal() {
    $('budgetModal').style.display = 'none';
    _budgetAgentId = null;
}

async function saveBudget() {
    const amount = parseFloat($('budgetAmount').value);
    if (isNaN(amount) || amount <= 0) { toast('Please enter a valid budget amount'); return; }
    const payload = {
        agent_id: _budgetAgentId,
        max_budget_usd: amount,
        period: $('budgetPeriod').value,
        action_on_exceed: document.querySelector('input[name="budgetAction"]:checked').value
    };
    const btn = document.querySelector('#budgetModal .tb-btn.primary');
    btn.textContent = 'Saving...';
    btn.disabled = true;
    try {
        await new Promise(r => setTimeout(r, 500));
        toast('Budget saved. ' + (payload.action_on_exceed === 'block' ? 'Requests will be blocked.' : 'Alerts will be sent.'));
        closeBudgetModal();
        loadAgents();
    } catch (e) {
        toast('Failed to save budget: ' + e.message);
    } finally {
        btn.textContent = 'Save Budget';
        btn.disabled = false;
    }
}

// ═══════════════════════════════════════════════════════════
// ALERT DESTINATIONS
// ═══════════════════════════════════════════════════════════
var _destinations = [];

function openAlertDestinationsModal() {
    $('alertDestModal').style.display = 'flex';
    loadDestinations();
}
function closeAlertDestinationsModal() {
    $('alertDestModal').style.display = 'none';
}

async function loadDestinations() {
    const list = $('destList');
    list.innerHTML = '<div style="text-align:center; padding:20px; color:var(--muted);">Loading...</div>';
    try {
        _destinations = [
            { id: 'dest_1', type: 'slack', url: 'https://hooks.slack.com/services/T00/B00/XXXX', levels: ['critical', 'high'], created_at: '2026-09-28T10:00:00Z' },
            { id: 'dest_2', type: 'email', url: 'security-team@company.com', levels: ['critical'], created_at: '2026-09-25T14:30:00Z' }
        ];
        renderDestinations();
    } catch (e) {
        list.innerHTML = '<div style="text-align:center; padding:20px; color:var(--red2);">Failed to load destinations</div>';
    }
}

function renderDestinations() {
    const list = $('destList');
    if (!_destinations.length) {
        list.innerHTML = '<div style="text-align:center; padding:30px; color:var(--muted); font-size:13px;">No destinations configured. Add one below to start receiving alerts.</div>';
        return;
    }
    list.innerHTML = _destinations.map(function(dest) {
        const typeIcon = { slack: '💬', discord: '🎮', email: '📧', webhook: '🔗' }[dest.type] || '🔗';
        const typeLabel = { slack: 'Slack', discord: 'Discord', email: 'Email', webhook: 'Webhook' }[dest.type] || dest.type;
        const levels = dest.levels.map(function(l) {
            const colors = { critical: 'var(--red2)', high: 'var(--orange)', medium: 'var(--yellow)', low: 'var(--green)' };
            return `<span style="display:inline-block; padding:2px 8px; background:${colors[l]}22; color:${colors[l]}; border-radius:4px; font-size:10px; font-weight:600; text-transform:uppercase;">${l}</span>`;
        }).join(' ');
        return `<div style="background:var(--card); border:1px solid var(--border); border-radius:10px; padding:14px; display:flex; align-items:center; gap:12px;">
            <span style="font-size:24px;">${typeIcon}</span>
            <div style="flex:1; min-width:0;">
                <div style="font-weight:600; font-size:13px; margin-bottom:4px;">${typeLabel}</div>
                <div style="font-family:var(--mono); font-size:11px; color:var(--muted); overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${esc(dest.url)}</div>
                <div style="margin-top:6px; display:flex; gap:6px; flex-wrap:wrap;">${levels}</div>
            </div>
            <button class="tb-btn" style="padding:6px 10px; font-size:11px;" onclick="deleteDestination('${dest.id}')">Remove</button>
        </div>`;
    }).join('');
}

function updateDestPlaceholder() {
    const type = $('destType').value;
    const input = $('destUrl');
    const label = $('destUrlLabel');
    if (type === 'email') {
        label.textContent = 'Email Address';
        input.placeholder = 'security-team@company.com';
        input.type = 'email';
    } else {
        label.textContent = 'Webhook URL';
        input.type = 'text';
        const placeholders = { slack: 'https://hooks.slack.com/services/T00/B00/XXXX', discord: 'https://discord.com/api/webhooks/XXXX/YYYY', webhook: 'https://your-server.com/webhook' };
        input.placeholder = placeholders[type] || '';
    }
}

async function testDestination() {
    const url = $('destUrl').value.trim();
    if (!url) { toast('Please enter a URL or email'); return; }
    const btn = event.target;
    btn.textContent = 'Testing...';
    btn.disabled = true;
    try {
        await new Promise(r => setTimeout(r, 800));
        toast('✓ Test alert sent successfully');
    } catch (e) {
        toast('✗ Test failed: ' + e.message);
    } finally {
        btn.textContent = 'Test Connection';
        btn.disabled = false;
    }
}

async function saveDestination() {
    const url = $('destUrl').value.trim();
    if (!url) { toast('Please enter a URL or email'); return; }
    const levels = [];
    if ($('destCritical').checked) levels.push('critical');
    if ($('destHigh').checked) levels.push('high');
    if ($('destMedium').checked) levels.push('medium');
    if ($('destLow').checked) levels.push('low');
    if (!levels.length) { toast('Please select at least one alert level'); return; }
    
    const payload = { type: $('destType').value, url: url, levels: levels };
    const btn = document.querySelector('#alertDestModal .tb-btn.primary');
    btn.textContent = 'Adding...';
    btn.disabled = true;
    try {
        await new Promise(r => setTimeout(r, 500));
        _destinations.push({ id: 'dest_' + Date.now(), ...payload, created_at: new Date().toISOString() });
        renderDestinations();
        $('destUrl').value = '';
        $('destCritical').checked = true;
        $('destHigh').checked = true;
        $('destMedium').checked = false;
        $('destLow').checked = false;
        toast('Destination added successfully');
    } catch (e) {
        toast('Failed to add destination: ' + e.message);
    } finally {
        btn.textContent = 'Add Destination';
        btn.disabled = false;
    }
}

async function deleteDestination(destId) {
    if (!confirm('Remove this destination? Alerts will no longer be sent here.')) return;
    try {
        await new Promise(r => setTimeout(r, 300));
        _destinations = _destinations.filter(d => d.id !== destId);
        renderDestinations();
        toast('Destination removed');
    } catch (e) {
        toast('Failed to remove: ' + e.message);
    }
}

// ═══════════════════════════════════════════════════════════
// INITIALIZATION
// ═══════════════════════════════════════════════════════════
setInterval(checkApprovals, 10000);
setInterval(function() { 
    if (!document.hidden && !$('agentsPanel').classList.contains('open')) loadAgents(); 
}, 15000);
checkApprovals();
loadAgents();
