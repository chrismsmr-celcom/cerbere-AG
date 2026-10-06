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
        el.innerHTML = triggeredByMetric[metric] ? '<span class="alert-flag">' + iconSvg('alert', 12) + ' seuil dépassé</span>' : '';
    });
}
