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
        return '<label class="fitem"><input type="checkbox" ' + (checked ? 'checked' : '') + ' data-name="' + esc(name) + '" onchange="' + onchange + '(this,this.dataset.name)">' + esc(name) + '</label>';
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
