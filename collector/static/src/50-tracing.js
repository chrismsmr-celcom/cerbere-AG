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
