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
