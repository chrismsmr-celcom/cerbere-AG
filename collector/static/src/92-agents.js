// ─────────────────────────────────────────────────────────────
// CONNECTED AGENTS & TRAJECTORY
// ─────────────────────────────────────────────────────────────
var _ag = { list: [], counts: {}, armed: {}, timer: null };
var _AG_LABEL = { connected: 'Connected', idle: 'Idle', offline: 'Offline', disconnected: 'Disconnected' };
function openAgentsPanel() {
    _openDrawer('agentsPanel');
    loadAgents();
    if (_ag.timer) clearInterval(_ag.timer);
    _ag.timer = setInterval(loadAgents, 2000);
}
function closeAgentsPanel() {
    _closeDrawer('agentsPanel');
    if (_ag.timer) { clearInterval(_ag.timer); _ag.timer = null; }
}
var _DECISION_ICON = {
    ALLOW: iconSvg('check', 13),
    BLOCK: iconSvg('ban', 13),
    REQUIRE_APPROVAL: iconSvg('alert', 13)
};
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
    if (_ag.busy && Date.now() - _ag.busy < 15000) return;
    _ag.busy = Date.now();
    var seq = _ag.seq = (_ag.seq || 0) + 1;
    try {
        var data = await apiGet('/api/agents');
        if (seq <= (_ag.applied || 0)) return;   // réponse périmée : une action plus récente a déjà mis la liste à jour
        _ag.applied = seq;
        _ag.list = data.agents || [];
        _ag.counts = data.counts || {};
        _syncAgentsBadge();
        if ($('agentsPanel').classList.contains('open') && !Object.keys(_ag.armed).length) renderAgents();
    } catch (e) {
        if ($('agentsPanel').classList.contains('open')) {
            $('agentsList').innerHTML = '<div class="d-empty"><h4>Could not load agents</h4><p>' + esc(e.message) + '. It will retry automatically.</p></div>';
        }
    } finally {
        _ag.busy = 0;
    }
}
function _agSub(a) {
    var parts = [];
    if (a.name && a.name !== a.agent_id) parts.push(a.agent_id);
    if (a.sdk_version) parts.push('SDK ' + a.sdk_version);
    return parts.join(' · ') || 'Agent';
}

// CORRECTED _agRow function (fixed syntax error from copy-paste)
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
        // Retour visuel immédiat, sans attendre le prochain polling
        var a = (_ag.list || []).find(function(x) { return x.agent_id === agentId; });
        if (a) {
            a.state = (action === 'disconnect') ? 'disconnected' : 'connected';
            if (action === 'disconnect') { a.disconnected_at = new Date().toISOString(); a.disconnected_by = 'you'; }
        }
        _ag.applied = _ag.seq || 0;   // ignore toute réponse de polling partie avant l'action
        renderAgents();
        toast(action === 'disconnect' ? agentId + ' disconnected. Its requests are now refused.' : agentId + ' reconnected.');
        _ag.busy = 0;
        await loadAgents();
    } catch (e) {
        toast(/Human session/.test(e.message) ? 'Please sign in again to manage agents.' : 'Could not update the agent: ' + e.message);
        renderAgents();
    }
}
