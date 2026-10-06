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
    if (_ap.busy && Date.now() - _ap.busy < 15000) return;
    _ap.busy = Date.now();
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
            toast(fresh.length === 1 ? 'New action waiting for approval' : fresh.length + ' new actions waiting');
            openApprovalsPanel();
        }
        _ap.booted = true;
    } catch (e) {
        console.error('Failed to fetch approvals', e);
    } finally {
        _ap.busy = 0;
    }
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
