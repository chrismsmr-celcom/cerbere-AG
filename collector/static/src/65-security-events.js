// ═══════════════════════════════════════════════════════════
// SECURITY EVENT DRAWER & POLICY EDITOR
// ═══════════════════════════════════════════════════════════
function openSecurityEventPanel(eventId) {
    var event = (state.audit || []).find(function(e) { return e.event_id === eventId; });
    if (event) {
        renderSecurityEventPanel(event);
        _openDrawer('securityEventPanel');
        return;
    }
    fetch('/api/audit/event/' + encodeURIComponent(eventId), { credentials: 'include' })
        .then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
        .then(function(data) {
            renderSecurityEventPanel(data);
            _openDrawer('securityEventPanel');
        })
        .catch(function() { toast('Event not found'); });
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
    var current = $('securityEventId').textContent;
    var list = (state.audit || []).slice().sort(function(a, b) {
        return String(a.timestamp || '').localeCompare(String(b.timestamp || ''));
    });
    var i = list.findIndex(function(e) { return e.event_id === current; });
    if (i < 0) { toast('Event not in the current list'); return; }
    var back = (direction === 'previous' || direction === 'prev' || direction < 0);
    var target = list[back ? i - 1 : i + 1];
    if (!target) { toast(back ? 'This is the oldest event' : 'This is the most recent event'); return; }
    renderSecurityEventPanel(target);
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
        await apiSend('/api/policy-rules', 'POST', payload);
        toast('Policy rule saved.');
        closePolicyEditor();
    } catch (e) {
        toast('Failed to save policy: ' + e.message);
    } finally {
        btn.textContent = originalText;
        btn.disabled = false;
    }
}
