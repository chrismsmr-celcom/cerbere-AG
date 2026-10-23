// ─────────────────────────────────────────────────────────────
// SHADOW MODE TOGGLES (SaaS-controlled per-agent execution mode)
// ─────────────────────────────────────────────────────────────
// Redéfinit renderObservedAgents (70-connect.js) pour ajouter un
// bouton Shadow/Enforce par agent. La concaténation des src/*.js
// fait que cette définition remplace la précédente.

function renderObservedAgents() {
    var el = $('connectAgentList');
    if (!el) return;
    var agents = extractObservedAgents();
    if (!agents.length) {
        el.innerHTML = '<div class="empty" style="padding:18px 8px">No agent telemetry observed yet.</div>';
        return;
    }
    el.innerHTML = agents.slice(0, 10).map(function (agent) {
        var status = observedAgentStatus(agent.timestamp);
        var when = agent.timestamp ? String(agent.timestamp).replace('T', ' ').slice(0, 19) : 'recent telemetry';
        var aid = esc(agent.id);
        return '<div class="connect-agent-row" style="display:flex;align-items:center;gap:8px">' +
            '<span class="connect-agent-dot ' + status.cls + '"></span>' +
            '<span class="connect-agent-name">' + aid + '</span>' +
            '<span class="connect-agent-status">' + esc(status.label) + ' · ' + esc(when) + '</span>' +
            '<button type="button" class="agent-mode-toggle" data-agent="' + aid + '" data-mode="loading"' +
            ' title="Basculer Shadow / Enforce (prise en effet < 10 s)">' +
            '<span class="mode-label">…</span></button>' +
            '</div>';
    }).join('');
    // Charger le mode courant de chaque agent affiché.
    el.querySelectorAll('.agent-mode-toggle').forEach(function (btn) {
        fetch('/api/agent/mode?agent_id=' + encodeURIComponent(btn.dataset.agent), { credentials: 'same-origin' })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (data) {
                if (!data) { btn.dataset.mode = 'unknown'; btn.querySelector('.mode-label').textContent = 'Enforce'; return; }
                applyModeButton(btn, data.mode);
            })
            .catch(function () { btn.dataset.mode = 'unknown'; btn.querySelector('.mode-label').textContent = 'Enforce'; });
    });
}

function applyModeButton(btn, mode) {
    var shadow = mode === 'shadow';
    btn.dataset.mode = mode;
    btn.classList.toggle('shadow-on', shadow);
    btn.querySelector('.mode-label').textContent = shadow ? 'Shadow ON' : 'Enforce';
}

document.addEventListener('click', function (e) {
    var btn = e.target.closest ? e.target.closest('.agent-mode-toggle') : null;
    if (!btn || btn.dataset.mode === 'loading') return;
    var next = btn.dataset.mode === 'shadow' ? 'enforce' : 'shadow';
    btn.disabled = true;
    fetch('/api/agents/' + encodeURIComponent(btn.dataset.agent) + '/mode', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: next })
    })
        .then(function (r) { return r.ok ? r.json() : r.json().then(function (j) { throw new Error(j.error || ('HTTP ' + r.status)); }); })
        .then(function (data) {
            applyModeButton(btn, data.mode);
            toast('Agent ' + btn.dataset.agent + ' → ' + data.mode + ' (actif < 10 s)');
        })
        .catch(function (err) { toast('Mode change failed: ' + err.message); })
        .finally(function () { btn.disabled = false; });
});