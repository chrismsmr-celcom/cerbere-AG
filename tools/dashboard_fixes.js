/*
 * Correctifs appliqués par tools/migrate_dashboard.py (une seule fois, pendant la migration).
 * Chaque déclaration de premier niveau REMPLACE la fonction/variable de même nom dans src/.
 * Une déclaration précédée de "// @module NN-nom" et inexistante est AJOUTÉE à ce module.
 */

// ── Icônes officielles (remplacent les emojis) ───────────────────────────────
// Slack et Discord : Simple Icons (CC0). Mail, webhook, alerte, check, ban : Lucide (ISC).
// @module 00-core
var ICON_PATHS_EXTRA = {
    slack: '<path fill="currentColor" d="M5.042 15.165a2.528 2.528 0 0 1-2.52 2.523A2.528 2.528 0 0 1 0 15.165a2.527 2.527 0 0 1 2.522-2.52h2.52v2.52zM6.313 15.165a2.527 2.527 0 0 1 2.521-2.52 2.527 2.527 0 0 1 2.521 2.52v6.313A2.528 2.528 0 0 1 8.834 24a2.528 2.528 0 0 1-2.521-2.522v-6.313zM8.834 5.042a2.528 2.528 0 0 1-2.521-2.52A2.528 2.528 0 0 1 8.834 0a2.528 2.528 0 0 1 2.521 2.522v2.52H8.834zM8.834 6.313a2.528 2.528 0 0 1 2.521 2.521 2.528 2.528 0 0 1-2.521 2.521H2.522A2.528 2.528 0 0 1 0 8.834a2.528 2.528 0 0 1 2.522-2.521h6.312zM18.956 8.834a2.528 2.528 0 0 1 2.522-2.521A2.528 2.528 0 0 1 24 8.834a2.528 2.528 0 0 1-2.522 2.521h-2.522V8.834zM17.688 8.834a2.528 2.528 0 0 1-2.523 2.521 2.527 2.527 0 0 1-2.52-2.521V2.522A2.527 2.527 0 0 1 15.165 0a2.528 2.528 0 0 1 2.523 2.522v6.312zM15.165 18.956a2.528 2.528 0 0 1 2.523 2.522A2.528 2.528 0 0 1 15.165 24a2.527 2.527 0 0 1-2.52-2.522v-2.522h2.52zM15.165 17.688a2.527 2.527 0 0 1-2.52-2.523 2.526 2.526 0 0 1 2.52-2.52h6.313A2.527 2.527 0 0 1 24 15.165a2.528 2.528 0 0 1-2.522 2.523h-6.313z"/>',
    discord: '<path fill="currentColor" d="M20.317 4.3698a19.7913 19.7913 0 00-4.8851-1.5152.0741.0741 0 00-.0785.0371c-.211.3753-.4447.8648-.6083 1.2495-1.8447-.2762-3.68-.2762-5.4868 0-.1636-.3933-.4058-.8742-.6177-1.2495a.077.077 0 00-.0785-.037 19.7363 19.7363 0 00-4.8852 1.515.0699.0699 0 00-.0321.0277C.5334 9.0458-.319 13.5799.0992 18.0578a.0824.0824 0 00.0312.0561c2.0528 1.5076 4.0413 2.4228 5.9929 3.0294a.0777.0777 0 00.0842-.0276c.4616-.6304.8731-1.2952 1.226-1.9942a.076.076 0 00-.0416-.1057c-.6528-.2476-1.2743-.5495-1.8722-.8923a.077.077 0 01-.0076-.1277c.1258-.0943.2517-.1923.3718-.2914a.0743.0743 0 01.0776-.0105c3.9278 1.7933 8.18 1.7933 12.0614 0a.0739.0739 0 01.0785.0095c.1202.099.246.1981.3728.2924a.077.077 0 01-.0066.1276 12.2986 12.2986 0 01-1.873.8914.0766.0766 0 00-.0407.1067c.3604.698.7719 1.3628 1.225 1.9932a.076.076 0 00.0842.0286c1.961-.6067 3.9495-1.5219 6.0023-3.0294a.077.077 0 00.0313-.0552c.5004-5.177-.8382-9.6739-3.5485-13.6604a.061.061 0 00-.0312-.0286zM8.02 15.3312c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9555-2.4189 2.157-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419 0 1.3332-.9555 2.4189-2.1569 2.4189zm7.9748 0c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9554-2.4189 2.1569-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419 0 1.3332-.946 2.4189-2.1568 2.4189Z"/>',
    mail: '<g fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m22 7-8.991 5.727a2 2 0 0 1-2.009 0L2 7"/><rect x="2" y="4" width="20" height="16" rx="2"/></g>',
    webhook: '<g fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 16.98h-5.99c-1.1 0-1.95.94-2.48 1.9A4 4 0 0 1 2 17c.01-.7.2-1.4.57-2"/><path d="m6 17 3.13-5.78c.53-.97.1-2.18-.5-3.1a4 4 0 1 1 6.89-4.06"/><path d="m12 6 3.13 5.73C15.66 12.7 16.9 13 18 13a4 4 0 0 1 0 8"/></g>',
    alert: '<g fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/></g>',
    check: '<g fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></g>',
    ban: '<g fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M4.929 4.929 19.07 19.071"/></g>'
};

// @module 00-core
function iconSvg(name, size) {
    var p = ICON_PATHS_EXTRA[name] || ICON_PATHS[name];
    if (!p) return '';
    var s = size || 16;
    return '<svg viewBox="0 0 24 24" width="' + s + '" height="' + s + '" aria-hidden="true" focusable="false" style="flex:none;vertical-align:-2px">' + p + '</svg>';
}

// ── Sécurité : esc() ne doit pas transformer 0 en chaîne vide ────────────────
var esc = function(v) {
    return String(v === null || v === undefined ? '' : v).replace(/[&<>'"]/g, function(c) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[c];
    });
};

// ── Sécurité : le nom du modèle vient de l'agent. Il ne doit JAMAIS être injecté dans un
//    handler inline (les entités HTML sont décodées AVANT l'exécution du JS). On passe par data-name.
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

// ── Alertes : drapeau "seuil dépassé" avec une vraie icône ───────────────────
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

// ── Rafraîchissement : ne vide plus le dashboard quand une route échoue, charge les règles
//    d'alerte (elles n'étaient jamais chargées au démarrage), évite l'empilement de requêtes ────
function refreshAll() {
    // Verrou auto-libéré après 20 s : évite d'empiler des requêtes sur une connexion lente
    if (window._refreshBusy && Date.now() - window._refreshBusy < 20000) return Promise.resolve();
    window._refreshBusy = Date.now();

    function safeApi(endpoint) {
        return api(endpoint).catch(function(e) {
            console.warn("API endpoint failed (non-fatal):", endpoint, e.message);
            return null;
        });
    }

    return Promise.all([
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
        safeApi('/api/audit/stats'),
        safeApi('/api/checks/daily'),
        safeApi('/api/models/daily'),
        safeApi('/api/alert-rules')
    ]).then(function(results) {
        // Une route en échec (null) garde la dernière valeur connue au lieu de vider l'écran
        function take(i, key, fallback) {
            if (results[i] !== null && results[i] !== undefined) state[key] = results[i];
            else if (state[key] === undefined) state[key] = fallback;
        }
        take(0, 'metrics', {});
        take(1, 'traces', []);
        take(2, 'detection', {});
        take(3, 'models', []);
        take(4, 'checksBreakdown', []);
        take(5, 'heatmap', { cells: [] });
        take(6, 'expensive', []);
        take(7, 'costTrend', []);
        take(8, 'latencyDist', {});
        take(9, 'recentEvents', []);
        take(10, 'dailyTrend', []);
        take(11, 'audit', []);
        take(13, 'checksDaily', []);
        take(14, 'modelsDaily', []);

        var auditStats = results[12];
        if (auditStats) {
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
        }
        if (results[15]) state.alertRules = results[15].alert_rules || [];

        renderObservedAgents();
        try { evaluateAlertRules(); } catch (e) { console.warn('evaluateAlertRules failed', e); }

        var active = document.querySelector('.view.active');
        if (active) showView(active.id.replace('view-', ''));
    }).catch(function(e) {
        console.error("Dashboard refresh failed critically:", e);
    }).finally(function() { window._refreshBusy = 0; });
}

// ── Approbations : pas d'empilement de requêtes, plus d'emoji dans la notification ──────────
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

// ── Trajectoire : icônes de décision en SVG (plus d'emoji) ───────────────────────────────
var _DECISION_ICON = {
    ALLOW: iconSvg('check', 13),
    BLOCK: iconSvg('ban', 13),
    REQUIRE_APPROVAL: iconSvg('alert', 13)
};

// ── Agents : réponse périmée ignorée, verrou anti-empilement, retour visuel immédiat ─────
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

// ── Événements de sécurité : vraie navigation précédent/suivant, erreurs HTTP gérées ─────
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

// ── Éditeur de politique : enregistre réellement la règle ─────────────────────────────────
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

// ── Budgets : lecture et écriture réelles (plus de valeurs fictives) ──────────────────────
async function openBudgetModal(agentId) {
    _budgetAgentId = agentId;
    $('budgetAgentName').textContent = agentId;
    $('budgetAmount').value = '';
    $('budgetPeriod').value = 'daily';
    var warn = document.querySelector('input[name="budgetAction"][value="warn"]');
    if (warn) warn.checked = true;
    updateBudgetProgress(0, 0);
    $('budgetModal').style.display = 'flex';
    try {
        var data = await apiGet('/api/budgets/' + encodeURIComponent(agentId));
        var b = data.budget || data;
        var max = Number(b.max_budget_usd != null ? b.max_budget_usd : b.amount);
        if (!isNaN(max) && max > 0) {
            $('budgetAmount').value = max;
            if (b.period) $('budgetPeriod').value = b.period;
            var act = b.action_on_exceed || b.action;
            var radio = act ? document.querySelector('input[name="budgetAction"][value="' + act + '"]') : null;
            if (radio) radio.checked = true;
            updateBudgetProgress(Number(b.spent_usd != null ? b.spent_usd : (b.spent || 0)), max);
        }
    } catch (e) { /* pas encore de budget pour cet agent : formulaire vide */ }
}

function updateBudgetProgress(spent, max) {
    const pct = max > 0 ? Math.min(100, (spent / max) * 100) : 0;
    $('budgetProgressBar').style.width = pct + '%';
    $('budgetCurrentUsage').textContent = '$' + Number(spent || 0).toFixed(2);
    $('budgetMaxDisplay').textContent = max > 0 ? '$' + Number(max).toFixed(2) : 'no limit';
    const bar = $('budgetProgressBar');
    if (pct > 90) bar.style.background = 'var(--red2)';
    else if (pct > 70) bar.style.background = 'var(--yellow)';
    else bar.style.background = 'var(--green)';
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
        await apiSend('/api/budgets/' + encodeURIComponent(_budgetAgentId), 'PUT', payload);
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

// ── Destinations d'alerte : API réelle + icônes officielles (plus d'emojis) ───────────────
// @module 96-destinations
function _normDest(d) {
    var lv = d.levels || d.alert_levels || [];
    if (typeof lv === 'string') {
        try { lv = JSON.parse(lv); } catch (e) { lv = lv.split(','); }
    }
    return {
        id: d.id || d.dest_id,
        type: d.type || d.dest_type || 'webhook',
        url: d.url || d.target || d.address || '',
        levels: (lv || []).map(function(s) { return String(s).trim(); }).filter(Boolean)
    };
}

// @module 96-destinations
function destIcon(type) {
    var tiles = { slack: '#4A154B', discord: '#5865F2', email: '#2b3040', webhook: '#2b3040' };
    var names = { slack: 'slack', discord: 'discord', email: 'mail', webhook: 'webhook' };
    return '<span style="width:38px;height:38px;border-radius:10px;background:' + (tiles[type] || '#2b3040') +
           ';color:#fff;display:inline-flex;align-items:center;justify-content:center;flex:none">' +
           iconSvg(names[type] || 'webhook', 20) + '</span>';
}

async function loadDestinations() {
    const list = $('destList');
    list.innerHTML = '<div style="text-align:center; padding:20px; color:var(--muted);">Loading...</div>';
    try {
        var data = await apiGet('/api/alert-destinations');
        var raw = data.destinations || data.alert_destinations || (Array.isArray(data) ? data : []);
        _destinations = raw.map(_normDest);
        renderDestinations();
    } catch (e) {
        list.innerHTML = '<div style="text-align:center; padding:20px; color:var(--red2);">Failed to load destinations: ' + esc(e.message) + '</div>';
    }
}

function renderDestinations() {
    const list = $('destList');
    if (!_destinations.length) {
        list.innerHTML = '<div style="text-align:center; padding:30px; color:var(--muted); font-size:13px;">No destinations configured. Add one below to start receiving alerts.</div>';
        return;
    }
    const colors = { critical: 'var(--red2)', high: 'var(--orange)', medium: 'var(--yellow)', low: 'var(--green)' };
    const labels = { slack: 'Slack', discord: 'Discord', email: 'Email', webhook: 'Webhook' };
    list.innerHTML = _destinations.map(function(dest) {
        const typeLabel = labels[dest.type] || dest.type;
        const levels = dest.levels.map(function(l) {
            const c = colors[l] || 'var(--muted)';
            return '<span style="display:inline-block; padding:2px 8px; background:color-mix(in srgb, ' + c + ' 16%, transparent); color:' + c + '; border-radius:4px; font-size:10px; font-weight:600; text-transform:uppercase;">' + esc(l) + '</span>';
        }).join(' ');
        return '<div style="background:var(--card); border:1px solid var(--border); border-radius:10px; padding:14px; display:flex; align-items:center; gap:12px;">' +
            destIcon(dest.type) +
            '<div style="flex:1; min-width:0;">' +
                '<div style="font-weight:600; font-size:13px; margin-bottom:4px;">' + esc(typeLabel) + '</div>' +
                '<div style="font-family:var(--mono); font-size:11px; color:var(--muted); overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">' + esc(dest.url) + '</div>' +
                '<div style="margin-top:6px; display:flex; gap:6px; flex-wrap:wrap;">' + levels + '</div>' +
            '</div>' +
            '<button class="tb-btn" style="padding:6px 10px; font-size:11px;" data-id="' + esc(dest.id) + '" onclick="deleteDestination(this.dataset.id)">Remove</button>' +
        '</div>';
    }).join('');
}

async function testDestination() {
    const url = $('destUrl').value.trim();
    if (!url) { toast('Please enter a URL or email'); return; }
    const btn = document.querySelector('#alertDestModal [onclick*="testDestination"]');
    const label = btn ? btn.textContent : '';
    if (btn) { btn.textContent = 'Testing...'; btn.disabled = true; }
    try {
        await apiSend('/api/alert-destinations/test', 'POST', { type: $('destType').value, url: url });
        toast('Test alert sent successfully');
    } catch (e) {
        toast('Test failed: ' + e.message);
    } finally {
        if (btn) { btn.textContent = label || 'Test Connection'; btn.disabled = false; }
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
        await apiSend('/api/alert-destinations', 'POST', payload);
        $('destUrl').value = '';
        $('destCritical').checked = true;
        $('destHigh').checked = true;
        $('destMedium').checked = false;
        $('destLow').checked = false;
        toast('Destination added successfully');
        await loadDestinations();
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
        await apiSend('/api/alert-destinations/' + encodeURIComponent(destId), 'DELETE');
        toast('Destination removed');
        await loadDestinations();
    } catch (e) {
        toast('Failed to remove: ' + e.message);
    }
}
