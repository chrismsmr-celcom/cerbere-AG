// ─────────────────────────────────────────────────────────────
// REFRESH LOOP & API KEYS
// ─────────────────────────────────────────────────────────────
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
