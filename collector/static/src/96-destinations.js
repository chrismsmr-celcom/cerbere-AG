// ═══════════════════════════════════════════════════════════
// ALERT DESTINATIONS
// ═══════════════════════════════════════════════════════════
var _destinations = [];

function openAlertDestinationsModal() {
    $('alertDestModal').style.display = 'flex';
    loadDestinations();
}
function closeAlertDestinationsModal() {
    $('alertDestModal').style.display = 'none';
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

function updateDestPlaceholder() {
    const type = $('destType').value;
    const input = $('destUrl');
    const label = $('destUrlLabel');
    if (type === 'email') {
        label.textContent = 'Email Address';
        input.placeholder = 'security-team@company.com';
        input.type = 'email';
    } else {
        label.textContent = 'Webhook URL';
        input.type = 'text';
        const placeholders = { slack: 'https://hooks.slack.com/services/T00/B00/XXXX', discord: 'https://discord.com/api/webhooks/XXXX/YYYY', webhook: 'https://your-server.com/webhook' };
        input.placeholder = placeholders[type] || '';
    }
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

function destIcon(type) {
    var tiles = { slack: '#4A154B', discord: '#5865F2', email: '#2b3040', webhook: '#2b3040' };
    var names = { slack: 'slack', discord: 'discord', email: 'mail', webhook: 'webhook' };
    return '<span style="width:38px;height:38px;border-radius:10px;background:' + (tiles[type] || '#2b3040') +
           ';color:#fff;display:inline-flex;align-items:center;justify-content:center;flex:none">' +
           iconSvg(names[type] || 'webhook', 20) + '</span>';
}
