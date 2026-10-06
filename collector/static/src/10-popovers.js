// ─────────────────────────────────────────────────────────────
// GENERIC POPOVER PLUMBING
// ─────────────────────────────────────────────────────────────
function closeAllPopovers() {
    ['cardMenuPopover', 'infoPopover', 'auditExportMenu'].forEach(function(id) {
        var el = $(id);
        if (el) el.classList.remove('open');
    });
}
document.addEventListener('click', function(e) {
    if (e.target.closest && (e.target.closest('.menu') || e.target.closest('.info') || e.target.closest('.popover') || e.target.closest('.audit-export-wrap'))) return;
    closeAllPopovers();
});
function positionPopover(el, anchorEl) {
    var r = anchorEl.getBoundingClientRect();
    el.style.display = 'block';
    var w = el.offsetWidth || 180;
    var left = Math.min(r.left, window.innerWidth - w - 12);
    el.style.top = (r.bottom + 6) + 'px';
    el.style.left = Math.max(8, left) + 'px';
}

// ─────────────────────────────────────────────────────────────
// INFO TOOLTIPS
// ─────────────────────────────────────────────────────────────
var INFO_TEXT = {
    traffic: "Volume de requêtes et temps de réponse de vos agents sur la période sélectionnée. Basculez AVG/p50/p90/p95 pour changer la statistique affichée.",
    cost: "Consommation de tokens et coût par requête. Utilisez « + New alert » sur une carte pour être averti visuellement quand un seuil est dépassé.",
    guardrails: "Nombre de requêtes ayant déclenché un contrôle de sécurité (injection, PII, politique d'outil...) et répartition par type de contrôle."
};
function showInfoPopover(evt, key) {
    evt.stopPropagation();
    var pop = $('infoPopover');
    if (pop.classList.contains('open') && pop.dataset.key === key) { closeAllPopovers(); return; }
    closeAllPopovers();
    pop.textContent = INFO_TEXT[key] || '';
    pop.dataset.key = key;
    pop.classList.add('open');
    positionPopover(pop, evt.currentTarget);
}

// ─────────────────────────────────────────────────────────────
// CARD MENU
// ─────────────────────────────────────────────────────────────
var _cardMenuTarget = null;
function openCardMenu(evt, btn) {
    evt.stopPropagation();
    var card = btn.closest('.card');
    var pop = $('cardMenuPopover');
    if (pop.classList.contains('open') && _cardMenuTarget === card) { closeAllPopovers(); return; }
    closeAllPopovers();
    _cardMenuTarget = card;
    pop.innerHTML = '<button onclick="exportCardData(\'json\')">Copier en JSON</button>' +
                    '<button onclick="exportCardData(\'csv\')">Exporter en CSV</button>' +
                    '<button onclick="hideCard()">Masquer cette carte</button>';
    pop.classList.add('open');
    positionPopover(pop, btn);
}
function extractCardRows(card) {
    var label = (card.querySelector('.clabel') || {}).textContent || 'metric';
    var rows = [];
    var hero = card.querySelector('.hero');
    if (hero) rows.push([label.trim(), hero.textContent.trim()]);
    card.querySelectorAll('.legend span').forEach(function(sp) { rows.push([sp.textContent.trim(), '']); });
    return rows;
}
function exportCardData(fmt) {
    if (!_cardMenuTarget) return;
    var rows = extractCardRows(_cardMenuTarget);
    var label = (_cardMenuTarget.querySelector('.clabel') || {}).textContent || 'card';
    label = label.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-');
    if (fmt === 'json') {
        var obj = {};
        rows.forEach(function(r) { obj[r[0]] = r[1]; });
        navigator.clipboard.writeText(JSON.stringify(obj, null, 2)).then(function() { toast('Copié en JSON'); }).catch(function() { toast('Impossible de copier'); });
    } else {
        var csv = rows.map(function(r) { return '"' + r[0].replace(/"/g, '""') + '","' + r[1].replace(/"/g, '""') + '"'; }).join('\n');
        var blob = new Blob([csv], { type: 'text/csv' });
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = label + '.csv';
        document.body.appendChild(a); a.click(); a.remove();
        toast('Export CSV lancé');
    }
    closeAllPopovers();
}
function hideCard() {
    if (!_cardMenuTarget) return;
    _cardMenuTarget.style.display = 'none';
    state.hiddenCards = (state.hiddenCards || 0) + 1;
    closeAllPopovers();
}
