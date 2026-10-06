// ─────────────────────────────────────────────────────────────
// DRAWERS SHARED HELPERS
// ─────────────────────────────────────────────────────────────
function _openDrawer(id) { $(id).classList.add('open'); document.body.style.overflow = 'hidden'; }
function _closeDrawer(id) {
    $(id).classList.remove('open');
    if (!document.querySelector('.drawer-wrap.open')) document.body.style.overflow = '';
}
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') { closeApprovalsPanel(); closeAgentsPanel(); closeSecurityEventPanel(); closePolicyEditor(); closeBudgetModal(); closeAlertDestinationsModal(); }
});
function _secondsSince(iso) {
    var t = Date.parse(iso);
    return isNaN(t) ? null : Math.max(0, Math.round((Date.now() - t) / 1000));
}
function _dur(iso) {
    var s = _secondsSince(iso);
    if (s === null) return '—';
    if (s < 45) return 'seconds';
    if (s < 3600) return Math.round(s / 60) + ' min';
    if (s < 86400) return Math.round(s / 3600) + ' h';
    return Math.round(s / 86400) + ' d';
}
function _ago(iso) {
    var d = _dur(iso);
    if (d === '—') return '—';
    return d === 'seconds' ? 'just now' : d + ' ago';
}
