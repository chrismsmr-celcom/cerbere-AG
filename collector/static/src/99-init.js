// ═══════════════════════════════════════════════════════════
// INITIALIZATION
// ═══════════════════════════════════════════════════════════
setInterval(checkApprovals, 2000);
setInterval(function() { 
    if (!document.hidden && !$('agentsPanel').classList.contains('open')) loadAgents(); 
}, 3000);
checkApprovals();
loadAgents();
