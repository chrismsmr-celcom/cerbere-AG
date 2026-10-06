// ═══════════════════════════════════════════════════════════
// BUDGET MANAGEMENT
// ═══════════════════════════════════════════════════════════
var _budgetAgentId = null;

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

function closeBudgetModal() {
    $('budgetModal').style.display = 'none';
    _budgetAgentId = null;
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
