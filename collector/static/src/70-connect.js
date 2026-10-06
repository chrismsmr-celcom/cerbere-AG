// ─────────────────────────────────────────────────────────────
// CONNECT INTEGRATIONS
// ─────────────────────────────────────────────────────────────
var CONNECT_INTEGRATIONS = {
    python: {target:'connectPython', title:'Python SDK', description:'Native AgentGuard instrumentation. Wrap LLM calls with guard_llm_call and side-effecting tools with guard_tool_call.', code:`pip install agentguard\n\nfrom agentguard_sdk import AgentGuard\n\nguard = AgentGuard(\n    collector_url="https://YOUR_AGENTGUARD_HOST",\n    api_key="YOUR_AGENTGUARD_API_KEY",\n    agent_id="my-agent",\n)\n\n@guard.guard_llm_call\ndef call_model(prompt, model="gpt-5"):\n    from openai import OpenAI\n    return OpenAI().responses.create(model=model, input=prompt)`},
    mcp: {target:'connectMcp', title:'MCP', description:'Use an AgentGuard MCP adapter at the execution boundary.', code:`export AGENTGUARD_API_KEY="YOUR_AGENTGUARD_API_KEY"\nexport AGENTGUARD_COLLECTOR_URL="https://YOUR_AGENTGUARD_HOST"`},
    http: {target:'connectHttp', title:'HTTP Gateway', description:'Language-agnostic ingestion.', code:`curl -X POST "https://YOUR_AGENTGUARD_HOST/api/spans" \\\n  -H "Content-Type: application/json" \\\n  -H "X-API-Key: YOUR_AGENTGUARD_API_KEY"`},
    composio: {target:'connectComposio', title:'Composio', description:'Use AgentGuard immediately before Composio executes a tool.', code:`from agentguard_sdk import AgentGuard\nguard = AgentGuard(collector_url="https://YOUR_AGENTGUARD_HOST", api_key="YOUR_AGENTGUARD_API_KEY", agent_id="composio-agent")`},
    openai: {target:'connectOpenai', title:'OpenAI', description:'AgentGuard wraps the OpenAI call path.', code:`from agentguard_sdk import AgentGuard\nfrom openai import OpenAI\nguard = AgentGuard(collector_url="https://YOUR_AGENTGUARD_HOST", api_key="YOUR_AGENTGUARD_API_KEY", agent_id="openai-agent")`},
    anthropic: {target:'connectAnthropic', title:'Anthropic', description:'Protect Claude requests with the same AgentGuard runtime boundary.', code:`from agentguard_sdk import AgentGuard\nfrom anthropic import Anthropic\nguard = AgentGuard(collector_url="https://YOUR_AGENTGUARD_HOST", api_key="YOUR_AGENTGUARD_API_KEY", agent_id="claude-agent")`},
    langgraph: {target:'connectLanggraph', title:'LangGraph', description:'Framework integration through node and tool wrappers.', code:`from agentguard_sdk import AgentGuard\nguard = AgentGuard(collector_url="https://YOUR_AGENTGUARD_HOST", api_key="YOUR_AGENTGUARD_API_KEY", agent_id="langgraph-agent")`},
    crewai: {target:'connectCrewai', title:'CrewAI', description:'Framework integration through guarded task tools.', code:`from agentguard_sdk import AgentGuard\nguard = AgentGuard(collector_url="https://YOUR_AGENTGUARD_HOST", api_key="YOUR_AGENTGUARD_API_KEY", agent_id="crewai-agent")`}
};

function openConnectAgentModal() {
    var modal = $('connectAgentModal');
    if (!modal) { toast('Connection modal unavailable'); return; }
    modal.classList.add('open');
    document.body.style.overflow = 'hidden';
    showConnectChooser();
    renderObservedAgents();
    renderIcons(modal);
}
var connectModal = $('connectAgentModal');
if (connectModal) {
    connectModal.addEventListener('click', function(e) { if (e.target === connectModal) closeConnectAgentModal(); });
}
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        if ($('connectAgentModal') && $('connectAgentModal').classList.contains('open')) closeConnectAgentModal();
    }
});
function openConnectModal() { openConnectAgentModal(); }
function closeConnectAgentModal() {
    var modal = $('connectAgentModal');
    if (!modal) return;
    modal.classList.remove('open');
    document.body.style.overflow = '';
}
function closeConnectModal() { closeConnectAgentModal(); }
function showConnectChooser() {
    document.querySelectorAll('#connectAgentModal .connect-view').forEach(function(v) { v.classList.remove('active'); });
    var chooser = $('connectChooser');
    if (chooser) chooser.classList.add('active');
}
function showConnectDetail(kind) {
    var cfg = CONNECT_INTEGRATIONS[kind];
    if (!cfg) return;
    document.querySelectorAll('#connectAgentModal .connect-view').forEach(function(v) { v.classList.remove('active'); });
    var target = $(cfg.target);
    if (!target) { toast('Integration view unavailable'); return; }
    target.innerHTML = '<button class="connect-back" type="button" onclick="showConnectChooser()"><span class="ui-icon" data-icon="back"></span> Back to integrations</button>' +
        '<h3>' + esc(cfg.title) + '</h3><p>' + esc(cfg.description) + '</p>' +
        '<div class="connect-code-wrap"><pre class="connect-code" id="connectCode-' + esc(kind) + '">' + esc(cfg.code) + '</pre>' +
        '<button class="connect-copy" type="button" onclick="copyConnectCode(\'' + esc(kind) + '\', this)">Copy</button></div>' +
        '<div class="connect-note"><b>Next:</b> run the integration from your server, send one real event, then return to the dashboard.</div>';
    target.classList.add('active');
    renderIcons(target);
}
function copyConnectCode(kind, button) {
    var cfg = CONNECT_INTEGRATIONS[kind];
    if (!cfg) return;
    var done = function(){ var old=button.textContent; button.textContent='Copied'; setTimeout(function(){ button.textContent=old; }, 1400); };
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(cfg.code).then(done).catch(function(){ toast('Copy failed'); });
        return;
    }
    var ta=document.createElement('textarea'); ta.value=cfg.code; ta.style.position='fixed'; ta.style.opacity='0'; document.body.appendChild(ta); ta.select();
    try{ document.execCommand('copy'); done(); }catch(e){ toast('Copy failed'); } document.body.removeChild(ta);
}
function extractObservedAgents() {
    var candidates=[];
    var add=function(value,timestamp){ if(value===null||value===undefined)return; var id=String(value).trim(); if(!id||id==='undefined'||id==='null')return; candidates.push({id:id,timestamp:timestamp||null}); };
    (state.recentEvents||[]).forEach(function(e){ add(e.agent_id||e.agentId||e.org_id||e.orgId, e.created_at||e.timestamp||e.ts); });
    (state.traces||[]).forEach(function(t){ add(t.agent_id||t.agentId||t.org_id||t.orgId, t.created_at||t.timestamp||t.started_at); });
    (state.spans||[]).forEach(function(s){ add(s.agent_id||s.agentId||s.org_id||s.orgId, s.created_at||s.timestamp||s.ts); });
    var byId={}; candidates.forEach(function(item){ var prev=byId[item.id]; if(!prev||String(item.timestamp||'')>String(prev.timestamp||'')) byId[item.id]=item; });
    return Object.keys(byId).map(function(id){ return byId[id]; }).sort(function(a,b){ return String(b.timestamp||'').localeCompare(String(a.timestamp||'')); });
}
function observedAgentStatus(timestamp){
    if(!timestamp) return {label:'Observed',cls:''};
    var t=Date.parse(String(timestamp).replace(' ','T')); if(isNaN(t)) return {label:'Observed',cls:''};
    var age=Date.now()-t; if(age<5*60*1000) return {label:'Connected',cls:'connected'}; if(age<60*60*1000) return {label:'Idle',cls:'idle'}; return {label:'Offline',cls:''};
}
function renderObservedAgents(){
    var el=$('connectAgentList'); if(!el) return; var agents=extractObservedAgents();
    if(!agents.length){ el.innerHTML='<div class="empty" style="padding:18px 8px">No agent telemetry observed yet.</div>'; return; }
    el.innerHTML=agents.slice(0,10).map(function(agent){ var status=observedAgentStatus(agent.timestamp); var when=agent.timestamp?String(agent.timestamp).replace('T',' ').slice(0,19):'recent telemetry'; return '<div class="connect-agent-row"><span class="connect-agent-dot '+status.cls+'"></span><span class="connect-agent-name">'+esc(agent.id)+'</span><span class="connect-agent-status">'+esc(status.label)+' · '+esc(when)+'</span></div>'; }).join('');
}
