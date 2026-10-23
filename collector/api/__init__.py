"""Package collector.api — endpoints REST (blueprint api_bp).

Découpage de l'ancien api.py monolithique :
  helpers.py     : connexions DB (WAL), signer, registre d'agents, helpers partagés
  static_assets  : logo / favicon
  spans          : ingestion POST /span + events canoniques (Control Room)
  traces         : listes / détails de traces
  timeline       : Trajectory Timeline + Policy Decision Center
  metrics        : métriques globales, detection/llm stats, modèles
  dashboard      : heatmap, breakdowns, trends, audit trail
  decisions      : décisions signées Ed25519 (/api/decide)
  agents         : registre d'agents + kill switch
  approvals      : HITL — file d'approbations
  health         : health / readiness
  alert_rules    : CRUD alert rules
  settings       : budgets par agent, règles de politique, destinations d'alertes
  insights       : agrégations Data flow / Agent graph / Risk vs latency
"""

import collector.api.agents
import collector.api.alert_rules
import collector.api.approvals
import collector.api.dashboard
import collector.api.decisions
import collector.api.health
import collector.api.incidents
import collector.api.insights
import collector.api.metrics
import collector.api.settings
import collector.api.spans

# --- Modules de routes : chacun enregistre ses routes sur api_bp à l'import. ---
# ⚠️ Style ABSOLU obligatoire (from collector.api import X échouerait : package
# partiellement initialisé). PAS de try/except ici : une erreur doit éclater.
import collector.api.static_assets
import collector.api.timeline
import collector.api.traces  # noqa: F401

# Ré-exports pour compatibilité avec les imports existants (app.py, tests, SDK).
from collector.api.helpers import (  # noqa: F401
    _AGENT_SEEN,  # ré-exporté pour les fixtures de tests (reset)
    _AGENT_STATUS,  # idem
    _agent_state,
    _agent_status,
    _as_json,
    _db_run,
    _iso_utc,
    _reject_if_agent_disconnected,
    _request_agent_id,
    _serialize_event,
    _sqlite_connect,
    _touch_agent,
    api_bp,
    decision_engine,
    get_decision_signer,
    is_server_registered_tool,
    logger,
)

# Compatibilité monkeypatch des tests : collector.api.require_human_auth
from collector.auth import require_auth, require_human_auth  # noqa: F401
