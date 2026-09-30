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
"""

from collector.api.helpers import api_bp  # noqa: F401

# Ré-exports pour compatibilité avec les imports existants (app.py, tests, SDK).
from collector.api.helpers import (  # noqa: F401
    logger,
    decision_engine,
    get_decision_signer,
    is_server_registered_tool,
    _as_json,
    _iso_utc,
    _db_run,
    _sqlite_connect,
    _request_agent_id,
    _agent_status,
    _reject_if_agent_disconnected,
    _serialize_event,
    _AGENT_SEEN,       # ré-exporté pour les fixtures de tests (reset)
    _AGENT_STATUS,     # idem
    _touch_agent,
    _agent_state,
)

# Compatibilité monkeypatch des tests : collector.api.require_human_auth
from collector.auth import require_auth, require_human_auth  # noqa: F401

# --- Modules de routes : chacun enregistre ses routes sur api_bp à l'import. ---
# ⚠️ Style ABSOLU obligatoire (from collector.api import X échouerait : package
# partiellement initialisé). PAS de try/except ici : une erreur doit éclater.
import collector.api.static_assets  # noqa: F401,E402
import collector.api.spans          # noqa: F401,E402
import collector.api.traces         # noqa: F401,E402
import collector.api.timeline       # noqa: F401,E402
import collector.api.metrics        # noqa: F401,E402
import collector.api.dashboard      # noqa: F401,E402
import collector.api.decisions      # noqa: F401,E402
import collector.api.agents         # noqa: F401,E402
import collector.api.approvals      # noqa: F401,E402
import collector.api.health         # noqa: F401,E402
import collector.api.alert_rules    # noqa: F401,E402
import collector.api.settings       # noqa: F401,E402
