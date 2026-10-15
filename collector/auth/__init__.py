"""Package d'authentification de Cerbere (ancien collector/auth.py de ~4000 lignes).

Ce package conserve exactement la surface publique de l'ancien module : tout ce qui faisait
`from collector.auth import X` continue de fonctionner. Découpage :

  blueprint.py            Blueprint Flask `auth_bp` partagé
  config.py               TTL, cookie, SMTP, PROTECTED_ENDPOINTS
  utils.py                hash, comparaison constante, temps, validation email
  users.py                accès DB aux utilisateurs humains
  magic_link.py           magic link (flow SMTP historique)
  sessions.py             cookie de session humain + session clé API legacy
  api_keys.py             résolution des clés API (platform / système / agent / tables)
  identity_resolution.py  identité résolue (agent, humain, système)
  rbac.py                 authorize_resource_access, require_role, require_permission
  middleware.py           require_auth, require_human_auth, hook before_app_request
  audit_helpers.py        audit des logins
  pages.py                HTML login / login legacy / signup
  routes_*.py             routes Flask (supabase, login, signup, session, clés API)
"""

from collector.supabase_auth import (  # noqa: F401
    SUPABASE_ANON_KEY,
    SUPABASE_ENABLED,
    SUPABASE_URL,
    SupabaseAuthError,
    get_or_provision_user,
    verify_supabase_jwt,
)

from .api_keys import (  # noqa: F401
    _ensure_api_keys_table,
    _ensure_api_keys_table_safe,
    _lookup_org_by_key,
    resolve_org_id,
)
from .audit_helpers import (  # noqa: F401
    _audit_login,
)
from .blueprint import auth_bp  # noqa: F401
from .config import (  # noqa: F401
    APP_BASE_URL,
    HUMAN_SESSION_TTL_SECONDS,
    MAGIC_LINK_COOKIE,
    MAGIC_LINK_ENABLED,
    MAGIC_LINK_TOKEN_BYTES,
    MAGIC_LINK_TTL_SECONDS,
    PROTECTED_ENDPOINTS,
    SMTP_FROM,
    SMTP_HOST,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_USE_TLS,
    SMTP_USERNAME,
    _env_first,
)
from .identity_resolution import (  # noqa: F401
    _build_user_identity,
    resolve_full_identity,
)
from .magic_link import (  # noqa: F401
    _build_magic_link,
    _consume_magic_link,
    _ensure_magic_link_table,
    _invalidate_existing_magic_links,
    _send_magic_link_email,
    _store_magic_link,
)
from .middleware import (  # noqa: F401
    check_auth,
    require_auth,
    require_human_auth,
)
from .pages import (  # noqa: F401
    LOGIN_HTML,
    SIGNUP_HTML,
    SUPABASE_LOGIN_HTML,
)
from .rbac import (  # noqa: F401
    authorize_resource_access,
    require_permission,
    require_role,
)
from .routes_keys import (  # noqa: F401
    create_api_key,
    list_api_keys,
    revoke_api_key,
)
from .routes_login import (  # noqa: F401
    login,
    verify_magic_link,
)
from .routes_session import (  # noqa: F401
    auth_login,
    auth_me,
    dashboard,
    healthz,
    logout,
)
from .routes_signup import (  # noqa: F401
    signup,
)
from .routes_supabase import (  # noqa: F401
    supabase_public_config,
    supabase_session,
)
from .sessions import (  # noqa: F401
    _clear_human_session,
    _human_session_token,
    _resolve_human_session,
    _session_org_id,
    _session_token,
    _set_human_session,
)
from .users import (  # noqa: F401
    _db_execute,
    _user_by_email,
    _user_by_id,
    _user_is_active,
)
from .utils import (  # noqa: F401
    _hash_magic_token,
    _normalize_email,
    _parse_datetime,
    _utc_iso,
    _utcnow,
    _valid_email,
    hash_key,
    safe_compare,
)
