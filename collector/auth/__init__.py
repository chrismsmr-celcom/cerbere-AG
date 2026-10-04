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

from .blueprint import auth_bp  # noqa: F401

from .config import (  # noqa: F401
    MAGIC_LINK_TTL_SECONDS,
    HUMAN_SESSION_TTL_SECONDS,
    MAGIC_LINK_TOKEN_BYTES,
    MAGIC_LINK_COOKIE,
    MAGIC_LINK_ENABLED,
    _env_first,
    SMTP_HOST,
    SMTP_PORT,
    SMTP_USERNAME,
    SMTP_PASSWORD,
    SMTP_FROM,
    SMTP_USE_TLS,
    APP_BASE_URL,
    PROTECTED_ENDPOINTS,
)

from .utils import (  # noqa: F401
    safe_compare,
    hash_key,
    _hash_magic_token,
    _utcnow,
    _utc_iso,
    _parse_datetime,
    _normalize_email,
    _valid_email,
)

from .users import (  # noqa: F401
    _db_execute,
    _user_by_email,
    _user_by_id,
    _user_is_active,
)

from .magic_link import (  # noqa: F401
    _ensure_magic_link_table,
    _invalidate_existing_magic_links,
    _store_magic_link,
    _consume_magic_link,
    _build_magic_link,
    _send_magic_link_email,
)

from .sessions import (  # noqa: F401
    _human_session_token,
    _resolve_human_session,
    _set_human_session,
    _clear_human_session,
    _session_token,
    _session_org_id,
)

from .api_keys import (  # noqa: F401
    _ensure_api_keys_table,
    _ensure_api_keys_table_safe,
    _lookup_org_by_key,
    resolve_org_id,
)

from .identity_resolution import (  # noqa: F401
    _build_user_identity,
    resolve_full_identity,
)

from .middleware import (  # noqa: F401
    require_auth,
    require_human_auth,
    check_auth,
)

from .rbac import (  # noqa: F401
    authorize_resource_access,
    require_role,
    require_permission,
)

from .audit_helpers import (  # noqa: F401
    _audit_login,
)

from .pages import (  # noqa: F401
    SUPABASE_LOGIN_HTML,
    LOGIN_HTML,
    SIGNUP_HTML,
)

from .routes_supabase import (  # noqa: F401
    supabase_public_config,
    supabase_session,
)

from .routes_login import (  # noqa: F401
    login,
    verify_magic_link,
)

from .routes_signup import (  # noqa: F401
    signup,
)

from .routes_session import (  # noqa: F401
    auth_login,
    auth_me,
    logout,
    healthz,
    dashboard,
)

from .routes_keys import (  # noqa: F401
    create_api_key,
    list_api_keys,
    revoke_api_key,
)

from collector.supabase_auth import (  # noqa: F401,E402
    SUPABASE_ANON_KEY,
    SUPABASE_ENABLED,
    SUPABASE_URL,
    SupabaseAuthError,
    get_or_provision_user,
    verify_supabase_jwt,
)
