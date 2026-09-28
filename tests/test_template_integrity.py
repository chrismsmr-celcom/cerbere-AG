"""
Garde-fou d'intégrité des templates - filet de sécurité AVANT découpage.

Contexte (issue #4) : collector/auth.py, collector/dashboard.py et
collector/api.py sont des modules historiquement volumineux. Avant et
pendant leur découpage, on fige ici les invariants observables afin que
chaque extraction incrémentale soit vérifiable.

Le dashboard est désormais séparé en deux artefacts :

    collector/templates/dashboard.html
    collector/static/dashboard.js

DASHBOARD_HTML contient uniquement le HTML.
DASHBOARD_JS contient le JavaScript du dashboard.

Les assertions de structure HTML portent donc uniquement sur
DASHBOARD_HTML, tandis que les marqueurs fonctionnels/API qui peuvent
vivre dans le JavaScript sont vérifiés sur DASHBOARD_SOURCE.

Ce test complète tests/test_dashboard_wiring.py, qui vérifie notamment
que les handlers onclick du HTML correspondent à des fonctions réellement
définies dans le dashboard.

NOTE : ces assertions portent sur le CONTENU, pas sur l'emplacement.
Lorsqu'un bloc est extrait vers un template ou un fichier statique,
le test doit être adapté à la nouvelle architecture plutôt que de
réintroduire artificiellement du code inline.
"""

from pathlib import Path
import re

import pytest


# ---------------------------------------------------------------------------
# Imports des artefacts sous test
# ---------------------------------------------------------------------------

try:
    from collector.dashboard import DASHBOARD_HTML
except ImportError as exc:  # pragma: no cover
    pytest.skip(
        f"collector.dashboard indisponible: {exc}",
        allow_module_level=True,
    )


# Le JavaScript du dashboard est désormais servi comme fichier statique.
DASHBOARD_JS_PATH = (
    Path(__file__).resolve().parents[1]
    / "collector"
    / "static"
    / "dashboard.js"
)

if not DASHBOARD_JS_PATH.exists():  # pragma: no cover
    pytest.fail(
        f"Fichier JavaScript du dashboard introuvable : {DASHBOARD_JS_PATH}"
    )

DASHBOARD_JS = DASHBOARD_JS_PATH.read_text(encoding="utf-8")

# Source logique complète du dashboard.
#
# On ne modifie PAS DASHBOARD_HTML pour y réinjecter le JS.
# On combine simplement les deux artefacts pour les assertions qui portent
# sur le comportement global du dashboard.
DASHBOARD_SOURCE = DASHBOARD_HTML + "\n" + DASHBOARD_JS


AUTH_HTML_NAMES = (
    "SUPABASE_LOGIN_HTML",
    "LOGIN_HTML",
    "SIGNUP_HTML",
)


def _import_auth_html():
    """Retourne un dict {nom: contenu} des blocs HTML de auth.py."""
    import collector.auth as auth_mod

    return {
        name: getattr(auth_mod, name, None)
        for name in AUTH_HTML_NAMES
    }


AUTH_HTML = _import_auth_html()


# ---------------------------------------------------------------------------
# 1. Blocs HTML inline de auth.py
# ---------------------------------------------------------------------------

AUTH_HTML_MARKERS = {
    "SUPABASE_LOGIN_HTML": [
        "<!DOCTYPE html>",
        "supabase.createClient",
        "signInWithOtp",
        "signInWithOAuth",
        "btn-google",
        "btn-github",
        "/api/auth/supabase-session",
        "{{ supabase_url }}",
        "{{ supabase_anon_key }}",
    ],
    "LOGIN_HTML": [
        "<!DOCTYPE html>",
        'action="/login"',
        'name="email"',
        "switchTab",
        "{% if error %}",
        "{% if success %}",
        "/signup",
    ],
    "SIGNUP_HTML": [
        "<!DOCTYPE html>",
        'action="/signup"',
        'name="email"',
        'name="name"',
        'name="company"',
        "{% if error %}",
        "/login",
    ],
}


@pytest.mark.parametrize(
    "block_name",
    sorted(AUTH_HTML_MARKERS),
)
def test_auth_html_block_exists_and_is_non_empty(block_name):
    """Chaque bloc HTML de auth.py doit exister et ne pas être vide."""
    content = AUTH_HTML.get(block_name)

    assert content is not None, (
        f"{block_name} introuvable dans collector.auth - "
        "a-t-il été extrait vers un template ? "
        "Mettre à jour cet import."
    )

    assert isinstance(content, str), (
        f"{block_name} doit être une str"
    )

    assert len(content.strip()) > 500, (
        f"{block_name} semble tronqué ({len(content)} octets)"
    )


@pytest.mark.parametrize(
    "block_name",
    sorted(AUTH_HTML_MARKERS),
)
def test_auth_html_block_contains_markers(block_name):
    """Chaque bloc HTML doit contenir ses marqueurs structurels."""
    content = AUTH_HTML.get(block_name) or ""

    missing = [
        marker
        for marker in AUTH_HTML_MARKERS[block_name]
        if marker not in content
    ]

    assert not missing, (
        f"{block_name} : marqueurs manquants {missing}"
    )


def test_auth_html_blocks_are_distinct():
    """Les 3 blocs doivent être distincts."""
    present = {
        key: value
        for key, value in AUTH_HTML.items()
        if value
    }

    values = list(present.values())

    assert len(values) == len(set(values)), (
        "Deux blocs HTML de auth.py sont identiques - "
        "duplication suspecte"
    )


def test_auth_html_blocks_are_balanced_html():
    """Chaque bloc doit être un document HTML complet et équilibré."""
    for name, content in AUTH_HTML.items():
        if not content:
            continue

        assert content.count("<html") == content.count("</html>"), (
            f"{name} : balises <html> déséquilibrées"
        )

        assert content.count("<body") == content.count("</body>"), (
            f"{name} : balises <body> déséquilibrées"
        )

        assert content.count("<head") == content.count("</head>"), (
            f"{name} : balises <head> déséquilibrées"
        )


# ---------------------------------------------------------------------------
# 2. Marqueurs structurels de DASHBOARD
# ---------------------------------------------------------------------------

DASHBOARD_HTML_MARKERS = [
    'id="approvalsPanel"',
    'id="agentsPanel"',
    'id="connectAgentModal"',
    'id="apiKeyModal"',
    'id="helpModal"',
    'id="btnApprovals"',
    'id="btnAgents"',
    'id="approvalsBadge"',
    'id="agentsBadge"',
    'id="view-overview"',
    'id="view-health"',
    'id="view-tracing"',
    'id="view-audit"',
]


@pytest.mark.parametrize(
    "marker",
    DASHBOARD_HTML_MARKERS,
)
def test_dashboard_html_contains_marker(marker):
    """
    DASHBOARD_HTML doit contenir les marqueurs structurels HTML.

    Ces marqueurs doivent réellement appartenir au document HTML et ne
    sont donc pas recherchés dans le JavaScript.
    """
    assert marker in DASHBOARD_HTML, (
        f"DASHBOARD_HTML : marqueur manquant {marker!r}"
    )


# Ces marqueurs peuvent légitimement se trouver dans dashboard.js.
DASHBOARD_SOURCE_MARKERS = [
    "/api/approvals?status=",
    "/api/agents",
    "/api/metrics",
    "/api/traces",
    "/api/keys",
    "resolveApproval(",
    "toggleAgent(",
    "openApprovalsPanel(",
    "openAgentsPanel(",
    "openConnectAgentModal(",
    "refreshAll(",
]


@pytest.mark.parametrize(
    "marker",
    DASHBOARD_SOURCE_MARKERS,
)
def test_dashboard_source_contains_marker(marker):
    """
    La surface fonctionnelle complète du dashboard doit contenir chaque
    marqueur API/fonction attendu.

    Le marqueur peut être présent dans dashboard.html ou dashboard.js.
    """
    assert marker in DASHBOARD_SOURCE, (
        f"DASHBOARD_SOURCE : marqueur manquant {marker!r}"
    )


def test_dashboard_html_is_non_empty_and_balanced():
    """
    DASHBOARD_HTML doit être un document HTML complet et équilibré.

    Le seuil de taille historique de 50 Ko est volontairement supprimé :
    le JavaScript a été extrait vers collector/static/dashboard.js, donc
    une taille plus faible du HTML est désormais normale.
    """
    assert isinstance(DASHBOARD_HTML, str)
    assert len(DASHBOARD_HTML.strip()) > 10_000, (
        "DASHBOARD_HTML semble anormalement petit "
        f"({len(DASHBOARD_HTML)} octets)"
    )

    assert "<!DOCTYPE html>" in DASHBOARD_HTML, (
        "DASHBOARD_HTML ne contient pas de DOCTYPE"
    )

    assert "<html" in DASHBOARD_HTML, (
        "DASHBOARD_HTML ne contient pas de balise <html>"
    )

    assert "</html>" in DASHBOARD_HTML, (
        "DASHBOARD_HTML ne contient pas de fermeture </html>"
    )

    assert "<body" in DASHBOARD_HTML, (
        "DASHBOARD_HTML ne contient pas de balise <body>"
    )

    assert "</body>" in DASHBOARD_HTML, (
        "DASHBOARD_HTML ne contient pas de fermeture </body>"
    )

    assert '<script src="/static/dashboard.js"></script>' in DASHBOARD_HTML, (
        "DASHBOARD_HTML ne référence pas collector/static/dashboard.js"
    )

    assert DASHBOARD_HTML.count("<html") == DASHBOARD_HTML.count("</html>"), (
        "DASHBOARD_HTML : balises <html> déséquilibrées"
    )

    assert DASHBOARD_HTML.count("<body") == DASHBOARD_HTML.count("</body>"), (
        "DASHBOARD_HTML : balises <body> déséquilibrées"
    )


def test_dashboard_js_exists_and_is_non_empty():
    """Le JavaScript extrait du dashboard doit exister et être exploitable."""
    assert DASHBOARD_JS_PATH.is_file(), (
        f"Dashboard JS introuvable : {DASHBOARD_JS_PATH}"
    )

    assert DASHBOARD_JS.strip(), (
        "dashboard.js est vide"
    )

    assert len(DASHBOARD_JS.strip()) > 1_000, (
        "dashboard.js semble anormalement petit "
        f"({len(DASHBOARD_JS)} octets)"
    )


def test_dashboard_html_references_dashboard_js():
    """
    Le HTML doit charger explicitement le JavaScript extrait.

    Cela évite qu'un refactor rende le dashboard silencieusement
    non fonctionnel en supprimant la balise script.
    """
    assert '<script src="/static/dashboard.js"></script>' in DASHBOARD_HTML


def test_dashboard_source_contains_javascript_functions():
    """
    La source fonctionnelle complète du dashboard doit contenir des
    définitions JavaScript.
    """
    assert re.search(
        r"\bfunction\s+[A-Za-z_$][\w$]*\s*\(",
        DASHBOARD_JS,
    ), "dashboard.js ne contient aucune fonction JavaScript détectable"


def test_dashboard_html_has_no_unresolved_jinja():
    """
    DASHBOARD_HTML est servi tel quel : pas de balises Jinja de contrôle.
    """
    for token in (
        "{% if",
        "{% endif",
        "{% for",
        "{% endfor",
    ):
        assert token not in DASHBOARD_HTML, (
            f"DASHBOARD_HTML contient du Jinja non résolu : {token!r}"
        )


# ---------------------------------------------------------------------------
# 3. Surface publique de auth.py
# ---------------------------------------------------------------------------

AUTH_PUBLIC_SYMBOLS = [
    "auth_bp",
    "require_auth",
    "require_human_auth",
    "require_role",
    "require_permission",
    "resolve_org_id",
    "resolve_full_identity",
    "authorize_resource_access",
    "safe_compare",
    "hash_key",
]


@pytest.mark.parametrize(
    "symbol",
    AUTH_PUBLIC_SYMBOLS,
)
def test_auth_public_symbol_exists(symbol):
    """auth.py doit continuer d'exposer ses symboles publics."""
    import collector.auth as auth_mod

    assert hasattr(auth_mod, symbol), (
        f"collector.auth.{symbol} manquant - "
        "le découpage a cassé la surface publique"
    )


def test_auth_blueprint_is_registered_with_expected_routes():
    """Le Blueprint auth doit déclarer au moins une route."""
    import collector.auth as auth_mod

    bp = auth_mod.auth_bp

    assert bp.name == "auth"

    assert len(bp.deferred_functions) > 0, (
        "auth_bp n'a aucune route enregistrée"
    )


# ---------------------------------------------------------------------------
# 4. Contrat de module de dashboard.py
# ---------------------------------------------------------------------------

def test_dashboard_module_exports_single_html_constant():
    """
    dashboard.py doit exposer DASHBOARD_HTML comme artefact HTML.

    Le JavaScript n'est volontairement pas compté ici puisqu'il vit
    maintenant dans collector/static/dashboard.js.
    """
    import collector.dashboard as dash_mod

    assert hasattr(dash_mod, "DASHBOARD_HTML")

    big_html_attrs = [
        name
        for name in dir(dash_mod)
        if name.isupper()
        and isinstance(getattr(dash_mod, name), str)
        and len(getattr(dash_mod, name)) > 10_000
    ]

    assert big_html_attrs == ["DASHBOARD_HTML"], (
        "dashboard.py expose plusieurs gros blocs HTML : "
        f"{big_html_attrs}"
    )


def test_dashboard_html_has_no_duplicate_ids():
    """Aucun id HTML ne doit être dupliqué dans DASHBOARD_HTML."""
    ids = re.findall(
        r'(?<![-\w])id="([^"]+)"',
        DASHBOARD_HTML,
    )

    duplicates = {
        html_id
        for html_id in ids
        if ids.count(html_id) > 1
    }

    assert not duplicates, (
        f"IDs HTML dupliqués dans DASHBOARD_HTML : {duplicates}"
    )
