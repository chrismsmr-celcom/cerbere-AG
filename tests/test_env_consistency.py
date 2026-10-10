"""
Régression : cohérence des noms de variables d'environnement.

Contexte (audit 2026-10) : trois familles de variables étaient incohérentes
entre le code, env.example, docker-compose.yml et le README :

1. SMTP — collector/app.py lisait AGENTGUARD_SMTP_USERNAME/_PASSWORD et
   AGENTGUARD_EMAIL_FROM, alors que le vrai chemin magic-link
   (collector/auth/config.py) lit AGENTGUARD_SMTP_USER/_PASS/_FROM.
   Un SMTP configuré via env.example était donc silencieusement ignoré
   par la moitié du code.

2. Juge LLM — env.example documentait AGENTGUARD_JUDGE_API_KEY, mais
   judges.py lisait DEEPSEEK_API_KEY : la variable documentée n'était
   lue par personne. Décision finale : AGENTGUARD_JUDGE_API_KEY est le
   seul nom lu ; DEEPSEEK_API_KEY est supprimé (indépendance
   fournisseur).

3. Clé de signature — helpers.py lisait CERBERE_SIGNING_KEY (non
   documenté) en priorité avant AGENTGUARD_SIGNING_KEY. Décision
   finale : AGENTGUARD_SIGNING_KEY prioritaire, CERBERE_SIGNING_KEY
   accepté comme alias legacy.

Ces tests verrouillent les trois conventions pour qu'une future
modification ne réintroduise pas silencieusement une divergence.
Ils lisent les sources (pas d'import de l'app) : rapides, sans DB,
sans réseau — utilisables dans la CI dès le checkout.
"""
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


# ==============================================================
# 1. SMTP — un seul jeu de noms canoniques
# ==============================================================

def test_smtp_app_reads_canonical_names():
    """collector/app.py doit lire les mêmes noms SMTP que
    collector/auth/config.py (le chemin magic-link réel)."""
    app_src = _read("collector/app.py")

    # Noms canoniques lus
    assert '"AGENTGUARD_SMTP_USER",' in app_src
    assert '"AGENTGUARD_SMTP_PASS",' in app_src
    assert '"AGENTGUARD_SMTP_FROM",' in app_src

    # Les anciens noms divergents ne doivent plus être lus
    assert '"AGENTGUARD_SMTP_USERNAME",' not in app_src
    assert '"AGENTGUARD_SMTP_PASSWORD",' not in app_src
    assert '"AGENTGUARD_EMAIL_FROM",' not in app_src


def test_smtp_documented_names_are_the_read_ones():
    """env.example et docker-compose.yml exposent exactement les noms
    que le code lit — ni plus, ni moins."""
    env_doc = _read("env.example")
    compose = _read("docker-compose.yml")

    for name in (
        "AGENTGUARD_SMTP_HOST=",
        "AGENTGUARD_SMTP_PORT=",
        "AGENTGUARD_SMTP_USER=",
        "AGENTGUARD_SMTP_PASS=",
    ):
        assert name in env_doc, f"{name} manquant dans env.example"
        assert name.rstrip("=") + ":" in compose, (
            f"{name.rstrip('=')} manquant dans docker-compose.yml"
        )

    # Les anciens noms ne doivent plus être documentés
    assert "AGENTGUARD_SMTP_USERNAME" not in env_doc
    assert "AGENTGUARD_SMTP_PASSWORD" not in env_doc
    assert "AGENTGUARD_EMAIL_FROM" not in env_doc


# ==============================================================
# 2. Juge LLM — AGENTGUARD_JUDGE_API_KEY, sans DeepSeek
# ==============================================================

def test_judge_api_key_documented_is_actually_read():
    """AGENTGUARD_JUDGE_API_KEY (documentée) doit être la variable lue
    par judges.py pour le provider deepseek de la cascade."""
    judges_src = _read("agentguard/judges.py")

    assert '"env_key": "AGENTGUARD_JUDGE_API_KEY"' in judges_src

    # Décision d'architecture : indépendance fournisseur.
    # Aucune lecture de DEEPSEEK_API_KEY ne doit réapparaître.
    assert "DEEPSEEK_API_KEY" not in judges_src


def test_judge_api_key_wired_through_compose_and_doc():
    """docker-compose.yml et env.example portent le même nom, sans
    fallback DEEPSEEK_API_KEY."""
    compose = _read("docker-compose.yml")
    env_doc = _read("env.example")

    assert "AGENTGUARD_JUDGE_API_KEY: ${AGENTGUARD_JUDGE_API_KEY:-}" in compose
    assert "DEEPSEEK_API_KEY" not in compose

    assert "AGENTGUARD_JUDGE_API_KEY=" in env_doc


# ==============================================================
# 3. Clé de signature — AGENTGUARD_SIGNING_KEY prioritaire
# ==============================================================

def test_signing_key_priority():
    """helpers.py doit lire AGENTGUARD_SIGNING_KEY avant l'alias
    legacy CERBERE_SIGNING_KEY (ordre = priorité)."""
    helpers_src = _read("collector/api/helpers.py")

    idx_canonical = helpers_src.index('"AGENTGUARD_SIGNING_KEY")')
    idx_legacy = helpers_src.index('"CERBERE_SIGNING_KEY")')
    assert idx_canonical < idx_legacy, (
        "AGENTGUARD_SIGNING_KEY doit être lu avant CERBERE_SIGNING_KEY"
    )


def test_signing_key_documented():
    """AGENTGUARD_SIGNING_KEY doit figurer dans env.example."""
    env_doc = _read("env.example")
    assert "AGENTGUARD_SIGNING_KEY=" in env_doc


# ==============================================================
# 4. Garde-fou global — aucune divergence doc / code / compose
# ==============================================================

def test_no_deepseek_env_var_anywhere():
    """Décision d'architecture : le projet ne dépend plus du nom de
    variable DEEPSEEK_API_KEY nulle part (code, doc, compose).
    La CI (py_compile, pip-audit) et ce test verrouillent la convention."""
    for path in (
        "judges.py",
        "env.example",
        "docker-compose.yml",
    ):
        src = _read(path)
        assert "DEEPSEEK_API_KEY" not in src, (
            f"DEEPSEEK_API_KEY ne doit plus apparaître dans {path}"
        )
