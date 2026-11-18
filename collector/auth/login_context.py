"""Variables de la page de connexion (méthodes actives), partagées par les gabarits."""

from collector.ee_loader import sso_config

from . import config as auth_config
from .blueprint import auth_bp


@auth_bp.app_context_processor
def login_page_context():
    cfg = sso_config()
    return {
        "sso_enabled": cfg is not None,
        "sso_name": cfg.button_label if cfg else "",
        # Anti-verrouillage : le mot de passe ne peut être masqué que tant que le SSO
        # fonctionne réellement (configuré ET couvert par la licence).
        "password_enabled": auth_config.PASSWORD_LOGIN_ENABLED or cfg is None,
        "magic_enabled": auth_config.MAGIC_LINK_ENABLED,
        "signup_enabled": auth_config.SIGNUP_ENABLED,
    }
