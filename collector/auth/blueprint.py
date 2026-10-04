"""Blueprint Flask partagé par tous les modules de routes d'authentification."""

from flask import Blueprint

# IMPORTANT : collector/app.py importe exactement ce symbole via `from collector.auth import auth_bp`.
auth_bp = Blueprint("auth", __name__)
