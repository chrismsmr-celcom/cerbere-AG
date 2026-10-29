#!/usr/bin/env python3
"""collector/app.py : deux protections (sauvegarde .bak, relançable, vérifie la compilation).

 1. Logs : ajoute structlog.processors.format_exc_info. Sans lui, JSONRenderer écrit
    "exc_info": true et JAMAIS la trace : un 500 en production reste muet.
 2. Limiteur de débit : une panne de son stockage (Redis) ne doit pas faire tomber tout
    le site. On pose RATELIMIT_SWALLOW_ERRORS et RATELIMIT_IN_MEMORY_FALLBACK_ENABLED
    juste avant limiter.init_app(app) : repli sur la mémoire locale (limites par worker).

Usage (racine du projet) :  python patch_app_py.py
Chaque étape est indépendante ; le script dit laquelle il a appliquée ou ignorée."""
import pathlib
import re
import shutil
import sys

path = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "collector/app.py")
try:
    raw = path.read_bytes().decode("utf-8")
except UnicodeDecodeError:
    sys.exit("ABANDON : le fichier n'est pas en UTF-8 valide. Fichier non modifié.")
crlf = "\r\n" in raw
src = raw.replace("\r\n", "\n")
done, skipped = [], []

# --- 1. traces dans les logs ---
if "format_exc_info" in src:
    skipped.append("1/2 logs : format_exc_info déjà présent")
else:
    new, n = re.subn(
        r"^([ \t]*)(structlog\.processors\.add_log_level,\n)([ \t]*)(structlog\.processors\.JSONRenderer\(\),)",
        r"\1\2\3structlog.processors.format_exc_info,\n\3\4",
        src, count=1, flags=re.M)
    if n:
        src = new
        done.append("1/2 logs : format_exc_info ajouté")
    else:
        skipped.append("1/2 logs : bloc structlog.configure non reconnu (ancre introuvable)")

# --- 2. repli du limiteur ---
if "RATELIMIT_SWALLOW_ERRORS" in src:
    skipped.append("2/2 limiteur : déjà configuré")
else:
    matches = re.findall(r"^[ \t]*limiter\.init_app\(app\)[ \t]*$", src, flags=re.M)
    if len(matches) == 1:
        src = re.sub(
            r"^([ \t]*)(limiter\.init_app\(app\))[ \t]*$",
            r'\1# Une panne du stockage du limiteur (Redis) ne doit jamais faire tomber le site :\n'
            r'\1# repli sur la mémoire locale (limites par worker) et erreurs avalées.\n'
            r'\1app.config.setdefault("RATELIMIT_SWALLOW_ERRORS", True)\n'
            r'\1app.config.setdefault("RATELIMIT_IN_MEMORY_FALLBACK_ENABLED", True)\n'
            r'\1\2',
            src, count=1, flags=re.M)
        done.append("2/2 limiteur : repli mémoire + erreurs avalées")
    else:
        skipped.append(f"2/2 limiteur : `limiter.init_app(app)` trouvé {len(matches)} fois (attendu : 1), ignoré")

for m in done:
    print("OK      ", m)
for m in skipped:
    print("IGNORÉ  ", m)
if not done:
    sys.exit("Rien modifié.")

try:
    compile(src, str(path), "exec")
except SyntaxError as e:
    sys.exit(f"ABANDON : le résultat ne compile pas ({e}). Fichier non modifié.")
shutil.copy(path, str(path) + ".bak")
path.write_bytes((src.replace("\n", "\r\n") if crlf else src).encode("utf-8"))
print(f"Écrit : {path} (sauvegarde : {path}.bak)")
