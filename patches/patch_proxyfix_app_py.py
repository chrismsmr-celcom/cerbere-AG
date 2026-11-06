#!/usr/bin/env python3
"""collector/app.py : IP client réelle derrière un proxy, activable par variable.

Ajoute (après RATELIMIT_STORAGE_URI) :
    AGENTGUARD_TRUSTED_PROXIES=<n>   n = nombre de proxys de confiance devant l'app
                                     (0 ou absent = désactivé : comportement actuel)
Avec n > 0, werkzeug ProxyFix lit X-Forwarded-For depuis la DROITE sur n sauts. Une valeur
trop grande permettrait à un client de falsifier son IP (et d'échapper au limiteur) : choisis n
avec /api/_whoami (whoami.py), jamais au hasard. L'en-tête de schéma (https) n'est pas touché.

Usage (racine du projet) :  python patch_proxyfix_app_py.py
Sauvegarde .bak ; n'écrit rien si l'ancre est introuvable ; relançable."""
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

if "AGENTGUARD_TRUSTED_PROXIES" in src:
    sys.exit("Déjà appliqué : app.py contient déjà AGENTGUARD_TRUSTED_PROXIES.")

BLOCK = '''
    # IP client réelle derrière un proxy (Render). Désactivé par défaut (0) : le limiteur
    # voit alors l'adresse du proxy. n = nombre de proxys de confiance (voir /api/_whoami).
    trusted_proxies = int(os.environ.get("AGENTGUARD_TRUSTED_PROXIES", "0") or 0)
    if trusted_proxies > 0:
        from werkzeug.middleware.proxy_fix import ProxyFix

        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=trusted_proxies, x_proto=0, x_host=0, x_prefix=0)
'''
new, n = re.subn(r'^(    app\.config\["RATELIMIT_STORAGE_URI"\] = limiter_storage\n)',
                 lambda m: m.group(1) + BLOCK, src, count=1, flags=re.MULTILINE)
if n != 1:
    sys.exit("ABANDON : ancre app.config[\"RATELIMIT_STORAGE_URI\"] introuvable. Fichier non modifié.")
try:
    compile(new, str(path), "exec")
except SyntaxError as e:
    sys.exit(f"ABANDON : le résultat ne compile pas ({e}). Fichier non modifié.")
shutil.copy(path, str(path) + ".bak")
path.write_bytes((new.replace("\n", "\r\n") if crlf else new).encode("utf-8"))
print(f"OK : {path} modifié (sauvegarde : {path}.bak). Active avec AGENTGUARD_TRUSTED_PROXIES=<n> sur Render.")
