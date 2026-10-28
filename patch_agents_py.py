#!/usr/bin/env python3
"""Supprime de collector/api/agents.py l'ANCIENNE implémentation du mode shadow :
    _ensure_agent_modes_table, _agent_mode, GET /api/agent/mode (api_agent_mode),
    POST /api/agents/<id>/mode (api_agent_set_mode)
Raison : GET /api/agent/mode est déclaré aussi dans settings.py (table
agent_runtime_modes, celle que le dashboard écrit). Celle d'agents.py gagnait et
lisait la table agent_modes, jamais écrite -> le SDK voyait toujours « enforce ».

Usage (racine du projet) :  python patch_agents_py.py
Sauvegarde .bak ; n'écrit RIEN si la structure n'est pas celle attendue ;
vérifie que le résultat compile."""
import pathlib
import re
import shutil
import sys

path = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "collector/api/agents.py")
try:
    raw = path.read_bytes().decode("utf-8")
except UnicodeDecodeError:
    sys.exit("ABANDON : le fichier n'est pas en UTF-8 valide. Fichier non modifié.")
crlf = "\r\n" in raw
lines = raw.replace("\r\n", "\n").split("\n")

try:
    d = next(i for i, l in enumerate(lines) if l.startswith("def _ensure_agent_modes_table("))
    s = next(i for i, l in enumerate(lines) if l.startswith("def api_agent_set_mode("))
except StopIteration:
    sys.exit("Rien à faire (ou structure inattendue) : _ensure_agent_modes_table / "
             "api_agent_set_mode introuvables. Fichier non modifié.")
if s < d:
    sys.exit("ABANDON : ordre inattendu des fonctions. Fichier non modifié.")

# début : on remonte sur les lignes vides et le bandeau de commentaire juste au-dessus
start = d
while start > 0 and (lines[start - 1].strip() == "" or lines[start - 1].lstrip().startswith("#")):
    start -= 1
# fin : première ligne non vide sans indentation après api_agent_set_mode
end = next((j for j in range(s + 1, len(lines)) if lines[j] and not lines[j][0].isspace()), len(lines))

chunk = "\n".join(lines[start:end])
routes = set(re.findall(r'@api_bp\.route\(\s*"([^"]+)"', chunk))
expected = {"/api/agent/mode", "/api/agents/<agent_id>/mode"}
if routes != expected:
    sys.exit(f"ABANDON : le bloc à supprimer contient des routes inattendues {sorted(routes)}. "
             "Fichier non modifié.")
if re.search(r"^def (?!_ensure_agent_modes_table|_agent_mode|api_agent_mode|api_agent_set_mode)\w+", chunk, flags=re.MULTILINE):
    sys.exit("ABANDON : le bloc à supprimer contient une autre fonction. Fichier non modifié.")

new_lines = lines[:start] + ([""] * 2 if end < len(lines) else [""]) + lines[end:]
new = "\n".join(new_lines)
try:
    compile(new, str(path), "exec")
except SyntaxError as e:
    sys.exit(f"ABANDON : le résultat ne compile pas ({e}). Fichier non modifié.")

shutil.copy(path, str(path) + ".bak")
path.write_bytes((new.replace("\n", "\r\n") if crlf else new).encode("utf-8"))
print(f"OK : lignes {start + 1} à {end} supprimées de {path} (sauvegarde : {path}.bak)")
print("Ensuite : python -m ruff check --fix --select F401 collector/api/agents.py   (imports devenus inutiles)")
