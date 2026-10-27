#!/usr/bin/env python3
"""Ajoute le bouton « Log » et la modale d'incident à
dashboard/src/pages/settings/Incidents.tsx (7 modifications, sauvegarde .bak).

Usage (depuis la racine du projet) :
    python patch_incidents_tsx.py
    python patch_incidents_tsx.py chemin\\vers\\Incidents.tsx

N'écrit RIEN si une des 7 ancres est introuvable (il indique laquelle).
Relançable : s'arrête proprement si le patch est déjà appliqué.
"""
import pathlib
import re
import shutil
import sys

path = pathlib.Path(
    sys.argv[1] if len(sys.argv) > 1 else "dashboard/src/pages/settings/Incidents.tsx"
)
raw = path.read_bytes().decode("utf-8")
crlf = "\r\n" in raw
src = raw.replace("\r\n", "\n")

if "IncidentLogModal" in src:
    sys.exit("Déjà appliqué : Incidents.tsx référence déjà IncidentLogModal.")


def step(n, label, pattern, repl):
    global src
    new, count = re.subn(pattern, repl, src, count=1, flags=re.M)
    if count != 1:
        sys.exit(f"ABANDON (étape {n}/7 : {label}) : ancre introuvable. Fichier non modifié.")
    src = new


step(1, "import", r"^(import \{ Modal \} from '\.\./\.\./components/Modal')[ \t]*$",
     r"\1\nimport { IncidentLogModal } from '../../components/IncidentLogModal'")
step(2, "signature de IncidentRow",
     r"function IncidentRow\(\{ incident \}: \{ incident: Incident \}\) \{",
     "function IncidentRow({\n  incident,\n  onOpenLog,\n}: {\n  incident: Incident\n  onOpenLog: (id: string) => void\n}) {")
step(3, "bouton Log",
     r"(<div className=\"flex justify-end gap-2\">\n)([ \t]*)(\{phase === 'capturing' && \()",
     r"\1\2<Button onClick={() => onOpenLog(incident.id)}>Log</Button>\n\2\3")
step(4, "état logId",
     r"^([ \t]*)(const \[target, setTarget\] = useState<Agent \| null>\(null\))[ \t]*$",
     r"\1\2\n\1const [logId, setLogId] = useState<string | null>(null)")
step(5, "logIncident",
     r"^([ \t]*)(const incidents = incidentsQ\.data\?\.incidents \|\| \[\])[ \t]*$",
     r"\1\2\n\1const logIncident = incidents.find((i) => i.id === logId)")
step(6, "IncidentRow dans le tableau",
     r"<IncidentRow key=\{i\.id\} incident=\{i\} />",
     "<IncidentRow key={i.id} incident={i} onOpenLog={setLogId} />")
step(7, "modale en bas de page",
     r"^([ \t]*)(\{target && <OpenCaptureModal agent=\{target\} cfg=\{cfg\} onClose=\{\(\) => setTarget\(null\)\} />\})[ \t]*$",
     r"\1\2\n\1{logIncident && <IncidentLogModal incident={logIncident} onClose={() => setLogId(null)} />}")

shutil.copy(path, str(path) + ".bak")
out = src.replace("\n", "\r\n") if crlf else src
path.write_bytes(out.encode("utf-8"))
print(f"OK : {path} modifié (7/7). Sauvegarde : {path}.bak")
print("Étape suivante : copier IncidentLogModal.tsx dans dashboard/src/components/ puis npm run build")
