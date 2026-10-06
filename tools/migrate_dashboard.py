#!/usr/bin/env python3
"""Migration UNIQUE : découpe collector/static/dashboard.js en modules (collector/static/src/*.js)
puis applique les correctifs de tools/dashboard_fixes.js.

    git add -A && git commit -m "wip: avant découpage dashboard"   # filet de sécurité
    python tools/migrate_dashboard.py
    python tools/build_dashboard.py
    python -m pytest tests/test_dashboard_build.py tests/test_dashboard_wiring.py tests/test_template_integrity.py -q

Ensuite, supprime migrate_dashboard.py et dashboard_fixes.js : le code corrigé vit dans src/.

Principe : le découpage se fait sur les bannières de section déjà présentes dans le fichier
(`// ─── / // TITRE / // ───`). Le code non touché est copié tel quel (aucune retranscription) et le
script vérifie que la concaténation des modules redonne exactement l'original avant d'appliquer
les correctifs. Un correctif dont la cible est introuvable ou ambiguë arrête tout (rien n'est écrit).
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEGACY = ROOT / "collector" / "static" / "dashboard.js"
SRC = ROOT / "collector" / "static" / "src"
FIXES = Path(__file__).resolve().parent / "dashboard_fixes.js"

RULE = re.compile(r"^// [─═]{10,}\s*$")
TITLE = re.compile(r"^// ([A-Z][A-Z0-9 /&,\-]+?)\s*$")
START = re.compile(
    r"^(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\("
    r"|^var\s+([A-Za-z_$][\w$]*)\s*="
    r"|^window\.([A-Za-z_$][\w$]*)\s*="
)
MODULE_TAG = re.compile(r"^// @module\s+(\S+)\s*$")
EMOJI = re.compile("[\U0001F300-\U0001FAFF\u2600-\u27BF\u2B50\u2B55]\ufe0f?")

# titre de bannière -> module (l'ordre numérique doit suivre l'ordre du fichier)
MODULES = {
    "GENERIC POPOVER PLUMBING": "10-popovers",
    "INFO TOOLTIPS": "10-popovers",
    "CARD MENU": "10-popovers",
    "MODALS & ALERTS": "20-alerts",
    "CHARTS & VISUALIZATIONS": "30-charts",
    "CALENDAR HEATMAP": "30-charts",
    "VIEW SWITCHING & SIDEBAR": "40-views",
    "TRACING": "50-tracing",
    "AUDIT / COMPLIANCE & EXPORT": "60-audit",
    "AUDIT EXPORT LOGIC": "60-audit",
    "SECURITY EVENT DRAWER & POLICY EDITOR": "65-security-events",
    "CONNECT INTEGRATIONS": "70-connect",
    "REFRESH LOOP & API KEYS": "80-refresh-keys",
    "DRAWERS SHARED HELPERS": "85-drawers",
    "APPROVAL QUEUE": "90-approvals",
    "CONNECTED AGENTS & TRAJECTORY": "92-agents",
    "BUDGET MANAGEMENT": "94-budgets",
    "ALERT DESTINATIONS": "96-destinations",
    "INITIALIZATION": "99-init",
}


def die(msg):
    sys.exit("ERREUR : " + msg)


def split_modules(lines):
    cuts = [(0, "00-core")]
    for i in range(1, len(lines) - 1):
        if RULE.match(lines[i - 1]) and RULE.match(lines[i + 1]):
            m = TITLE.match(lines[i])
            if not m:
                continue
            mod = MODULES.get(m.group(1))
            if mod is None:
                print(f"  ! section inconnue, conservée dans le module précédent : {m.group(1)}")
                continue
            cuts.append((i - 1, mod))
    order = [m for _, m in cuts]
    if order != sorted(order):
        die("l'ordre des sections ne suit pas la numérotation des modules : " + ", ".join(order))
    bounds = [c for c, _ in cuts] + [len(lines)]
    modules = {}
    for k, (start, mod) in enumerate(cuts):
        modules.setdefault(mod, []).extend(lines[start:bounds[k + 1]])
    rebuilt = []
    for mod in sorted(modules):
        rebuilt.extend(modules[mod])
    if rebuilt != lines:
        die("la concaténation des modules ne redonne pas le fichier d'origine (abandon, rien n'est écrit)")
    return modules


def unit_end(lines, s):
    first = lines[s].rstrip()
    if first.endswith(("}", "};", ";")) and first.count("{") == first.count("}"):
        return s
    for j in range(s + 1, len(lines)):
        if lines[j].rstrip() in ("}", "};", "];"):
            return j
    die(f"fin de bloc introuvable pour : {lines[s][:70]}")


def find_units(lines):
    units, i = [], 0
    while i < len(lines):
        m = START.match(lines[i])
        if m:
            name = next(g for g in m.groups() if g)
            e = unit_end(lines, i)
            units.append((name, i, e))
            i = e + 1
        else:
            i += 1
    return units


def parse_fixes(text):
    lines = text.replace("\r\n", "\n").split("\n")
    out, pending, i = [], None, 0
    while i < len(lines):
        tag = MODULE_TAG.match(lines[i])
        if tag:
            pending = tag.group(1)
            i += 1
            continue
        m = START.match(lines[i])
        if m:
            name = next(g for g in m.groups() if g)
            e = unit_end(lines, i)
            out.append((name, lines[i:e + 1], pending))
            pending = None
            i = e + 1
        else:
            i += 1
    return out


def strip_comment_emoji(modules):
    """Retire les emojis des lignes de commentaire (ex. « // ✅ CORRECTED ... »)."""
    n = 0
    for lines in modules.values():
        for i, line in enumerate(lines):
            body = line.lstrip()
            if body.startswith("//") and EMOJI.search(body):
                indent = line[: len(line) - len(body)]
                lines[i] = indent + re.sub(r"^// +", "// ", EMOJI.sub("", body))
                n += 1
    return n


def apply_fixes(modules, fixes):
    replaced, added = [], []
    for name, new_lines, tag in fixes:
        hits = [(mod, s, e)
                for mod, lines in modules.items()
                for (n, s, e) in find_units(lines) if n == name]
        if len(hits) > 1:
            die(f"« {name} » est défini {len(hits)} fois : " + ", ".join(h[0] for h in hits))
        if hits:
            mod, s, e = hits[0]
            modules[mod][s:e + 1] = new_lines
            replaced.append(f"{name} ({mod})")
        elif tag:
            if tag not in modules:
                die(f"module inconnu « {tag} » pour {name}")
            modules[tag] += [""] + new_lines
            added.append(f"{name} (+{tag})")
        else:
            die(f"« {name} » introuvable dans le fichier d'origine et sans « // @module » : correctif ignoré = erreur")
    return replaced, added


def main():
    if SRC.exists() and any(SRC.glob("*.js")):
        die(f"{SRC} existe déjà : migration déjà faite.")
    if not LEGACY.exists():
        die(f"{LEGACY} introuvable.")
    if not FIXES.exists():
        die(f"{FIXES} introuvable.")

    text = LEGACY.read_text(encoding="utf-8-sig").replace("\r\n", "\n")
    lines = text.split("\n")
    print(f"Lecture : {len(lines)} lignes")

    modules = split_modules(lines)
    print("Découpage vérifié (concaténation == original) :")
    for mod in sorted(modules):
        print(f"  {mod}.js  {len(modules[mod])} lignes")

    cleaned = strip_comment_emoji(modules)
    if cleaned:
        print(f"Emojis retirés de {cleaned} ligne(s) de commentaire")

    replaced, added = apply_fixes(modules, parse_fixes(FIXES.read_text(encoding="utf-8")))
    print(f"Correctifs : {len(replaced)} fonctions remplacées, {len(added)} ajoutées")
    for r in replaced:
        print("  ~", r)
    for a in added:
        print("  +", a)

    SRC.mkdir(parents=True, exist_ok=True)
    for mod, mod_lines in modules.items():
        (SRC / f"{mod}.js").write_text("\n".join(mod_lines).rstrip("\n") + "\n", encoding="utf-8", newline="\n")
    print(f"\nÉcrit dans {SRC.relative_to(ROOT)}/. Étape suivante : python tools/build_dashboard.py")


if __name__ == "__main__":
    main()
