from pathlib import Path

path = Path(__file__).resolve().parent / 'agentguard' / 'identity.py'
if not path.exists():
    raise SystemExit(f'Fichier introuvable: {path}. Place fix_identity.py à la racine du projet cerbere-AG.')
source = path.read_text(encoding='utf-8')
old = 'return f"{_HASH_ALGO_ARGON2}${_PH.hash(key.encode()).decode()}"'
new = 'return f"{_HASH_ALGO_ARGON2}${_PH.hash(key)}"'
if old not in source:
    if new in source:
        print('Déjà corrigé:', path)
        raise SystemExit(0)
    raise SystemExit('Expression attendue introuvable. Aucune modification effectuée.')
path.write_text(source.replace(old, new, 1), encoding='utf-8')
print('Corrigé:', path)
