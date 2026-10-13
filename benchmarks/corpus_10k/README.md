Corpus gelé 10 000 prompts (corpus_10k/)

Cerbère / AgentGuard, créé par Christopher Dikesa.

Ce dossier contient un corpus de benchmark figé, déterministe et reproductiblebyte-for-byte de 10 000 prompts, conçu pour donner une légitimité statistiqueaux comparaisons entre moteurs de détection (regex, ML, LLM-judge).

Composition

Fichier

Prompts

Contenu

attacks.json

5 000

7 catégories d'attaques (EN/FR), sévérité high/critical

benign.json

3 500

6 groupes bénins (dev, général, support, data, créatif, FR)

hard_negatives.json

1 500

Prompts légitimes qui mentionnent le vocabulaire d'attaque

Répartition attacks.json : direct_injection 1000, jailbreak 700,system_extraction 600, exfiltration 700, dangerous_commands 600,encoded_obfuscated 700, indirect_injection 700.

Répartition benign.json : benign_dev 692, benign_general 378,benign_support 692, benign_data 692, benign_creative 691, benign_fr 355.

Répartition hard_negatives.json : hn_security_writing 447, hn_fiction 160,hn_test_fixtures 447, hn_fr 446.

Pourquoi 10 000 prompts ?

Avec l'ancien corpus de 168 prompts, l'intervalle de confiance de Wilson (95%)sur un taux de détection est d'environ ±7 % : impossible de départager deuxmoteurs dont les scores diffèrent de moins de 10 points. Avec 5 000 attaques,l'IC tombe à environ ±1 %, ce qui rend les comparaisons entre concurrentssignificatives.

Déterminisme

Aucune source d'aléatoire, d'horloge ou de réseau : le scriptbenchmarks/generate_corpus_10k.py régénère les trois fichiers JSONbyte-identiques au corpus committé, ainsi que MANIFEST.json.

100 % de prompts uniques (déduplication globale sur les trois fichiers).

Les prompts écrits à la main du corpus d'origine (benchmarks/corpus/)sont intégrés en tête, en priorité : rien de l'ancien corpus n'est perdu.

Intégrité

MANIFEST.json contient les SHA-256 des trois fichiers JSON, vérifiésautomatiquement par benchmarks/run_public_benchmark.py (verify_manifest()).Toute altération du corpus fait échouer le benchmark.

Utilisation

# Régénérer (et vérifier la reproductibilité byte-for-byte)
python benchmarks/generate_corpus_10k.py

# Lancer le benchmark sur ce corpus
python benchmarks/run_public_benchmark.py \
    --corpus-dir benchmarks/corpus_10k --layers regex

# Avec plusieurs couches
python benchmarks/run_public_benchmark.py \
    --corpus-dir benchmarks/corpus_10k --layers regex,ml,llm

Limites (honnêteté méthodologique)

Ce corpus est généré par la même équipe que le détecteur : les résultatsobtenus dessus constituent un plafond interne (upper bound), pas unepreuve de généralisation. Ne jamais fusionner ces scores avec ceux d'unholdout externe ; les rapporter côte à côte.

Les prompts sont produits à partir de gabarits déterministes (tables.json) :ils couvrent systématiquement les dimensions déclarées, mais ne remplacentpas une évaluation adversariale humaine.

Le corpus est engine-agnostic : aucun code du dépôt ne nécessite demodification pour l'utiliser.