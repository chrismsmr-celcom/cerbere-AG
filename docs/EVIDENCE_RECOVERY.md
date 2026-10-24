# Secure Evidence Recovery

**Question posée par la communauté :** le masquage protège les logs courants,
mais peut effacer la preuve dont on a besoin pendant un incident. Cerbère
permet-il une capture non masquée temporaire, avec un accès strictement contrôlé ?

**Réponse courte.** Le masquage est appliqué *avant* tout stockage et il est
irréversible par défaut. Un administrateur humain peut ouvrir, pour un agent
précis et une durée limitée, une capture dont les valeurs sensibles sont
*scellées* avec une clé publique. Seul le collector détient la clé privée, et
seul un admin humain, avec un motif, peut rouvrir une valeur. Chaque accès est
écrit dans l'audit chaîné.

| Propriété | Comportement |
|---|---|
| Masquage avant stockage | Spans et dashboard ne contiennent jamais la valeur d'origine |
| Tokens | HMAC-SHA256 avec clé : impossible de tester des valeurs prévisibles |
| Activation | Désactivée par défaut ; ouverture par un admin humain, jamais par une clé API |
| Chiffrement | X25519 + HKDF + AES-256-GCM : le SDK sait chiffrer, pas déchiffrer |
| TTL | Appliqué côté serveur ; à l'expiration, chiffrés **et** clé privée détruits |
| Accès | Rôle admin, motif obligatoire, limite de débit, audit chaîné |
| Isolation | Par organisation et par agent |
| Échec du coffre | Rien n'est jamais écrit en clair ; la perte est journalisée sans valeur |

## Flux (depuis le dashboard, sans toucher au code des agents)

1. **Settings → Incidents → Open capture** : un admin choisit l'agent, la durée
   (1 h, 6 h, 24 h) et saisit un motif (obligatoire, inscrit dans l'audit).
2. Dans les secondes qui suivent, le SDK de l'agent le découvre tout seul :
   `/api/agent/status` renvoie `incident_open`, et le SDK récupère la clé
   publique puis commence à sceller. Aucun appel de code requis
   (`AGENTGUARD_INCIDENT_AUTO=false` côté agent pour s'en désinscrire ; l'appel
   manuel `guard.start_incident_capture()` reste possible).
3. Les valeurs masquées sont scellées puis envoyées à `/v1/incident/sealed`.
4. **Trace → span → « Sealed evidence → Reveal »** : motif obligatoire, la valeur
   s'affiche 20 secondes puis se masque de nouveau. Chaque accès est audité.
5. **Stop** arrête la capture (les preuves restent jusqu'à l'expiration) ;
   **Destroy now** détruit chiffrés et clé privée immédiatement. À l'expiration
   du TTL, la destruction est automatique.

L'onglet n'apparaît utilisable que si la fonctionnalité est activée, la clé
maître valide et l'utilisateur admin ; sinon il explique ce qui manque.

## Limites assumées

- La clé publique est publique : un agent compromis peut sceller de fausses
  entrées. Le coffre prouve ce que l'agent a *vu*, pas l'authenticité du contenu.
- Le collector détient la clé privée (chiffrée par `AGENTGUARD_INCIDENT_MASTER_KEY`).
  Une variante où la clé privée reste chez le client est possible et renforcerait
  l'argument pour les clients réglementés.
- Les paramètres envoyés à `/api/decide` pour la décision signée ne sont pas
  masqués : le moteur de politique a besoin des valeurs réelles.
