#!/usr/bin/env python3
"""Branche agentguard/background.py dans agentguard/sdk.py (7 modifications, tout ou rien).

Chemin chaud sans réseau : envoi des spans en file d'attente (par GRAPPES), statut/mode
lus par un thread. Le code synchrone d'origine reste en place (AGENTGUARD_ASYNC_IO=false).

⚠ Contrat collector : le POST /span envoie désormais une LISTE JSON de spans (même
d'un seul élément). Le collector doit accepter `list[dict]` sur /span — les deux côtés
doivent être déployés ensemble.

Usage (racine du projet, background.py déjà copié dans agentguard/) :
    python patch_sdk_py.py
Sauvegarde .bak ; n'écrit RIEN si une ancre est introuvable ou si le résultat ne compile pas."""
import pathlib
import re
import shutil
import sys

path = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "agentguard/sdk.py")
try:
    raw = path.read_bytes().decode("utf-8")
except UnicodeDecodeError:
    sys.exit("ABANDON : le fichier n'est pas en UTF-8 valide. Fichier non modifié.")
crlf = "\r\n" in raw
src = raw.replace("\r\n", "\n")

if "_deliver_span" in src:
    sys.exit("Déjà appliqué : sdk.py contient déjà _deliver_span.")

TOTAL = 7


def step(n, label, pattern, repl, flags=re.M | re.S):
    global src
    new, count = re.subn(pattern, repl, src, count=1, flags=flags)
    if count != 1:
        sys.exit(f"ABANDON (étape {n}/{TOTAL} : {label}) : ancre introuvable. Fichier non modifié.")
    src = new


step(1, "import threading", r"^import time$", "import threading\nimport time", re.M)
step(2, "import background + verrou module", r"^from \.ids import uuid7$",
     "from .background import SpanSender, StatusPoller, bg_enabled\n"
     "from .ids import uuid7\n\n"
     "# Protège seulement la création des threads d'E/S ; partagé entre instances,\n"
     "# jamais tenu pendant un appel réseau.\n"
     "_BG_LOCK = threading.Lock()", re.M)

step(3, "attributs de classe", r"^class AgentGuard:\n",
     'class AgentGuard:\n'
     '    # E/S réseau en arrière-plan (voir background.py)\n'
     '    _poller = None\n'
     '    _sender = None\n'
     '    _applied_status_version = -1\n'
     '    _incident_sync_at = 0.0\n\n', re.M)

step(4, "hook _refresh_runtime_mode",
     r'^(    def _refresh_runtime_mode\(self\) -> None:\n        """[^\n]*"""\n)',
     r"\1        if bg_enabled():\n            return self._refresh_mode_fast()\n", re.M)

step(5, "hook _ensure_connected",
     r'^(    def _ensure_connected\(self\):\n        """[^\n]*"""\n)',
     r"\1        if bg_enabled():\n            return self._ensure_connected_fast()\n", re.M)

step(6, "envoi du span",
     r'( {12})response = requests\.post\(\n {16}f"\{self\.collector_url\}/span",.*?'
     r'collector_url=self\.collector_url,\n {16}\)\n(?=\n {8}except Exception as exc:)',
     r"\1self._deliver_span(payload)\n")

NEW_METHODS = '''    # ==========================================================
    # E/S EN ARRIÈRE-PLAN (voir background.py)
    # ==========================================================

    def _ensure_poller(self) -> StatusPoller:
        if self._poller is None:
            with _BG_LOCK:
                if self._poller is None:
                    poller = StatusPoller(self)
                    poller.poll_once()  # 1re lecture synchrone : état exact dès le 1er appel
                    poller.start()
                    self._poller = poller
        return self._poller

    def _get_sender(self) -> SpanSender:
        if self._sender is None:
            with _BG_LOCK:
                if self._sender is None:
                    # La méthode liée est épinglée sur l'instance : elle vit
                    # exactement aussi longtemps que l'agent. Le thread d'envoi
                    # (WeakMethod) s'arrête donc tout seul quand l'agent est
                    # libéré — sans jamais retenir l'agent en vie lui-même.
                    self._post_spans_bound = self._post_spans
                    self._sender = SpanSender(self._post_spans_bound)
        return self._sender

    def _ensure_connected_fast(self):
        """Kill switch : lit l'instantané du thread de statut, aucun appel réseau."""
        if not self._status_check:
            return

        snap = self._ensure_poller().snapshot()

        if snap.status_version != self._applied_status_version:
            self._applied_status_version = snap.status_version
            self._conn_state = snap.conn_state

        self._apply_incident_hint(snap.incident_open)

        if self._conn_state == "disconnected":
            raise AgentDisconnectedException(
                f"Agent '{self.agent_id}' was disconnected "
                "from the Cerbere dashboard. Reconnect it there to resume."
            )

    def _refresh_mode_fast(self) -> None:
        """Mode shadow/enforce : instantané du thread de statut. Fail-safe : erreur
        ou lecture périmée => enforce."""
        env_shadow = os.getenv("AGENTGUARD_SHADOW_MODE")

        if env_shadow is not None:
            self.shadow_mode = env_shadow.strip().lower() == "true"
            return

        if not self.api_key:
            self.shadow_mode = False
            return

        snap = self._ensure_poller().snapshot()
        max_age = max(3 * self._runtime_mode_ttl, 30.0)
        fresh = (time.time() - snap.mode_ok_at) <= max_age
        self.shadow_mode = bool(snap.shadow and fresh)

    def _apply_incident_hint(self, incident_open: bool | None) -> None:
        """Ouvre/ferme la capture d'incident sur CE thread (le coffre n'est jamais
        touché par un thread d'arrière-plan), au plus une tentative par TTL."""
        if incident_open is None:
            return
        needs_change = (
            incident_open and (self._vault is None or self._vault.expired)
        ) or (not incident_open and self._vault is not None)
        if not needs_change:
            return
        now = time.time()
        if now - self._incident_sync_at < self._status_ttl:
            return
        self._incident_sync_at = now
        self._sync_incident_capture(incident_open)

    def _deliver_span(self, payload: dict) -> None:
        if bg_enabled():
            self._get_sender().submit(payload)
        else:
            self._post_spans([payload])

    def _post_spans(self, payloads: list, session=None) -> None:
        """POST d'un LOT de spans déjà masqués. Compatibilité arrière : un lot
        d'UN span part en objet JSON (l'ancien contrat /span), un lot de
        plusieurs part en LISTE JSON (le collector doit l'accepter). Appelé en
        direct (mode synchrone) ou par le thread d'envoi (avec une session HTTP
        réutilisée). NOTE : `_conn_state` peut être écrit ici depuis le thread
        d'envoi sur un 403 — assignation atomique, sûr sous le GIL."""
        post = session.post if session is not None else requests.post
        body = payloads[0] if len(payloads) == 1 else payloads
        try:
            response = post(
                f"{self.collector_url}/span",
                json=body,
                headers=self._headers(),
                timeout=self.collector_timeout,
            )

            if response.status_code in (401, 403):
                warnings.warn(
                    "Cerbere rejected your API key or agent is disconnected",
                    RuntimeWarning,
                )
                self._conn_state = "disconnected"

            if response.status_code >= 400:
                logger.warning(
                    "collector_rejected_span",
                    status_code=response.status_code,
                    body=response.text[:300],
                    collector_url=self.collector_url,
                )

        except Exception as exc:
            logger.warning(
                "collector_send_failed",
                error=str(exc),
            )

    def close(self, timeout: float = 5.0) -> bool:
        """Fermeture propre de l'E/S en arrière-plan : vide la file de spans,
        arrête le thread d'envoi et le poller. À appeler en fin de vie d'un
        AgentGuard ; sans cela, les threads daemons vivent avec le processus
        (et le thread d'envoi s'arrête de lui-même dès que l'agent est libéré)."""
        if self._poller is not None:
            self._poller.stop()
        ok = True
        if self._sender is not None:
            ok = self._sender.stop(drain=True, timeout=timeout)
        return ok

    def flush(self, timeout: float = 5.0) -> bool:
        """Attend l'envoi des spans en attente (utile avant de quitter un script)."""
        return True if self._sender is None else self._sender.flush(timeout)

'''
step(7, "nouvelles méthodes", r"^(    def _send_to_collector\(self, span: GuardSpan\):\n)",
     lambda m: NEW_METHODS + m.group(1), re.M)

try:
    compile(src, str(path), "exec")
except SyntaxError as e:
    sys.exit(f"ABANDON : le résultat ne compile pas ({e}). Fichier non modifié.")

shutil.copy(path, str(path) + ".bak")
path.write_bytes((src.replace("\n", "\r\n") if crlf else src).encode("utf-8"))
print(f"OK : {path} modifié ({TOTAL}/{TOTAL}). Sauvegarde : {path}.bak")
print("RAPPEL : un lot de PLUSIEURS spans part en LISTE JSON — le collector doit accepter list[dict] sur /span.")
print("         Un span seul part toujours en objet JSON (compatibilité arrière).")
print("Ensuite : python -m ruff check --fix agentguard/ && python -m ruff format agentguard/ && python -m pytest tests/ -x -q")