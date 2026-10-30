"""E/S réseau hors du chemin chaud du SDK.

Avant : chaque appel gardé faisait un POST /span (une nouvelle connexion TCP+TLS
à chaque fois) et, à chaque expiration de cache, un GET /api/agent/status et un
GET /api/agent/mode. Avec une latence réseau de 200 ms à 3 s, c'est autant de
temps ajouté à CHAQUE appel d'outil de l'agent.

Après (par défaut, hors tests) :
  * SpanSender    : file FIFO bornée + un thread daemon, connexion HTTP réutilisée.
                    Les spans partent par GRAPPES : un seul POST transporte jusqu'à
                    AGENTGUARD_TELEMETRY_BATCH spans (fenêtre d'attente du lot :
                    AGENTGUARD_TELEMETRY_FLUSH_MS). Débit ≈ grappe / latence réseau
                    au lieu de 1 span / latence réseau.
                    submit() ne bloque jamais et ne lève jamais.
  * StatusPoller  : deux threads daemon (statut, mode) relisent le kill switch,
                    l'incident et le mode shadow/enforce ; le chemin chaud ne lit
                    qu'un instantané. Personne n'attend ces lectures : elles ont
                    des timeouts généreux (AGENTGUARD_POLL_CONNECT_TIMEOUT /
                    AGENTGUARD_POLL_READ_TIMEOUT) et un recul exponentiel borné
                    en cas d'échec, pour réussir même sur un réseau très lent.

Garanties conservées :
  * Fail-safe mode : lecture du mode en erreur => enforce (jamais de shadow
    « resté allumé » si le collector est injoignable).
  * Premier appel BORNÉ : le premier appel attend au plus
    AGENTGUARD_COLD_BUDGET_MS (250 ms par défaut) la première lecture de fond
    (voir StatusPoller.wait_first). Passé ce budget, l'instantané garde ses
    valeurs par défaut (enforce, « connected ») : mode dégradé, jamais bloquant.
    La politique de repli sur un statut périmé (ouvert/fermé) se décide côté
    SDK avec StatusPoller.status_age() / Snapshot.status_ok_at.
  * Les mutations du coffre d'incident (masquage, scellement) restent sur le
    thread de l'appelant : seul le réseau passe en arrière-plan.
  * Ordre : un seul thread d'envoi et une FIFO stricte ; les spans d'un lot
    partent dans l'ordre d'arrivée (la timeline de trajectoire du collector
    repose sur l'ordre d'arrivée).

Désactivation : AGENTGUARD_ASYNC_IO=false (comportement synchrone d'origine).
Défaut : activé, sauf sous pytest (tests déterministes ; forcer avec =true).
"""

from __future__ import annotations

import atexit
import dataclasses
import os
import queue
import threading
import time
import weakref
from collections.abc import Callable
from typing import Any

import requests
import structlog

logger = structlog.get_logger("agentguard.background")


# ── extinction propre ───────────────────────────────────────────────────────
# Les threads d'E/S sont des daemons : à la fermeture de l'interpréteur, ils
# doivent cesser toute activité (journal compris) AVANT la finalisation, sinon
# CPython peut planter sur le verrou du buffer stdout (« Fatal Python error:
# _enter_buffered_busy ... due to daemon threads »). Les atexit s'exécutent en
# LIFO : les flush() des SpanSender (enregistrés plus tard) vident la file
# d'abord, puis _SHUTDOWN coupe les boucles de polling.

_SHUTDOWN = threading.Event()
atexit.register(_SHUTDOWN.set)


def bg_enabled() -> bool:
    """E/S en arrière-plan actives ? Lu à chaque appel (pas figé à l'import)."""
    value = os.getenv("AGENTGUARD_ASYNC_IO")
    if value is not None:
        return value.strip().lower() == "true"
    return "PYTEST_CURRENT_TEST" not in os.environ


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return float(default)


def _poll_timeout() -> tuple[float, float]:
    """(connexion, lecture) des lectures de fond. Lu à chaque lecture : un
    réglage d'environnement tardif est pris en compte. Les valeurs sont
    volontairement larges : ces lectures n'attendent personne, et un timeout
    court les ferait échouer en boucle sur un réseau lent (ex. 2-3 s d'aller-
    retour), laissant l'instantané figé sur ses valeurs par défaut."""
    return (
        max(0.5, _env_float("AGENTGUARD_POLL_CONNECT_TIMEOUT", 5.0)),
        max(0.5, _env_float("AGENTGUARD_POLL_READ_TIMEOUT", 8.0)),
    )


# ── envoi des spans ─────────────────────────────────────────────────────────

_STOP = object()  # sentinelle d'arrêt explicite du thread d'envoi


class SpanSender:
    """File FIFO bornée + thread daemon + envoi par grappes.

    Le thread prend le premier span de la file, rassemble les suivants pendant au
    plus `flush_interval` secondes (jusqu'à `max_batch` spans) puis livre le lot
    en un seul POST sur une connexion réutilisée. Sous charge faible, le lot est
    de 1 et aucune latence n'est ajoutée ; sous charge forte, le coût par span
    chute d'un facteur proche de la taille de grappe. Au-delà de la capacité de
    la file, les plus récents sont écartés et comptés."""

    def __init__(
        self,
        deliver: Callable[[list, Any], None],
        maxsize: int | None = None,
        max_batch: int | None = None,
        flush_interval: float | None = None,
    ):
        self._deliver = deliver
        size = (
            maxsize
            if maxsize is not None
            else int(os.getenv("AGENTGUARD_TELEMETRY_QUEUE", "2000"))
        )
        batch = (
            max_batch
            if max_batch is not None
            else int(os.getenv("AGENTGUARD_TELEMETRY_BATCH", "50"))
        )
        ms = (
            flush_interval
            if flush_interval is not None
            else float(os.getenv("AGENTGUARD_TELEMETRY_FLUSH_MS", "50"))
        )
        self._q: queue.Queue[dict] = queue.Queue(maxsize=max(1, size))
        self._max_batch = max(1, batch)
        self._flush_interval = max(0.0, ms / 1000.0 if ms > 1 else ms)
        # Référence faible quand `deliver` est une méthode liée (le thread ne
        # retient PAS l'AgentGuard : il s'arrête tout seul quand l'agent est
        # libéré). Référence forte sinon (fonctions/lambdas de test).
        self._strong_deliver: Callable | None
        try:
            self._deliver = weakref.WeakMethod(deliver)
            self._strong_deliver = None
        except TypeError:
            self._deliver = None
            self._strong_deliver = deliver
        self.dropped = 0
        # Compteurs consultatifs (indicatifs sous concurrence ; utiles en
        # exploitation et dans les tests de charge) :
        self.submitted = 0  # spans acceptés dans la file
        self.delivered = 0  # spans livrés SANS exception — ce n'est PAS une
        #                      garantie de persistance côté collector (un rejet
        #                      HTTP >= 400 est journalisé dans _post_spans et
        #                      compte ici comme « livré »)
        self.failed = 0  # spans dont le lot a levé une exception de transport
        self._last_drop_log = 0.0
        self._thread = threading.Thread(
            target=self._run, name="agentguard-telemetry", daemon=True
        )
        self._thread.start()
        atexit.register(self.flush, 5.0)

    def submit(self, payload: dict) -> bool:
        try:
            self._q.put_nowait(payload)
            self.submitted += 1
            return True
        except queue.Full:
            self.dropped += 1
            now = time.monotonic()
            if now - self._last_drop_log > 30:
                self._last_drop_log = now
                logger.warning(
                    "telemetry_queue_full",
                    dropped_total=self.dropped,
                    maxsize=self._q.maxsize,
                )
            return False

    @property
    def pending(self) -> int:
        """Spans soumis ni livrés, ni échoués, ni écartés (indicatif)."""
        return max(0, self.submitted - self.delivered - self.failed - self.dropped)

    def _resolve_deliver(self) -> Callable | None:
        """Méthode de livraison, ou None si l'agent propriétaire a disparu."""
        if self._strong_deliver is not None:
            return self._strong_deliver
        return self._deliver()  # WeakMethod : None quand la méthode liée est morte

    def _run(self) -> None:
        session = requests.Session()  # connexion keep-alive : 1 aller-retour par LOT
        while not _SHUTDOWN.is_set():
            try:
                payload = self._q.get(timeout=0.5)  # réveil périodique (0,5 s)
            except queue.Empty:
                if self._resolve_deliver() is None:
                    return  # agent libéré : arrêt propre, sans rien attendre
                continue

            taken = 0
            exit_thread = False
            try:
                if payload is _STOP:
                    exit_thread = True
                    taken = 1
                else:
                    deliver = self._resolve_deliver()
                    if deliver is None:
                        # l'AgentGuard propriétaire a été libéré : arrêt propre
                        # (la file restante est abandonnée, plus personne n'émet)
                        exit_thread = True
                        taken = 1
                    else:
                        batch = [payload]
                        taken = 1
                        deadline = time.monotonic() + self._flush_interval
                        while len(batch) < self._max_batch:
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                break
                            try:
                                item = self._q.get(timeout=remaining)
                            except queue.Empty:
                                break
                            if item is _STOP:  # arrêt demandé pendant la grappe
                                exit_thread = True
                                taken += 1
                                break
                            batch.append(item)
                            taken += 1
                        try:
                            deliver(batch, session)
                            self.delivered += len(batch)
                        except Exception as exc:
                            self.failed += len(batch)
                            if not _SHUTDOWN.is_set():
                                logger.warning(
                                    "telemetry_deliver_failed",
                                    error=str(exc),
                                    batch_size=len(batch),
                                )
            finally:
                for _ in range(taken):
                    self._q.task_done()
            if exit_thread:  # hors du finally : ne masque aucune exception
                return

    def stop(self, drain: bool = True, timeout: float = 5.0) -> bool:
        """Arrêt explicite du thread d'envoi (les threads sont daemons : stop()
        sert à la fermeture propre d'un AgentGuard en fin de vie). drain=True
        vide la file d'abord. False si le vidage dépasse `timeout`."""
        if drain and not self.flush(timeout):
            return False
        self._q.put(_STOP)
        self._thread.join(2.0)
        return not self._thread.is_alive()

    def flush(self, timeout: float = 5.0) -> bool:
        """Attend que la file soit vidée. CONTRAT : True signifie que tous les
        lots soumis ont été TRAITÉS — livrés ou en échec compté (`failed`), pas
        « persistés côté collector » (un rejet HTTP >= 400 est journalisé mais
        compte comme traité ; voir les compteurs submitted/delivered/failed/
        dropped/pending). False : délai dépassé, des lots restent en attente."""
        deadline = time.monotonic() + timeout
        with self._q.all_tasks_done:
            while self._q.unfinished_tasks:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._q.all_tasks_done.wait(remaining)
        return True


# ── statut et mode ──────────────────────────────────────────────────────────


@dataclasses.dataclass(frozen=True)
class Snapshot:
    conn_state: str = "connected"
    status_version: int = 0
    incident_open: bool | None = None
    shadow: bool = False
    mode_ok_at: float = 0.0  # dernière lecture RÉUSSIE du mode (0 = jamais)
    status_ok_at: float = 0.0  # dernière lecture RÉUSSIE du statut (0 = jamais)


class StatusPoller:
    """Relit /api/agent/status et /api/agent/mode hors du chemin chaud.

    Un thread par lecture : un collector lent sur l'une ne retarde pas l'autre.
    Aucune lecture n'est faite par l'appelant ; il lit seulement snapshot()."""

    _BACKOFF_CAP = 15.0  # recul maximal (s) entre deux tentatives après échecs

    def __init__(self, owner: Any):
        self._owner = weakref.ref(owner)  # le thread s'arrête quand l'agent est libéré
        self._lock = threading.Lock()
        self._snap = Snapshot()
        self._stop = threading.Event()
        self._session = requests.Session()
        self._next_status = 0.0
        self._next_mode = 0.0
        self._status_fails = 0
        self._mode_fails = 0
        self.started_at = time.time()
        # Posé à la fin du 1er cycle de chaque lecture (succès OU échec).
        self._done = {"status": threading.Event(), "mode": threading.Event()}
        self._ready = False
        self._budget_spent = False  # le budget du 1er appel n'est payé qu'une fois

    # -- état partagé --
    def snapshot(self) -> Snapshot:
        with self._lock:
            return self._snap

    def _update(self, bump_status: bool = False, **changes: Any) -> None:
        with self._lock:
            if bump_status:
                changes["status_version"] = self._snap.status_version + 1
            self._snap = dataclasses.replace(self._snap, **changes)

    def status_age(self) -> float:
        """Secondes depuis la dernière lecture RÉUSSIE du statut (ou depuis le
        démarrage du poller si aucune n'a encore réussi). Sert à la politique de
        repli du kill switch quand le collector est injoignable."""
        ok_at = self.snapshot().status_ok_at or self.started_at
        return max(0.0, time.time() - ok_at)

    # -- premier appel borné --
    def wait_first(self, budget: float) -> bool:
        """Attend au plus `budget` secondes que chaque lecture ait terminé son
        premier cycle. True si les deux ont terminé (succès ou échec), False si
        le budget est épuisé — l'instantané garde alors ses valeurs par défaut
        (mode dégradé). Après le premier cycle, coût quasi nul."""
        if self._ready:
            return True
        if self._budget_spent:
            # Le budget a déjà été payé par un appel précédent : on ne le paie
            # JAMAIS deux fois (ni par appel, ni par vérification successive
            # dans un même appel). On regarde seulement si c'est prêt.
            if all(e.is_set() for e in self._done.values()):
                self._ready = True
            return self._ready
        deadline = time.monotonic() + max(0.0, budget)
        ok = True
        for event in self._done.values():
            if not event.wait(max(0.0, deadline - time.monotonic())):
                ok = False
        self._budget_spent = True
        if ok:
            self._ready = True
        return ok

    # -- cycle de vie --
    def start(self) -> None:
        for which in ("status", "mode"):
            threading.Thread(
                target=self._loop,
                args=(which,),
                name=f"agentguard-{which}",
                daemon=True,
            ).start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self, which: str) -> None:
        poll = self._poll_status if which == "status" else self._poll_mode
        while not self._stop.is_set():
            owner = self._owner()
            if _SHUTDOWN.is_set() or owner is None:
                return
            enabled = owner._status_check if which == "status" else bool(owner.api_key)
            due = self._next_status if which == "status" else self._next_mode
            if not enabled:
                self._done[which].set()  # rien à lire : ne bloque pas le 1er appel
            elif time.time() >= due:
                try:
                    poll(owner)
                except Exception as exc:
                    logger.debug("status_poll_failed", error=str(exc))
                self._done[which].set()
            del owner  # ne pas retenir l'agent pendant l'attente (weakref)
            self._stop.wait(0.25)

    def poll_once(self) -> None:
        """Une lecture synchrone des deux sources (tests, diagnostic). Le SDK
        ne l'appelle plus dans le chemin chaud."""
        owner = self._owner()
        if owner is None:
            return
        now = time.time()
        if owner._status_check and now >= self._next_status:
            self._poll_status(owner)
        if owner.api_key and now >= self._next_mode:
            self._poll_mode(owner)

    # -- lectures --
    @classmethod
    def _backoff(cls, ttl: float, fails: int) -> float:
        # Exponentiel à partir du TTL, plafonné, jamais inférieur au TTL.
        # (Remplace l'ancien recul fixe de ttl + 25 s, qui retardait aussi la
        # propagation d'un vrai « déconnecter » après une coupure réseau.)
        return max(ttl, min(ttl * (2 ** min(fails, 10)), cls._BACKOFF_CAP))

    def _poll_status(self, owner: Any) -> None:
        ttl = owner._status_ttl
        self._next_status = time.time() + ttl
        try:
            response = self._session.get(
                f"{owner.collector_url}/api/agent/status",
                headers=owner._headers(),
                timeout=_poll_timeout(),
            )
            if response.status_code == 200:
                body = response.json()
                self._status_fails = 0
                self._update(
                    bump_status=True,
                    status_ok_at=time.time(),
                    conn_state=body.get("status", "connected"),
                    incident_open=bool(body.get("incident_open")),
                )
            elif response.status_code == 403 and "agent_disconnected" in response.text:
                self._status_fails = 0
                self._update(
                    bump_status=True,
                    status_ok_at=time.time(),
                    conn_state="disconnected",
                )
        except Exception as exc:
            self._status_fails += 1
            self._next_status = time.time() + self._backoff(ttl, self._status_fails)
            if not _SHUTDOWN.is_set():
                logger.debug("agent_status_check_failed", error=str(exc))

    def _poll_mode(self, owner: Any) -> None:
        ttl = owner._runtime_mode_ttl
        self._next_mode = time.time() + ttl
        try:
            response = self._session.get(
                f"{owner.collector_url}/api/agent/mode",
                headers=owner._headers(),
                timeout=_poll_timeout(),
            )
            response.raise_for_status()
            mode = response.json().get("mode")
            if mode in ("enforce", "shadow"):
                self._mode_fails = 0
                self._update(shadow=(mode == "shadow"), mode_ok_at=time.time())
            else:
                logger.warning(
                    "invalid_agent_runtime_mode", agent_id=owner.agent_id, mode=mode
                )
                self._update(shadow=False)
        except Exception as exc:
            self._mode_fails += 1
            self._next_mode = time.time() + self._backoff(ttl, self._mode_fails)
            self._update(shadow=False)  # fail-safe immédiat : enforce
            if not _SHUTDOWN.is_set():
                logger.debug(
                    "agent_runtime_mode_check_failed",
                    agent_id=owner.agent_id,
                    error=str(exc),
                )