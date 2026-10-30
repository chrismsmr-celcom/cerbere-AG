"""Tests de l'E/S en arrière-plan (agentguard/background.py + chemin rapide du SDK).

Un faux collector HTTP local (stdlib) est piloté par chaque test. Ces tests forcent
AGENTGUARD_ASYNC_IO=true : par défaut, sous pytest, le SDK reste synchrone.

Le collector accepte désormais une LISTE de spans dans le POST /span (grappes),
mais tolère aussi un objet unique (compatibilité arrière).
"""

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from agentguard import AgentGuard
from agentguard.background import SpanSender, bg_enabled
from agentguard.models import AgentDisconnectedException


class _Fake:
    """État du faux collector, modifiable par les tests."""

    def __init__(self):
        self.spans = []
        self.span_posts = 0  # nombre de POST /span reçus (grappes = moins que spans)
        self.mode = "enforce"
        self.mode_code = 200
        self.status_code = 200
        self.status_body = {"status": "connected", "incident_open": False}
        self.span_code = 201
        self.delay = 0.0


@pytest.fixture
def collector():
    fake = _Fake()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, code, body):
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            time.sleep(fake.delay)
            if self.path == "/span":
                fake.span_posts += 1
                if fake.span_code >= 400:
                    # rejet AVANT persistance : un span rejeté n'est JAMAIS
                    # enregistré dans fake.spans (sémantique du collector réel)
                    return self._send(fake.span_code, {"error": "agent_disconnected"})
                fake.spans.extend(payload if isinstance(payload, list) else [payload])
            self._send(201, {"status": "ok"})

        def do_GET(self):
            time.sleep(fake.delay)
            if self.path.startswith("/api/agent/status"):
                if fake.status_code != 200:
                    return self._send(fake.status_code, {"error": "agent_disconnected"})
                return self._send(200, fake.status_body)
            if self.path.startswith("/api/agent/mode"):
                if fake.mode_code != 200:
                    return self._send(fake.mode_code, {"error": "boom"})
                return self._send(200, {"mode": fake.mode})
            self._send(404, {"error": "not found"})

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield fake, f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.fixture
def async_env(monkeypatch):
    monkeypatch.setenv("AGENTGUARD_ASYNC_IO", "true")
    monkeypatch.setenv("AGENTGUARD_MODE_TTL", "1")
    monkeypatch.setenv("AGENTGUARD_STATUS_TTL", "1")
    monkeypatch.delenv("AGENTGUARD_SHADOW_MODE", raising=False)


def _guard_and_tool(url):
    guard = AgentGuard(collector_url=url, api_key="k", agent_id="t")

    def lookup(q):
        return f"ok {q}"

    return guard, guard.guard_tool_call(lookup)


def _wait(cond, timeout=6.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


# ── activation ──────────────────────────────────────────────────────────────


def test_bg_enabled_defaults_and_overrides(monkeypatch):
    monkeypatch.delenv("AGENTGUARD_ASYNC_IO", raising=False)
    assert bg_enabled() is False  # sous pytest : synchrone par défaut
    monkeypatch.setenv("AGENTGUARD_ASYNC_IO", "true")
    assert bg_enabled() is True
    monkeypatch.setenv("AGENTGUARD_ASYNC_IO", "false")
    assert bg_enabled() is False
    monkeypatch.delenv("PYTEST_CURRENT_TEST")
    monkeypatch.delenv("AGENTGUARD_ASYNC_IO")
    assert bg_enabled() is True  # hors pytest : actif par défaut


def test_sync_mode_is_unchanged(collector, monkeypatch):
    fake, url = collector
    monkeypatch.setenv("AGENTGUARD_ASYNC_IO", "false")
    guard, tool = _guard_and_tool(url)
    tool(q="a")
    assert len(fake.spans) == 1  # livré avant le retour, sans flush
    assert guard._poller is None and guard._sender is None


# ── envoi des spans ─────────────────────────────────────────────────────────


def test_spans_do_not_block_and_arrive_in_order(collector, async_env):
    fake, url = collector
    guard, tool = _guard_and_tool(url)
    tool(q="warmup")  # 1re lecture synchrone du statut/mode
    guard.flush(5)
    fake.spans.clear()
    fake.delay = 0.3

    t0 = time.perf_counter()
    for i in range(5):
        tool(q=str(i))
    elapsed = time.perf_counter() - t0

    assert elapsed < 0.25  # sans file d'attente : au moins 5 x 0,3 s
    assert guard.flush(15) is True
    sent = [p["span_id"] for p in fake.spans]
    assert sent == [s.span_id for s in guard.spans[-5:]]  # ordre préservé, même par grappes


def test_spans_are_batched_off_the_hot_path(collector, async_env):
    fake, url = collector
    guard, tool = _guard_and_tool(url)
    tool(q="warmup")
    assert guard.flush(5) is True
    fake.spans.clear()
    fake.span_posts = 0

    for i in range(20):
        tool(q=str(i))  # rafale : le thread d'envoi doit les grouper

    assert guard.flush(15) is True
    assert len(fake.spans) == 20  # rien de perdu
    assert fake.span_posts <= 3  # plusieurs spans par POST, pas un POST par span
    assert [p["span_id"] for p in fake.spans] == [s.span_id for s in guard.spans[-20:]]


def test_single_span_is_delivered_without_added_delay(collector, async_env):
    fake, url = collector
    guard, tool = _guard_and_tool(url)
    tool(q="warmup")
    assert guard.flush(5) is True
    fake.spans.clear()
    fake.span_posts = 0

    tool(q="seul")
    assert _wait(lambda: len(fake.spans) == 1, 3)  # pas d'attente de grappe qui retarde
    assert fake.span_posts == 1


def test_queue_full_drops_and_counts():
    started, release = threading.Event(), threading.Event()

    def deliver(batch, session):
        started.set()
        release.wait(5)

    sender = SpanSender(deliver, maxsize=2, flush_interval=0.0)
    assert sender.submit({"n": 1})
    assert started.wait(2)  # le thread d'envoi tient le 1er lot ; la file est vide
    assert sender.submit({"n": 2}) and sender.submit({"n": 3})
    assert sender.submit({"n": 4}) is False and sender.submit({"n": 5}) is False
    assert sender.dropped == 2 and sender.submitted == 3  # pertes comptées, entrées comptées
    release.set()
    assert sender.flush(5) is True


def test_sender_survives_delivery_errors():
    got = []

    def deliver(batch, session):
        if batch[0]["n"] == 1:
            raise RuntimeError("boom")
        got.extend(p["n"] for p in batch)

    sender = SpanSender(deliver, maxsize=10, flush_interval=0.0)
    sender.submit({"n": 1})
    assert sender.flush(5) is True  # la file est TRAITÉE (lot échoué compté), pas « persistée »
    sender.submit({"n": 2})
    assert sender.flush(5) is True
    assert got == [2]
    assert sender.submitted == 2 and sender.delivered == 1 and sender.failed == 1
    assert sender.dropped == 0 and sender.pending == 0  # compteurs cohérents


def test_flush_returns_false_when_delivery_is_stuck():
    release = threading.Event()
    sender = SpanSender(lambda batch, session: release.wait(5), maxsize=10, flush_interval=0.0)
    sender.submit({"n": 1})
    assert sender.flush(0.2) is False
    release.set()
    assert sender.flush(5) is True


def test_span_rejected_with_403_marks_agent_disconnected(collector, async_env):
    fake, url = collector
    fake.span_code = 403
    guard, tool = _guard_and_tool(url)
    with pytest.warns(RuntimeWarning):
        tool(q="a")
        assert guard.flush(5) is True
        assert _wait(lambda: guard._conn_state == "disconnected", 3)


# ── saturation et fiabilité sous charge ─────────────────────────────────────


def test_no_span_lost_when_collector_is_slow(collector, async_env):
    fake, url = collector
    guard, tool = _guard_and_tool(url)
    tool(q="warmup")
    assert guard.flush(5) is True
    fake.spans.clear()

    fake.delay = 0.3  # collector lent : le thread d'envoi prend du retard
    for _ in range(30):
        tool(q="a")

    t0 = time.perf_counter()
    for i in range(10):
        tool(q=str(i))  # le chemin chaud reste rapide malgré le retard accumulé
    assert time.perf_counter() - t0 < 0.5

    assert guard.flush(30) is True
    assert len(fake.spans) == 40  # rien de perdu : tout finit par partir
    assert [p["span_id"] for p in fake.spans] == [s.span_id for s in guard.spans[-40:]]


def test_saturation_counts_drops_and_keeps_oldest_spans(collector, async_env, monkeypatch):
    fake, url = collector
    monkeypatch.setenv("AGENTGUARD_TELEMETRY_QUEUE", "4")
    monkeypatch.setenv("AGENTGUARD_TELEMETRY_BATCH", "2")
    guard, tool = _guard_and_tool(url)
    tool(q="warmup")
    assert guard.flush(5) is True
    fake.spans.clear()

    fake.delay = 0.2
    start = len(guard.spans)
    for i in range(50):
        tool(q=str(i))  # débit volontairement >> capacité : la file déborde

    sender = guard._sender
    assert sender.dropped > 0  # les pertes sont COMPTÉES, jamais silencieuses

    assert guard.flush(30) is True
    delivered = [p["span_id"] for p in fake.spans]
    expected = [s.span_id for s in guard.spans[start:]]

    # Ordre relatif préservé : « livrés » = « émis » moins les écartés.
    # Un écart peut survenir N'IMPORTE OÙ dans la rafale (queue.Full à la
    # soumission), donc les livrés forment une SOUS-SÉQUENCE des émis,
    # pas nécessairement un préfixe.
    expected_set = set(expected)
    assert all(sid in expected_set for sid in delivered)  # aucun span fantôme
    it = iter(expected)
    assert all(any(e == d for e in it) for d in delivered)  # ordre FIFO respecté

    # invariant de conservation : livrés + écartés == émis (aucune perte silencieuse)
    assert len(delivered) + sender.dropped == len(expected)


# ── cycle de vie des threads ───────────────────────────────────────────────


def test_sender_stop_drains_queue_and_exits_thread():
    got = []

    def deliver(batch, session):
        got.extend(batch)

    sender = SpanSender(deliver, maxsize=10, flush_interval=0.0)
    sender.submit({"n": 1})
    sender.submit({"n": 2})
    assert sender.stop() is True
    assert not sender._thread.is_alive()  # thread réellement arrêté
    assert len(got) == 2  # file VIDÉE avant l'arrêt : rien d'abandonné


def test_close_stops_threads_and_drains_queue(collector, async_env):
    fake, url = collector
    guard, tool = _guard_and_tool(url)
    tool(q="a")
    tool(q="b")
    assert guard.close() is True  # fermeture propre de l'agent en fin de vie
    assert not guard._sender._thread.is_alive()  # thread d'envoi RÉELLEMENT arrêté
    assert guard._poller._stop.is_set()  # poller arrêté
    assert len(fake.spans) == 2  # file VIDÉE avant l'arrêt : rien d'abandonné
    assert guard.flush(1) is True  # idempotent : plus rien en attente


# ── panne du collector puis retour ──────────────────────────────────────────


def test_outage_then_recovery_resumes_without_duplicates(collector, async_env):
    fake, url = collector
    guard, tool = _guard_and_tool(url)
    tool(q="warmup")
    assert guard.flush(5) is True
    fake.spans.clear()

    fake.span_code = 500  # panne : le collector rejette les POST /span AVANT persistance
    tool(q="rejeté")  # lot rejeté et journalisé : le thread d'envoi SURVIT
    assert guard.flush(5) is True
    assert fake.spans == []  # RIEN n'est persisté pendant la panne (rejet avant écriture)
    assert guard._sender.delivered >= 1  # compteur : le lot est traité, pas persisté

    fake.span_code = 201  # retour du collector

    t0 = time.perf_counter()
    for i in range(5):
        tool(q=str(i))
    assert _wait(lambda: len(fake.spans) == 5, 5)  # reprise immédiate, sans rejeu du lot perdu
    assert time.perf_counter() - t0 < 5
    ids = [p["span_id"] for p in fake.spans]
    assert len(ids) == len(set(ids))  # aucun DOUBLON après la panne
    assert ids == [s.span_id for s in guard.spans[-5:]]  # ordre préservé à la reprise


def test_consecutive_timeouts_then_recovery(collector, async_env):
    fake, url = collector
    guard, tool = _guard_and_tool(url)
    tool(q="warmup")
    assert guard.flush(5) is True
    fake.spans.clear()

    # plusieurs timeouts successifs : chaque livraison expire (read timeout 5 s)
    fake.delay = 6.0
    for i in range(3):
        tool(q=str(i))
    time.sleep(1.0)  # le thread d'envoi échoue sur son lot, journalise, survit

    fake.delay = 0.0  # le collector revient : délai de récupération mesuré
    t0 = time.perf_counter()
    tool(q="après")
    assert _wait(lambda: len(fake.spans) >= 1, 5)
    recovery = time.perf_counter() - t0
    # Pire cas réaliste : la requête POST EN VOL au moment du retour du
    # collector doit d'abord expirer (read timeout = 5 s) ; le lot suivant
    # part aussitôt. Récupération = collector_timeout + 1 grappe, pas de retrait long.
    assert recovery < 6.5

    ids = [p["span_id"] for p in fake.spans]
    assert len(ids) == len(set(ids))  # aucun doublon après les timeouts


# ── décision de sécurité en mode enforce ────────────────────────────────────


def test_enforce_never_executes_protected_action_when_disconnected(collector, async_env):
    fake, url = collector
    fake.status_body = {"status": "disconnected", "incident_open": False}
    guard = AgentGuard(collector_url=url, api_key="k", agent_id="t")
    ran = []

    def dangerous(q):
        ran.append(q)  # l'action protégée ne doit JAMAIS s'exécuter
        return q

    tool = guard.guard_tool_call(dangerous)
    with pytest.raises(AgentDisconnectedException):
        tool(q="secret")
    assert ran == []  # asynchronisme = télémétrie uniquement, jamais l'autorisation


# ── charge réelle : agents concurrents ──────────────────────────────────────


def test_multiple_concurrent_agents_no_cross_talk(collector, async_env):
    fake, url = collector
    pairs = []
    for n in range(3):
        g = AgentGuard(collector_url=url, api_key="k", agent_id=f"a{n}")

        def lookup(q, _n=n):
            return f"ok {_n} {q}"

        pairs.append((g, g.guard_tool_call(lookup)))

    for round_ in range(10):  # appels entremêlés des 3 agents
        for _, t in pairs:
            t(q=f"r{round_}")

    for g, _ in pairs:
        assert g.flush(10) is True

    delivered = [p["span_id"] for p in fake.spans]
    delivered_set = set(delivered)

    for g, _ in pairs:
        mine = [s.span_id for s in g.spans]
        assert set(mine) <= delivered_set  # chaque agent a tout son telemetry livré
        it = iter(delivered)
        assert all(any(e == d for e in it) for d in mine)  # ordre relatif préservé par agent


def test_true_concurrency_hundreds_of_calls_from_thread_pool(collector, async_env):
    from concurrent.futures import ThreadPoolExecutor

    fake, url = collector
    guard, tool = _guard_and_tool(url)
    tool(q="warmup")
    assert guard.flush(5) is True
    fake.spans.clear()
    start = len(guard.spans)
    sender = guard._sender
    baseline = (sender.submitted, sender.delivered, sender.dropped)  # cumulatif : mesurer un DELTA

    def hammer(i):
        return tool(q=str(i))

    with ThreadPoolExecutor(max_workers=32) as pool:
        results = list(pool.map(hammer, range(200)))  # 200 appels, 32 threads simultanés

    assert all(r.startswith("ok ") for r in results)  # aucune exception, aucun appel perdu
    assert guard.flush(30) is True

    sender = guard._sender
    # les compteurs sont cumulatifs : on vérifie le DELTA depuis la ligne de base
    assert sender.submitted - baseline[0] == 200
    assert sender.dropped - baseline[2] == 0  # rien écarté
    assert sender.pending == 0  # tout traité
    assert (
        sender.submitted - baseline[0]
        == (sender.delivered - baseline[1]) + (sender.dropped - baseline[2]) + sender.pending
    )  # invariants comptables cohérents

    delivered = [p["span_id"] for p in fake.spans]
    expected = [s.span_id for s in guard.spans[start:]]
    assert len(delivered) == 200  # tout livré
    assert len(delivered) == len(set(delivered))  # aucun DOUBLON, aucune collision d'ID
    expected_set = set(expected)
    assert all(sid in expected_set for sid in delivered)  # aucun span fantôme
    it = iter(expected)
    assert all(any(e == d for e in it) for d in delivered)  # sous-séquence ordonnée de l'émission
    assert len(expected_set) == 200  # identifiants uniques par agent et par appel


# ── mode shadow / enforce ───────────────────────────────────────────────────


def test_shadow_mode_propagates_then_fails_safe_to_enforce(collector, async_env):
    fake, url = collector
    fake.mode = "shadow"
    guard, tool = _guard_and_tool(url)
    tool(q="a")
    assert guard.shadow_mode is True  # 1re lecture synchrone : exact dès le 1er appel

    fake.mode_code = 500  # collector en panne : on revient à enforce
    def back_to_enforce():
        tool(q="b")
        return guard.shadow_mode is False
    assert _wait(back_to_enforce, 6)


def test_stale_mode_reading_means_enforce(collector, async_env):
    from agentguard.background import Snapshot

    fake, url = collector
    guard, _ = _guard_and_tool(url)

    class Stub:
        def snapshot(self):
            return Snapshot(shadow=True, mode_ok_at=time.time() - 1000)

    guard._poller = Stub()
    guard._refresh_runtime_mode()
    assert guard.shadow_mode is False  # lecture périmée : jamais de shadow « resté allumé »

    class Fresh:
        def snapshot(self):
            return Snapshot(shadow=True, mode_ok_at=time.time())

    guard._poller = Fresh()
    guard._refresh_runtime_mode()
    assert guard.shadow_mode is True


def test_env_override_still_wins(collector, async_env, monkeypatch):
    _, url = collector
    monkeypatch.setenv("AGENTGUARD_SHADOW_MODE", "true")
    guard, tool = _guard_and_tool(url)
    tool(q="a")
    assert guard.shadow_mode is True


# ── kill switch et incident ─────────────────────────────────────────────────


def test_kill_switch_blocks_first_call_then_recovers(collector, async_env):
    fake, url = collector
    fake.status_body = {"status": "disconnected", "incident_open": False}
    guard, tool = _guard_and_tool(url)
    with pytest.raises(AgentDisconnectedException):
        tool(q="a")  # la 1re lecture est synchrone : bloqué dès le 1er appel

    fake.status_body = {"status": "connected", "incident_open": False}

    def reconnected():
        try:
            tool(q="b")
            return True
        except AgentDisconnectedException:
            return False
    assert _wait(reconnected, 6)


def test_incident_capture_is_opened_on_the_callers_thread(collector, async_env):
    fake, url = collector
    fake.status_body = {"status": "connected", "incident_open": True}
    guard, tool = _guard_and_tool(url)
    seen = []
    guard.start_incident_capture = lambda: seen.append(threading.current_thread())
    tool(q="a")
    assert seen == [threading.current_thread()]  # jamais le thread d'arrière-plan