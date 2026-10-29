#!/usr/bin/env python3
"""Surcoût réel d'un appel d'outil gardé : synchrone (avant) vs arrière-plan (après).

Lance un faux collector local qui attend --delay-ms avant chaque réponse (latence
réseau simulée), puis appelle un outil gardé --calls fois dans chaque mode avec le
VRAI SDK. Hors réseau (aucun appel externe), reproductible.

    python bench_overhead.py                      # 300 ms simulés, 40 appels
    python bench_overhead.py --delay-ms 2500      # ta connexion depuis la RDC
    python bench_overhead.py --delay-ms 80        # un cloud proche

Notes :
  * Le SDK envoie les spans par GRAPPES (liste JSON) — on compte les SPANS reçus,
    pas les POST (sinon « 3/40 » juste parce que 40 spans partent en 3 requêtes).
  * Si --delay-ms dépasse le timeout de lecture statut/mode du SDK (2 s), les GET
    expirent côté client et le serveur écrit dans une connexion fermée : les
    « ConnectionAbortedError » affichés sont ce bruit attendu, ils sont étouffés
    ici. En vrai déploiement avec une telle latence, le mode retombe en enforce
    (fail-safe voulu) — vise un collector à < 2 s de latence.
"""
import argparse
import json
import os
import statistics
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Collector(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    delay = 0.3
    received = 0  # SPANS reçus (un POST peut en transporter plusieurs)
    posts = 0     # requêtes POST /span reçues

    def _send(self, code, body):
        data = json.dumps(body).encode()
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except OSError:
            pass  # le client a expiré avant notre réponse : bruit attendu, pas une erreur

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        time.sleep(self.delay)
        if self.path == "/span":
            type(self).posts += 1
            try:
                body = json.loads(raw or b"{}")
            except ValueError:
                body = {}
            type(self).received += len(body) if isinstance(body, list) else 1
        self._send(201, {"status": "ok"})

    def do_GET(self):
        time.sleep(self.delay)
        if self.path.startswith("/api/agent/status"):
            self._send(200, {"status": "connected", "incident_open": False})
        elif self.path.startswith("/api/agent/mode"):
            self._send(200, {"mode": "enforce"})
        else:
            self._send(404, {"error": "not found"})

    def log_message(self, *a):
        pass


def pct(values, p):
    values = sorted(values)
    return values[min(len(values) - 1, int(round(p / 100 * (len(values) - 1))))]


def run(async_io, calls, gap, url):
    os.environ["AGENTGUARD_ASYNC_IO"] = "true" if async_io else "false"
    os.environ["AGENTGUARD_MODE_TTL"] = "2"
    os.environ["AGENTGUARD_STATUS_TTL"] = "2"
    from agentguard import AgentGuard  # import tardif : lit les variables ci-dessus

    Collector.received = 0
    Collector.posts = 0
    guard = AgentGuard(collector_url=url, api_key="bench-key", agent_id="bench")

    def lookup(q):
        return f"résultat pour {q}"

    tool = guard.guard_tool_call(lookup)
    times = []
    for i in range(calls):
        t0 = time.perf_counter()
        tool(q=f"requête {i}")
        times.append((time.perf_counter() - t0) * 1000)
        time.sleep(gap)  # l'agent « réfléchit » : laisse passer les TTL de statut/mode
    t0 = time.perf_counter()
    flush = getattr(guard, "flush", None)
    ok = flush(60) if flush else True
    drain = (time.perf_counter() - t0) * 1000
    if not async_io:
        time.sleep(0.2)
    rest = times[1:]
    return {
        "first": times[0], "p50": statistics.median(rest), "p95": pct(rest, 95),
        "max": max(rest), "sum": sum(times), "received": Collector.received,
        "posts": Collector.posts, "drain": drain, "flush_ok": ok,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--delay-ms", type=float, default=300)
    ap.add_argument("--calls", type=int, default=40)
    ap.add_argument("--gap-ms", type=float, default=100)
    a = ap.parse_args()
    Collector.delay = a.delay_ms / 1000
    server = ThreadingHTTPServer(("127.0.0.1", 0), Collector)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}"

    rows = [("synchrone (avant)", run(False, a.calls, a.gap_ms / 1000, url)),
            ("arrière-plan (après)", run(True, a.calls, a.gap_ms / 1000, url))]
    print(f"\nLatence simulée du collector : {a.delay_ms:.0f} ms par requête · {a.calls} appels gardés · "
          f"pause de {a.gap_ms:.0f} ms entre appels")
    print(f"{'mode':<22}{'1er appel':>10}{'p50':>9}{'p95':>9}{'max':>9}{'vidage':>9}{'spans reçus':>13}{'POST':>6}")
    for name, r in rows:
        print(f"{name:<22}{r['first']:>8.0f}ms{r['p50']:>7.1f}ms{r['p95']:>7.1f}ms{r['max']:>7.0f}ms"
              f"{r['drain']:>7.0f}ms{r['received']:>9}/{a.calls}{r['posts']:>6}")
    print("\n« vidage » = temps pour envoyer en arrière-plan les spans encore en file à la fin (hors chemin de l'agent).")
    print("« POST » = requêtes /span : avec les grappes, quelques requêtes suffisent pour tous les spans.")
    sys.stdout.flush()
    os._exit(0)  # threads daemon du serveur et du SDK


if __name__ == "__main__":
    main()