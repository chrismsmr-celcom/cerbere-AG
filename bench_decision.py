"""Bench de la latence COMPLÈTE de la décision de sécurité de Cerbère.

Mesure le temps de l'appel protégé de bout en bout (décision + masquage +
kill switch + soumission du span), en isolant les 3 composants de latence :

  1. CHAUD      : snapshot local frais (StatusPoller), chemin nominal.
  2. TTL EXPIRÉ : chaque appel relit le statut/mode sur le réseau (pire cas
                  synchrone du chemin de décision).
  3. LENT       : TTL expiré + collector artificiellement lent (réseau dégradé).

Le faux collector est piloté par `--delay` (latence réseau simulée en ms).
Le nombre d'appels, la latence et les TTL se règlent en ligne de commande.
Résultats bruts imprimés en JSON (à publier tels quels avec la méthodo).

Usage :
    python bench_decision.py --calls 200
    python bench_decision.py --calls 200 --delay 1500
    python bench_decision.py --calls 200 --ttl-ms 0      # TTL nul = réseau à chaque appel
"""

import argparse
import json
import os
import statistics
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from agentguard import AgentGuard


class _Fake:
    def __init__(self, delay):
        self.delay = delay / 1000.0
        self.mode = "enforce"
        self.get_hits = 0  # lectures réseau statut/mode (≠ appels protégés)


def _serve(fake):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, code, body):
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            time.sleep(fake.delay)
            fake.get_hits += 1
            if self.path.startswith("/api/agent/status"):
                return self._send(200, {"status": "connected", "incident_open": False})
            if self.path.startswith("/api/agent/mode"):
                return self._send(200, {"mode": fake.mode})
            self._send(404, {"error": "not found"})

        def do_POST(self):
            time.sleep(fake.delay)
            self._send(201, {"status": "ok"})

        def log_message(self, *args):
            pass  # étouffe le bruit de shutdown (connexions coupées)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def _pct(sorted_ms, p):
    """Percentile linéaire sur une liste TRIÉE de millisecondes."""
    k = (len(sorted_ms) - 1) * (p / 100.0)
    lo, hi = int(k), min(int(k) + 1, len(sorted_ms) - 1)
    frac = k - lo
    return sorted_ms[lo] + (sorted_ms[hi] - sorted_ms[lo]) * frac


def _run(label, url, calls, ttl_ms, mode_ttl_s, status_ttl_s, warmup=5):
    """Exécute `calls` appels protégés et renvoie les stats de latence."""
    os.environ["AGENTGUARD_MODE_TTL"] = str(mode_ttl_s)
    os.environ["AGENTGUARD_STATUS_TTL"] = str(status_ttl_s)
