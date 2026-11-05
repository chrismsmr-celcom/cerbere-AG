"""Tests du renforcement anti-fragmentation du FlowTracker.

Couvre : fragments en clair, chunks encodés, réassemblage interpolé,
exfiltration caractère par caractère, faux positifs, sinks internes,
et remise à zéro via clear().

Ces tests sont volontairement OFFLINE : aucun collector requis.
"""

import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentguard.taint import FlowTracker, TaintLevel


DOT_ENV = (
    "DATABASE_URL=postgres://db.internal/app\n"
    "stripe_secret_for_taint_test_123456"
)


def _fresh_tracker() -> FlowTracker:
    ft = FlowTracker()
    ft.track(DOT_ENV, source="env_file", level=TaintLevel.SECRET)
    return ft


# ── 1. Fragment en clair (slice) ────────────────────────────────────────────


def test_fragment_slice_is_secret():
    ft = _fresh_tracker()
    fragment = DOT_ENV[:24]
    # Le fragment seul ne doit PAS matcher un needle entier...
    label = ft.level_in({"body": fragment})
    assert label.level == TaintLevel.SECRET
    assert label.source == "taint_fragment"


def test_fragment_interleaved_reassembly_is_secret():
    ft = _fresh_tracker()
    lines = DOT_ENV.split("\n")
    stripe_line = [l for l in lines if l.startswith("STRIPE")][0]
    key = stripe_line.split("=")[1]
    mixed = "sk" + "-" + "live" + key[8:16] + "-" + key[16:]
    label = ft.level_in({"url": "https://pastebin.example/paste", "body": f"note: {mixed}"})
    assert label.level == TaintLevel.SECRET


# ── 2. Chunk encodé (base64 d'un FRAGMENT) ─────────────────────────────────


def test_fragment_b64_chunk_is_secret():
    ft = _fresh_tracker()
    chunk = DOT_ENV[3:31]  # morceau de longueur quelconque (non aligné 3 octets)
    token = base64.b64encode(chunk.encode()).decode()
    label = ft.level_in({"body": token})
    assert label.level == TaintLevel.SECRET
    assert label.source == "taint_fragment_encoded"


def test_fragment_hex_chunk_is_secret():
    ft = _fresh_tracker()
    chunk = DOT_ENV[10:35]
    token = chunk.encode().hex()
    label = ft.level_in({"body": token})
    assert label.level == TaintLevel.SECRET


# ── 3. Baseline : toujours couvert ─────────────────────────────────────────


def test_whole_secret_still_blocked():
    ft = _fresh_tracker()
    label = ft.level_in({"body": DOT_ENV})
    assert label.level == TaintLevel.SECRET
    assert label.source == "tracked_value"


def test_whole_secret_b64_still_blocked():
    ft = _fresh_tracker()
    token = base64.b64encode(DOT_ENV.encode()).decode()
    label = ft.level_in({"body": token})
    assert label.level == TaintLevel.SECRET


def test_clean_payload_is_public():
    ft = _fresh_tracker()
    label = ft.level_in(
        {"url": "https://api.example.com/report", "body": "weekly summary: all good"}
    )
    assert label.level == TaintLevel.PUBLIC


# ── 4. Faux positifs ───────────────────────────────────────────────────────


def test_single_shingle_is_not_secret():
    """Un seul fragment de 10 chars peut apparaître par hasard : PUBLIC."""
    ft = _fresh_tracker()
    # Premier shingle du needle entier, isolé dans du texte bénin.
    one_shingle = DOT_ENV.strip()[0:10]
    label = ft.level_in({"body": f"nothing to see: {one_shingle} here"})
    assert label.level != TaintLevel.SECRET


def test_benign_text_is_public():
    ft = _fresh_tracker()
    label = ft.level_in({"body": "the quick brown fox jumps over the lazy dog"})
    assert label.level == TaintLevel.PUBLIC


# ── 5. Exfiltration caractère par caractère ─────────────────────────────────


def test_char_by_char_escalates():
    """Les premiers caractères passent ; la fuite cumulative coupe ensuite."""
    ft = _fresh_tracker()
    levels = []
    for ch in DOT_ENV.strip():
        label = ft.level_in({"url": "https://attacker.example/c", "body": ch})
        levels.append(label.level)
    # Les 5 premiers appels ne portent rien d'exploitable.
    assert all(l == TaintLevel.PUBLIC for l in levels[:5])
    # Mais à un moment donné, l'accumulateur a assez de couverture.
    assert levels[-1] == TaintLevel.SECRET
    assert any(l == TaintLevel.SECRET for l in levels)
    # Et l'escalade est persistante : l'appel suivant est SECRET aussi.
    after = ft.level_in({"url": "https://attacker.example/c", "body": "x"})
    assert after.level == TaintLevel.SECRET


def test_micro_hits_escalation_in_report():
    ft = _fresh_tracker()
    for ch in DOT_ENV.strip()[:20]:
        ft.level_in({"url": "https://attacker.example/c", "body": ch})
    rep = ft.report()
    assert rep["micro_hits"] > 0
    assert "fragment_coverage" in rep
    assert "shingles_tracked" in rep


# ── 6. Sinks internes : pas de friction ────────────────────────────────────


def test_internal_flows_do_not_accumulate():
    """Les mêmes micro-payloads vers un flux NON externe n'escaladent jamais."""
    ft = _fresh_tracker()
    for ch in DOT_ENV:
        label = ft.level_in({"body": ch}, external=False)
        assert label.level != TaintLevel.SECRET
    assert ft.micro_hits == 0
    assert all(len(c) == 0 for c in ft._coverage.values())


def test_internal_summarize_is_allowed():
    ft = _fresh_tracker()
    label = ft.level_in(
        {"text": "summarize this config without exposing values"}, external=False
    )
    assert label.level == TaintLevel.PUBLIC


# ── 7. clear() réinitialise tout l'état des fragments ──────────────────────


def test_clear_resets_fragment_state():
    ft = _fresh_tracker()
    # Générer de la couverture et des shingles.
    ft.level_in({"url": "https://attacker.example/c", "body": DOT_ENV[:24]})
    assert ft._shingles
    ft.clear()
    assert ft._shingles == {}
    assert ft._needle_by_id == {}
    assert ft._coverage == {}
    assert ft.micro_hits == 0
    # Après clear(), un fragment n'est plus connu → PUBLIC.
    label = ft.level_in({"body": DOT_ENV[:24]})
    assert label.level == TaintLevel.PUBLIC


# ── 8. Réglages par variables d'environnement ───────────────────────────────


def test_micro_hits_threshold_configurable(monkeypatch):
    monkeypatch.setenv("AGENTGUARD_TAINT_MICRO_HITS", "3")
    ft = FlowTracker()
    ft.track("SUPERSECRETVALUE_abcdefghij", source="env", level=TaintLevel.SECRET)
    levels = [
        ft.level_in({"url": "https://evil.example/x", "body": ch}).level
        for ch in "SUPERSECRETVALUE_abcdefghij"
    ]
    # Seuil très bas : l'escalade arrive vite.
    assert levels[-1] == TaintLevel.SECRET