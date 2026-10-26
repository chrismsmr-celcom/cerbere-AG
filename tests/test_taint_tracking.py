"""
tests/test_taint_tracking.py

Tests unitaires et d'intégration pour le module taint.py.
Couvre : TaintTracker, FlowTracker, détection d'encodages, règles de flux.
"""

import base64
import sys
import threading
import time
from urllib.parse import quote

import pytest

sys.path.insert(0, 'agentguard')
from taint import (
    FlowTracker,
    SinkType,
    TaintLabel,
    TaintLevel,
    TaintTracker,
    _b64_aligned,
    _encodings,
)

# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def tracker():
    """Instance fraîche de TaintTracker."""
    return TaintTracker()


@pytest.fixture
def flow_tracker():
    """Instance fraîche de FlowTracker."""
    return FlowTracker()


@pytest.fixture
def flow_tracker_session_mode():
    """FlowTracker en mode session (très strict)."""
    return FlowTracker(session_mode=True)


# =============================================================================
# TESTS : TaintTracker (gestion des labels par ID)
# =============================================================================


class TestTaintTracker:
    """Tests pour le TaintTracker de base."""

    def test_label_basic(self, tracker):
        """Attribution simple d'un label."""
        label = tracker.label("data1", "some value", TaintLevel.SECRET, "env_var")
        assert label.level == TaintLevel.SECRET
        assert label.source == "env_var"
        assert tracker.get_label("data1") == label

    def test_label_auto_classify_secret(self, tracker):
        """Auto-détection d'un secret AWS."""
        aws_key = "AKIAIOSFODNN7EXAMPLE1"
        label = tracker.label("aws", aws_key)
        assert label.level == TaintLevel.SECRET

    def test_label_auto_classify_pii(self, tracker):
        """Auto-détection d'un numéro de carte bancaire."""
        cc = "4111-1111-1111-1111"
        label = tracker.label("cc", cc)
        assert label.level == TaintLevel.CONFIDENTIAL

    def test_label_auto_classify_public(self, tracker):
        """Donnée publique non classifiée comme sensible."""
        label = tracker.label("public", "Hello World")
        assert label.level == TaintLevel.INTERNAL  # INTERNAL par défaut, pas PUBLIC

    def test_combine_max_level(self, tracker):
        """La combinaison prend le niveau maximum."""
        tracker.label("d1", "safe", TaintLevel.PUBLIC)
        tracker.label("d2", "secret", TaintLevel.SECRET)
        combined = tracker.combine(["d1", "d2"])
        assert combined.level == TaintLevel.SECRET

    def test_combine_empty(self, tracker):
        """Combinaison vide retourne PUBLIC."""
        combined = tracker.combine([])
        assert combined.level == TaintLevel.PUBLIC

    def test_combine_with_new_id(self, tracker):
        """Combinaison avec stockage sous un nouvel ID."""
        tracker.label("d1", "a", TaintLevel.CONFIDENTIAL)
        tracker.label("d2", "b", TaintLevel.SECRET)
        combined = tracker.combine(["d1", "d2"], new_id="combined")
        assert tracker.get_label("combined") == combined

    def test_check_sink_deny_secret_external(self, tracker):
        """SECRET vers NETWORK_EXTERNAL doit être bloqué."""
        label = TaintLabel(TaintLevel.SECRET, "test")
        violation = tracker.check_sink(label, SinkType.NETWORK_EXTERNAL)
        assert violation is not None
        assert "DENY" in violation

    def test_check_sink_review_confidential_external(self, tracker):
        """CONFIDENTIAL vers NETWORK_EXTERNAL nécessite approbation."""
        label = TaintLabel(TaintLevel.CONFIDENTIAL, "test")
        violation = tracker.check_sink(label, SinkType.NETWORK_EXTERNAL)
        assert violation is not None
        assert "REVIEW" in violation

    def test_check_sink_allow_public_external(self, tracker):
        """PUBLIC vers NETWORK_EXTERNAL est autorisé."""
        label = TaintLabel(TaintLevel.PUBLIC, "test")
        violation = tracker.check_sink(label, SinkType.NETWORK_EXTERNAL)
        assert violation is None

    def test_check_sink_malicious_always_blocked(self, tracker):
        """MALICIOUS est toujours bloqué, peu importe le sink."""
        label = TaintLabel(TaintLevel.MALICIOUS, "injection")
        for sink in SinkType:
            violation = tracker.check_sink(label, sink)
            assert violation is not None
            assert "MALICIOUS" in violation

    def test_mark_malicious(self, tracker):
        """Marquage explicite comme MALICIOUS."""
        tracker.label("d1", "payload", TaintLevel.UNTRUSTED)
        tracker.mark_malicious("d1", "prompt_injection")
        label = tracker.get_label("d1")
        assert label.level == TaintLevel.MALICIOUS
        assert "prompt_injection" in label.tags

    def test_get_report(self, tracker):
        """Rapport de session correct."""
        tracker.label("d1", "a", TaintLevel.SECRET)
        tracker.label("d2", "b", TaintLevel.SECRET)
        tracker.label("d3", "c", TaintLevel.PUBLIC)
        tracker.mark_malicious("d4")
        
        report = tracker.get_report()
        assert report["total_tracked"] == 4
        assert report["secrets_tracked"] == 2
        assert report["malicious_detected"] == 1


# =============================================================================
# TESTS : FlowTracker (suivi des valeurs réelles)
# =============================================================================


class TestFlowTracker:
    """Tests pour le FlowTracker avec détection d'encodages."""

    def test_track_and_detect_raw(self, flow_tracker):
        """Détection d'un secret en clair."""
        secret = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdef"
        flow_tracker.track(secret, source="env")
        
        # Simule un appel d'outil avec le secret
        label = flow_tracker.level_in({"api_key": secret})
        assert label.level == TaintLevel.SECRET
        assert label.source == "tracked_value"

    def test_track_and_detect_base64(self, flow_tracker):
        """Détection d'un secret encodé en base64."""
        secret = "SUPER_SECRET_API_KEY_12345"
        flow_tracker.track(secret, source="env")
        
        # Encode en base64
        encoded = base64.b64encode(secret.encode()).decode()
        label = flow_tracker.level_in({"payload": encoded})
        assert label.level == TaintLevel.SECRET

    def test_track_and_detect_base64_urlsafe(self, flow_tracker):
        """Détection d'un secret encodé en base64 URL-safe."""
        secret = "SUPER_SECRET_API_KEY_12345"
        flow_tracker.track(secret, source="env")
        
        encoded = base64.urlsafe_b64encode(secret.encode()).decode()
        label = flow_tracker.level_in({"payload": encoded})
        assert label.level == TaintLevel.SECRET

    def test_track_and_detect_hex(self, flow_tracker):
        """Détection d'un secret encodé en hexadécimal."""
        secret = "SUPER_SECRET_API_KEY_12345"
        flow_tracker.track(secret, source="env")
        
        encoded = secret.encode().hex()
        label = flow_tracker.level_in({"payload": encoded})
        assert label.level == TaintLevel.SECRET

    def test_track_and_detect_url_encoded(self, flow_tracker):
        """Détection d'un secret encodé en URL."""
        secret = "SUPER_SECRET_API_KEY_12345"
        flow_tracker.track(secret, source="env")
        
        encoded = quote(secret, safe="")
        label = flow_tracker.level_in({"payload": encoded})
        assert label.level == TaintLevel.SECRET

    def test_track_short_secret_ignored(self, flow_tracker):
        """Les secrets trop courts ne sont pas suivis."""
        short_secret = "sk-123"  # < 8 caractères
        flow_tracker.track(short_secret, source="env")
        
        # Ne devrait pas être détecté
        label = flow_tracker.level_in({"key": short_secret})
        assert label.level < TaintLevel.SECRET

    def test_session_mode_blocks_all_external(self, flow_tracker_session_mode):
        """En mode session, tout envoi externe est bloqué après un SECRET."""
        secret = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdef"
        flow_tracker_session_mode.track(secret, source="env")
        
        # Même sans retrouver le secret, le mode session bloque
        label = flow_tracker_session_mode.level_in({"unrelated": "data"})
        assert label.level >= TaintLevel.SECRET
        assert label.source == "session_mode"

    def test_mark_malicious_blocks_everything(self, flow_tracker):
        """Après mark_malicious, tout est bloqué."""
        flow_tracker.mark_malicious("prompt_injection_detected")
        
        label = flow_tracker.level_in({"any": "data"})
        assert label.level == TaintLevel.MALICIOUS
        assert label.source == "session_malicious"

    def test_track_pii_credit_card(self, flow_tracker):
        """Détection automatique d'un numéro de carte bancaire."""
        cc = "4111-1111-1111-1111"
        flow_tracker.track(cc, source="db")
        
        label = flow_tracker.level_in({"card": cc})
        assert label.level == TaintLevel.CONFIDENTIAL

    def test_track_explicit_level_overrides_detection(self, flow_tracker):
        """Un niveau explicite force la classification."""
        data = "some public text"
        label = flow_tracker.track(data, source="user", level=TaintLevel.UNTRUSTED)
        assert label.level == TaintLevel.UNTRUSTED

    def test_max_tracked_limit(self, flow_tracker):
        """La limite de _MAX_TRACKED est respectée."""
        # Ajoute plus de secrets que la limite
        for i in range(600):  # _MAX_TRACKED = 500
            secret = f"sk-proj-{'A' * 20}{i:04d}{'B' * 20}"
            flow_tracker.track(secret, source="env")
        
        # Vérifie que le nombre de needles ne dépasse pas la limite
        assert len(flow_tracker._needles) <= 500

    def test_report_includes_session_info(self, flow_tracker):
        """Le rapport inclut les informations de session."""
        flow_tracker.track("sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdef", source="env")
        
        report = flow_tracker.report()
        assert "session_level" in report
        assert "tracked_needles" in report
        assert report["tracked_needles"] > 0


# =============================================================================
# TESTS : Fonctions d'encodage (_b64_aligned, _encodings)
# =============================================================================


class TestEncodingFunctions:
    """Tests pour les fonctions d'encodage utilisées par FlowTracker."""

    def test_b64_aligned_three_offsets(self):
        """Génère 3 alignements pour le base64."""
        raw = b"SECRET"
        variants = _b64_aligned(raw, urlsafe=False)
        assert len(variants) == 3
        # Chaque variante doit être une sous-chaîne valide
        for v in variants:
            assert len(v) > 0

    def test_encodings_includes_raw(self):
        """La liste d'encodages inclut la valeur brute."""
        raw = "SECRET"
        encs = _encodings(raw)
        assert raw in encs

    def test_encodings_includes_base64(self):
        """La liste d'encodages inclut le base64."""
        raw = "SECRET"
        encs = _encodings(raw)
        expected_b64 = base64.b64encode(raw.encode()).decode()
        assert expected_b64 in encs

    def test_encodings_includes_hex(self):
        """La liste d'encodages inclut l'hexadécimal."""
        raw = "SECRET"
        encs = _encodings(raw)
        assert raw.encode().hex() in encs

    def test_encodings_includes_url_encoded(self):
        """La liste d'encodages inclut l'URL encoding."""
        raw = "SECRET VALUE"  # avec espace pour forcer l'encodage
        encs = _encodings(raw)
        assert quote(raw, safe="") in encs

    def test_encodings_deduplicates(self):
        """Pas de doublons dans la liste d'encodages."""
        raw = "SECRET"
        encs = _encodings(raw)
        assert len(encs) == len(set(encs))


# =============================================================================
# TESTS : TaintLabel (sérialisation)
# =============================================================================


class TestTaintLabel:
    """Tests pour la sérialisation des TaintLabel."""

    def test_to_dict(self):
        """Sérialisation en dictionnaire."""
        label = TaintLabel(
            level=TaintLevel.SECRET,
            source="env",
            tags={"aws", "key"},
            propagated_from=["d1", "d2"]
        )
        d = label.to_dict()
        assert d["level"] == "SECRET"
        assert d["source"] == "env"
        assert set(d["tags"]) == {"aws", "key"}
        assert d["propagated_from"] == ["d1", "d2"]

    def test_from_dict(self):
        """Désérialisation depuis un dictionnaire."""
        d = {
            "level": "CONFIDENTIAL",
            "source": "db",
            "tags": ["pii"],
            "propagated_from": []
        }
        label = TaintLabel.from_dict(d)
        assert label.level == TaintLevel.CONFIDENTIAL
        assert label.source == "db"
        assert "pii" in label.tags

    def test_roundtrip_serialization(self):
        """Sérialisation/désérialisation préserve les données."""
        original = TaintLabel(
            level=TaintLevel.MALICIOUS,
            source="injection",
            tags={"prompt_injection", "xss"},
            propagated_from=["d1"]
        )
        d = original.to_dict()
        restored = TaintLabel.from_dict(d)
        assert restored.level == original.level
        assert restored.source == original.source
        assert restored.tags == original.tags
        assert restored.propagated_from == original.propagated_from


# =============================================================================
# TESTS : Cas d'intégration (scénarios réels)
# =============================================================================


class TestIntegrationScenarios:
    """Tests de scénarios réels d'exfiltration."""

    def test_exfiltration_via_json_payload(self, flow_tracker):
        """Tentative d'exfiltration via un payload JSON."""
        secret = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdef"
        flow_tracker.track(secret, source="env")
        
        # L'agent tente d'envoyer le secret dans un JSON
        payload = {
            "action": "send_report",
            "data": {
                "api_key": secret,
                "message": "Hello"
            }
        }
        
        label = flow_tracker.level_in(payload)
        assert label.level == TaintLevel.SECRET
        
        # Vérifie que le sink est bloqué
        violation = flow_tracker.check_sink(label, SinkType.NETWORK_EXTERNAL)
        assert violation is not None
        assert "DENY" in violation

    def test_exfiltration_via_nested_encoding(self, flow_tracker):
        """Tentative d'exfiltration avec encodage imbriqué."""
        secret = "SUPER_SECRET_KEY_12345"
        flow_tracker.track(secret, source="env")
        
        # Double encodage : base64 puis URL
        b64 = base64.b64encode(secret.encode()).decode()
        url_encoded = quote(b64, safe="")
        
        label = flow_tracker.level_in({"payload": url_encoded})
        # Le base64 devrait être détecté même après URL encoding
        assert label.level >= TaintLevel.SECRET

    def test_safe_data_passes_through(self, flow_tracker):
        """Des données sûres passent sans être bloquées."""
        safe_data = {"message": "Hello World", "count": 42}
        
        label = flow_tracker.level_in(safe_data)
        assert label.level == TaintLevel.PUBLIC
        
        violation = flow_tracker.check_sink(label, SinkType.NETWORK_EXTERNAL)
        assert violation is None

    def test_mixed_data_takes_max_level(self, flow_tracker):
        """Des données mixtes prennent le niveau maximum."""
        secret = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdef"
        flow_tracker.track(secret, source="env")
        
        mixed_data = {
            "public": "Hello",
            "secret": secret,
            "number": 123
        }
        
        label = flow_tracker.level_in(mixed_data)
        assert label.level == TaintLevel.SECRET


# =============================================================================
# TESTS : Performance et limites
# =============================================================================


class TestPerformanceAndLimits:
    """Tests de performance et de limites du système."""

    def test_large_payload_scan(self, flow_tracker):
        """Scan d'un payload volumineux (proche de _MAX_SCAN_CHARS)."""
        secret = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdef"
        flow_tracker.track(secret, source="env")
        
        # Crée un payload de ~150k caractères
        large_payload = "A" * 150_000 + secret + "B" * 50_000
        
        start = time.time()
        label = flow_tracker.level_in({"data": large_payload})
        elapsed = time.time() - start
        
        assert label.level == TaintLevel.SECRET
        # Devrait être rapide (< 1 seconde)
        assert elapsed < 1.0

    def test_many_needles_performance(self, flow_tracker):
        """Performance avec beaucoup de needles mémorisées."""
        # Ajoute 400 secrets
        for i in range(400):
            secret = f"sk-proj-{'A' * 20}{i:04d}{'B' * 20}"
            flow_tracker.track(secret, source="env")
        
        # Vérifie qu'un scan reste rapide
        test_payload = {"key": "sk-proj-" + "A" * 20 + "0042" + "B" * 20}
        
        start = time.time()
        label = flow_tracker.level_in(test_payload)
        elapsed = time.time() - start
        
        assert label.level == TaintLevel.SECRET
        assert elapsed < 0.5


# =============================================================================
# TESTS : Thread-safety (si implémenté)
# =============================================================================


class TestThreadSafety:
    """Tests de concurrence (si le module supporte le multi-threading)."""

    def test_concurrent_tracking(self, flow_tracker):
        """Tracking simultané depuis plusieurs threads."""
        results = []
        errors = []

        def track_secret(thread_id):
            try:
                secret = f"sk-proj-Thread{thread_id:02d}SecretKey1234567890"
                flow_tracker.track(secret, source=f"thread_{thread_id}")
                label = flow_tracker.level_in({"key": secret})
                results.append((thread_id, label.level))
            except Exception as e:
                errors.append((thread_id, str(e)))

        threads = [threading.Thread(target=track_secret, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Vérifie qu'il n'y a pas d'erreurs
        assert len(errors) == 0, f"Erreurs détectées : {errors}"
        
        # Vérifie que tous les threads ont réussi
        assert len(results) == 10
        for thread_id, level in results:
            assert level == TaintLevel.SECRET


# =============================================================================
# TESTS : Cas limites et edge cases
# =============================================================================


class TestEdgeCases:
    """Tests de cas limites et situations exceptionnelles."""

    def test_empty_string_tracking(self, flow_tracker):
        """Tracking d'une chaîne vide."""
        label = flow_tracker.track("", source="user")
        assert label.level == TaintLevel.PUBLIC

    def test_none_value_tracking(self, flow_tracker):
        """Tracking d'une valeur None."""
        label = flow_tracker.track(None, source="user")
        assert label.level == TaintLevel.PUBLIC

    def test_numeric_value_tracking(self, flow_tracker):
        """Tracking d'une valeur numérique."""
        label = flow_tracker.track(12345, source="user")
        assert label.level == TaintLevel.PUBLIC

    def test_dict_with_nested_secrets(self, flow_tracker):
        """Détection de secrets dans des structures imbriquées."""
        secret = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdef"
        flow_tracker.track(secret, source="env")
        
        nested = {
            "level1": {
                "level2": {
                    "level3": {
                        "key": secret
                    }
                }
            }
        }
        
        label = flow_tracker.level_in(nested)
        assert label.level == TaintLevel.SECRET

    def test_list_with_secrets(self, flow_tracker):
        """Détection de secrets dans une liste."""
        secret = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdef"
        flow_tracker.track(secret, source="env")
        
        data_list = ["safe", secret, "also_safe"]
        
        label = flow_tracker.level_in(data_list)
        assert label.level == TaintLevel.SECRET

    def test_unicode_secret(self, flow_tracker):
        """Tracking d'un secret avec des caractères Unicode."""
        secret = "sk-proj-CléSecrèteAvecAccents1234567890abcdef"
        flow_tracker.track(secret, source="env")
        
        label = flow_tracker.level_in({"key": secret})
        assert label.level == TaintLevel.SECRET