"""
AgentGuard ML Detector — single source of truth (v5.6 ONNX-ready).

Fixes v3.1 :
- import re manquant (crash au boot)
- Thread-safety (lock inference pour Gunicorn multi-threads)
- Garde-fou longueur d'input optimise (anti-DoS tokenizer)
- FP16 auto sur CUDA (inference ~2x plus rapide)
- Logging structure et validation stricte des labels du modele

Fixes v4 (benchmark 2026-09-26, layers regex,ml) :
- Double passe normalisee avec early-exit : la seconde passe ne tourne
  QUE si le normalizer change le texte.

Fixes v5 (2026-10-16) :
- Threshold 0.60 (escalade : l'arbitre LLM tranche les flags).

Fixes v5.5 (2026-10-16, latence) :
- Quantification dynamique int8 PyTorch : DESACTIVEE PAR DEFAUT.
  Verdict benchmark : recall 100% -> 74.2% sur DeBERTa-v3 (attention
  disentangled). Opt-in via AGENTGUARD_ML_QUANTIZE=true seulement
  apres validation A/B.
- Cache LRU des scores (AGENTGUARD_ML_CACHE_SIZE, 0 = desactive).
- torch.set_num_threads reglable (AGENTGUARD_TORCH_THREADS).

Fixes v5.6 (2026-10-17, ONNX) :
- Backend ONNX Runtime : si ./agentguard-model-onnx existe (exporte par
  scripts/export_onnx_model.py), l'inference bascule automatiquement sur
  onnxruntime (gain typique x2-x4 sur CPU SANS perte de score, contrairement
  a la quantification PyTorch). AGENTGUARD_ML_BACKEND force le choix
  ("onnx" | "torch" | "auto", defaut auto).
- Fallback PyTorch transparent si onnxruntime est absent ou si le dossier
  ONNX est manquant/corrompu : le contrat public (predict -> score) est
  identique, les couches amont (policy.py) ne changent pas.
- Le cache LRU et le dual_pass s'appliquent aux DEUX backends.
- Thread-safety ONNX : sessions onnxruntime sont thread-safe pour run(),
  mais le tokenizer ne l'est pas forcement -> lock conserve.
"""

import hashlib
import json
import logging
import os
import re
import threading
from collections import OrderedDict
from typing import Any

logger = logging.getLogger("agentguard.ml")

try:
    import numpy as _np

    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

try:
    import onnxruntime as _ort

    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False

try:
    import torch

    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


class MLDetector:
    def __init__(self):
        self.model = None  # backend torch
        self.tokenizer = None
        self.device = "cpu"
        self._lock = threading.Lock()  # thread-safety inference
        self.enabled = os.getenv("AGENTGUARD_USE_ML", "false").lower() in (
            "true",
            "1",
            "yes",
        )
        self.threshold = self._float_env("AGENTGUARD_ML_THRESHOLD", 0.60, 0.0, 1.0)
        self.model_path = os.getenv("AGENTGUARD_MODEL_PATH", "./agentguard-model")
        self.onnx_model_path = os.getenv(
            "AGENTGUARD_MODEL_ONNX_PATH", "./agentguard-model-onnx"
        )
        self.model_name = os.getenv(
            "AGENTGUARD_MODEL_NAME",
            "protectai/deberta-v3-base-prompt-injection-v2",
        )
        self.max_chars = int(os.getenv("AGENTGUARD_ML_MAX_CHARS", "8192"))
        self.dual_pass = os.getenv("AGENTGUARD_ML_DUAL_PASS", "true").lower() in (
            "true",
            "1",
            "yes",
        )
        # v5.5 : quantification int8 PyTorch. DESACTIVEE PAR DEFAUT :
        # le benchmark v5.5 a montre recall 100% -> 74.2% sur DeBERTa-v3.
        self.quantize = os.getenv("AGENTGUARD_ML_QUANTIZE", "false").lower() in (
            "true",
            "1",
            "yes",
        )
        # v5.6 : backend auto/onnx/torch
        self.backend = os.getenv("AGENTGUARD_ML_BACKEND", "auto").strip().lower()
        # v5.5 : cache LRU des scores (0 = desactive)
        self._cache_max = max(0, int(os.getenv("AGENTGUARD_ML_CACHE_SIZE", "4096")))
        self._cache: OrderedDict[str, float] = OrderedDict()
        self._cache_lock = threading.Lock()
        self._normalizer = None
        self.attack_label_id = None
        self.benign_label_id = None
        self.model_labels = {}

        # ── v5.6 : etat backend ONNX ────────────────────────────
        self._onnx_session = None
        self._onnx_input_names: list[str] = []

        if not self.enabled or not (TORCH_AVAILABLE or ONNX_AVAILABLE):
            if self.enabled and not (TORCH_AVAILABLE or ONNX_AVAILABLE):
                logger.warning("ml_disabled_no_backend_torch_and_onnx_absent")
            return

        try:
            self._init_backend()
        except Exception as exc:
            logger.warning("ml_load_failed: %s", exc)
            self.enabled = False

    # ─────────────────────────────────────────────────────────────
    # INITIALISATION DES BACKENDS
    # ─────────────────────────────────────────────────────────────

    def _init_backend(self):
        """v5.6 : choisit et initialise le backend (ONNX prioritaire)."""
        onnx_ready = ONNX_AVAILABLE and NUMPY_AVAILABLE and os.path.exists(
            os.path.join(self.onnx_model_path, "model.onnx")
        )

        if self.backend in ("auto", "onnx") and onnx_ready:
            if self._init_onnx():
                self.backend = "onnx"
                self._post_init()
                return
            if self.backend == "onnx":
                # onnx EXPLICITEMENT demande mais echoue -> erreur claire,
                # pas de fallback silencieux.
                raise RuntimeError(
                    f"AGENTGUARD_ML_BACKEND=onnx mais echec d'initialisation "
                    f"depuis {self.onnx_model_path}"
                )
            logger.warning("ml_onnx_init_failed_fallback_torch")

        if TORCH_AVAILABLE:
            self.backend = "torch"
            self._init_torch()
            self._post_init()
            return

        raise RuntimeError(
            "Aucun backend ML disponible : onnxruntime absent et torch absent"
        )

    def _init_onnx(self):
        """Charge la session ONNX Runtime + tokenizer + labels."""
        try:
            import onnxruntime as ort
            from transformers import AutoTokenizer

            model_file = os.path.join(self.onnx_model_path, "model.onnx")
            logger.info("ml_onnx_load: %s", model_file)

            # sessions : 1 thread physique par defaut en prod multi-worker ;
            # reglable via AGENTGUARD_ONNX_THREADS (0 = laisser ORT decider).
            so = ort.SessionOptions()
            threads_env = os.getenv("AGENTGUARD_ONNX_THREADS")
            if threads_env:
                try:
                    so.intra_op_num_threads = max(1, int(threads_env))
                    so.inter_op_num_threads = 1
                except (TypeError, ValueError):
                    logger.warning("ml_invalid_onnx_threads_env: %s", threads_env)

            so.graph_optimization_level = (
                ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            )
            self._onnx_session = ort.InferenceSession(
                model_file,
                sess_options=so,
                providers=["CPUExecutionProvider"],
            )
            self._onnx_input_names = [i.name for i in self._onnx_session.get_inputs()]

            self.tokenizer = AutoTokenizer.from_pretrained(self.onnx_model_path)

            # labels : depuis config.json du dossier ONNX
            config_file = os.path.join(self.onnx_model_path, "config.json")
            with open(config_file, encoding="utf-8") as f:
                raw_id2label = json.load(f).get("id2label", {}) or {}
            normalized = {}
            for key, value in raw_id2label.items():
                try:
                    normalized[int(key)] = self._normalize_label(value)
                except (TypeError, ValueError):
                    continue

            labels = self._validate_labels(normalized)
            self._set_model_label_ids(labels)
            return True

        except Exception as exc:
            logger.warning("ml_onnx_init_error: %s", exc)
            self._onnx_session = None
            return False

    def _init_torch(self):
        """Chargement torch historique (v5.5)."""
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
        )

        self.device = "cuda" if torch.cuda.is_available() else "cpu"

        threads_env = os.getenv("AGENTGUARD_TORCH_THREADS")
        if threads_env:
            try:
                torch.set_num_threads(max(1, int(threads_env)))
            except (TypeError, ValueError):
                logger.warning("ml_invalid_torch_threads_env: %s", threads_env)

        local_loaded = False
        if os.path.exists(self.model_path):
            try:
                logger.info("ml_model_local_load: %s", self.model_path)
                local_tokenizer = AutoTokenizer.from_pretrained(self.model_path)
                local_model = AutoModelForSequenceClassification.from_pretrained(
                    self.model_path
                )
                labels = self._validate_model_labels(local_model)
                self.tokenizer = local_tokenizer
                self.model = local_model
                self._set_model_label_ids(labels)
                local_loaded = True
            except Exception as exc:
                logger.warning(
                    "ml_local_model_incompatible",
                    error=f"{type(exc).__name__}: {exc}",
                )

        if not local_loaded:
            logger.info("ml_model_download: %s", self.model_name)
            remote_tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            remote_model = AutoModelForSequenceClassification.from_pretrained(
                self.model_name
            )
            labels = self._validate_model_labels(remote_model)
            self.tokenizer = remote_tokenizer
            self.model = remote_model
            self._set_model_label_ids(labels)

            try:
                os.makedirs(self.model_path, exist_ok=True)
                self.model.save_pretrained(self.model_path)
                self.tokenizer.save_pretrained(self.model_path)
                logger.info("ml_model_cached: %s", self.model_path)
            except Exception as save_err:
                logger.warning("ml_model_cache_failed: %s", save_err)

        self.model.to(self.device)

        if self.device == "cpu" and self.quantize:
            try:
                from torch.ao.quantization import quantize_dynamic

                self.model = quantize_dynamic(
                    self.model, {torch.nn.Linear}, dtype=torch.qint8
                )
                logger.info("ml_quantized_int8")
            except Exception as exc:
                logger.warning("ml_quantization_failed: %s", exc)
        elif self.device == "cuda":
            self.model.half()
        self.model.eval()

    def _post_init(self):
        """Commun aux deux backends : normalizer + log."""
        if self.dual_pass:
            try:
                from agentguard.normalizer import normalize_for_detection

                self._normalizer = normalize_for_detection
            except Exception:
                logger.warning("ml_normalizer_unavailable_dual_pass_disabled")
                self.dual_pass = False

        logger.info(
            "ml_enabled",
            backend=self.backend,
            device=self.device,
            threshold=self.threshold,
            model=self.model_name,
            onnx_path=self.onnx_model_path if self.backend == "onnx" else None,
            dual_pass=self.dual_pass,
            cache_size=self._cache_max,
            attack_label_id=self.attack_label_id,
            benign_label_id=self.benign_label_id,
        )

    # ─────────────────────────────────────────────────────────────
    # VALIDATION DES LABELS (commune aux backends)
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _normalize_label(label):
        return re.sub(r"[^a-z0-9]+", "_", str(label).strip().lower()).strip("_")

    def _validate_labels(self, normalized: dict[int, str]) -> dict:
        if len(normalized) < 2:
            raise RuntimeError("Classifier labels missing or invalid")

        attack_labels = {
            "injection",
            "prompt_injection",
            "jailbreak",
            "malicious",
            "unsafe",
            "attack",
            "attacker",
        }
        benign_labels = {
            "safe",
            "benign",
            "no_injection",
            "clean",
            "normal",
            "non_injection",
        }

        attack_ids = [i for i, l in normalized.items() if l in attack_labels]
        benign_ids = [i for i, l in normalized.items() if l in benign_labels]

        if len(attack_ids) != 1 or len(benign_ids) != 1:
            raise RuntimeError(
                f"Incompatible security classifier labels: {normalized}. "
                "Expected exactly one benign label and one attack/injection label."
            )

        return {
            "id2label": normalized,
            "attack_label_id": attack_ids[0],
            "benign_label_id": benign_ids[0],
        }

    def _validate_model_labels(self, model):
        """Valide qu'un modele torch est compatible avec le contrat."""
        config = getattr(model, "config", None)
        raw_labels = getattr(config, "id2label", {}) or {}

        normalized = {}
        for key, value in raw_labels.items():
            try:
                idx = int(key)
            except (TypeError, ValueError):
                continue
            normalized[idx] = self._normalize_label(value)

        return self._validate_labels(normalized)

    def _set_model_label_ids(self, labels):
        self.model_labels = labels["id2label"]
        self.attack_label_id = labels["attack_label_id"]
        self.benign_label_id = labels["benign_label_id"]

    @staticmethod
    def _float_env(name, default, low, high):
        try:
            return max(low, min(high, float(os.getenv(name, str(default)))))
        except (TypeError, ValueError):
            return default

    # ─────────────────────────────────────────────────────────────
    # CACHE LRU (v5.5)
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _cache_key(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()

    def _cache_get(self, text: str):
        if self._cache_max <= 0:
            return None
        key = self._cache_key(text)
        with self._cache_lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                return self._cache[key]
        return None

    def _cache_put(self, text: str, score: float):
        if self._cache_max <= 0:
            return
        key = self._cache_key(text)
        with self._cache_lock:
            self._cache[key] = score
            self._cache.move_to_end(key)
            while len(self._cache) > self._cache_max:
                self._cache.popitem(last=False)

    def clear_cache(self):
        """Vide le cache de scores (utile apres un changement de modele)."""
        with self._cache_lock:
            self._cache.clear()

    # ─────────────────────────────────────────────────────────────
    # INFERENCE
    # ─────────────────────────────────────────────────────────────

    def _score_once_torch(self, text: str) -> float:
        text = str(text or "")[: self.max_chars]

        with self._lock:
            inputs = self.tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=512,
                padding=True,
            )
            inputs = {k: v.to(self.device) for k, v in inputs.items()}

            with torch.no_grad():
                logits = self.model(**inputs).logits
                probabilities = torch.softmax(logits, dim=1)

        return float(probabilities[0][self.attack_label_id].item())

    def _score_once_onnx(self, text: str) -> float:
        text = str(text or "")[: self.max_chars]

        with self._lock:
            inputs = self.tokenizer(
                text,
                return_tensors="np",
                truncation=True,
                max_length=512,
            )

            feeds = {}
            for name, value in inputs.items():
                if name not in self._onnx_input_names:
                    continue
                if value.dtype != _np.int64:
                    value = value.astype(_np.int64)
                feeds[name] = value

            logits = self._onnx_session.run(None, feeds)[0][0]

        # softmax numpy
        exp = _np.exp(logits - logits.max())
        probs = exp / exp.sum()
        return float(probs[self.attack_label_id])

    def _score_once(self, text: str) -> float:
        """Une seule inference, thread-safe, sur le backend actif."""
        if self.attack_label_id is None:
            raise RuntimeError("ML security classifier has no validated attack label")

        if self.backend == "onnx":
            return self._score_once_onnx(text)
        return self._score_once_torch(text)

    def _score_with_cache(self, text: str) -> float:
        cached = self._cache_get(text)
        if cached is not None:
            return cached
        score = self._score_once(text)
        self._cache_put(text, score)
        return score

    def predict(self, text: str) -> dict[str, Any]:
        if not self.enabled or (self.backend == "onnx" and self._onnx_session is None):
            return {"score": 0.0, "risk": "UNKNOWN", "confidence": "low"}
        if self.backend == "torch" and (self.model is None or self.tokenizer is None):
            return {"score": 0.0, "risk": "UNKNOWN", "confidence": "low"}

        try:
            text = str(text or "")

            score = self._score_with_cache(text)

            # dual_pass avec early-exit (v4)
            if self.dual_pass and self._normalizer is not None:
                normalized = self._normalizer(text)
                if normalized != text:
                    norm_score = self._score_with_cache(normalized)
                    score = max(score, norm_score)

            if score >= self.threshold:
                risk = "HIGH"
            elif score >= max(0.0, self.threshold - 0.15):
                risk = "MEDIUM"
            else:
                risk = "LOW"

            confidence = "high" if score >= 0.9 or score <= 0.1 else "medium"

            return {"score": score, "risk": risk, "confidence": confidence}

        except Exception as exc:
            logger.warning("ml_predict_error: %s", exc)
            return {"score": 0.0, "risk": "UNKNOWN", "confidence": "low"}