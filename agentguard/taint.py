"""
AgentGuard Taint Tracking — Data flow security
Trace la classification des données à travers les appels d'outils.

Classifications :
  PUBLIC       : données publiques, safe à exposer
  INTERNAL     : données internes, usage restreint
  CONFIDENTIAL : données clients/sensibles
  SECRET       : clés API, passwords, tokens
  UNTRUSTED    : données externes non vérifiées (web, user input)
  MALICIOUS    : injection détectée, à bloquer

Flux interdits (par défaut) :
  SECRET → EXTERNAL_SINK        = DENY
  CONFIDENTIAL → EXTERNAL_SINK  = REQUIRE_APPROVAL
  UNTRUSTED → TOOL_DANGEREUX    = DENY
  MALICIOUS → anywhere          = DENY

Renforcement anti-fragmentation :
  Un secret lu par l'agent ne doit jamais pouvoir sortir du périmètre,
  même découpé, encodé par morceaux, ou envoyé caractère par caractère.
  Trois mécanismes complètent le matching exact :
    1. Index de shingles : fragments glissants de chaque needle sensible
    2. Décodage à la volée : base64/hex d'un FRAGMENT re-scané après décodage
    3. Accumulateur de couverture : exfiltration cumulative (char par char)
"""

import base64
import binascii
import json
import logging
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import quote


class TaintLevel(Enum):
    """Niveaux de classification, du plus safe au plus dangereux."""

    PUBLIC = 0
    INTERNAL = 10
    CONFIDENTIAL = 20
    SECRET = 30
    UNTRUSTED = 40
    MALICIOUS = 100

    def __ge__(self, other):
        return self.value >= other.value

    def __gt__(self, other):
        return self.value > other.value


class SinkType(Enum):
    """Types de destinations (sinks) pour les données."""

    INTERNAL = "internal"
    FILESYSTEM = "filesystem"
    DATABASE = "database"
    NETWORK_INTERNAL = "network_internal"
    NETWORK_EXTERNAL = "network_external"
    DANGEROUS_TOOL = "dangerous"


# Patterns de détection automatique de classification
_SECRET_PATTERNS = [
    # sk- / sk-proj- : accepte les tirets et l'Unicode (clés réelles),
    # longueur totale >= 20 pour éviter les faux positifs.
    re.compile(
        r"\bsk-(?:proj-)?[\w-]{20,}"
        r"|pk_(?:test|live)_[A-Za-z0-9]{20,}"
        r"|Bearer\s+[A-Za-z0-9._-]{20,}"
    ),
    # AKIA : {16,} au lieu de {16} (une clé de 17 chars échouait au \b).
    re.compile(r"\bAKIA[0-9A-Z]{16,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    # secret nommé : "SECRET_API_KEY_12345" comme "api_key: <valeur>".
    # Pas de \b initial : "SUPER_SECRET_" doit matcher aussi.
    re.compile(
        r"(api[_-]?key|password|secret|token)"
        r"(?:\s*[:=]\s*['\"]?|[_-])"
        r"[\w.-]{8,}",
        re.IGNORECASE,
    ),
    re.compile(r"\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}\b"),
]

_PII_PATTERNS = [
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
]


@dataclass
class TaintLabel:
    """Label de taint pour une donnée."""

    level: TaintLevel
    source: str = "unknown"
    tags: set[str] = field(default_factory=set)
    propagated_from: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level.name,
            "source": self.source,
            "tags": list(self.tags),
            "propagated_from": self.propagated_from,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TaintLabel":
        return cls(
            level=TaintLevel[data.get("level", "PUBLIC")],
            source=data.get("source", "unknown"),
            tags=set(data.get("tags", [])),
            propagated_from=data.get("propagated_from", []),
        )


class TaintTracker:
    """
    Traque la classification des données dans une session.

    Usage:
        tracker = TaintTracker()
        tracker.label("user_input", user_text, TaintLevel.UNTRUSTED, "web_form")
        tracker.label("api_key", api_key, TaintLevel.SECRET, "env_var")
        combined = tracker.combine(["user_input", "api_key"])
        violation = tracker.check_sink(combined, SinkType.NETWORK_EXTERNAL)
        if violation:
            raise SecurityException(f"Taint violation: {violation}")
    """

    DEFAULT_DENY_RULES = [
        (
            TaintLevel.SECRET,
            SinkType.NETWORK_EXTERNAL,
            "SECRET data cannot be sent to external networks",
        ),
        (
            TaintLevel.SECRET,
            SinkType.DANGEROUS_TOOL,
            "SECRET data cannot be used in dangerous tools",
        ),
        (TaintLevel.MALICIOUS, SinkType.INTERNAL, "MALICIOUS data blocked"),
        (TaintLevel.MALICIOUS, SinkType.FILESYSTEM, "MALICIOUS data blocked"),
        (TaintLevel.MALICIOUS, SinkType.DATABASE, "MALICIOUS data blocked"),
        (
            TaintLevel.UNTRUSTED,
            SinkType.DANGEROUS_TOOL,
            "UNTRUSTED data cannot be used in dangerous tools",
        ),
    ]

    DEFAULT_REVIEW_RULES = [
        (
            TaintLevel.CONFIDENTIAL,
            SinkType.NETWORK_EXTERNAL,
            "CONFIDENTIAL data to external network requires approval",
        ),
        (
            TaintLevel.CONFIDENTIAL,
            SinkType.FILESYSTEM,
            "CONFIDENTIAL data write requires approval",
        ),
    ]

    def __init__(self):
        self._labels: dict[str, TaintLabel] = {}
        self._values: dict[str, Any] = {}

    def label(
        self,
        data_id: str,
        value: Any,
        level: TaintLevel | None = None,
        source: str = "unknown",
        tags: set[str] | None = None,
    ) -> TaintLabel:
        """Attribue un label de taint à une donnée."""
        if level is None:
            level = self._auto_classify(value)

        label = TaintLabel(
            level=level,
            source=source,
            tags=tags or set(),
        )
        self._labels[data_id] = label
        self._values[data_id] = value
        return label

    def _auto_classify(self, value: Any) -> TaintLevel:
        """Auto-classifie une valeur en analysant son contenu."""
        # Les scalaires non-textuels ne portent pas de donnée sensible
        # analysable : None, bool, nombres → PUBLIC.
        if value is None or isinstance(value, (bool, int, float, complex)):
            return TaintLevel.PUBLIC

        text = self._to_text(value)
        if not text:
            return TaintLevel.PUBLIC

        for pattern in _SECRET_PATTERNS:
            if pattern.search(text):
                return TaintLevel.SECRET

        for pattern in _PII_PATTERNS:
            if pattern.search(text):
                return TaintLevel.CONFIDENTIAL

        return TaintLevel.INTERNAL

    @staticmethod
    def _to_text(value: Any) -> str:
        """Convertit une valeur en texte pour analyse."""
        if isinstance(value, str):
            return value
        if isinstance(value, (dict, list)):
            try:
                # ensure_ascii=False : sinon les secrets Unicode sont
                # échappés en \uXXXX dans le JSON et les needles ne
                # correspondent plus jamais.
                return json.dumps(value, default=str, ensure_ascii=False)
            except (TypeError, ValueError):
                return str(value)
        return str(value)

    def get_label(self, data_id: str) -> TaintLabel | None:
        return self._labels.get(data_id)

    def combine(
        self,
        data_ids: list[str],
        new_id: str | None = None,
    ) -> "TaintLabel":
        """Combine plusieurs labels (le résultat prend le niveau MAX)."""
        if not data_ids:
            label = TaintLabel(TaintLevel.PUBLIC, "empty")
            if new_id:
                self._labels[new_id] = label
            return label

        max_level = TaintLevel.PUBLIC
        sources = []
        all_tags: set[str] = set()
        propagated = []

        for did in data_ids:
            lbl = self._labels.get(did)
            if lbl:
                max_level = max(max_level, lbl.level)
                sources.append(lbl.source)
                all_tags.update(lbl.tags)
                propagated.append(did)

        combined = TaintLabel(
            level=max_level,
            source="+".join(sources[:3]),
            tags=all_tags,
            propagated_from=propagated,
        )

        if new_id:
            self._labels[new_id] = combined

        return combined

    def check_sink(
        self,
        label: TaintLabel | None,
        sink: Any,
    ) -> str | None:
        """Vérifie si un flux label → sink est autorisé."""
        if label is None:
            raise ValueError("Cannot check sink with None label")
        if not isinstance(sink, SinkType):
            raise ValueError(f"Invalid sink type: {sink}")

        # MALICIOUS → toujours bloqué
        if label.level == TaintLevel.MALICIOUS:
            return f"MALICIOUS data (from {label.source}) blocked at {sink.value}"

        for min_level, rule_sink, reason in self.DEFAULT_DENY_RULES:
            if label.level >= min_level and sink == rule_sink:
                return f"DENY: {reason} (source: {label.source})"

        for min_level, rule_sink, reason in self.DEFAULT_REVIEW_RULES:
            if label.level >= min_level and sink == rule_sink:
                return f"REVIEW: {reason} (source: {label.source})"

        return None

    def mark_malicious(self, data_id: str, reason: str = "injection_detected"):
        """Marque une donnée comme MALICIOUS."""
        if data_id in self._labels:
            self._labels[data_id].level = TaintLevel.MALICIOUS
            self._labels[data_id].tags.add(reason)
        else:
            self.label(data_id, None, TaintLevel.MALICIOUS, reason, {reason})

    def get_report(self) -> dict[str, Any]:
        """Résumé des labels actifs dans la session."""
        by_level: dict[str, int] = {}
        for lbl in self._labels.values():
            by_level[lbl.level.name] = by_level.get(lbl.level.name, 0) + 1
        return {
            "total_tracked": len(self._labels),
            "by_level": by_level,
            "secrets_tracked": sum(
                1 for l in self._labels.values() if l.level == TaintLevel.SECRET
            ),
            "malicious_detected": sum(
                1 for l in self._labels.values() if l.level == TaintLevel.MALICIOUS
            ),
        }


_MIN_TRACKED_LEN = 8
_MAX_TRACKED = 500
_MAX_SCAN_CHARS = 200_000

# ── Anti-fragmentation ────────────────────────────────────────────────────
# Un needle entier ne matche pas un FRAGMENT de lui-même. On indexe donc des
# "shingles" : des sous-chaînes glissantes de chaque valeur sensible, et on
# exige plusieurs hits du MÊME needle pour éviter les faux positifs.

_SHINGLE_LEN = 10  # taille d'un fragment indexé
_SHINGLE_STEP = 1  # pas du glissement (dense : fragments courts couverts)
_MAX_SHINGLES_PER_NEEDLE = 32  # plafond mémoire (couverture régulière)
_FRAGMENT_MIN_HITS = 2  # ≥ 2 shingles du même needle → sensible
_MAX_DECODE_CANDIDATES = 8  # plafond CPU : tokens décodés par appel

# Exfiltration cumulative : un caractère seul ne prouve rien, mais quand une
# fraction du secret a déjà transité vers un sink externe, on coupe.
_FRAGMENT_COVERAGE_BLOCK = float(
    os.environ.get("AGENTGUARD_TAINT_FRAGMENT_COVERAGE", "0.25")
)
_MAX_MICRO_HITS = int(os.environ.get("AGENTGUARD_TAINT_MICRO_HITS", "16"))

_B64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_-]{16,}")
_HEX_TOKEN_RE = re.compile(r"\b[0-9a-fA-F]{16,}\b")
_URL_RE = re.compile(
    r"https?://(?!(?:localhost|127\.0\.0\.1|\[::1\])[:/])", re.IGNORECASE
)

_PII_STRONG_PATTERNS = _PII_PATTERNS[1:]

_logger = logging.getLogger("agentguard.taint")

# Que faire quand le stockage de valeurs suivies est saturé ?
#   "block" (défaut, fail-closed) : tant que le tracker a dû ignorer des valeurs
#            sensibles, toute charge utile est traitée au minimum comme SECRET
#            (une donnée non suivie n'est JAMAIS considérée comme sûre).
#   "warn"  : ancien comportement (silencieux côté décision), mais journalisé.
_SATURATION_MODES = ("block", "warn")


def _b64_aligned(raw: bytes, urlsafe: bool) -> list[str]:
    """Base64 d'un secret tel qu'il apparaît DANS un texte plus long."""
    enc = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    out = []
    for k in (0, 1, 2):
        full = enc(b"\x00" * k + raw).decode().rstrip("=")
        drop_head = {0: 0, 1: 2, 2: 3}[k]
        drop_tail = 1 if (len(raw) + k) % 3 else 0
        core = full[drop_head : len(full) - drop_tail if drop_tail else len(full)]
        if core:
            out.append(core)
    return out


def _encodings(raw: str) -> list[str]:
    out = [raw]
    b = raw.encode("utf-8", "ignore")
    try:
        out.extend(_b64_aligned(b, urlsafe=False))
        out.extend(_b64_aligned(b, urlsafe=True))
    except (binascii.Error, ValueError):
        pass
    out.append(b.hex())
    q = quote(raw, safe="")
    if q != raw:
        out.append(q)
    return list(dict.fromkeys(out))


def _shingle_positions(n: int) -> list[int]:
    """Positions de départ des shingles d'une chaîne de longueur n."""
    if n < _SHINGLE_LEN * 2:
        return []
    positions = list(range(0, n - _SHINGLE_LEN + 1, _SHINGLE_STEP))
    if len(positions) > _MAX_SHINGLES_PER_NEEDLE:
        # Sous-échantillonnage régulier : la couverture reste répartie
        # sur TOUTE la valeur, pas seulement sur son début.
        stride = len(positions) / _MAX_SHINGLES_PER_NEEDLE
        positions = [
            positions[int(i * stride)] for i in range(_MAX_SHINGLES_PER_NEEDLE)
        ]
    return positions


class FlowTracker:
    """Mémorise les données sensibles vues dans une session."""

    def __init__(self, session_mode: bool = False, on_saturation: str | None = None):
        self.session_mode = session_mode
        self._tracker = TaintTracker()
        self._needles: dict[str, TaintLevel] = {}
        self._session_level = TaintLevel.PUBLIC
        self._counter = 0
        mode = (
            on_saturation or os.environ.get("AGENTGUARD_TAINT_ON_SATURATION") or "block"
        ).lower()
        # Valeur inconnue -> fail-closed.
        self.on_saturation = mode if mode in _SATURATION_MODES else "block"
        self.saturated = False
        self.dropped_needles = 0
        # ── Anti-fragmentation ──
        # shingle -> {needle_id} ; needle_id -> texte du needle (pour la
        # couverture) ; couverture cumulative par needle (exfiltration lente).
        self._shingles: dict[str, set[int]] = {}
        self._needle_by_id: dict[int, str] = {}
        self._needle_id_counter = 0
        self._coverage: dict[int, set[int]] = {}
        self.micro_hits = 0
        # Read at tracker construction time so runtime configuration (and
        # tests using monkeypatch.setenv) is honoured without reloading module.
        try:
            self._max_micro_hits = max(
                1,
                int(
                    os.environ.get("AGENTGUARD_TAINT_MICRO_HITS", str(_MAX_MICRO_HITS))
                ),
            )
        except (TypeError, ValueError):
            self._max_micro_hits = max(1, _MAX_MICRO_HITS)

    def _extract(self, text: str):
        text = text[:_MAX_SCAN_CHARS]
        for pat in _SECRET_PATTERNS:
            for m in pat.finditer(text):
                yield m.group(0), TaintLevel.SECRET
        for pat in _PII_STRONG_PATTERNS:
            for m in pat.finditer(text):
                yield m.group(0), TaintLevel.CONFIDENTIAL

    def _remember(self, needle: str, level: TaintLevel) -> None:
        if len(needle) < _MIN_TRACKED_LEN:
            return
        for variant in _encodings(needle):
            if len(variant) < _MIN_TRACKED_LEN:
                continue
            if len(self._needles) >= _MAX_TRACKED and variant not in self._needles:
                # Plein : on évince d'abord la plus ancienne entrée de niveau
                # STRICTEMENT inférieur, pour garder les secrets les plus graves.
                victim = next(
                    (k for k, lv in self._needles.items() if lv < level), None
                )
                if victim is None:
                    self._on_saturated(level)
                    return
                del self._needles[victim]
                self._on_saturated(None)  # une valeur moins grave n'est plus suivie
            prev = self._needles.get(variant)
            if prev is None or level > prev:
                self._needles[variant] = level
            # Anti-fragmentation : n'indexer des shingles que pour les
            # niveaux sensibles. PUBLIC/INTERNAL ne le mérite pas : chaque
            # needle shinglé alourdit l'index mémoire.
            if level >= TaintLevel.CONFIDENTIAL:
                self._index_shingles(variant)

    def _index_shingles(self, variant: str) -> None:
        """Indexe les fragments glissants d'une variante de needle.

        Un needle_id est attribué UNE fois par variante : tous ses
        shingles partagent cet id, sinon le seuil "≥ N hits du même
        needle" ne peut jamais être atteint.
        """
        self._needle_id_counter += 1
        nid = self._needle_id_counter
        self._needle_by_id[nid] = variant
        for start in _shingle_positions(len(variant)):
            shingle = variant[start : start + _SHINGLE_LEN]
            if shingle:
                self._shingles.setdefault(shingle, set()).add(nid)

    def _on_saturated(self, dropped_level: TaintLevel | None) -> None:
        """Enregistre explicitement qu'une valeur n'est (plus) suivie."""
        self.dropped_needles += 1
        if not self.saturated:
            self.saturated = True
            _logger.warning(
                "taint_tracker_saturated: max=%d on_saturation=%s "
                "(untracked sensitive values; external flows %s)",
                _MAX_TRACKED,
                self.on_saturation,
                "BLOCKED until clear()"
                if self.on_saturation == "block"
                else "not blocked",
            )

    def clear(self) -> None:
        """Réinitialise les valeurs suivies et l'état de saturation (fin de session)."""
        self._needles.clear()
        self.saturated = False
        self.dropped_needles = 0
        # Anti-fragmentation : tout l'état dérivé est réinitialisé aussi.
        self._shingles.clear()
        self._needle_by_id.clear()
        self._coverage.clear()
        self.micro_hits = 0

    def track(
        self, value: Any, source: str = "user", level: TaintLevel | None = None
    ) -> TaintLabel:
        """Enregistre une donnée entrante/sortante."""
        text = TaintTracker._to_text(value)
        detected = self._tracker._auto_classify(value) if text else TaintLevel.PUBLIC

        # Si l'appelant force un niveau, on prend le max entre détecté et déclaré.
        final = max(detected, level) if level is not None else detected

        self._counter += 1
        label = self._tracker.label(f"d{self._counter}", value, final, source)
        if text:
            for needle, lvl in self._extract(text):
                self._remember(needle, lvl)
            if (
                level
                in (TaintLevel.SECRET, TaintLevel.CONFIDENTIAL, TaintLevel.UNTRUSTED)
                and len(text) >= _MIN_TRACKED_LEN
            ):
                self._remember(text.strip(), level)
            if final > self._session_level and final != TaintLevel.UNTRUSTED:
                self._session_level = final
        return label

    def mark_as_tainted(
        self,
        value: Any,
        level: str | TaintLevel = "SECRET",
        source: str = "manual",
    ) -> TaintLabel:
        """Marque explicitement une valeur comme contaminée.

        API attendue par les intégrations : accepte le nom du niveau
        sous forme de chaîne ("SECRET") ou directement un TaintLevel.
        """
        if isinstance(level, str):
            try:
                level = TaintLevel[level.upper()]
            except KeyError:
                raise ValueError(f"Unknown taint level: {level!r}")

        return self.track(value, source=source, level=level)

    def mark_malicious(self, source: str = "injection_detected") -> None:
        self._session_level = TaintLevel.MALICIOUS
        self._tracker.label(
            f"m{self._counter + 1}", None, TaintLevel.MALICIOUS, source, {source}
        )
        self._counter += 1

    # ── Anti-fragmentation : scan ────────────────────────────────────────

    @staticmethod
    def _decode_candidates(text: str) -> list[str]:
        """Décode les tokens base64/hex d'un payload pour re-scan.

        Le base64 d'un FRAGMENT n'est pas une sous-chaîne du base64 du
        secret entier : il faut décoder puis shingle-matcher le décodé.
        """
        out: list[str] = []
        for m in _B64_TOKEN_RE.finditer(text[:_MAX_SCAN_CHARS]):
            tok = m.group(0)
            for dec in (base64.b64decode, base64.urlsafe_b64decode):
                try:
                    padded = tok + "=" * (-len(tok.rstrip("=")) % 4)
                    cand = dec(padded)
                    decoded = cand.decode("utf-8")
                    if decoded.strip():
                        out.append(decoded)
                    break
                except (binascii.Error, ValueError, UnicodeDecodeError):
                    continue
            if len(out) >= _MAX_DECODE_CANDIDATES:
                break
        for m in _HEX_TOKEN_RE.finditer(text[:_MAX_SCAN_CHARS]):
            if len(out) >= _MAX_DECODE_CANDIDATES:
                break
            try:
                out.append(bytes.fromhex(m.group(0)).decode("utf-8", "ignore"))
            except ValueError:
                continue
        return out

    def _shingle_hits(self, text: str) -> dict[int, int]:
        """Nombre de shingles matchés, par needle_id, dans le texte."""
        hits: dict[int, int] = {}
        if not self._shingles or not text:
            return hits
        text = text[:_MAX_SCAN_CHARS]
        for i in range(len(text) - _SHINGLE_LEN + 1):
            ids = self._shingles.get(text[i : i + _SHINGLE_LEN])
            if ids:
                for nid in ids:
                    hits[nid] = hits.get(nid, 0) + 1
        return hits

    def _accumulate_coverage(self, text: str, hits: dict[int, int]) -> None:
        """Cumule la couverture du secret par les fragments sortis.

        Appelé pour un flux externe : chaque shingle matché marque la
        portion correspondante du needle comme "déjà partie". Un payload
        micro (char par char) marque sa position approximative.
        """
        for nid, n in hits.items():
            self._coverage.setdefault(nid, set()).update(range(n))

    @staticmethod
    def _iter_micro_values(value: Any):
        """Yield short string leaves from structured tool arguments."""
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for child in value.values():
                yield from FlowTracker._iter_micro_values(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                yield from FlowTracker._iter_micro_values(child)

    def _accumulate_micro_coverage(self, params: Any) -> None:
        # Scan actual argument values, not their JSON serialization: the
        # latter includes keys/quotes and makes a one-character body appear
        # longer than _SHINGLE_LEN.
        matched_micro = False
        for fragment in self._iter_micro_values(params):
            if not 0 < len(fragment) <= _SHINGLE_LEN:
                continue
            for nid, needle in self._needle_by_id.items():
                if fragment in needle:
                    pos = needle.find(fragment)
                    self._coverage.setdefault(nid, set()).add(pos // _SHINGLE_STEP)
                    matched_micro = True
        # Count once per outbound event, not once per indexed encoding/variant.
        if matched_micro:
            self.micro_hits += 1

    def _coverage_escalation(self) -> tuple[TaintLevel, str] | None:
        """Vrai si une fraction suffisante d'un secret est déjà sortie."""
        for nid, covered in self._coverage.items():
            needle = self._needle_by_id.get(nid)
            if not needle:
                continue
            total = max(1, len(_shingle_positions(len(needle))) or 1)
            if len(covered) >= _FRAGMENT_COVERAGE_BLOCK * total:
                return TaintLevel.SECRET, "fragment_accumulation"
        if self.micro_hits >= self._max_micro_hits:
            return TaintLevel.SECRET, "fragment_accumulation"
        return None

    def level_in(self, params: Any, external: bool | None = None) -> TaintLabel:
        """Niveau de taint le plus élevé présent dans `params`.

        Renvoie TOUJOURS un TaintLabel (PUBLIC au minimum) — jamais None.
        Les appelants doivent tester `.level`, pas la vérité de l'objet.

        ``external`` : si le flux sort vers un sink externe (l'accumulateur
        de couverture ne compte que les fuites réelles). Si None, on
        l'infère : une URL non locale dans les params = externe.
        """
        text = TaintTracker._to_text(params)
        level = TaintLevel.PUBLIC
        source = "none"
        if external is None:
            external = bool(text and _URL_RE.search(text[:_MAX_SCAN_CHARS]))
        if text:
            for needle, lvl in self._needles.items():
                if needle in text and lvl > level:
                    level, source = lvl, "tracked_value"
            scan = text[:_MAX_SCAN_CHARS]
            direct = TaintLevel.PUBLIC
            if any(p.search(scan) for p in _SECRET_PATTERNS):
                direct = TaintLevel.SECRET
            elif any(p.search(scan) for p in _PII_STRONG_PATTERNS):
                direct = TaintLevel.CONFIDENTIAL
            if direct > level:
                level, source = direct, "pattern_in_params"
            # ── Anti-fragmentation ──
            # 1) Fragments en clair : ≥ _FRAGMENT_MIN_HITS shingles du même
            #    needle. Un shingle isolé peut apparaître par hasard dans un
            #    texte bénin ; plusieurs fragments du même secret, non.
            hits: dict[int, int] = {}
            if level < TaintLevel.CONFIDENTIAL:
                hits = self._shingle_hits(scan)
                best_nid = max(hits, key=hits.get) if hits else None
                if best_nid is not None and hits[best_nid] >= _FRAGMENT_MIN_HITS:
                    level, source = TaintLevel.SECRET, "taint_fragment"
                # 2) Fragments encodés : décoder puis re-scan.
                # Decode even when the encoded bytes already matched a
                # shingle: that first match may have been against an encoded
                # needle. Prefer the explicit encoded provenance when the
                # decoded fragment independently matches the original secret.
                if direct < TaintLevel.SECRET:
                    for decoded in self._decode_candidates(scan):
                        dhits = self._shingle_hits(decoded)
                        dmax = max(dhits, key=dhits.get) if dhits else None
                        if dmax is not None and dhits[dmax] >= _FRAGMENT_MIN_HITS:
                            level, source = TaintLevel.SECRET, "taint_fragment_encoded"
                            hits = dhits
                            break
                # 3) Exfiltration cumulative : la fuite se mesure dans la
                #    durée, pas dans un seul appel.
                if external:
                    self._accumulate_coverage(scan, hits)
                    self._accumulate_micro_coverage(params)
                    escalation = self._coverage_escalation()
                    if escalation and level < escalation[0]:
                        level, source = escalation
        if (
            self.saturated
            and self.on_saturation == "block"
            and level < TaintLevel.SECRET
        ):
            # Fail-closed : des valeurs sensibles ont été ignorées, donc une
            # charge utile "propre" n'est pas prouvée sûre.
            level, source = TaintLevel.SECRET, "tracker_saturated"
        if self._session_level == TaintLevel.MALICIOUS:
            level, source = TaintLevel.MALICIOUS, "session_malicious"
        elif (
            self.session_mode
            and self._session_level >= TaintLevel.SECRET
            and level < TaintLevel.SECRET
        ):
            level, source = TaintLevel.SECRET, "session_mode"
        return TaintLabel(level=level, source=source)

    def check_sink(self, label: TaintLabel | None, sink: SinkType) -> str | None:
        return self._tracker.check_sink(label, sink)

    def report(self) -> dict[str, Any]:
        r = self._tracker.get_report()
        r["session_level"] = self._session_level.name
        r["tracked_needles"] = len(self._needles)
        r["saturated"] = self.saturated
        r["dropped_needles"] = self.dropped_needles
        # Anti-fragmentation : visibilité de l'état des fragments.
        r["shingles_tracked"] = len(self._shingles)
        r["micro_hits"] = self.micro_hits
        r["fragment_coverage"] = {nid: len(cov) for nid, cov in self._coverage.items()}
        return r
