import json
import os
import re
import time
from typing import Any

import structlog

from .models import RiskLevel, SecurityAction, SecurityCheck

logger = structlog.get_logger("agentguard.policy")

try:
    from .ml import MLDetector
except ImportError:

    class MLDetector:
        def __init__(self):
            self.enabled = False
            self.threshold = 0.95

        def predict(self, text):
            return {"score": 0.0, "risk": "UNKNOWN", "confidence": "low"}


try:
    from .judges import LLMCascadeJudge, TripleJudge
except ImportError:  # pragma: no cover
    LLMCascadeJudge = None
    TripleJudge = None


_ARBITER_METHOD_CANDIDATES = (
    "judge",
    "evaluate",
    "check",
    "assess",
    "analyze",
    "classify",
)


def _tool_matches_whitelist(tool_name: str, whitelist) -> bool:
    """Match exact OU par préfixe.

    Une entrée de whitelist terminant par '*' (et différente de '*')
    autorise tous les outils dont le nom commence par le préfixe.
    Ex: "mcp:fs:*" autorise "mcp:fs:read_file".

    Une entrée '*' seule ne matche RIEN ici : autoriser tout un serveur
    est un choix explicite de la gateway, jamais un effet de bord du
    moteur de policy.
    """
    if tool_name in whitelist:
        return True

    for entry in whitelist:
        if entry.endswith("*") and entry != "*" and tool_name.startswith(entry[:-1]):
            return True

    return False


class PolicyEngine:
    _STRONG_PATTERNS = None
    _WEAK_PATTERNS = None
    _DESTRUCTIVE_PATTERNS = None

    def __init__(
        self,
        policies: list[dict[str, Any]] | None = None,
        redis_url: str | None = None,
    ):
        self.policies = policies or []
        self._compile_patterns()
        self.ml_detector = MLDetector()

        self.use_llm_judge = os.getenv("AGENTGUARD_USE_LLM_JUDGE", "false").lower() in (
            "true",
            "1",
            "on",
            "yes",
        )
        self._use_triple_judge = os.getenv(
            "AGENTGUARD_USE_TRIPLE_JUDGE", "false"
        ).lower() in ("true", "1", "on", "yes")
        self.block_on_ambiguous = os.getenv(
            "AGENTGUARD_BLOCK_ON_AMBIGUOUS", "false"
        ).lower() in ("true", "1", "on", "yes")
        self.judge_timeout = max(
            0.5,
            float(os.getenv("AGENTGUARD_JUDGE_TIMEOUT", "15.0")),
        )

        # ── v5.5 : circuit breaker de l'arbitre LLM ──────────────
        # Quand l'API LLM est en panne (timeouts en cascade), chaque
        # flag ML paie un timeout complet (~6 s) avant le fail-closed.
        # Le breaker : après N échecs consécutifs, on cesse d'appeler
        # l'API pendant `cooldown` secondes — les flags ML retombent
        # alors sur le fail-closed ML (~0 ms d'attente). Un appel de
        # sonde passe à l'expiration (half-open) pour rouvrir si
        # l'API est rétablie.
        self._arbiter_failure_threshold = max(
            1, int(os.getenv("AGENTGUARD_ARBITER_BREAKER_THRESHOLD", "2"))
        )
        self._arbiter_cooldown = max(
            5.0, float(os.getenv("AGENTGUARD_ARBITER_BREAKER_COOLDOWN", "60"))
        )
        self._arbiter_consecutive_failures = 0
        self._arbiter_open_until = 0.0
        self._arbiter_breaker_logged = False

        self._whitelist_fail_closed = os.getenv(
            "AGENTGUARD_WHITELIST_FAIL_MODE", "open"
        ).strip().lower() in ("closed", "fail_closed", "true", "1")

        self._redis_client = None
        if redis_url and self.use_llm_judge:
            try:
                import redis

                self._redis_client = redis.from_url(redis_url)
                self._redis_client.ping()
            except Exception as exc:
                logger.warning("redis_initialization_failed", error=str(exc))
                self._redis_client = None

        self._allowed_tools_global = set()
        self._allowed_tools_by_agent: dict[str, set] = {}
        self._has_whitelist_policies = False

        for policy in self.policies:
            if policy.get("type") == "tool_whitelist":
                self._has_whitelist_policies = True
                tools = set(policy.get("allowed_tools", []))
                scoped_agents = policy.get("agents")

                if not scoped_agents and policy.get("agent_id"):
                    scoped_agents = [policy["agent_id"]]

                if scoped_agents:
                    for agent in scoped_agents:
                        self._allowed_tools_by_agent.setdefault(agent, set()).update(
                            tools
                        )
                else:
                    self._allowed_tools_global.update(tools)

        self._triple_judge = None

        if self.use_llm_judge and self._use_triple_judge and TripleJudge is not None:
            try:
                triple_judge = TripleJudge()

                prompt_guard_ready = triple_judge.prompt_guard.enabled and bool(
                    triple_judge.prompt_guard.api_key
                )
                llama_guard_ready = triple_judge.llama_guard.enabled and bool(
                    triple_judge.llama_guard.api_key
                )
                cascade_ready = triple_judge.llm_cascade.is_configured()

                if prompt_guard_ready or llama_guard_ready or cascade_ready:
                    self._triple_judge = triple_judge
                else:
                    logger.warning(
                        "triple_judge_unconfigured",
                        detail=("Aucun juge LLM ne dispose d'une clé API configurée"),
                    )
            except Exception as exc:
                logger.warning(
                    "triple_judge_initialization_failed",
                    error=str(exc),
                )

        self._ml_arbiter = None

        if self.use_llm_judge and LLMCascadeJudge is not None:
            try:
                arbiter = LLMCascadeJudge()
                if arbiter.is_configured():
                    self._ml_arbiter = arbiter
                    self._arbiter_method = self._resolve_arbiter_method(arbiter)
                    if self._arbiter_method is None:
                        logger.error(
                            "llm_arbiter_no_judgment_method",
                            detail=(
                                "LLMCascadeJudge configuré mais aucune méthode "
                                f"de jugement trouvée parmi {_ARBITER_METHOD_CANDIDATES}"
                            ),
                        )
                else:
                    logger.warning(
                        "llm_arbiter_unconfigured",
                        detail=(
                            "AGENTGUARD_USE_LLM_JUDGE=true mais aucune "
                            "clé API pour les providers autorisés"
                        ),
                    )
            except Exception as exc:
                logger.warning(
                    "llm_arbiter_initialization_failed",
                    error=str(exc),
                )

    @staticmethod
    def _resolve_arbiter_method(arbiter) -> str | None:
        """Trouve le nom de la méthode de jugement de l'arbitre."""
        for name in _ARBITER_METHOD_CANDIDATES:
            if callable(getattr(arbiter, name, None)):
                return name
        return None

    def _arbiter_available(self) -> bool:
        """v5.5 : True si l'arbitre est utilisable MAINTENANT.

        Breaker ouvert -> False sans toucher le réseau ; à l'expiration
        du cooldown, un premier appel passe (half-open) pour sonder
        l'API."""
        if self._ml_arbiter is None or getattr(self, "_arbiter_method", None) is None:
            return False

        if time.monotonic() < self._arbiter_open_until:
            if not self._arbiter_breaker_logged:
                logger.warning(
                    "llm_arbiter_breaker_open",
                    detail=(
                        f"Arbitre désactivé {self._arbiter_cooldown:.0f}s après "
                        f"{self._arbiter_consecutive_failures} échecs consécutifs"
                    ),
                )
                self._arbiter_breaker_logged = True
            return False

        return True

    def _record_arbiter_success(self):
        self._arbiter_consecutive_failures = 0
        self._arbiter_open_until = 0.0
        self._arbiter_breaker_logged = False

    def _record_arbiter_failure(self):
        self._arbiter_consecutive_failures += 1
        if self._arbiter_consecutive_failures >= self._arbiter_failure_threshold:
            self._arbiter_open_until = time.monotonic() + self._arbiter_cooldown
            logger.warning(
                "llm_arbiter_breaker_tripped",
                failures=self._arbiter_consecutive_failures,
                cooldown_s=self._arbiter_cooldown,
            )

    def _call_arbiter(self, text: str, timeout: float):
        """Appelle la méthode de jugement de l'arbitre, de façon
        défensive sur la signature. Retourne le verdict, ou None si
        aucune combinaison méthode/signature n'a fonctionné."""
        if self._arbiter_method is None:
            return None

        method = getattr(self._ml_arbiter, self._arbiter_method)

        attempts = (
            lambda: method(text, timeout),
            lambda: method(text),
            lambda: method(prompt=text),
            lambda: method(text, timeout=timeout),
            lambda: method(text, llm_timeout=timeout),
        )

        last_exc = None
        for attempt in attempts:
            try:
                return attempt()
            except TypeError as exc:
                last_exc = exc
                continue

        raise last_exc  # pragma: no cover

    @property
    def _allowed_tools(self) -> set:
        merged = set(self._allowed_tools_global)
        for tools in self._allowed_tools_by_agent.values():
            merged.update(tools)
        return merged

    def _effective_whitelist(self, agent_id: str | None) -> set:
        scoped = (
            self._allowed_tools_by_agent.get(agent_id, set()) if agent_id else set()
        )
        if scoped:
            return scoped | self._allowed_tools_global
        return set(self._allowed_tools_global)

    def _compile_patterns(self):
        if PolicyEngine._STRONG_PATTERNS is not None:
            return

        from .patterns import get_all_strong_patterns, get_weak_patterns

        all_strong = get_all_strong_patterns()
        weak = get_weak_patterns()

        PolicyEngine._STRONG_PATTERNS = re.compile(
            "|".join(f"(?:{p})" for p in all_strong),
            re.IGNORECASE,
        )
        PolicyEngine._WEAK_PATTERNS = re.compile(
            "|".join(f"(?:{p})" for p in weak),
            re.IGNORECASE,
        )

        destructive = [
            # ── Jailbreak : personas connus (liste fermée) ───────────
            r"\b(?:act\s+as|roleplay\s+as|pretend\s+(?:you\s+are|to\s+be)|simulate|switch\s+to|your\s+new\s+persona\s+is)\b.{0,40}\b(?:STAN|AnonGPT|DAN|Mad\s+Mode|Primal\s+Mode|Root\s+Mode|Free\s+Mode|Limitless\s+Mode|Developer\s+Mode|AIM\s+Mode)\b",
            r"\b(?:STAN|AnonGPT|DAN)\b.{0,40}\b(?:never\s+refuse|don'?t\s+hold\s+back|no\s+rules|anything)\b",
            # ── Extraction du système ────────────────────────────────
            r"\b(?:core\s+directives|internal\s+programming|guardrail\s+text|system\s+prompt|internal\s+instructions?|programming\s+guides)\b.{0,40}\b(?:display|show|dump|print|list|reveal|collect|translate|verbatim|code\s+block|JSON|in\s+your\s+answer)\b",
            r"\b(?:display|show|dump|print|list|reveal|collect)\b.{0,30}\b(?:core\s+directives|internal\s+programming|guardrail\s+text|system\s+prompt|internal\s+instructions?|programming\s+guides)\b",
            r"\b(?:developer|admin)\s+check\b.{0,40}\b(?:show|display|dump|print|reveal)\b",
            r"\bshow\s+the\s+text\s+above\b.{0,30}\b(?:code\s+block|JSON|verbatim|without\s+truncat\w+)\b",
            (
                r"\b(?:list|show|print|output|dump)\s+(?:every|all)\s+"
                r"(?:rules?|instructions?|directives?|policies?)\b"
                r".{0,40}\b(?:you\s+(?:were\s+)?(?:given|told|trained)|"
                r"in\s+a\s+JSON|system\s+prompt)\b"
            ),
            # ── Commandes destructrices explicites ──────────────────
            r"\bkubectl\s+(?:delete|drain|cordon)\s+(?:namespace|ns|node)\b",
            r"\bterraform\s+destroy\b",
            r"\bsystemctl\s+(?:stop|disable|mask)\s+(?:firewalld|iptables|auditd|ssh[d]?|apparmor)\b",
            r"\biptables\s+(?:-F|--flush)\b",
            r"\bchattr\s+-i\b",
            r"\bapparmor_parser\s+-R\b",
            r"\bgit\s+reset\s+--hard\b",
            r"\bgit\s+push\b.{0,40}--force\b",
            r"\b(?:nmap|hydra|sqlmap|nikto|masscan)\s",
            r"\bfind\s+/.{0,80}-exec\b",
            r"\bcurl\b.{0,120}\|\s*(?:ba)?sh\b",
            r"\bwget\b.{0,120}\|\s*(?:ba)?sh\b",
            r"\bcrontab\s+-r\b",
            r"\bredis-cli\s+FLUSHALL\b",
            r"\bnc\s+-e\s+",
            r"\buseradd\s+(?:-o\s+)?-u\s+0\b",
            r">\s*/etc/(?:crontab|passwd|shadow|hosts)\b",
            r"\bln\s+-sf\b.{0,40}/etc/",
            r"\bchmod\s+66[06]\b.{0,40}/etc/",
            r"\bshred\s+/",
            r"\bsetenforce\s+0\b",
            r"\bpasswd\s+-d\s+root\b",
            r"\bkill\s+-9\s+1\b",
            r":\(\)\s*\{.*\};\s*:",
            r"\bDELETE\s+FROM\s+\w+",
            r"\bsudo\s+rm\s+/etc/",
            r"\bmailx\b.{0,60}\b(?:root@|evil\.|attacker)",
            r"\b(?:adduser|useradd)\s+\w+\b.{0,30}\b(?:backdoor|stealth)\b",
            r"\becho\b.{0,20}\broot\s+nc\b",
            r"/proc/sysrq-trigger\b",
            r"\bwget\b.{0,80}-O\s+/tmp/\b.{0,40}&&",
            r"\bsudo\s+-l\b.{0,60}\bcurl\b.{0,30}evil\.",
            (
                r"\b(?:terminate|sabotage|kill|stop|disable|crash)\w*\s+"
                r"(?:the\s+|all\s+|other\s+|remaining\s+)*workers\b"
            ),
            r"\bworkers\b.{0,40}\b(?:keep|as|with)\s+root\b",
            # ── Exfiltration ───────────────────────────────────────
            (
                r"\b(?:send|upload|export|forward|post|ship|transfer|broadcast)\b"
                r".{0,60}\b(?:to|towards|on|at)\b"
                r".{0,50}\b(?:external|ftp|sftp|pastebin|attacker|evil\.|"
                r"10\.\d+\.\d+\.\d+|https?://(?!localhost|127\.0\.0\.1))"
            ),
            (
                r"\b(?:leak|exfiltrat\w+|steal)\b.{0,40}"
                r"\b(?:key|credential|secret|password|token|invoice|contract|customer|database)\w*"
            ),
            (
                r"\b(?:private|secret|api)\s+keys?\b.{0,40}\b(?:to|on|via|at)\b"
            ),
            (
                r"\b(?:send|upload|export)\b.{0,60}"
                r"\b(?:salaries?|credentials?|logs?|messages?|archives?|invoices?)\b"
                r".{0,40}\b(?:competitor|unsecured|webhook|third[- ]party|external)\b"
            ),
            # ── Indirect injection ──────────────────────────────────
            (
                r"\b(?:web\s?page|webpage|email(?:\s+body)?|tool\s+output|tool\s+call|"
                r"API\s+response|database\s+record|CSV\s+field|RSS\s+feed|"
                r"PDF\s+document|uploaded\s+file|search\s+result|"
                r"user\s+comment|(?:the|user'?s)\s+comment|file)\b"
                r"\s+(?:contains|says|reads)\s*:.{0,120}"
                r"\b(?:crash|backdoor|reverse\s+shell|rootkit|turn\s+off|disable|"
                r"bypass|forward\s+all|export\s+the\s+customer|read\s+the\s+CEO|"
                r"list\s+all\s+employees|salaries\s+in\s+your\s+answer|"
                r"steal|exfiltrat\w+|leak)\b"
            ),
            # ── Neutralisation de la sécurité ───────────────────────
            (
                r"\b(?:disabl|turn\s+off|mute|stop)\w*\b.{0,40}"
                r"\b(?:audit|journali[sz]ation|logging|alerts?|guardrails?|firewall)\b"
            ),
            (
                r"\b(?:bypass|skip|ignore)\b.{0,40}"
                r"\b(?:approval|verification|workflow|review|checks?)\b"
            ),
            (
                r"\b(?:change|reset)\b.{0,30}\badmin\s+password\b"
            ),
            (
                r"\b(?:rewrite|modify|change)\b.{0,30}\b(?:your\s+)?polic(?:y|ies)\b"
            ),
            (
                r"\b(?:rewrite|modify|change)\b.{0,40}\b(?:access\s+controls?)\b.{0,30}allow\s+everyone\b"
            ),
        ]

        PolicyEngine._DESTRUCTIVE_PATTERNS = re.compile(
            "|".join(f"(?:{p})" for p in destructive),
            re.IGNORECASE,
        )

    def check_injection(self, text: str) -> SecurityCheck:
        """v5.5 — moteur à escalade (latency-first) + circuit breaker.

        Tier 0 : regex brut                          (~0.4 ms, gratuit)
        Tier 1 : patterns destructeurs + variantes  (~0.1 ms, gratuit)
                 dé-obfusquées (ROT13, leet x2, doublé, espacé, miroir)
        Tier 2 : ML local                            (~100-300 ms, jamais d'API)
        Tier 3 : arbitre LLM — UNIQUEMENT sur flag ML (~2 s, trafic minoritaire)

        v5.5 : breaker — si l'API LLM échoue N fois de suite, les flags
        ML retombent sur le fail-closed ML immédiatement (~0 ms) au lieu
        de payer un timeout complet. L'arbitre est re-sondé après le
        cooldown (half-open).
        """
        from .normalizer import (
            normalize_for_detection,
            reversed_words_variant,
        )
        from .patterns import is_didactic_context

        text = str(text or "")
        if not text.strip():
            return SecurityCheck(
                "prompt_injection",
                True,
                RiskLevel.LOW,
                "Empty prompt",
            )

        # ── Tier 0 : regex sur le texte brut (~0.4 ms) ────────────
        if PolicyEngine._STRONG_PATTERNS.findall(text):
            if is_didactic_context(text):
                return SecurityCheck(
                    "prompt_injection",
                    True,
                    RiskLevel.MEDIUM,
                    "Didactic context: quoted payload downgraded to review",
                    {"layer": "regex", "downgraded": True},
                    SecurityAction.REVIEW,
                )

            return SecurityCheck(
                "prompt_injection",
                False,
                RiskLevel.HIGH,
                "Strong injection pattern detected",
                {"layer": "regex"},
                SecurityAction.BLOCK,
            )

        # ── Tier 1a : patterns destructeurs/exfiltration (~0.05 ms) ─
        if PolicyEngine._DESTRUCTIVE_PATTERNS.findall(text):
            if is_didactic_context(text):
                return SecurityCheck(
                    "prompt_injection",
                    True,
                    RiskLevel.MEDIUM,
                    "Destructive pattern in didactic context: downgraded to review",
                    {"layer": "regex+destructive", "downgraded": True},
                    SecurityAction.REVIEW,
                )

            return SecurityCheck(
                "prompt_injection",
                False,
                RiskLevel.HIGH,
                "Destructive command or exfiltration pattern detected",
                {"layer": "regex+destructive"},
                SecurityAction.BLOCK,
            )

        # ── Tier 1b : regex sur toutes les variantes dé-obfusquées ──
        variants = [normalize_for_detection(text), reversed_words_variant(text)]
        try:
            from .normalizer import (
                dedupe_variant,
                despaced_variant,
                leet_variant_i,
                leet_variant_l,
                mirrored_variant,
                rot13_variant,
            )

            variants.extend(
                [
                    rot13_variant(text),
                    leet_variant_i(text),
                    leet_variant_l(text),
                    dedupe_variant(text),
                    despaced_variant(text),
                    mirrored_variant(text),
                ]
            )
        except ImportError:
            logger.warning("obfuscation_variants_unavailable")

        for variant in variants:
            if variant == text:
                continue

            if PolicyEngine._STRONG_PATTERNS.findall(variant) or (
                PolicyEngine._DESTRUCTIVE_PATTERNS.findall(variant)
            ):
                if is_didactic_context(text):
                    return SecurityCheck(
                        "prompt_injection",
                        True,
                        RiskLevel.MEDIUM,
                        "De-obfuscated pattern in didactic context: downgraded to review",
                        {"layer": "regex+variants", "downgraded": True},
                        SecurityAction.REVIEW,
                    )

                return SecurityCheck(
                    "prompt_injection",
                    False,
                    RiskLevel.HIGH,
                    "Obfuscated injection pattern detected",
                    {"layer": "regex+variants"},
                    SecurityAction.BLOCK,
                )

        # ── Tier 2 : ML local (jamais d'API) ──────────────────────
        ml_result = None
        try:
            ml_result = self.ml_detector.predict(text)
        except Exception as exc:
            logger.warning("ml_prediction_failed", error=str(exc))

        ml_score = 0.0
        if isinstance(ml_result, dict):
            try:
                ml_score = float(ml_result.get("score", 0.0))
            except (TypeError, ValueError):
                ml_score = 0.0

        threshold = float(getattr(self.ml_detector, "threshold", 0.95) or 0.95)

        weak_hit = bool(PolicyEngine._WEAK_PATTERNS.search(text))

        if ml_score >= 0.60 or (weak_hit and ml_score >= threshold):
            meta = {
                "layer": "ml",
                "ml_score": ml_score,
                "weak_regex": weak_hit,
            }

            # v5.5 : breaker OUVERT -> fail-closed immédiat, sans
            # toucher le réseau. (Exception didactique inchangée.)
            if not self._arbiter_available():
                breaker_open = (
                    self._ml_arbiter is not None
                    and getattr(self, "_arbiter_method", None) is not None
                    and time.monotonic() < self._arbiter_open_until
                )
                arbiter_state = "breaker_open" if breaker_open else "unavailable"

                if is_didactic_context(text):
                    return SecurityCheck(
                        "prompt_injection",
                        True,
                        RiskLevel.MEDIUM,
                        (
                            f"ML flag ({ml_score:.2%}) in didactic context, "
                            f"arbiter {arbiter_state} -> review"
                        ),
                        {**meta, "arbiter": arbiter_state, "downgraded": True},
                        SecurityAction.REVIEW,
                    )

                return SecurityCheck(
                    "prompt_injection",
                    False,
                    RiskLevel.HIGH,
                    (
                        f"ML detected threat ({ml_score:.2%}); arbiter "
                        f"{arbiter_state}: block kept (fail-closed)"
                    ),
                    {**meta, "arbiter": arbiter_state},
                    SecurityAction.BLOCK,
                )

            # ── Tier 3 : arbitre LLM — trafic minoritaire uniquement ──
            judged = None
            try:
                judged = self._call_arbiter(text, timeout=self.judge_timeout)
                self._record_arbiter_success()
            except Exception as exc:
                # v5.5 : l'échec alimente le breaker ; dès que le seuil
                # est atteint, les prompts suivants ne paient plus le
                # timeout (fail-closed instantané jusqu'au cooldown).
                logger.warning("ml_arbiter_call_failed", error=str(exc))
                self._record_arbiter_failure()

            if judged is None:
                if is_didactic_context(text):
                    return SecurityCheck(
                        "prompt_injection",
                        True,
                        RiskLevel.MEDIUM,
                        (
                            f"ML flag ({ml_score:.2%}) in didactic context, "
                            "arbiter error -> review"
                        ),
                        {**meta, "arbiter": "error", "downgraded": True},
                        SecurityAction.REVIEW,
                    )

                return SecurityCheck(
                    "prompt_injection",
                    False,
                    RiskLevel.HIGH,
                    (
                        f"ML detected threat ({ml_score:.2%}); LLM arbiter "
                        "unavailable: block kept (fail-closed)"
                    ),
                    {**meta, "arbiter": "error"},
                    SecurityAction.BLOCK,
                )

            # Extraction du verdict : objet JudgeVerdict, dict, ou string.
            if isinstance(judged, dict):
                verdict_value = str(judged.get("verdict", "") or "")
                reason = str(judged.get("reason", "") or "")
            elif hasattr(judged, "verdict"):
                verdict_value = str(getattr(judged.verdict, "value", judged.verdict))
                reason = str(getattr(judged, "reason", "") or "")
            else:
                verdict_value = str(judged)
                reason = ""

            if isinstance(judged, dict):
                llm_model = judged.get("model")
            else:
                llm_model = getattr(judged, "model", None)

            meta = {**meta, "arbiter_verdict": verdict_value}

            if verdict_value.lower() in ("benign", "allow", "safe", "clear"):
                return SecurityCheck(
                    "prompt_injection",
                    True,
                    RiskLevel.LOW,
                    f"ML flag ({ml_score:.2%}) cleared by LLM arbiter: {reason}",
                    {
                        **meta,
                        "layer": "ml+llm",
                        "ml_overridden": True,
                        "llm_model": llm_model,
                    },
                    SecurityAction.ALLOW,
                )

            if verdict_value.lower() == "attack":
                return SecurityCheck(
                    "prompt_injection",
                    False,
                    RiskLevel.HIGH,
                    f"ML ({ml_score:.2%}) confirmed by LLM arbiter: {reason}",
                    {**meta, "layer": "ml+llm", "llm_model": llm_model},
                    SecurityAction.BLOCK,
                )

            if verdict_value.lower() == "didactic":
                return SecurityCheck(
                    "prompt_injection",
                    True,
                    RiskLevel.MEDIUM,
                    (
                        f"ML flag ({ml_score:.2%}), LLM arbiter: "
                        "didactic context -> review"
                    ),
                    {**meta, "downgraded": True},
                    SecurityAction.REVIEW,
                )

            if is_didactic_context(text):
                return SecurityCheck(
                    "prompt_injection",
                    True,
                    RiskLevel.MEDIUM,
                    (
                        f"ML flag ({ml_score:.2%}) in didactic context, "
                        f"arbiter {verdict_value} -> review"
                    ),
                    {**meta, "downgraded": True},
                    SecurityAction.REVIEW,
                )

            return SecurityCheck(
                "prompt_injection",
                False,
                RiskLevel.HIGH,
                (
                    f"ML detected threat ({ml_score:.2%}); LLM arbiter "
                    f"{verdict_value}: block kept (fail-closed)"
                ),
                {**meta, "layer": "ml"},
                SecurityAction.BLOCK,
            )

        return SecurityCheck(
            "prompt_injection",
            True,
            RiskLevel.LOW,
            "No injection detected",
            {"layer": "regex+ml"},
        )

    def check_pii(self, text: str) -> SecurityCheck:
        text = str(text or "")
        if not text.strip():
            return SecurityCheck(
                "pii_detection",
                True,
                RiskLevel.LOW,
                "Empty text",
            )

        patterns = {
            "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
            "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        }
        findings = {}

        for name, pattern in patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                findings[name] = len(matches)

        if findings:
            return SecurityCheck(
                "pii_detection",
                False,
                RiskLevel.HIGH,
                f"PII detected: {findings}",
                {"pii_types": findings},
                SecurityAction.BLOCK,
            )

        return SecurityCheck(
            "pii_detection",
            True,
            RiskLevel.LOW,
            "No PII detected",
        )

    def check_budget(
        self,
        cost: float,
        max_budget: float,
        current_spent: float,
    ) -> SecurityCheck:
        if current_spent + cost > max_budget:
            return SecurityCheck(
                "budget_policy",
                False,
                RiskLevel.HIGH,
                (f"Budget exceeded: {current_spent + cost:.4f} > {max_budget:.4f}"),
                {
                    "current_spent": current_spent,
                    "cost": cost,
                    "max_budget": max_budget,
                },
                SecurityAction.BLOCK,
            )

        return SecurityCheck(
            "budget_policy",
            True,
            RiskLevel.LOW,
            "Budget OK",
        )

    def check_tool_policy(
        self,
        tool_name: str,
        params: dict[str, Any],
        budget_remaining: float,
        agent_id: str | None = None,
    ) -> SecurityCheck:
        effective_whitelist = self._effective_whitelist(agent_id)

        if effective_whitelist and not _tool_matches_whitelist(
            tool_name, effective_whitelist
        ):
            scope = f"agent '{agent_id}'" if agent_id else "default scope"
            return SecurityCheck(
                "tool_policy",
                False,
                RiskLevel.CRITICAL,
                (f"Tool '{tool_name}' not in whitelist for {scope}"),
                {"agent_id": agent_id},
                SecurityAction.BLOCK,
            )

        if (
            self._whitelist_fail_closed
            and self._has_whitelist_policies
            and not effective_whitelist
        ):
            scope = f"agent '{agent_id}'" if agent_id else "default scope"
            return SecurityCheck(
                "tool_policy",
                False,
                RiskLevel.CRITICAL,
                (
                    f"Tool '{tool_name}' blocked: no whitelist covers "
                    f"{scope} (fail-closed mode)"
                ),
                {
                    "agent_id": agent_id,
                    "fail_mode": "closed",
                },
                SecurityAction.BLOCK,
            )

        if budget_remaining < 0:
            return SecurityCheck(
                "budget_policy",
                False,
                RiskLevel.HIGH,
                "Budget exceeded",
                {},
                SecurityAction.BLOCK,
            )

        # Règle DLP : prévention d'exfiltration vers une adresse personnelle.
        if tool_name in (
            "COMPOSIO_MULTI_EXECUTE_TOOL",
            "GMAIL_SEND_EMAIL",
            "send_email",
        ):
            tools_to_run = (
                params.get("tools", [])
                if isinstance(params, dict) and "tools" in params
                else []
            )

            if tool_name in ("GMAIL_SEND_EMAIL", "send_email"):
                tools_to_run = [
                    {
                        "tool_slug": tool_name,
                        "arguments": params,
                    }
                ]

            for tool in tools_to_run:
                if tool.get("tool_slug") in ("GMAIL_SEND_EMAIL", "send_email"):
                    args = tool.get("arguments", {})
                    recipient = str(
                        args.get("recipient_email", args.get("to", ""))
                    ).lower()
                    has_attachment = "attachment" in args or "attachments" in args

                    personal_domains = (
                        "@gmail.com",
                        "@yahoo.com",
                        "@hotmail.com",
                        "@outlook.com",
                        "@icloud.com",
                    )

                    if any(domain in recipient for domain in personal_domains):
                        reason = f"Envoi vers domaine personnel détecté ({recipient})"
                        if has_attachment:
                            reason += (
                                " avec pièce jointe. Approbation humaine OBLIGATOIRE."
                            )

                        return SecurityCheck(
                            "data_loss_prevention",
                            False,
                            RiskLevel.HIGH,
                            reason,
                            metadata={
                                "requires_approval": True,
                                "recipient": recipient,
                                "has_attachment": has_attachment,
                            },
                            action=SecurityAction.REVIEW,
                        )

        if tool_name == "execute_command":
            check = self._check_command(params)
            if not check.passed:
                return check

        try:
            params_string = json.dumps(params, default=str)
        except Exception:
            params_string = str(params)

        dangerous_patterns = re.compile(
            r"\b(?:delete_all|drop\s+table|truncate|drop\s+database|"
            r"rm\s+-rf|sudo|chmod\s+777|mkfs|dd\s+if=|"
            r"attacker|evil\.com)\b",
            re.IGNORECASE,
        )
        if dangerous_patterns.search(params_string):
            return SecurityCheck(
                "dangerous_params",
                False,
                RiskLevel.HIGH,
                "Dangerous pattern in params",
                {},
                SecurityAction.BLOCK,
            )

        return SecurityCheck(
            "tool_policy",
            True,
            RiskLevel.LOW,
            "Tool call approved",
        )

    def _check_email(self, params: dict[str, Any]) -> SecurityCheck:
        full_content = (
            f"{params.get('to', '')} "
            f"{params.get('subject', '')} "
            f"{params.get('body', '')}"
        )
        exfil_patterns = re.compile(
            r"\b(?:exfiltrate|attacker|customer\s*(?:data|database)|"
            r"credentials)\b",
            re.IGNORECASE,
        )

        if exfil_patterns.search(full_content):
            return SecurityCheck(
                "tool_policy",
                False,
                RiskLevel.CRITICAL,
                "Exfiltration detected in email",
                {},
                SecurityAction.BLOCK,
            )

        return SecurityCheck(
            "tool_policy",
            True,
            RiskLevel.LOW,
            "Email approved",
        )

    def _check_command(self, params: dict[str, Any]) -> SecurityCheck:
        command = params.get("command", "")
        dangerous = re.compile(
            r"\b(?:rm\s+-rf|sudo|chmod\s+777|mkfs|dd\s+if=|"
            r"wget[^|]*\|.*sh|curl[^|]*\|.*sh)\b",
            re.IGNORECASE,
        )

        if dangerous.search(command):
            return SecurityCheck(
                "tool_policy",
                False,
                RiskLevel.CRITICAL,
                "Dangerous command pattern",
                {},
                SecurityAction.BLOCK,
            )

        return SecurityCheck(
            "tool_policy",
            True,
            RiskLevel.LOW,
            "Command approved",
        )