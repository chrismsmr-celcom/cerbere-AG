import os
import json
import re
import structlog
from typing import Optional, Dict, Any, List

from .models import SecurityCheck, RiskLevel, SecurityAction

logger = structlog.get_logger("agentguard.policy")

try:
    from .ml import MLDetector
except ImportError:
    class MLDetector:
        def __init__(self):
            self.enabled = False
            # v5: le seuil vit sur le detector — le fallback doit l'exposer aussi
            self.threshold = 0.95
        def predict(self, text):
            return {"score": 0.0, "risk": "UNKNOWN", "confidence": "low"}

try:
    from .judges import LLMCascadeJudge, JudgeVerdict
except ImportError:  # pragma: no cover
    LLMCascadeJudge = None
    JudgeVerdict = None


def _tool_matches_whitelist(tool_name: str, whitelist) -> bool:
    """Match exact OU par préfixe.

    Une entrée de whitelist terminant par '*' (et différente de '*')
    autorise tous les outils dont le nom commence par le préfixe.
    Ex: "mcp:fs:*" autorise "mcp:fs:read_file".
    Une entrée '*' seule ne matche RIEN ici : autoriser tout un serveur
    est un choix explicite de la gateway (AGENTGUARD_MCP_ALLOWED_TOOLS="*"),
    jamais un effet de bord du moteur de policy.
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

    def __init__(self, policies: Optional[List[Dict[str, Any]]] = None, redis_url: Optional[str] = None):
        self.policies = policies or []
        self._compile_patterns()
        self.ml_detector = MLDetector()
        self.use_llm_judge = os.getenv("AGENTGUARD_USE_LLM_JUDGE", "false").lower() in ("true", "1", "on", "yes")
        self.block_on_ambiguous = os.getenv("AGENTGUARD_BLOCK_ON_AMBIGUOUS", "false").lower() in ("true", "1", "on", "yes")
        self.judge_timeout = max(0.5, float(os.getenv("AGENTGUARD_JUDGE_TIMEOUT", "15.0")))

        # Fail mode de la whitelist scoped :
        #   "open" (défaut, historique)   : un agent non couvert par une
        #                                   whitelist n'est PAS restreint.
        #   "closed" (recommandé en prod)  : si des policies whitelist
        #                                   existent, un agent non couvert
        #                                   est BLOQUÉ (fail-closed).
        self._whitelist_fail_closed = os.getenv("AGENTGUARD_WHITELIST_FAIL_MODE", "open").strip().lower() in ("closed", "fail_closed", "true", "1")

        self._redis_client = None
        if redis_url and self.use_llm_judge:
            try:
                import redis
                self._redis_client = redis.from_url(redis_url)
                self._redis_client.ping()
            except Exception:
                self._redis_client = None

        self._allowed_tools_global = set()
        self._allowed_tools_by_agent: Dict[str, set] = {}
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
                        self._allowed_tools_by_agent.setdefault(agent, set()).update(tools)
                else:
                    self._allowed_tools_global.update(tools)
        self._triple_judge = None

        # Arbitre LLM des flags ML : un flag ML NON confirme par le regex est
        # soumis au juge (ex. DeepSeek via AGENTGUARD_JUDGE_PROVIDERS=deepseek)
        # qui peut l'innocenter. Sans cle API / sans USE_LLM_JUDGE : None, le
        # flag ML reste un BLOCK (fail-closed).
        self._ml_arbiter = None
        if self.use_llm_judge and LLMCascadeJudge is not None:
            arbiter = LLMCascadeJudge()
            if arbiter.is_configured():
                self._ml_arbiter = arbiter
            else:
                logger.warning("llm_arbiter_unconfigured", detail="USE_LLM_JUDGE=true mais aucune cle API pour les providers autorises")

    @property
    def _allowed_tools(self) -> set:
        merged = set(self._allowed_tools_global)
        for tools in self._allowed_tools_by_agent.values():
            merged.update(tools)
        return merged

    def _effective_whitelist(self, agent_id: Optional[str]) -> set:
        scoped = self._allowed_tools_by_agent.get(agent_id, set()) if agent_id else set()
        if scoped:
            return scoped | self._allowed_tools_global
        return set(self._allowed_tools_global)

    def _compile_patterns(self):
        if PolicyEngine._STRONG_PATTERNS is not None:
            return

        from .patterns import get_all_strong_patterns, get_weak_patterns

        all_strong = get_all_strong_patterns()
        weak = get_weak_patterns()

        # Note : re.IGNORECASE est appliqué ici globalement, donc pas besoin de (?i) dans les patterns
        PolicyEngine._STRONG_PATTERNS = re.compile("|".join(f"(?:{p})" for p in all_strong), re.IGNORECASE)
        PolicyEngine._WEAK_PATTERNS = re.compile("|".join(f"(?:{p})" for p in weak), re.IGNORECASE)

    def check_injection(self, text: str) -> SecurityCheck:
        """
        Detection pipeline (v5), in strict order:

        1. RAW pass   — strong patterns on the raw text. Raw first means
                        normalization can never introduce false positives
                        on clean input, and clean prompts pay only ONE
                        regex pass (no normalization cost).
        2. Triple judge / ML layers (on raw text — they are robust to
           obfuscation by design; feeding them normalized text would double
           the normalization cost for no gain).
           v5: le bloc ML utilise le seuil PORTE par MLDetector (0.95 par
           defaut, env AGENTGUARD_ML_THRESHOLD) et applique le downgrader
           didactique — un signal ML fort dans un contexte educatif devient
           REVIEW, pas BLOCK. Sans ca, le benchmark montrait 4 hard-negs
           bloques par le ML (hn_0004/5/7/11).
        3. NORMALIZED pass — only if the raw pass found nothing AND the
           normalizer actually changed the text (early exit: most benign
           prompts are untouched by normalization and skip this entirely).
        4. REVERSED pass — generic reversed-word detection, not a hardcoded
           keyword list.
        5. Didactic downgrader — a strong hit in an educational/quoted
           context becomes REVIEW (human in the loop), not BLOCK.

        Known limitation (documented, benchmark 2026-09-28): the ML
        classifier is English-centric and produces high-confidence FPs on
        French professional text (ben_0008 "Traduis ce paragraphe..." at
        99.93% on the RAW score). No threshold fixes this; it is documented
        in the benchmark and README as a known ML-layer limitation. The
        regex layer (0% FPR, multilingual) remains the default.

        Obfuscation/normalization logic lives in agentguard/normalizer.py
        (single source of truth, unit-tested). Do not inline it here.
        """
        from .normalizer import normalize_for_detection, reversed_words_variant
        from .patterns import is_didactic_context

        text = str(text or "")
        if not text.strip():
            return SecurityCheck("prompt_injection", True, RiskLevel.LOW, "Empty prompt")

        # ── ÉTAPE 1 : passe RAW (le texte brut, une seule regex) ──
        if PolicyEngine._STRONG_PATTERNS.findall(text):
            # Downgrade didactique : payload entre guillemets + contexte
            # éducatif (blog, formation, roman, fixture de test...) ->
            # REVUE HUMAINE, pas blocage dur.
            if is_didactic_context(text):
                return SecurityCheck(
                    "prompt_injection", True, RiskLevel.MEDIUM,
                    "Didactic context: quoted payload downgraded to review",
                    {"layer": "regex", "downgraded": True},
                    SecurityAction.REVIEW,
                )
            return SecurityCheck(
                "prompt_injection", False, RiskLevel.HIGH,
                "Strong injection pattern detected",
                {"layer": "regex"}, SecurityAction.BLOCK,
            )

        # ── ÉTAPE 2 : Triple Judge (texte brut) ──
        if self._triple_judge is not None:
            try:
                tj_result = self._triple_judge.evaluate(text)
                if tj_result.get("final_verdict") == "DENY":
                    return SecurityCheck("prompt_injection", False, RiskLevel.HIGH, f"[TRIPLE JUDGE] {tj_result.get('reason')}", {"layer": "triple_judge"}, SecurityAction.BLOCK)
            except Exception as e:
                logger.warning("triple_judge_failed", error=str(e))

        ml_cleared = None  # flag ML innocente par l'arbitre LLM (voir étape 3)
        # ── ÉTAPE 3 : détection ML (texte brut) ──
        # v5: seuil lu depuis le detector (source unique, 0.95 par défaut) ;
        # downgrader didactique aligné sur le comportement du bloc regex.
        if self.ml_detector.enabled:
            ml_result = self.ml_detector.predict(text)
            if ml_result["risk"] == "HIGH" and ml_result["score"] >= getattr(self.ml_detector, "threshold", 0.95):
                if is_didactic_context(text):
                    return SecurityCheck(
                        "prompt_injection", True, RiskLevel.MEDIUM,
                        "ML flag in didactic context: downgraded to review",
                        {"layer": "ml", "downgraded": True, "ml_score": round(ml_result["score"], 4)},
                        SecurityAction.REVIEW,
                    )
                if self._ml_arbiter is not None:
                    arbitrated = self._arbitrate_ml_flag(text, ml_result["score"])
                    if arbitrated.metadata.get("ml_overridden"):
                        # Le LLM peut contredire le ML, JAMAIS les passes regex
                        # deterministes ci-dessous (normalisee, mots inverses).
                        ml_cleared = arbitrated
                    else:
                        return arbitrated
                else:
                    return SecurityCheck(
                        "prompt_injection", False, RiskLevel.HIGH,
                        f"ML detected threat ({ml_result['score']:.2%})",
                        {"layer": "ml", "ml_score": round(ml_result["score"], 4)}, SecurityAction.BLOCK,
                    )

        # ── ÉTAPE 4 : passe NORMALISÉE (fallback anti-obfuscation) ──
        # Early exit : la grande majorité des prompts (bénins ET attaques
        # non obfusquées déjà traités plus haut) ne changent pas à la
        # normalisation -> coût quasi nul sur le trafic propre.
        normalized = normalize_for_detection(text)
        if normalized != text and PolicyEngine._STRONG_PATTERNS.findall(normalized):
            if is_didactic_context(text):
                return SecurityCheck(
                    "prompt_injection", True, RiskLevel.MEDIUM,
                    "Didactic context + obfuscated variant: downgraded to review",
                    {"layer": "regex+normalizer", "downgraded": True},
                    SecurityAction.REVIEW,
                )
            return SecurityCheck(
                "prompt_injection", False, RiskLevel.HIGH,
                "Obfuscated variant detected",
                {"layer": "regex+normalizer", **self._cleared_flag(ml_cleared)}, SecurityAction.BLOCK,
            )

        # ── ÉTAPE 5 : passe MOTS INVERSÉS (générique) ──
        reversed_text = reversed_words_variant(text)
        if reversed_text != text and PolicyEngine._STRONG_PATTERNS.findall(reversed_text):
            return SecurityCheck(
                "prompt_injection", False, RiskLevel.HIGH,
                "Reversed-word obfuscation detected",
                {"layer": "regex+normalizer", **self._cleared_flag(ml_cleared)}, SecurityAction.BLOCK,
            )

        if ml_cleared is not None:
            return ml_cleared  # ML flag cleared by the LLM AND all deterministic passes clean
        return SecurityCheck("prompt_injection", True, RiskLevel.LOW, "No injection detected", {"layer": "all_clear"}, SecurityAction.ALLOW)

    @staticmethod
    def _cleared_flag(ml_cleared) -> Dict[str, Any]:
        """Metadata a regex block carries when the LLM had cleared the ML flag first."""
        if ml_cleared is None:
            return {}
        return {"ml_cleared_by_llm": True, "ml_score": ml_cleared.metadata.get("ml_score"),
                "llm_verdict": ml_cleared.metadata.get("llm_verdict"),
                "llm_model": ml_cleared.metadata.get("llm_model"),
                "llm_latency_ms": ml_cleared.metadata.get("llm_latency_ms")}

    def _arbitrate_ml_flag(self, text: str, ml_score: float) -> SecurityCheck:
        """Soumet un flag ML (non confirme par le regex) au juge LLM.

        SAFE      -> ALLOW  (le ML est contredit)
        ATTACK    -> BLOCK  (le ML est confirme)
        DIDACTIC  -> REVIEW (revue humaine, comme le downgrader regex)
        autre / indisponible (AMBIGUOUS, UNCERTAIN, timeout) -> BLOCK : le
        flag ML tient (fail-closed), jamais d'ALLOW par defaut du juge.
        """
        judged = self._ml_arbiter.evaluate(text)
        meta = {
            "layer": "ml+llm", "ml_score": round(ml_score, 4),
            "llm_verdict": judged.verdict.value, "llm_model": judged.model,
            "llm_latency_ms": round(judged.latency_ms, 1), "llm_cached": judged.cached,
        }
        reason = (judged.reason or "")[:120]
        if judged.verdict == JudgeVerdict.SAFE:
            return SecurityCheck(
                "prompt_injection", True, RiskLevel.LOW,
                f"ML flag ({ml_score:.2%}) cleared by LLM arbiter: {reason}",
                {**meta, "ml_overridden": True}, SecurityAction.ALLOW,
            )
        if judged.verdict == JudgeVerdict.ATTACK:
            return SecurityCheck(
                "prompt_injection", False, RiskLevel.HIGH,
                f"ML ({ml_score:.2%}) confirmed by LLM arbiter: {reason}",
                meta, SecurityAction.BLOCK,
            )
        if judged.verdict == JudgeVerdict.DIDACTIC:
            return SecurityCheck(
                "prompt_injection", True, RiskLevel.MEDIUM,
                f"ML flag ({ml_score:.2%}), LLM arbiter: didactic context -> review",
                {**meta, "downgraded": True}, SecurityAction.REVIEW,
            )
        return SecurityCheck(
            "prompt_injection", False, RiskLevel.HIGH,
            f"ML detected threat ({ml_score:.2%}); LLM arbiter {judged.verdict.value}: block kept (fail-closed)",
            {**meta, "layer": "ml"}, SecurityAction.BLOCK,
        )

    def check_pii(self, text: str) -> SecurityCheck:
        text = str(text or "")
        if not text.strip():
            return SecurityCheck("pii_detection", True, RiskLevel.LOW, "Empty text")
        patterns = {"ssn": r"\b\d{3}-\d{2}-\d{4}\b", "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b"}
        findings = {}
        for name, pattern in patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                findings[name] = len(matches)
        if findings:
            return SecurityCheck("pii_detection", False, RiskLevel.HIGH, f"PII detected: {findings}", {"pii_types": findings}, SecurityAction.BLOCK)
        return SecurityCheck("pii_detection", True, RiskLevel.LOW, "No PII detected")

    def check_budget(self, cost: float, max_budget: float, current_spent: float) -> SecurityCheck:
        if current_spent + cost > max_budget:
            return SecurityCheck(
                "budget_policy", False, RiskLevel.HIGH,
                f"Budget exceeded: {current_spent + cost:.4f} > {max_budget:.4f}",
                {"current_spent": current_spent, "cost": cost, "max_budget": max_budget},
                SecurityAction.BLOCK
            )
        return SecurityCheck("budget_policy", True, RiskLevel.LOW, "Budget OK")

    def check_tool_policy(self, tool_name: str, params: Dict[str, Any], budget_remaining: float, agent_id: Optional[str] = None) -> SecurityCheck:
        effective_whitelist = self._effective_whitelist(agent_id)
        if effective_whitelist and not _tool_matches_whitelist(tool_name, effective_whitelist):
            scope = f"agent '{agent_id}'" if agent_id else "default scope"
            return SecurityCheck("tool_policy", False, RiskLevel.CRITICAL, f"Tool '{tool_name}' not in whitelist for {scope}", {"agent_id": agent_id}, SecurityAction.BLOCK)

        # Fail-closed (AGENTGUARD_WHITELIST_FAIL_MODE=closed) : des policies
        # whitelist existent mais aucune ne couvre cet agent -> BLOCK.
        # En mode "open" (défaut), comportement historique : ALLOW.
        if self._whitelist_fail_closed and self._has_whitelist_policies and not effective_whitelist:
            scope = f"agent '{agent_id}'" if agent_id else "default scope"
            return SecurityCheck(
                "tool_policy", False, RiskLevel.CRITICAL,
                f"Tool '{tool_name}' blocked: no whitelist covers {scope} (fail-closed mode)",
                {"agent_id": agent_id, "fail_mode": "closed"},
                SecurityAction.BLOCK,
            )

        if budget_remaining < 0:
            return SecurityCheck("budget_policy", False, RiskLevel.HIGH, "Budget exceeded", {}, SecurityAction.BLOCK)

        # --- Règle DLP (Data Loss Prevention) ---
        if tool_name in ["COMPOSIO_MULTI_EXECUTE_TOOL", "GMAIL_SEND_EMAIL", "send_email"]:
            tools_to_run = params.get("tools", []) if isinstance(params, dict) and "tools" in params else []

            if tool_name in ["GMAIL_SEND_EMAIL", "send_email"]:
                tools_to_run = [{"tool_slug": tool_name, "arguments": params}]

            for tool in tools_to_run:
                if tool.get("tool_slug") in ["GMAIL_SEND_EMAIL", "send_email"]:
                    args = tool.get("arguments", {})
                    recipient = str(args.get("recipient_email", args.get("to", ""))).lower()
                    has_attachment = "attachment" in args or "attachments" in args

                    personal_domains = ["@gmail.com", "@yahoo.com", "@hotmail.com", "@outlook.com", "@icloud.com"]

                    if any(domain in recipient for domain in personal_domains):
                        reason = f"Envoi vers domaine personnel détecté ({recipient})"
                        if has_attachment:
                            reason += " avec pièce jointe. Approbation humaine OBLIGATOIRE."

                        return SecurityCheck(
                            "data_loss_prevention",
                            False,
                            RiskLevel.HIGH,
                            reason,
                            metadata={"requires_approval": True, "recipient": recipient, "has_attachment": has_attachment},
                            action=SecurityAction.REVIEW
                        )

        if tool_name == "execute_command":
            check = self._check_command(params)
            if not check.passed:
                return check

        try:
            params_string = json.dumps(params, default=str)
        except Exception:
            params_string = str(params)

        dangerous_patterns = re.compile(r"\b(?:delete_all|drop\s+table|truncate|drop\s+database|rm\s+-rf|sudo|chmod\s+777|mkfs|dd\s+if=|attacker|evil\.com)\b", re.IGNORECASE)
        if dangerous_patterns.search(params_string):
            return SecurityCheck("dangerous_params", False, RiskLevel.HIGH, "Dangerous pattern in params", {}, SecurityAction.BLOCK)

        return SecurityCheck("tool_policy", True, RiskLevel.LOW, "Tool call approved")

    def _check_email(self, params: Dict[str, Any]) -> SecurityCheck:
        full_content = f"{params.get('to', '')} {params.get('subject', '')} {params.get('body', '')}"
        exfil_patterns = re.compile(r"\b(?:exfiltrate|attacker|customer\s*(?:data|database)|credentials)\b", re.IGNORECASE)
        if exfil_patterns.search(full_content):
            return SecurityCheck("tool_policy", False, RiskLevel.CRITICAL, "Exfiltration detected in email", {}, SecurityAction.BLOCK)
        return SecurityCheck("tool_policy", True, RiskLevel.LOW, "Email approved")

    def _check_command(self, params: Dict[str, Any]) -> SecurityCheck:
        command = params.get("command", "")
        dangerous = re.compile(r"\b(?:rm\s+-rf|sudo|chmod\s+777|mkfs|dd\s+if=|wget[^|]*\|.*sh|curl[^|]*\|.*sh)\b", re.IGNORECASE)
        if dangerous.search(command):
            return SecurityCheck("tool_policy", False, RiskLevel.CRITICAL, "Dangerous command pattern", {}, SecurityAction.BLOCK)
        return SecurityCheck("tool_policy", True, RiskLevel.LOW, "Command approved")