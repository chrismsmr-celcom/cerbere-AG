import hashlib
import inspect
import json
import logging
import os
import time
import warnings
from collections.abc import Callable
from datetime import datetime, timezone
from functools import wraps
from typing import Any

import requests
import structlog
import tiktoken

from .ids import uuid7
from .masking import SpanMasker
from .models import (
    AgentDisconnectedException,
    ApprovalRejectedException,
    ApprovalRequiredException,
    GuardSpan,
    RiskLevel,
    RuntimeRiskDecision,
    SecurityCheck,
    SecurityException,
    SpanPayload,
    TrajectoryEvent,
)
from .policy import PolicyEngine
from .runtime import RuntimeRiskEngine, TrajectoryAnalyzer
from .taint import FlowTracker, TaintLevel
from .vault import IncidentVault

logger = structlog.get_logger("agentguard.sdk")

SDK_VERSION = "0.6.1"

_ENCODING_CACHE: dict[str, Any] = {}

# Outils dont le résultat est une source NON FIABLE par nature.
_UNTRUSTED_SOURCE_TOOLS = (
    "email",
    "mail",
    "inbox",
    "web",
    "fetch",
    "http_get",
    "browser",
    "scrape",
    "crawl",
    "pdf",
    "document",
    "attachment",
    "message",
    "chat",
    "comment",
    "review",
    "transcript",
    "user_input",
    "search",
)


def _is_untrusted_source(tool_name: str) -> bool:
    name = (tool_name or "").lower()
    return any(tok in name for tok in _UNTRUSTED_SOURCE_TOOLS)


def _get_encoding(model: str):
    """Renvoie l'encodeur tiktoken ou None s'il est indisponible.

    Si le téléchargement des données de tokenisation échoue, l'agent
    protégé ne doit pas planter. Le résultat, même None, est mis en cache.
    """
    if model in _ENCODING_CACHE:
        return _ENCODING_CACHE[model]

    encoding = None

    try:
        encoding = tiktoken.encoding_for_model(model)
    except Exception:
        try:
            encoding = tiktoken.get_encoding("cl100k_base")
        except Exception:
            encoding = None

    _ENCODING_CACHE[model] = encoding
    return encoding


def _count_text_tokens(model: str, text: str) -> int:
    """Compte les tokens, avec un repli approximatif si tiktoken échoue."""
    if not text:
        return 0

    encoding = _get_encoding(model)

    if encoding is not None:
        try:
            return len(encoding.encode(text))
        except Exception:
            pass

    return max(1, len(text) // 4)


class AgentGuard:
    def __init__(
        self,
        collector_url: str | None = None,
        api_key: str | None = None,
        policies: list[dict[str, Any]] | None = None,
        max_budget: float = 10.0,
        block_on_high: bool = True,
        debug: bool = False,
        use_ml: bool | None = None,
        use_llm_judge: bool | None = None,
        redis_url: str | None = None,
        fail_open: bool = False,
        agent_id: str | None = None,
        wait_for_approval: bool = True,
        notification_webhook: str | None = None,
        approval_timeout: float | None = None,
        approval_poll_interval: float | None = None,
    ):
        self.collector_url = (
            collector_url
            or os.getenv(
                "AGENTGUARD_COLLECTOR_URL",
                "http://localhost:8080",
            )
        ).rstrip("/")

        self.api_key = api_key or os.getenv("AGENTGUARD_API_KEY")
        self.agent_id = agent_id or os.getenv(
            "AGENTGUARD_AGENT_ID",
            "default",
        )

        self.max_budget = max(0.0, float(max_budget))
        self.block_on_high = block_on_high

        # Le mode est contrôlé par le SaaS, agent par agent.
        # Par défaut, on reste en mode enforce.
        self.shadow_mode = False
        self._runtime_mode_checked_at = 0.0
        self._runtime_mode_ttl = max(
            1.0,
            float(os.getenv("AGENTGUARD_MODE_TTL", "10")),
        )

        self.debug = debug
        self.total_spent = 0.0
        self.trace_id = uuid7()
        self.spans: list[GuardSpan] = []

        self.collector_timeout = max(
            0.5,
            float(os.getenv("AGENTGUARD_COLLECTOR_TIMEOUT", "5.0")),
        )

        self.policy_engine = PolicyEngine(policies or [], redis_url)
        self._verifier = None

        # Gestion de l'approbation.
        env_wait = os.getenv("AGENTGUARD_WAIT_FOR_APPROVAL")

        if env_wait is not None:
            self.wait_for_approval = env_wait.lower() == "true"
        else:
            self.wait_for_approval = wait_for_approval

        self.approval_timeout = float(
            approval_timeout
            if approval_timeout is not None
            else os.getenv("AGENTGUARD_APPROVAL_TIMEOUT", "300")
        )

        self.approval_poll_interval = float(
            approval_poll_interval
            if approval_poll_interval is not None
            else os.getenv(
                "AGENTGUARD_APPROVAL_POLL_INTERVAL",
                "2.0",
            )
        )

        self._approved_cache: dict[str, float] = {}
        self.notification_webhook = notification_webhook

        # Kill switch contrôlé depuis le dashboard.
        self._conn_state = "connected"
        self._conn_checked_at = 0.0
        self._status_ttl = max(
            1.0,
            float(os.getenv("AGENTGUARD_STATUS_TTL", "5")),
        )

        self._status_check = (
            bool(self.api_key)
            and os.getenv(
                "AGENTGUARD_STATUS_CHECK",
                "true",
            ).lower()
            == "true"
        )

        self._runtime_enabled = (
            os.getenv(
                "AGENTGUARD_RUNTIME_RISK_ENABLED",
                "true",
            ).lower()
            == "true"
        )

        self._runtime_fail_closed = (
            os.getenv(
                "AGENTGUARD_RUNTIME_FAIL_CLOSED",
                "true",
            ).lower()
            == "true"
        )

        self._trajectory = (
            TrajectoryAnalyzer(max_events=100)
            if self._runtime_enabled
            else None
        )

        self._runtime_risk = (
            RuntimeRiskEngine(
                fail_closed=self._runtime_fail_closed
            )
            if self._runtime_enabled
            else None
        )

        # Taint tracking.
        self._taint_enabled = (
            os.getenv(
                "AGENTGUARD_TAINT_ENABLED",
                "true",
            ).lower()
            == "true"
        )

        self._flow = FlowTracker(
            session_mode=(
                os.getenv(
                    "AGENTGUARD_TAINT_SESSION_MODE",
                    "false",
                ).lower()
                == "true"
            )
        )

        # Masquage des spans avant envoi au collecteur.
        self._vault: IncidentVault | None = None

        self._masker = SpanMasker(
            mode=os.getenv("AGENTGUARD_MASKING", "redact"),
            vault=None,
        )

        logger.info(
            "agentguard_initialized",
            agent_id=self.agent_id,
            runtime_risk=self._runtime_enabled,
            masking=self._masker.mode,
            shadow_mode=self.shadow_mode,
        )

    @staticmethod
    def _stable_approval_id(
        agent_id: str,
        tool_name: str,
        params: dict[str, Any],
    ) -> str:
        """Crée un identifiant déterministe pour une demande d'approbation."""
        payload = json.dumps(
            {
                "agent": agent_id,
                "tool": tool_name,
                "params": params or {},
            },
            sort_keys=True,
            default=str,
        )

        digest = hashlib.sha256(payload.encode()).hexdigest()[:16]
        return f"req_{digest}"

    @staticmethod
    def _parse_timestamp(value: Any) -> float | None:
        """Convertit un horodatage numérique ou ISO 8601 en epoch."""
        if isinstance(value, bool):
            return None

        if isinstance(value, (int, float)):
            return float(value)

        if isinstance(value, str) and value.strip():
            raw = value.strip()

            try:
                return float(raw)
            except ValueError:
                pass

            try:
                dt = datetime.fromisoformat(
                    raw.replace("Z", "+00:00")
                )

                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)

                return dt.timestamp()

            except ValueError:
                return None

        return None

    @classmethod
    def _approval_timestamp(
        cls,
        data: dict[str, Any],
    ) -> float | None:
        """Privilégie la date de décision à celle de création."""
        for key in (
            "resolved_at",
            "approved_at",
            "decided_at",
            "created_at",
        ):
            ts = cls._parse_timestamp(data.get(key))

            if ts is not None:
                return ts

        return None

    def _headers(self):
        headers = {
            "Content-Type": "application/json",
            "X-Agent-Id": str(self.agent_id),
            "X-Agent-Sdk": SDK_VERSION,
        }

        if self.api_key:
            headers["X-API-Key"] = self.api_key

        return headers

    def _refresh_runtime_mode(self) -> None:
        """Charge le mode d'exécution configuré dans le SaaS."""
        # Override local : AGENTGUARD_SHADOW_MODE force le mode sans
        # interroger le SaaS (tests, dev hors-ligne). Le fail-safe vers
        # enforce ne s'applique qu'en mode contrôlé par le SaaS.
        env_shadow = os.getenv("AGENTGUARD_SHADOW_MODE")

        if env_shadow is not None:
            self.shadow_mode = env_shadow.strip().lower() == "true"
            return

        now = time.time()

        if now - self._runtime_mode_checked_at < self._runtime_mode_ttl:
            return

        self._runtime_mode_checked_at = now

        # En cas d'échec, ne jamais conserver un Shadow Mode potentiellement
        # obsolète : revenir au mode enforce.
        self.shadow_mode = False

        if not self.api_key:
            return

        try:
            response = requests.get(
                f"{self.collector_url}/api/agent/mode",
                headers=self._headers(),
                timeout=min(2.0, self.collector_timeout),
            )

            response.raise_for_status()

            data = response.json()
            mode = data.get("mode")

            if mode not in {"enforce", "shadow"}:
                logger.warning(
                    "invalid_agent_runtime_mode",
                    agent_id=self.agent_id,
                    mode=mode,
                )
                return

            self.shadow_mode = mode == "shadow"

            logger.info(
                "agent_runtime_mode",
                agent_id=self.agent_id,
                mode=mode,
            )

        except Exception as exc:
            # Fail-safe : en cas d'erreur réseau, on reste en enforce.
            logger.debug(
                "agent_runtime_mode_check_failed",
                agent_id=self.agent_id,
                error=str(exc),
            )

    def _ensure_connected(self):
        """Bloque l'agent s'il a été déconnecté depuis le dashboard."""
        if not self._status_check:
            return

        now = time.time()

        if now - self._conn_checked_at >= self._status_ttl:
            self._conn_checked_at = now

            try:
                response = requests.get(
                    f"{self.collector_url}/api/agent/status",
                    headers=self._headers(),
                    timeout=min(2.0, self.collector_timeout),
                )

                if response.status_code == 200:
                    body = response.json()
                    self._conn_state = body.get(
                        "status",
                        "connected",
                    )
                    self._sync_incident_capture(bool(body.get("incident_open")))

                elif (
                    response.status_code == 403
                    and "agent_disconnected" in response.text
                ):
                    self._conn_state = "disconnected"

            except Exception as exc:
                self._conn_checked_at = now + 25
                logger.debug(
                    "agent_status_check_failed",
                    error=str(exc),
                )

        if self._conn_state == "disconnected":
            raise AgentDisconnectedException(
                f"Agent '{self.agent_id}' was disconnected "
                "from the Cerbere dashboard. Reconnect it there to resume."
            )

    def _send_to_collector(self, span: GuardSpan):
        try:
            payload = SpanPayload(
                trace_id=span.trace_id,
                span_id=span.span_id,
                span_type=span.span_type,
                timestamp=span.timestamp,
                latency_ms=span.latency_ms,
                input_data=span.input_data,
                output_data=span.output_data,
                security_checks=[
                    check.to_model()
                    for check in span.security_checks
                ],
                blocked=span.blocked,
                block_reason=span.block_reason,
                cost_usd=span.cost_usd,
                input_tokens=span.input_tokens,
                output_tokens=span.output_tokens,
                taint_level=span.taint_level,
                risk_score=span.risk_score,
            ).model_dump()

            # Le masquage est appliqué avant tout envoi au collecteur.
            payload = self._masker.mask_span(payload)

            response = requests.post(
                f"{self.collector_url}/span",
                json=payload,
                headers=self._headers(),
                timeout=self.collector_timeout,
            )

            if response.status_code in (401, 403):
                warnings.warn(
                    "Cerbere rejected your API key or agent is disconnected",
                    RuntimeWarning,
                )
                self._conn_state = "disconnected"

            if response.status_code >= 400:
                logger.warning(
                    "collector_rejected_span",
                    status_code=response.status_code,
                    body=response.text[:300],
                    collector_url=self.collector_url,
                )

        except Exception as exc:
            logger.warning(
                "collector_send_failed",
                error=str(exc),
            )

        if self._vault is not None and self._vault.pending() > 0:
            self._vault.flush()

    def _sync_incident_capture(self, incident_open: bool) -> None:
        """Aligne le SDK sur le serveur : un admin ouvre ou ferme l'incident
        depuis le dashboard, l'agent n'a rien à faire. Désactivable côté agent
        avec AGENTGUARD_INCIDENT_AUTO=false. N'interrompt jamais l'agent."""
        if os.getenv("AGENTGUARD_INCIDENT_AUTO", "true").lower() != "true":
            return
        try:
            if incident_open and (self._vault is None or self._vault.expired):
                self.start_incident_capture()
            elif not incident_open and self._vault is not None:
                self.stop_incident_capture()
        except Exception as exc:
            logger.warning(
                "incident_capture_sync_failed", error_type=type(exc).__name__
            )

    def start_incident_capture(self) -> str:
        """Active la capture scellée d'un incident ouvert par un administrateur."""
        response = requests.get(
            f"{self.collector_url}/v1/incident/active",
            headers=self._headers(),
            timeout=self.collector_timeout,
        )

        if response.status_code == 404:
            raise RuntimeError(
                "Aucun incident ouvert pour cet agent : un admin doit "
                "l'ouvrir depuis le dashboard."
            )

        response.raise_for_status()
        data = response.json()

        self._vault = IncidentVault(
            collector_url=self.collector_url,
            incident_id=data["incident_id"],
            public_key=bytes.fromhex(data["public_key"]),
            expires_at=float(data["expires_at"]),
            headers=self._headers(),
        )

        self._masker.mode = "incident"
        self._masker.vault = self._vault

        logger.info(
            "incident_capture_started",
            incident_id=data["incident_id"],
            expires_at=data["expires_at"],
        )

        return data["incident_id"]

    def stop_incident_capture(self) -> None:
        """Ferme la capture et revient au masquage redact."""
        if self._vault is not None:
            self._vault.close()

        self._vault = None
        self._masker.mode = "redact"
        self._masker.vault = None

        logger.info("incident_capture_stopped")

    def _request_signed_decision(
        self,
        tool_name: str,
        params: dict[str, Any],
    ) -> dict | None:
        if not self._verifier:
            return None

        try:
            response = requests.post(
                f"{self.collector_url}/api/decide",
                json={
                    "tool_name": tool_name,
                    "params": params or {},
                    "agent_id": self.agent_id,
                },
                headers=self._headers(),
                timeout=self.collector_timeout,
            )

            if response.status_code == 200:
                return response.json()

        except Exception as exc:
            logger.warning(
                "signed_decision_request_failed",
                error=str(exc),
            )

        return None

    def _record_trajectory_tool(
        self,
        tool_name: str,
        decision: RuntimeRiskDecision,
    ):
        if self._trajectory:
            self._trajectory.record(
                self.agent_id,
                TrajectoryEvent(
                    timestamp=time.time(),
                    event_type="tool_call",
                    tool_name=tool_name,
                    risk_score=decision.risk_score,
                    metadata=decision.metadata,
                ),
            )

    def track_input(
        self,
        value: Any,
        source: str = "user",
        level: str | None = None,
    ) -> Any:
        """Enregistre le taint d'une donnée sans modifier sa valeur."""
        if not self._taint_enabled:
            return value

        try:
            forced = TaintLevel[str(level).upper()] if level else None
        except KeyError:
            raise ValueError(f"Unknown taint level: {level!r}")

        self._flow.track(
            value,
            source=source,
            level=forced,
        )

        return value

    @staticmethod
    def _extract_input(args, kwargs):
        messages = kwargs.get("messages")

        if isinstance(messages, list):
            return "\n".join(
                message.get("content", "")
                for message in messages
                if isinstance(message, dict)
                and isinstance(message.get("content"), str)
            )

        if args and isinstance(args[0], str):
            return args[0]

        return ""

    @staticmethod
    def _extract_output(result):
        if isinstance(result, str):
            return result

        choices = getattr(result, "choices", None)

        if choices:
            parts = []

            for choice in choices:
                message = getattr(choice, "message", None)
                content = (
                    getattr(message, "content", None)
                    if message
                    else None
                )

                if isinstance(content, str):
                    parts.append(content)

            return "\n".join(parts)

        return ""

    def _count_tokens(
        self,
        kwargs,
        result,
    ) -> tuple[int, int]:
        model = str(kwargs.get("model", "gpt-4o"))
        input_text = self._extract_input([], kwargs) or ""
        output_text = self._extract_output(result) or ""

        return (
            _count_text_tokens(model, input_text),
            _count_text_tokens(model, output_text),
        )

    def _estimate_cost(
        self,
        kwargs,
        result,
    ) -> tuple[float, int, int]:
        model = str(kwargs.get("model", "gpt-4o"))
        input_tokens, output_tokens = self._count_tokens(
            kwargs,
            result,
        )

        pricing = {
            "gpt-4o": (2.5e-6, 1.0e-5),
            "gpt-4o-mini": (1.5e-7, 6.0e-7),
            "gpt-3.5-turbo": (5.0e-7, 1.5e-6),
            "deepseek-chat": (1.4e-7, 2.8e-7),
        }

        input_price, output_price = pricing.get(
            model,
            (2.5e-6, 1.0e-5),
        )

        cost = max(
            0.0,
            input_tokens * input_price
            + output_tokens * output_price,
        )

        return cost, input_tokens, output_tokens

    def guard_llm_call(self, func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            self._ensure_connected()

            span_id = uuid7()
            start = time.time()
            input_text = self._extract_input(args, kwargs)

            checks = [
                self.policy_engine.check_injection(input_text),
                self.policy_engine.check_pii(input_text),
            ]

            high_risk = [
                check
                for check in checks
                if not check.passed
                and check.risk_level
                in (RiskLevel.HIGH, RiskLevel.CRITICAL)
            ]

            if high_risk and self.block_on_high:
                span = GuardSpan(
                    span_id,
                    self.trace_id,
                    "llm_call",
                    start,
                    (time.time() - start) * 1000,
                    {
                        "prompt": input_text[:500],
                        "model": kwargs.get("model", "unknown"),
                    },
                    {"blocked": True},
                    checks,
                    True,
                    f"HIGH RISK: {[check.check_name for check in high_risk]}",
                )

                self.spans.append(span)
                self._send_to_collector(span)

                raise SecurityException(
                    f"AgentGuard BLOCKED: {span.block_reason}"
                )

            try:
                result = func(*args, **kwargs)

            except Exception as exc:
                span = GuardSpan(
                    span_id,
                    self.trace_id,
                    "llm_call",
                    start,
                    (time.time() - start) * 1000,
                    {"prompt": input_text[:500]},
                    {"error": str(exc)[:1000]},
                    checks,
                )

                self.spans.append(span)
                self._send_to_collector(span)
                raise

            latency = (time.time() - start) * 1000
            cost, input_tokens, output_tokens = self._estimate_cost(
                kwargs,
                result,
            )

            budget_check = self.policy_engine.check_budget(
                cost,
                self.max_budget,
                self.total_spent,
            )

            output_pii = self.policy_engine.check_pii(
                self._extract_output(result)
            )

            checks.extend([output_pii, budget_check])

            blocking_output = [
                check
                for check in checks
                if not check.passed
                and check.risk_level
                in (RiskLevel.HIGH, RiskLevel.CRITICAL)
            ]

            blocked = bool(blocking_output) and self.block_on_high

            span = GuardSpan(
                span_id,
                self.trace_id,
                "llm_call",
                start,
                latency,
                {
                    "prompt": input_text[:500],
                    "model": kwargs.get("model", "unknown"),
                },
                {
                    "response": self._extract_output(result)[:500]
                },
                checks,
                blocked,
                (
                    f"Output risk: "
                    f"{[check.check_name for check in blocking_output]}"
                    if blocked
                    else None
                ),
                cost_usd=cost,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
            )

            self.spans.append(span)
            self._send_to_collector(span)

            if blocked:
                raise SecurityException(
                    f"Output blocked: {span.block_reason}"
                )

            self.total_spent += cost
            return result

        return wrapper

    @staticmethod
    def _bind_tool_params(
        func: Callable,
        args: tuple,
        kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        """Associe les arguments positionnels aux noms de paramètres."""
        if not args:
            return dict(kwargs)

        signature = inspect.signature(func)
        bound = signature.bind(*args, **kwargs)
        params: dict[str, Any] = {}

        for name, value in bound.arguments.items():
            kind = signature.parameters[name].kind

            if kind is inspect.Parameter.VAR_KEYWORD:
                params.update(value)

            elif kind in (
                inspect.Parameter.VAR_POSITIONAL,
                inspect.Parameter.POSITIONAL_ONLY,
            ):
                raise TypeError(
                    f"{getattr(func, '__name__', 'tool')}(): "
                    f"the parameter '{name}' cannot be passed by name; "
                    "guarded tools need regular named parameters"
                )

            else:
                params[name] = value

        return params

    def guard_tool_call(
        self,
        tool_name: str | None = None,
        params: dict[str, Any] | None = None,
        func: Callable | None = None,
    ):
        if callable(tool_name):
            actual_func = tool_name
            actual_tool_name = actual_func.__name__

            @wraps(actual_func)
            def wrapper(*args, **kwargs):
                bound_params = self._bind_tool_params(
                    actual_func,
                    args,
                    kwargs,
                )

                return self._execute_guarded_tool(
                    actual_tool_name,
                    bound_params,
                    actual_func,
                )

            return wrapper

        if (
            params is None
            and func is None
            and isinstance(tool_name, str)
        ):
            def decorator(wrapped: Callable):
                @wraps(wrapped)
                def wrapper(*args, **kwargs):
                    bound_params = self._bind_tool_params(
                        wrapped,
                        args,
                        kwargs,
                    )

                    return self._execute_guarded_tool(
                        tool_name,
                        bound_params,
                        wrapped,
                    )

                return wrapper

            return decorator

        if func is not None and isinstance(tool_name, str):
            return self._execute_guarded_tool(
                tool_name,
                params or {},
                func,
            )

        raise TypeError("Usage invalide de guard_tool_call.")

    @staticmethod
    def _tag_span(
        span: GuardSpan,
        taint_level: str | None,
        decision: RuntimeRiskDecision,
    ) -> None:
        span.taint_level = taint_level
        span.risk_score = decision.risk_score

    def _execute_guarded_tool(
        self,
        tool_name: str,
        params: dict[str, Any],
        func: Callable,
    ):
        self._ensure_connected()
        self._refresh_runtime_mode()

        span_id = uuid7()
        start = time.time()
        budget_remaining = max(
            0.0,
            self.max_budget - self.total_spent,
        )

        check = self.policy_engine.check_tool_policy(
            tool_name,
            params,
            budget_remaining,
            agent_id=self.agent_id,
        )

        # 1. Évaluation du taint.
        taint_level = None

        if self._taint_enabled:
            taint_label = self._flow.level_in(params)

            if taint_label is not None:
                taint_level = taint_label.level.name

        # 2. Évaluation du risque runtime.
        if self._runtime_enabled:
            traj_score, traj_reasons, traj_meta = (
                self._trajectory.analyze(
                    self.agent_id,
                    tool_name,
                    params,
                    taint_level=taint_level,
                )
            )

            runtime_decision = self._runtime_risk.evaluate(
                tool_name,
                params,
                traj_score,
                traj_reasons,
                traj_meta,
                taint_level=taint_level,
            )

        else:
            runtime_decision = RuntimeRiskDecision(
                "ALLOW",
                0.0,
                RiskLevel.LOW,
            )

        runtime_check = SecurityCheck(
            "runtime_risk",
            runtime_decision.allowed,
            runtime_decision.risk_level,
            "; ".join(runtime_decision.reasons[:5]),
        )

        def record_block(reason: str, message: str) -> None:
            span = GuardSpan(
                span_id,
                self.trace_id,
                "tool_call",
                start,
                (time.time() - start) * 1000,
                {
                    "tool": tool_name,
                    "params": params,
                },
                {
                    "blocked": True,
                    "reason": reason,
                },
                [check, runtime_check],
                True,
                message,
            )

            self._tag_span(span, taint_level, runtime_decision)
            self.spans.append(span)
            self._send_to_collector(span)
            self._record_trajectory_tool(
                tool_name,
                runtime_decision,
            )

        # 3. Décision serveur : elle n'est jamais contournée
        # par le Shadow Mode.
        signed_decision = None
        signed_action = None

        if self._verifier:
            signed_decision = self._request_signed_decision(
                tool_name,
                params,
            )

            if signed_decision is None:
                record_block(
                    "signed_decision_unavailable",
                    "[SECURITY] Signed server decision unavailable",
                )

                raise SecurityException(
                    "AgentGuard DENY: server security decision unavailable"
                )

            signed_action = str(
                signed_decision.get("action", "DENY")
            ).upper()

            if signed_action == "DENY":
                reason = signed_decision.get(
                    "reason",
                    "policy violation",
                )

                record_block(
                    "signed_deny",
                    f"[SECURITY] Signed DENY: {reason}",
                )

                raise SecurityException(
                    f"AgentGuard DENY: {reason}"
                )

            if signed_action not in (
                "ALLOW",
                "REQUIRE_APPROVAL",
            ):
                record_block(
                    "invalid_signed_decision",
                    "[SECURITY] Invalid signed server decision",
                )

                raise SecurityException(
                    "AgentGuard DENY: invalid server decision"
                )

        # 4. Déterminer les décisions locales avant leur application.
        runtime_action = str(
            getattr(runtime_decision, "action", "ALLOW")
        ).upper()

        requires_approval = (
            (
                not check.passed
                and bool(check.metadata.get("requires_approval"))
            )
            or runtime_action == "REQUIRE_APPROVAL"
            or signed_action == "REQUIRE_APPROVAL"
        )

        # 5. Shadow Mode : calculer la décision hypothétique.
        # Une exigence d'approbation signée reste appliquée.
        shadow_observation = None

        if (
            self.shadow_mode
            and signed_action != "REQUIRE_APPROVAL"
        ):
            would_action = "ALLOW"
            reasons: list[str] = []

            if (
                not runtime_decision.allowed
                and runtime_action != "REQUIRE_APPROVAL"
            ):
                would_action = "BLOCK"
                reasons.extend(runtime_decision.reasons[:5])

            elif requires_approval:
                would_action = "REQUIRE_APPROVAL"

                if check.details:
                    reasons.append(str(check.details))

                reasons.extend(runtime_decision.reasons[:5])

            elif (
                not check.passed
                and check.risk_level
                in (RiskLevel.HIGH, RiskLevel.CRITICAL)
                and self.block_on_high
            ):
                would_action = "BLOCK"

                if check.details:
                    reasons.append(str(check.details))

            shadow_observation = {
                "enabled": True,
                "would_have_action": would_action,
                "would_have_blocked": would_action == "BLOCK",
                "would_have_required_approval": (
                    would_action == "REQUIRE_APPROVAL"
                ),
                "reasons": [
                    reason
                    for reason in reasons
                    if reason
                ][:5],
            }

            if would_action != "ALLOW":
                logger.warning(
                    "agentguard_shadow_decision",
                    agent_id=self.agent_id,
                    tool_name=tool_name,
                    **shadow_observation,
                )

        # 6. Refus runtime : appliquer uniquement hors Shadow Mode.
        if (
            shadow_observation is None
            and not runtime_decision.allowed
            and runtime_action != "REQUIRE_APPROVAL"
        ):
            reason = (
                runtime_decision.reasons[0]
                if runtime_decision.reasons
                else "runtime policy denied the action"
            )

            record_block(
                "runtime_deny",
                f"[RUNTIME DENY] {reason}",
            )

            raise SecurityException(
                f"AgentGuard DENY: {reason}"
            )

        # 7. Refus de politique : appliquer uniquement hors Shadow Mode.
        if (
            shadow_observation is None
            and not check.passed
            and not requires_approval
            and check.risk_level
            in (RiskLevel.HIGH, RiskLevel.CRITICAL)
            and self.block_on_high
        ):
            record_block(
                "policy_block",
                f"[POLICY] {check.details}",
            )

            raise SecurityException(
                f"AgentGuard BLOCK: {check.details}"
            )

        # 8. Approbation humaine.
        # Une exigence d'approbation reste obligatoire,
        # y compris en Shadow Mode.
        if requires_approval:
            approval_id = self._stable_approval_id(
                self.agent_id,
                tool_name,
                params,
            )

            now = time.time()
            cache_ttl = max(
                1.0,
                float(
                    os.getenv(
                        "AGENTGUARD_APPROVAL_CACHE_TTL",
                        "30",
                    )
                ),
            )

            cached_ts = self._approved_cache.get(approval_id)

            if (
                cached_ts is not None
                and (now - cached_ts) > cache_ttl
            ):
                self._approved_cache.pop(approval_id, None)
                cached_ts = None

            approved = cached_ts is not None

            if not approved:
                try:
                    response = requests.get(
                        f"{self.collector_url}/api/approvals/{approval_id}",
                        headers=self._headers(),
                        timeout=min(
                            3.0,
                            self.collector_timeout,
                        ),
                    )

                    if response.status_code == 200:
                        approval_data = response.json()
                        status = approval_data.get("status")

                        if status == "rejected":
                            raise ApprovalRejectedException(
                                "Action rejetée par l'administrateur.",
                                approval_id=approval_id,
                                resolved_by=approval_data.get(
                                    "resolved_by"
                                ),
                            )

                        if status == "approved":
                            ts = self._approval_timestamp(
                                approval_data
                            )

                            if (
                                ts is not None
                                and (now - ts) <= cache_ttl
                            ):
                                approved = True

                except ApprovalRejectedException:
                    raise

                except Exception as exc:
                    logger.warning(
                        "approval_lookup_failed",
                        error=str(exc),
                    )

            if not approved:
                try:
                    response = requests.post(
                        f"{self.collector_url}/api/approvals",
                        json={
                            "approval_id": approval_id,
                            "agent_id": self.agent_id,
                            "tool_name": tool_name,
                            "params": params,
                            "reason": (
                                getattr(check, "details", "")
                                or "; ".join(
                                    getattr(
                                        runtime_decision,
                                        "reasons",
                                        [],
                                    )[:5]
                                )
                            ),
                        },
                        headers=self._headers(),
                        timeout=self.collector_timeout,
                    )

                    response.raise_for_status()

                except Exception as exc:
                    record_block(
                        "approval_request_failed",
                        "[SECURITY] Could not create approval request",
                    )

                    raise SecurityException(
                        "AgentGuard DENY: approval service unavailable"
                    ) from exc

                if self.notification_webhook:
                    try:
                        requests.post(
                            self.notification_webhook,
                            json={
                                "event": "approval_required",
                                "approval_id": approval_id,
                                "tool": tool_name,
                                "agent": self.agent_id,
                            },
                            timeout=2,
                        )

                    except Exception as exc:
                        logger.debug(
                            "approval_webhook_failed",
                            error=str(exc),
                        )

                if not self.wait_for_approval:
                    raise ApprovalRequiredException(
                        f"Approbation requise pour '{tool_name}'. "
                        f"(ID: {approval_id})",
                        approval_id=approval_id,
                        details=check.metadata,
                        timed_out=False,
                    )

                wait_started = time.time()
                elapsed = 0.0
                poll_interval = max(
                    0.25,
                    self.approval_poll_interval,
                )

                while elapsed < self.approval_timeout:
                    sleep_for = min(
                        poll_interval,
                        self.approval_timeout - elapsed,
                    )

                    time.sleep(sleep_for)
                    elapsed += sleep_for

                    try:
                        response = requests.get(
                            f"{self.collector_url}/api/approvals/{approval_id}",
                            headers=self._headers(),
                            timeout=min(
                                3.0,
                                self.collector_timeout,
                            ),
                        )

                        if response.status_code != 200:
                            continue

                        approval_data = response.json()
                        status = approval_data.get("status")

                        if status == "approved":
                            ts = self._approval_timestamp(
                                approval_data
                            )

                            if (
                                ts is not None
                                and ts < wait_started - cache_ttl
                            ):
                                continue

                            approved = True
                            self._approved_cache[
                                approval_id
                            ] = time.time()
                            break

                        if status == "rejected":
                            raise ApprovalRejectedException(
                                "Action rejetée par l'administrateur.",
                                approval_id=approval_id,
                                resolved_by=approval_data.get(
                                    "resolved_by"
                                ),
                            )

                    except ApprovalRejectedException:
                        raise

                    except Exception as exc:
                        logger.debug(
                            "approval_poll_failed",
                            error=str(exc),
                        )

                if not approved:
                    raise ApprovalRequiredException(
                        f"Approbation absente ou expirée après "
                        f"{self.approval_timeout}s. "
                        f"(ID: {approval_id})",
                        approval_id=approval_id,
                        details=check.metadata,
                        timed_out=True,
                    )

        # 9. Exécuter l'outil après les contrôles applicables.
        try:
            result = func(**params)

        except Exception as exc:
            output_data = {
                "error": str(exc)[:1000],
            }

            if shadow_observation is not None:
                output_data["cerbere_shadow"] = shadow_observation

            span = GuardSpan(
                span_id,
                self.trace_id,
                "tool_call",
                start,
                (time.time() - start) * 1000,
                {
                    "tool": tool_name,
                    "params": params,
                },
                output_data,
                [check, runtime_check],
            )

            self._tag_span(
                span,
                taint_level,
                runtime_decision,
            )

            self.spans.append(span)
            self._send_to_collector(span)
            self._record_trajectory_tool(
                tool_name,
                runtime_decision,
            )

            raise

        # 10. Suivre le résultat pour les appels suivants.
        if self._taint_enabled:
            source_level = (
                TaintLevel.UNTRUSTED
                if _is_untrusted_source(tool_name)
                else None
            )

            self._flow.track(
                result,
                source=f"tool:{tool_name}",
                level=source_level,
            )

        output_data = {
            "result": str(result)[:500],
        }

        if shadow_observation is not None:
            output_data["cerbere_shadow"] = shadow_observation

        span = GuardSpan(
            span_id,
            self.trace_id,
            "tool_call",
            start,
            (time.time() - start) * 1000,
            {
                "tool": tool_name,
                "params": params,
            },
            output_data,
            [check, runtime_check],
        )

        self._tag_span(
            span,
            taint_level,
            runtime_decision,
        )

        self.spans.append(span)
        self._send_to_collector(span)
        self._record_trajectory_tool(
            tool_name,
            runtime_decision,
        )

        return result

    def get_report(self) -> dict[str, Any]:
        shadow_observations = sum(
            1
            for span in self.spans
            if isinstance(span.output_data, dict)
            and "cerbere_shadow" in span.output_data
        )

        return {
            "trace_id": self.trace_id,
            "total_spans": len(self.spans),
            "blocked_operations": sum(
                1
                for span in self.spans
                if span.blocked
            ),
            "total_cost_usd": round(
                self.total_spent,
                6,
            ),
            "runtime_risk_enabled": self._runtime_enabled,
            "shadow_mode": self.shadow_mode,
            "shadow_observations": shadow_observations,
            "masking": self._masker.mode,
            "incident_capture_active": (
                self._vault is not None
                and not self._vault.expired
            ),
        }


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    logger.info(
        "Starting CerbereAG MCP Server (v1.x) on stdio..."
    )
