"""
AgentGuard Immutable Audit Log
Log append-only cryptographiquement chaîné pour SOC 2 Type II compliance.

Architecture :
  - Chaque entrée contient le hash SHA256 de l'entrée précédente
  - Checkpoints signés Ed25519 : la signature couvre le VRAI état de la
    chaîne (head_hash + compte d'entrées), pas un message cosmétique.
  - Le déclenchement des checkpoints repose sur le compte PERSISTÉ
    (DB/fichier), pas sur un compteur RAM perdu au redémarrage.
  - Ancre externe anti-truncation : publish_anchor() journalise le
    head_hash dans un système append-only indépendant.
  - Détection instantanée de toute modification
  - Stockage Postgres (primary) + JSON Lines (backup)

Garanties :
  - Append-only (pas de UPDATE/DELETE)
  - Integrity : toute modification casse la chaîne
  - Non-repudiation : signatures cryptographiques vérifiées
  - Verifiable : rejouer la chaîne = preuve d'intégrité
"""

import hashlib
import json
import logging
import os
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from typing import Any

from agentguard.ids import uuid7

try:
    import psycopg
    import psycopg.rows

    PSYCOPG_AVAILABLE = True
except ImportError:
    PSYCOPG_AVAILABLE = False

logger = logging.getLogger("agentguard.audit")


class AuditEventType(str, Enum):
    """Types d'événements auditables."""

    # Sécurité
    PROMPT_BLOCKED = "prompt_blocked"
    TOOL_BLOCKED = "tool_blocked"
    TAINT_VIOLATION = "taint_violation"
    BUDGET_EXCEEDED = "budget_exceeded"
    SIGNED_DENY = "signed_deny"
    PII_DETECTED = "pii_detected"
    INJECTION_DETECTED = "injection_detected"

    # Accès
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    API_KEY_CREATED = "api_key_created"
    API_KEY_REVOKED = "api_key_revoked"

    # Décisions humaines (HITL) et contrôle des agents
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_REJECTED = "approval_rejected"
    AGENT_DISCONNECTED = "agent_disconnected"
    AGENT_RECONNECTED = "agent_reconnected"

    # Capture d'incident (preuves scellées)
    INCIDENT_OPENED = "incident_opened"
    INCIDENT_CLOSED = "incident_closed"
    INCIDENT_REVEALED = "incident_revealed"
    INCIDENT_REVEAL_DENIED = "incident_reveal_denied"

    # Système
    POLICY_LOADED = "policy_loaded"
    POLICY_CHANGED = "policy_changed"
    CONFIG_CHANGED = "config_changed"

    # Ancrage de la hash-chain
    AUDIT_CHECKPOINT = "audit_checkpoint"

    # Opérations
    LLM_CALL = "llm_call"
    TOOL_CALL = "tool_call"
    SPAN_INGESTED = "span_ingested"


@dataclass
class AuditEntry:
    """Une entrée dans l'audit log."""

    event_id: str
    timestamp: float
    event_type: str
    org_id: str
    actor: str  # user_id, agent_id, ou "system"
    resource: str  # ex: "span:abc123", "policy:finance"
    action: str  # ex: "blocked", "allowed", "created"
    details: dict[str, Any]
    risk_level: str = "info"  # info, warning, critical
    prev_hash: str = ""
    entry_hash: str = ""
    signature: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def canonical_json(self, include_hash: bool = False) -> str:
        """JSON canonique pour calcul de hash (stable, trié)."""
        data = {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "org_id": self.org_id,
            "actor": self.actor,
            "resource": self.resource,
            "action": self.action,
            "details": self.details,
            "risk_level": self.risk_level,
            "prev_hash": self.prev_hash,
        }
        if include_hash and self.entry_hash:
            data["entry_hash"] = self.entry_hash
        return json.dumps(data, sort_keys=True, separators=(",", ":"))

    def compute_hash(self) -> str:
        """Calcule le hash SHA256 de l'entrée."""
        return hashlib.sha256(self.canonical_json().encode()).hexdigest()


class ImmutableAuditLog:
    """
    Audit log append-only avec chaînage cryptographique.

    Usage :
        log = ImmutableAuditLog(database_url="postgresql://...", signing_key=...)
        log.log_event(
            event_type=AuditEventType.PROMPT_BLOCKED,
            org_id="org1",
            actor="agent_xyz",
            resource="span:abc123",
            action="blocked",
            details={"reason": "injection detected", "score": 0.95},
            risk_level="critical",
        )

        # Vérification d'intégrité (chaîne + signatures)
        is_valid, report = log.verify_chain()
    """

    # Signe toutes les N entrées persistées (0 = jamais)
    DEFAULT_SIGN_EVERY = 100
    # Limite de taille par entrée (protection anti-DoS)
    MAX_DETAILS_SIZE = 10_000  # caractères
    # Nom de table unifié (l'ancien code mélangeait audit_log
    # et agentguard.audit_log — la table est créée sans schéma)
    _TABLE = "audit_log"

    def __init__(
        self,
        database_url: str | None = None,
        backup_file: str | None = None,
        signing_key_pem: str | None = None,
        sign_every: int = DEFAULT_SIGN_EVERY,
        verifying_key_pem: str | None = None,
    ):
        self.database_url = database_url
        self.backup_file = backup_file or os.getenv(
            "AGENTGUARD_AUDIT_BACKUP", "/tmp/agentguard_audit.jsonl"
        )
        self.sign_every = sign_every
        self._write_lock = __import__("threading").RLock()

        # Signer (côté collector : clé privée)
        self._signer = None
        if signing_key_pem:
            try:
                from agentguard.signing import DecisionSigner

                self._signer = DecisionSigner(signing_key_pem)
            except Exception as e:
                logger.warning("AuditLog signing unavailable: %s", e)

        # Vérificateur (clé publique) : permet à verify_chain()
        # de VÉRIFIER réellement les checkpoints signés.
        self._verifier = None
        verify_pem = verifying_key_pem or os.getenv("AGENTGUARD_SIGNING_PUBLIC_KEY")
        if verify_pem:
            try:
                from agentguard.signing import DecisionVerifier

                self._verifier = DecisionVerifier(verify_pem)
            except Exception as e:
                logger.warning("AuditLog verification unavailable: %s", e)
        elif self._signer is not None:
            try:
                from agentguard.signing import DecisionVerifier

                self._verifier = DecisionVerifier(self._signer.public_key_pem())
            except Exception as e:
                logger.warning("AuditLog self-verification unavailable: %s", e)

        # Initialise le stockage
        self._init_storage()

    def _init_storage(self):
        """Initialise la table Postgres et/ou le fichier backup."""
        if self.database_url and PSYCOPG_AVAILABLE:
            try:
                conn = psycopg.connect(self.database_url)
                conn.autocommit = True
                with conn.cursor() as cur:
                    cur.execute(f"""
                        CREATE TABLE IF NOT EXISTS {self._TABLE} (
                            event_id TEXT PRIMARY KEY,
                            seq_no BIGSERIAL UNIQUE,
                            timestamp DOUBLE PRECISION NOT NULL,
                            event_type TEXT NOT NULL,
                            org_id TEXT NOT NULL,
                            actor TEXT NOT NULL,
                            resource TEXT NOT NULL,
                            action TEXT NOT NULL,
                            details JSONB,
                            risk_level TEXT DEFAULT 'info',
                            prev_hash TEXT NOT NULL,
                            entry_hash TEXT NOT NULL,
                            signature TEXT,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
                    cur.execute(f"""
                        CREATE INDEX IF NOT EXISTS idx_audit_seq
                        ON {self._TABLE}(seq_no)
                    """)
                    cur.execute(f"""
                        CREATE INDEX IF NOT EXISTS idx_audit_org_time
                        ON {self._TABLE}(org_id, timestamp DESC)
                    """)
                    cur.execute(f"""
                        CREATE INDEX IF NOT EXISTS idx_audit_type
                        ON {self._TABLE}(event_type, timestamp DESC)
                    """)
                conn.close()
                logger.info("AuditLog Postgres storage initialized")
            except Exception as e:
                logger.warning(
                    "AuditLog Postgres init failed, using file backup: %s", e
                )
                self.database_url = None

        # Backup file (toujours actif en parallèle)
        backup_dir = os.path.dirname(self.backup_file)
        if backup_dir and not os.path.exists(backup_dir):
            os.makedirs(backup_dir, exist_ok=True)

    def _get_last_hash(self) -> str:
        """Récupère le hash de la dernière entrée (pour chaînage)."""
        if self.database_url and PSYCOPG_AVAILABLE:
            try:
                conn = psycopg.connect(self.database_url)
                with conn.cursor() as cur:
                    cur.execute(
                        f"SELECT entry_hash FROM {self._TABLE} "
                        "ORDER BY seq_no DESC LIMIT 1"
                    )
                    row = cur.fetchone()
                conn.close()
                return row[0] if row else "GENESIS"

            except Exception:
                pass

        # Fallback fichier
        if os.path.exists(self.backup_file):
            try:
                with open(self.backup_file, "r") as f:
                    lines = f.readlines()
                    if lines:
                        last = json.loads(lines[-1])
                        return last.get("entry_hash", "GENESIS")
            except Exception:
                pass

        return "GENESIS"

    def _get_entry_count(self) -> int:
        """
        Compte d'entrées PERSISTÉ (DB d'abord, fichier ensuite).
        Jamais un compteur RAM : il serait perdu au redémarrage et
        fausserait la périodicité des checkpoints.
        """
        if self.database_url and PSYCOPG_AVAILABLE:
            try:
                conn = psycopg.connect(self.database_url)
                with conn.cursor() as cur:
                    cur.execute(f"SELECT COUNT(*) FROM {self._TABLE}")
                    n = cur.fetchone()[0]
                conn.close()
                return n
            except Exception:
                pass
        if os.path.exists(self.backup_file):
            try:
                with open(self.backup_file, "r") as f:
                    return sum(1 for line in f if line.strip())
            except Exception:
                pass
        return 0

    def _sign_checkpoint(self, entry: AuditEntry) -> None:
        """
        Signe l'état RÉEL de la chaîne au moment de cette entrée.

        Le payload signé (compatible DecisionSigner.sign_decision) couvre :
          - request_id  : l'event_id du checkpoint
          - action      : "audit_checkpoint"
          - policy_name : le head_hash (racine de la chaîne)
          - policy_version : le nombre d'entrées de la chaîne
          - reason      : human-readable

        Vérifier cette signature = prouver que la chaîne avait
        exactement ce head_hash et ce compte d'entrées à ce moment T.
        Toute suppression d'entrées antérieures (truncation) casse la preuve.
        """
        if not self._signer:
            return
        count = self._get_entry_count()
        signed = self._signer.sign_decision(
            {
                "request_id": entry.event_id,
                "action": "audit_checkpoint",
                "policy_name": f"chain:{entry.entry_hash}",
                "policy_version": count,
                "reason": (
                    f"Audit chain checkpoint at {count} entries, "
                    f"head_hash={entry.entry_hash}"
                ),
            }
        )
        # On stocke le payload signé complet (avec signature + expiration)
        # pour que verify_chain() puisse vérifier la signature.
        entry.signature = json.dumps(signed, sort_keys=True)

    def log_event(
        self,
        event_type: AuditEventType,
        org_id: str,
        actor: str,
        resource: str,
        action: str,
        details: dict[str, Any] | None = None,
        risk_level: str = "info",
    ) -> AuditEntry:
        """
        Log un événement de manière immutable.
        Retourne l'entrée créée.
        """
        # Sanitize details (protection taille)
        details = details or {}
        details_str = json.dumps(details)
        if len(details_str) > self.MAX_DETAILS_SIZE:
            details = {
                "_truncated": True,
                "_original_size": len(details_str),
                "_preview": details_str[:500],
            }

        # Récupère le hash précédent
        with self._write_lock:
            prev_hash = self._get_last_hash()

            entry = AuditEntry(
                event_id=uuid7(),
                timestamp=time.time(),
                event_type=(
                    event_type.value
                    if isinstance(event_type, AuditEventType)
                    else str(event_type)
                ),
                org_id=str(org_id),
                actor=str(actor),
                resource=str(resource),
                action=str(action),
                details=details,
                risk_level=risk_level,
                prev_hash=prev_hash,
            )

            entry.entry_hash = entry.compute_hash()

            # Checkpoint périodique : déclenché sur le compte PERSISTÉ.
            if (
                self._signer
                and self.sign_every > 0
                and self._get_entry_count() % self.sign_every == 0
            ):
                try:
                    self._sign_checkpoint(entry)
                except Exception as exc:
                    # Le checkpoint raté n'est pas fatal, mais visible
                    logger.warning("AuditLog checkpoint signing failed: %s", exc)

            self._persist(entry)

        return entry

    def _persist(self, entry: AuditEntry):
        """Persiste l'entrée dans Postgres ET backup file."""
        # Postgres
        if self.database_url and PSYCOPG_AVAILABLE:
            try:
                conn = psycopg.connect(self.database_url)
                with conn.cursor() as cur:
                    cur.execute(
                        f"""
                        INSERT INTO {self._TABLE}
                        (event_id, timestamp, event_type, org_id, actor, resource,
                         action, details, risk_level, prev_hash, entry_hash, signature)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                        (
                            entry.event_id,
                            entry.timestamp,
                            entry.event_type,
                            entry.org_id,
                            entry.actor,
                            entry.resource,
                            entry.action,
                            json.dumps(entry.details),
                            entry.risk_level,
                            entry.prev_hash,
                            entry.entry_hash,
                            entry.signature,
                        ),
                    )
                conn.commit()
                conn.close()
            except Exception as e:
                logger.warning("AuditLog Postgres persist failed: %s", e)

        # Backup file (append-only, toujours)
        try:
            with open(self.backup_file, "a") as f:
                f.write(json.dumps(entry.to_dict()) + "\n")
        except Exception as e:
            logger.warning("AuditLog file backup failed: %s", e)

    def verify_chain(self, limit: int | None = None) -> tuple:
        """
        Vérifie l'intégrité de toute la chaîne : chaînage, hashs,
        ET signatures de checkpoints (réellement vérifiées).

        Retourne :
            (is_valid: bool, report: dict)
        """
        entries = self._load_entries(limit=limit)

        if not entries:
            return True, {"status": "empty", "entries_checked": 0}

        report = {
            "entries_checked": 0,
            "first_entry": entries[0]["event_id"],
            "last_entry": entries[-1]["event_id"],
            "violations": [],
            "signatures_verified": 0,
            "signatures_failed": 0,
        }

        prev_hash = "GENESIS"

        for i, entry in enumerate(entries):
            report["entries_checked"] += 1

            # Vérifie chaînage
            if entry.get("prev_hash") != prev_hash:
                report["violations"].append(
                    {
                        "type": "chain_break",
                        "event_id": entry["event_id"],
                        "position": i,
                        "expected_prev": prev_hash,
                        "actual_prev": entry.get("prev_hash"),
                    }
                )

            # Vérifie hash
            reconstructed = AuditEntry(
                event_id=entry["event_id"],
                timestamp=entry["timestamp"],
                event_type=entry["event_type"],
                org_id=entry["org_id"],
                actor=entry["actor"],
                resource=entry["resource"],
                action=entry["action"],
                details=entry.get("details", {}),
                risk_level=entry.get("risk_level", "info"),
                prev_hash=entry.get("prev_hash", ""),
            )
            computed = reconstructed.compute_hash()
            if computed != entry.get("entry_hash"):
                report["violations"].append(
                    {
                        "type": "hash_mismatch",
                        "event_id": entry["event_id"],
                        "position": i,
                        "expected": entry.get("entry_hash"),
                        "computed": computed,
                    }
                )

            # Vérifie RÉELLEMENT la signature de checkpoint si présente
            if entry.get("signature") and self._verifier:
                try:
                    signed_payload = json.loads(entry["signature"])
                except Exception as exc:
                    report["signatures_failed"] += 1
                    report["violations"].append(
                        {
                            "type": "checkpoint_malformed",
                            "event_id": entry["event_id"],
                            "error": str(exc),
                        }
                    )
                    prev_hash = entry.get("entry_hash")
                    continue

                try:
                    if self._verifier.verify(signed_payload):
                        # Cohérence : le head_hash signé doit être celui
                        # de l'entrée checkpoint elle-même.
                        signed_head = str(
                            signed_payload.get("policy_name", "")
                        ).removeprefix("chain:")
                        if signed_head and signed_head != entry.get("entry_hash"):
                            report["signatures_failed"] += 1
                            report["violations"].append(
                                {
                                    "type": "checkpoint_head_mismatch",
                                    "event_id": entry["event_id"],
                                    "signed_head": signed_head,
                                    "actual_head": entry.get("entry_hash"),
                                }
                            )
                        else:
                            report["signatures_verified"] += 1
                    else:
                        report["signatures_failed"] += 1
                        report["violations"].append(
                            {
                                "type": "invalid_checkpoint_signature",
                                "event_id": entry["event_id"],
                            }
                        )
                except Exception as exc:
                    report["signatures_failed"] += 1
                    report["violations"].append(
                        {
                            "type": "checkpoint_verify_error",
                            "event_id": entry["event_id"],
                            "error": str(exc),
                        }
                    )

            prev_hash = entry.get("entry_hash")

        is_valid = len(report["violations"]) == 0
        report["status"] = "valid" if is_valid else "tampered"

        return is_valid, report

    def publish_anchor(self) -> dict:
        """
        Ancre externe anti-truncation : journalise le head_hash dans un
        système append-only INDÉPENDANT de la DB.

        Sans ancre externe, un attaquant avec accès à la DB peut
        supprimer les entrées postérieures au dernier checkpoint et
        rejouer une chaîne "valide". La divergence entre l'ancre
        publiée et la DB prouve la truncation.

        Options gratuites pour publier (documente celle que tu choisis) :
          - ce log WARNING ci-dessous, capturé par Loki/CloudWatch
            (les logs cloud sont append-only et rétentions longues)
          - un gist GitHub en écriture via API (l'historique de commits
            est immuable et publiquement horodaté)
          - un objet versionné dans un bucket S3
        """
        head = self._get_last_hash()
        count = self._get_entry_count()
        anchor = {
            "head_hash": head,
            "entry_count": count,
            "ts": time.time(),
        }
        # Log append-only : simple, aucune dépendance.
        logger.warning("AUDIT_ANCHOR %s", json.dumps(anchor, sort_keys=True))
        return anchor

    def _load_entries(self, limit: int | None = None) -> list[dict]:
        """Charge les entrées depuis Postgres ou fichier."""
        entries = []

        if self.database_url and PSYCOPG_AVAILABLE:
            try:
                conn = psycopg.connect(self.database_url)
                with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
                    query = f"SELECT * FROM {self._TABLE} ORDER BY seq_no ASC"
                    if limit:
                        query += f" LIMIT {int(limit)}"
                    cur.execute(query)
                    entries = [dict(row) for row in cur.fetchall()]
                conn.close()
                return entries
            except Exception as e:
                logger.warning("AuditLog Postgres load failed: %s", e)

        # Fallback fichier
        if os.path.exists(self.backup_file):
            try:
                with open(self.backup_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            entries.append(json.loads(line))
                            if limit and len(entries) >= limit:
                                break
            except Exception as e:
                logger.warning("AuditLog file load failed: %s", e)

        return entries

    def get_stats(self) -> dict[str, Any]:
        """Statistiques de l'audit log."""
        stats = {
            "total_entries": 0,
            "by_event_type": {},
            "by_risk_level": {},
            "oldest_entry": None,
            "newest_entry": None,
            "chain_intact": None,
        }

        if self.database_url and PSYCOPG_AVAILABLE:
            try:
                conn = psycopg.connect(self.database_url)
                with conn.cursor() as cur:
                    cur.execute(f"SELECT COUNT(*) FROM {self._TABLE}")
                    stats["total_entries"] = cur.fetchone()[0]

                    cur.execute(f"""
                        SELECT event_type, COUNT(*)
                        FROM {self._TABLE} GROUP BY event_type
                    """)
                    stats["by_event_type"] = dict(cur.fetchall())

                    cur.execute(f"""
                        SELECT risk_level, COUNT(*)
                        FROM {self._TABLE} GROUP BY risk_level
                    """)
                    stats["by_risk_level"] = dict(cur.fetchall())

                    cur.execute(f"""
                        SELECT MIN(timestamp), MAX(timestamp) FROM {self._TABLE}
                    """)
                    row = cur.fetchone()
                    if row and row[0]:
                        stats["oldest_entry"] = datetime.fromtimestamp(
                            row[0]
                        ).isoformat()
                        stats["newest_entry"] = datetime.fromtimestamp(
                            row[1]
                        ).isoformat()
                conn.close()
            except Exception as e:
                logger.warning("AuditLog stats failed: %s", e)
        # Fallback SQLite / fichier (pour tests)
        elif os.path.exists(self.backup_file):
            try:
                entries = []
                with open(self.backup_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                entries.append(json.loads(line))
                            except Exception:
                                continue

                stats["total_entries"] = len(entries)

                # by_event_type
                by_type = {}
                for e in entries:
                    t = e.get("event_type", "unknown")
                    by_type[t] = by_type.get(t, 0) + 1
                stats["by_event_type"] = by_type

                # by_risk_level
                by_risk = {}
                for e in entries:
                    r = e.get("risk_level", "info")
                    by_risk[r] = by_risk.get(r, 0) + 1
                stats["by_risk_level"] = by_risk

                # oldest/newest
                if entries:
                    timestamps = [
                        e.get("timestamp", 0) for e in entries if e.get("timestamp")
                    ]
                    if timestamps:
                        stats["oldest_entry"] = datetime.fromtimestamp(
                            min(timestamps)
                        ).isoformat()
                        stats["newest_entry"] = datetime.fromtimestamp(
                            max(timestamps)
                        ).isoformat()
            except Exception as e:
                logger.warning("AuditLog file stats failed: %s", e)

        # Vérification rapide (uniquement les 1000 dernières entrées)
        try:
            is_valid, _ = self.verify_chain(limit=1000)
            stats["chain_intact"] = is_valid
        except Exception:
            stats["chain_intact"] = None

        return stats

    def query(
        self,
        org_id: str | None = None,
        event_type: str | None = None,
        risk_level: str | None = None,
        since: float | None = None,
        until: float | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """Requête sur l'audit log."""
        if self.database_url and PSYCOPG_AVAILABLE:
            try:
                conn = psycopg.connect(self.database_url)
                with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
                    conditions = []
                    params = []

                    if org_id:
                        conditions.append("org_id = %s")
                        params.append(org_id)
                    if event_type:
                        conditions.append("event_type = %s")
                        params.append(event_type)
                    if risk_level:
                        conditions.append("risk_level = %s")
                        params.append(risk_level)
                    if since:
                        conditions.append("timestamp >= %s")
                        params.append(since)
                    if until:
                        conditions.append("timestamp <= %s")
                        params.append(until)

                    query = f"SELECT * FROM {self._TABLE}"
                    if conditions:
                        query += " WHERE " + " AND ".join(conditions)
                    query += " ORDER BY seq_no DESC LIMIT %s"
                    params.append(limit)

                    cur.execute(query, params)
                    rows = [dict(r) for r in cur.fetchall()]
                conn.close()
                return rows
            except Exception as e:
                logger.warning("AuditLog query failed: %s", e)

        # Fallback fichier
        results = []

        for entry in reversed(self._load_entries()):
            if org_id and entry.get("org_id") != org_id:
                continue
            if event_type and entry.get("event_type") != event_type:
                continue
            if risk_level and entry.get("risk_level") != risk_level:
                continue
            if since and entry.get("timestamp", 0) < since:
                continue
            if until and entry.get("timestamp", float("inf")) > until:
                continue
            results.append(entry)
            if len(results) >= limit:
                break
        return results
