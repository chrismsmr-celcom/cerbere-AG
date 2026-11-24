"""Least-privilege parent/child agent delegation with expiry and revocation."""

from __future__ import annotations

import time
from dataclasses import dataclass
from threading import RLock


@dataclass(frozen=True)
class Delegation:
    delegation_id: str
    tenant_id: str
    parent_agent_id: str
    child_agent_id: str
    scopes: frozenset[str]
    expires_at: float
    created_at: float
    revoked_at: float | None = None


class DelegationRegistry:
    """In-memory reference implementation. Production deployments must persist and share state."""

    def __init__(self):
        self._items: dict[str, Delegation] = {}
        self._lock = RLock()

    def grant(
        self,
        delegation_id: str,
        tenant_id: str,
        parent_agent_id: str,
        child_agent_id: str,
        scopes: set[str],
        ttl_seconds: float,
    ) -> Delegation:
        if (
            not all((delegation_id, tenant_id, parent_agent_id, child_agent_id))
            or parent_agent_id == child_agent_id
        ):
            raise ValueError("A valid, non-self delegation identity is required")
        if not scopes or ttl_seconds <= 0:
            raise ValueError("Delegation requires scopes and a positive TTL")
        now = time.time()
        item = Delegation(
            delegation_id,
            tenant_id,
            parent_agent_id,
            child_agent_id,
            frozenset(scopes),
            now + ttl_seconds,
            now,
        )
        with self._lock:
            if delegation_id in self._items:
                raise ValueError("Delegation ID already exists")
            self._items[delegation_id] = item
        return item

    def revoke(self, delegation_id: str) -> bool:
        with self._lock:
            item = self._items.get(delegation_id)
            if item is None or item.revoked_at is not None:
                return False
            self._items[delegation_id] = Delegation(
                **{**item.__dict__, "revoked_at": time.time()}
            )
            return True

    def authorize(
        self,
        delegation_id: str,
        *,
        tenant_id: str,
        parent_agent_id: str,
        child_agent_id: str,
        scope: str,
        now: float | None = None,
    ) -> bool:
        now = time.time() if now is None else now
        with self._lock:
            item = self._items.get(delegation_id)
            return bool(
                item
                and item.revoked_at is None
                and item.expires_at > now
                and item.tenant_id == tenant_id
                and item.parent_agent_id == parent_agent_id
                and item.child_agent_id == child_agent_id
                and any(
                    scope == s or (s.endswith(".*") and scope.startswith(s[:-1]))
                    for s in item.scopes
                )
            )
