"""Tool contracts and data provenance authorization built on data labels."""
from __future__ import annotations
from dataclasses import dataclass
from enum import IntEnum
from fnmatch import fnmatch
from typing import Iterable

class DataClass(IntEnum):
    PUBLIC = 0
    INTERNAL = 10
    CONFIDENTIAL = 20
    SECRET = 30
    UNTRUSTED = 40
    MALICIOUS = 100

@dataclass(frozen=True)
class DataOrigin:
    data_id: str
    source_agent_id: str
    source_tool: str
    classification: DataClass
    tenant_id: str
    org_id: str
    lineage: tuple[str, ...] = ()

@dataclass(frozen=True)
class ToolContract:
    tool_pattern: str
    accepts: tuple[DataClass, ...] = (DataClass.PUBLIC, DataClass.INTERNAL)
    emits: DataClass = DataClass.INTERNAL
    allowed_destinations: tuple[str, ...] = ()
    requires_provenance: bool = True
    description: str = ""

@dataclass(frozen=True)
class ContractDecision:
    allowed: bool
    reason: str
    requires_approval: bool = False

class ToolContractRegistry:
    """Explicit contract registry; missing contract is deny when strict=True."""
    def __init__(self, *, strict: bool = True):
        self.strict = strict
        self._contracts: list[ToolContract] = []

    def register(self, contract: ToolContract) -> None:
        self._contracts = [c for c in self._contracts if c.tool_pattern != contract.tool_pattern]
        self._contracts.append(contract)

    def resolve(self, tool_name: str) -> ToolContract | None:
        matches = [c for c in self._contracts if fnmatch(tool_name, c.tool_pattern)]
        return max(matches, key=lambda c: len(c.tool_pattern)) if matches else None

    def authorize(self, tool_name: str, origins: Iterable[DataOrigin], *,
                  tenant_id: str, org_id: str, destination: str | None = None) -> ContractDecision:
        contract = self.resolve(tool_name)
        if contract is None:
            return ContractDecision(not self.strict, "No contract registered" if self.strict else "Legacy permissive mode")
        items = list(origins)
        if contract.requires_provenance and not items:
            return ContractDecision(False, "Data provenance is required but missing")
        for origin in items:
            if origin.tenant_id != tenant_id or origin.org_id != org_id:
                return ContractDecision(False, "Cross-tenant or cross-org data flow denied")
            if origin.classification == DataClass.MALICIOUS:
                return ContractDecision(False, "Malicious data cannot enter a tool")
            if origin.classification == DataClass.SECRET:
                return ContractDecision(False, "Secret data cannot be passed to this tool")
            if origin.classification not in contract.accepts:
                if origin.classification == DataClass.CONFIDENTIAL:
                    return ContractDecision(False, "Confidential data requires explicit approval", True)
                return ContractDecision(False, f"{origin.classification.name} data is not accepted")
        if destination and contract.allowed_destinations and not any(fnmatch(destination, p) for p in contract.allowed_destinations):
            return ContractDecision(False, f"Destination '{destination}' is outside the tool contract")
        return ContractDecision(True, "Tool contract satisfied")
