"""Host command and artifact policy primitives; actual isolation requires an OS sandbox backend."""
from __future__ import annotations
import hashlib
import re
import shlex
from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True)
class HostDecision:
    allowed: bool
    reason: str
    subject: str

@dataclass(frozen=True)
class HostSecurityPolicy:
    allowed_executables: tuple[str, ...] = ()
    denied_command_patterns: tuple[str, ...] = (r"\brm\s+-rf\s+/", r"\bcurl\b.*\|\s*(?:sh|bash)", r"\bmkfs\b")
    allowed_artifact_sha256: tuple[str, ...] = ()
    require_artifact_hash: bool = True

    def evaluate_command(self, command: str) -> HostDecision:
        if not command.strip():
            return HostDecision(False, "Empty command denied", command)
        if any(re.search(pattern, command, re.IGNORECASE) for pattern in self.denied_command_patterns):
            return HostDecision(False, "Command matches a denied pattern", command[:160])
        try:
            executable = shlex.split(command, posix=True)[0]
        except (ValueError, IndexError):
            return HostDecision(False, "Command could not be parsed", command[:160])
        if self.allowed_executables and executable not in self.allowed_executables:
            return HostDecision(False, "Executable is not allowlisted", executable)
        return HostDecision(True, "Command passed static host policy", executable)

    def evaluate_artifact(self, path: str) -> HostDecision:
        target = Path(path)
        if not target.is_file():
            return HostDecision(False, "Artifact is not a regular file", path)
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        if self.require_artifact_hash and not self.allowed_artifact_sha256:
            return HostDecision(False, "No artifact hashes configured (fail-closed)", digest)
        if self.allowed_artifact_sha256 and digest not in self.allowed_artifact_sha256:
            return HostDecision(False, "Artifact SHA-256 is not allowlisted", digest)
        return HostDecision(True, "Artifact hash verified", digest)
