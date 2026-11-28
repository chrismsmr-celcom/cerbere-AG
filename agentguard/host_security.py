"""Host command and artifact policy primitives.

This is a static pre-execution policy, not an OS sandbox. It tokenizes a
restricted shell command subset and rejects syntax it cannot safely inspect.
Actual process isolation still requires an OS sandbox backend.
"""

from __future__ import annotations

import hashlib
import posixpath
import re
import shlex
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class HostDecision:
    allowed: bool
    reason: str
    subject: str


# Shell operators that divide commands or connect a pipeline. Redirections
# are handled separately so their targets cannot be mistaken for arguments.
_COMMAND_SEPARATORS = {";", "&&", "||", "|", "&"}
_REDIRECTIONS = {">", ">>", "<", "<<", "<<<", ">&", "<&"}
_UNSUPPORTED_TOKENS = {"(", ")", "$", "`"}
_NETWORK_TOOLS = {
    "curl",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "ftp",
    "sftp",
    "scp",
    "ssh",
    "rsync",
}
_SENSITIVE_PATH_PARTS = {
    ".env",
    ".aws",
    ".ssh",
    ".gnupg",
    ".config/gcloud",
    "id_rsa",
    "id_ed25519",
    "credentials",
    "secrets",
}
_DANGEROUS_ROOTS = {
    "/",
    "/boot",
    "/bin",
    "/dev",
    "/etc",
    "/home",
    "/lib",
    "/lib64",
    "/opt",
    "/proc",
    "/root",
    "/run",
    "/sbin",
    "/srv",
    "/sys",
    "/usr",
    "/var",
}


def _basename(executable: str) -> str:
    return posixpath.basename(executable).lower()


def _is_sensitive_path(value: str) -> bool:
    candidate = value.strip().strip("\"'")
    candidate = candidate.split("=", 1)[-1] if "=" in candidate else candidate
    candidate = re.sub(r"^-[A-Za-z]*@", "", candidate)
    candidate = candidate.lstrip("@")
    candidate = candidate.replace("\\", "/")
    normalized = posixpath.normpath(candidate)
    parts = {part.lower() for part in normalized.split("/") if part}
    if parts & _SENSITIVE_PATH_PARTS:
        return True
    return any(
        part.startswith(".env.") or part in {"id_rsa.pub", "id_ed25519.pub"}
        for part in parts
    )


def _is_dangerous_delete_target(value: str) -> bool:
    target = value.strip().strip("\"'")
    if target.startswith("~/"):
        target = "/root/" + target[2:]
    elif target == "~":
        target = "/root"
    target = posixpath.normpath(target)
    if target in _DANGEROUS_ROOTS:
        return True
    dangerous_globs = {
        "/*",
        "/home/*",
        "/root/*",
        "/etc/*",
        "/usr/*",
        "/var/*",
        "/boot/*",
        "/bin/*",
        "/sbin/*",
        "/lib/*",
        "/lib64/*",
        "/proc/*",
        "/sys/*",
        "/dev/*",
    }
    return target in dangerous_globs


def _tokenize(command: str) -> list[str]:
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>()")
    lexer.whitespace_split = True
    lexer.commenters = ""
    tokens = list(lexer)
    if not tokens:
        raise ValueError("empty command")
    if any(token in _UNSUPPORTED_TOKENS for token in tokens):
        raise ValueError("unsupported shell syntax")
    # Command substitution, process substitution and shell evaluation are
    # deliberately rejected rather than partially interpreted.
    if any("$(" in token or "`" in token for token in tokens):
        raise ValueError("unsupported shell expansion")
    return tokens


def _split_commands(tokens: list[str]) -> list[list[list[str]]]:
    """Return command groups; commands within a group are pipeline peers."""
    groups: list[list[list[str]]] = []
    pipeline: list[list[str]] = []
    current: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        # shlex emits file-descriptor prefixes (for example, 2>&1) as a
        # separate numeric token. Do not mistake that descriptor for a command.
        if (
            token.isdigit()
            and index + 1 < len(tokens)
            and tokens[index + 1] in _REDIRECTIONS
        ):
            index += 1
            continue
        if token in _REDIRECTIONS:
            if index + 1 >= len(tokens):
                raise ValueError("redirection has no target")
            target = tokens[index + 1]
            if target.startswith(("/dev/tcp/", "/dev/udp/")):
                raise ValueError("network redirection is not supported")
            current.extend((token, target))
            index += 2
            continue
        if token in _COMMAND_SEPARATORS:
            if current:
                pipeline.append(current)
                current = []
            elif token not in {";", "&&", "||"}:
                raise ValueError("empty command in pipeline")
            if token == "|":
                index += 1
                continue
            if pipeline:
                groups.append(pipeline)
                pipeline = []
            index += 1
            continue
        current.append(token)
        index += 1
    if current:
        pipeline.append(current)
    if pipeline:
        groups.append(pipeline)
    if not groups:
        raise ValueError("no executable found")
    return groups


def _strip_redirections(tokens: list[str]) -> list[str]:
    result: list[str] = []
    index = 0
    while index < len(tokens):
        if tokens[index] in _REDIRECTIONS:
            index += 2
        else:
            result.append(tokens[index])
            index += 1
    return result


def _command_parts(tokens: list[str]) -> tuple[str, list[str]]:
    args = _strip_redirections(tokens)
    if not args:
        raise ValueError("command has no executable")
    executable_index = 0
    # Common transparent wrappers: inspect the wrapped executable as well.
    while executable_index < len(args):
        wrapper = _basename(args[executable_index])
        if wrapper in {"command", "exec", "nohup", "time"}:
            executable_index += 1
            continue
        if wrapper == "env":
            executable_index += 1
            while executable_index < len(args):
                item = args[executable_index]
                if item == "--":
                    executable_index += 1
                    break
                if item in {"-i", "--ignore-environment", "-0", "--null"}:
                    executable_index += 1
                    continue
                if item in {"-u", "--unset", "-C", "--chdir"}:
                    executable_index += 2
                    continue
                if (
                    item.startswith(("--unset=", "--chdir="))
                    or (item.startswith("-") and item != "-")
                    or ("=" in item and not item.startswith("="))
                ):
                    executable_index += 1
                    continue
                break
            continue
        break
    if executable_index >= len(args):
        raise ValueError("command wrapper has no executable")
    executable = args[executable_index]
    return executable, args[executable_index + 1 :]


def _rm_targets(args: list[str]) -> tuple[bool, list[str]]:
    recursive = False
    targets: list[str] = []
    options = True
    for arg in args:
        if options and arg == "--":
            options = False
            continue
        if options and arg.startswith("-") and arg != "-":
            if arg.startswith("--"):
                recursive = recursive or arg in {"--recursive"}
            else:
                recursive = recursive or "r" in arg[1:].lower()
            continue
        targets.append(arg)
    return recursive, targets


def _inspect_command(tokens: list[str]) -> tuple[str, str | None, bool]:
    """Return executable, optional finding, and whether it is a network sink."""
    executable, args = _command_parts(tokens)
    name = _basename(executable)

    if name == "rm":
        recursive, targets = _rm_targets(args)
        if recursive and any(_is_dangerous_delete_target(target) for target in targets):
            return executable, "Recursive deletion targets a system or home root", False

    if name in {"curl", "wget", "nc", "ncat", "netcat", "socat"}:
        for arg in args:
            if _is_sensitive_path(arg) and (arg.startswith(("@", "-")) or "=" in arg):
                return executable, "Sensitive file is supplied to a network tool", True
        # curl/wget upload flags can be separated from their values.
        for index, arg in enumerate(args[:-1]):
            if arg in {
                "-d",
                "--data",
                "--data-raw",
                "--data-binary",
                "--data-urlencode",
                "-F",
                "--form",
                "-T",
                "--upload-file",
                "--post-file",
            } and _is_sensitive_path(args[index + 1]):
                return executable, "Sensitive file is uploaded to a network tool", True

    if name in {"sudo", "doas", "su", "pkexec"}:
        return (
            executable,
            "Privilege-escalation wrapper requires an explicit host policy",
            False,
        )

    if name in {"sh", "bash", "dash", "zsh", "fish"} and any(
        arg in {"-c", "-lc", "-ec"} or (arg.startswith("-") and "c" in arg[1:])
        for arg in args
    ):
        return (
            executable,
            "Inline shell execution requires an explicit host policy",
            False,
        )

    # Local archives are not automatically exfiltration. The pipeline check
    # below blocks them only when their output reaches a network sink.
    return executable, None, name in _NETWORK_TOOLS


@dataclass(frozen=True)
class HostSecurityPolicy:
    allowed_executables: tuple[str, ...] = ()
    denied_command_patterns: tuple[str, ...] = (
        r"\bmkfs\b",
        r"\bcurl\b.*\|\s*(?:sh|bash)",
    )
    allowed_artifact_sha256: tuple[str, ...] = ()
    require_artifact_hash: bool = True

    def evaluate_command(self, command: str) -> HostDecision:
        if not command.strip():
            return HostDecision(False, "Empty command denied", command)
        try:
            groups = _split_commands(_tokenize(command))
        except (ValueError, TypeError):
            return HostDecision(
                False, "Command syntax could not be safely analyzed", command[:160]
            )

        for pattern in self.denied_command_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return HostDecision(
                    False, "Command matches a denied pattern", command[:160]
                )

        inspected: list[tuple[str, list[str], bool]] = []
        for group in groups:
            for tokens in group:
                try:
                    executable, finding, is_network = _inspect_command(tokens)
                except ValueError:
                    return HostDecision(
                        False,
                        "Command syntax could not be safely analyzed",
                        command[:160],
                    )
                if finding:
                    return HostDecision(False, finding, executable)
                inspected.append((executable, tokens, is_network))

        # A sensitive archive feeding a network command in the same pipeline
        # is an exfiltration path even when neither command contains an @file.
        for group in groups:
            has_sensitive_archive = any(
                _basename(_command_parts(tokens)[0]) == "tar"
                and any(
                    _is_sensitive_path(arg) for arg in _strip_redirections(tokens)[1:]
                )
                for tokens in group
            )
            has_network_sink = any(_inspect_command(tokens)[2] for tokens in group)
            if has_sensitive_archive and has_network_sink:
                return HostDecision(
                    False, "Sensitive archive is piped to a network tool", "pipeline"
                )

        if self.allowed_executables:
            for executable, _, _ in inspected:
                if executable not in self.allowed_executables:
                    return HostDecision(
                        False, "Executable is not allowlisted", executable
                    )

        subject = inspected[0][0] if inspected else command[:160]
        return HostDecision(True, "Command passed static host policy", subject)

    def evaluate_artifact(self, path: str) -> HostDecision:
        target = Path(path)
        if not target.is_file():
            return HostDecision(False, "Artifact is not a regular file", path)
        digest = hashlib.sha256()
        with target.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        fingerprint = digest.hexdigest()
        if self.require_artifact_hash and not self.allowed_artifact_sha256:
            return HostDecision(
                False, "No artifact hashes configured (fail-closed)", fingerprint
            )
        if (
            self.allowed_artifact_sha256
            and fingerprint not in self.allowed_artifact_sha256
        ):
            return HostDecision(
                False, "Artifact SHA-256 is not allowlisted", fingerprint
            )
        return HostDecision(True, "Artifact hash verified", fingerprint)
