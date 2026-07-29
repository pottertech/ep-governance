"""EP-Governance restricted shell proxy.

This is the LAST proxy adapter implemented, as shell classification
cannot achieve complete semantic understanding. The proxy classifies
known bounded commands and rejects opaque operations.
"""

from __future__ import annotations

import re
import shlex
from typing import Any

from ..authorizations import AuthorizationToken
from ..classification import get_classifier
from ..errors import ClassificationError
from .base import ExecutionResult, GovernedProxy

__all__ = ["ShellProxy"]


# Known safe commands that can be classified with high confidence
SAFE_COMMANDS = frozenset(
    {
        "ls",
        "cat",
        "echo",
        "pwd",
        "whoami",
        "date",
        "uptime",
        "hostname",
        "df",
        "du",
        "free",
        "top",
        "ps",
        "head",
        "tail",
        "wc",
        "sort",
        "uniq",
        "grep",
        "find",
        "which",
        "env",
    }
)

# Dangerous patterns that make a command opaque
_DANGEROUS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\$\("),  # Command substitution
    re.compile(r"`"),  # Backtick command substitution
    re.compile(r"\beval\b", re.IGNORECASE),
    re.compile(r"\bexec\b", re.IGNORECASE),
    re.compile(r"\bsh\b"),  # Interpreter invocation
    re.compile(r"\bbash\b"),  # Interpreter invocation
    re.compile(r"\bpython\b", re.IGNORECASE),
    re.compile(r"\bperl\b", re.IGNORECASE),
    re.compile(r"\bruby\b", re.IGNORECASE),
    re.compile(r"\bnode\b", re.IGNORECASE),
    re.compile(r"\bwget\b", re.IGNORECASE),
    re.compile(r"\bcurl\b", re.IGNORECASE),
    re.compile(r"\bchmod\b", re.IGNORECASE),
    re.compile(r"\bchown\b", re.IGNORECASE),
    re.compile(r"\brm\b"),
    re.compile(r"\bmv\b"),
    re.compile(r"\bcp\b"),
    re.compile(r"\bmkfs\b", re.IGNORECASE),
    re.compile(r"\bdd\b", re.IGNORECASE),
    re.compile(r"\bsudo\b", re.IGNORECASE),
    re.compile(r"\bsu\b", re.IGNORECASE),
    re.compile(r"\bpip\b", re.IGNORECASE),
    re.compile(r"\bapt\b", re.IGNORECASE),
    re.compile(r"\byum\b", re.IGNORECASE),
    re.compile(r"\bbrew\b", re.IGNORECASE),
    re.compile(r"\bbase64\b", re.IGNORECASE),
    re.compile(r"\bopenssl\b", re.IGNORECASE),
    re.compile(r"\bnc\b"),
    re.compile(r"\bnetcat\b"),
    re.compile(r"\bkill\b", re.IGNORECASE),
    re.compile(r"\bpkill\b", re.IGNORECASE),
    re.compile(r"\breboot\b", re.IGNORECASE),
    re.compile(r"\bshutdown\b", re.IGNORECASE),
]


class ShellProxy(GovernedProxy):
    """Governed proxy for restricted shell execution.

    Classification approach (escalating treatment):
    1. Known safe commands (ls, cat, echo, etc.) — classified with high confidence
    2. Commands with dangerous patterns (eval, $(), backticks, interpreters) — classified as opaque
    3. Unknown commands — classified as opaque, require approval

    The proxy does NOT claim complete semantic understanding of shell commands.
    """

    def _execute_adapter(
        self,
        payload: dict[str, Any],
        token: AuthorizationToken,
        attempt_id: str,
    ) -> ExecutionResult:
        command = payload.get("command") or payload.get("cmd") or payload.get("script")
        if not command:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary="No 'command' in payload",
            )

        # Classify using the shell classifier
        classifier = get_classifier("shell.execute")
        if classifier is None:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary="No shell classifier available",
            )

        try:
            classification = classifier.classify("shell.execute", payload)
        except ClassificationError as exc:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary=f"Shell classification failed: {exc!s}",
            )

        # If classification is opaque, reject
        if classification.opaque:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary="Shell command is opaque — requires explicit approval or denial",
            )

        # Parse the command to extract the executable
        try:
            parts = shlex.split(command)
        except ValueError:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary="Shell command parsing failed — requires approval",
            )

        if not parts:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary="Empty shell command",
            )

        executable = parts[0]

        # Check if it's a known safe command
        if executable not in SAFE_COMMANDS:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary=f"Command '{executable}' is not in the safe commands list — requires approval",
            )

        # Check for dangerous patterns even in safe commands
        for pattern in _DANGEROUS_PATTERNS:
            if pattern.search(command):
                return ExecutionResult(
                    success=False,
                    exit_status="failure",
                    result_summary="Command contains dangerous pattern — classified as opaque, requires approval",
                )

        # Simulated execution
        return ExecutionResult(
            success=True,
            exit_status="success",
            result_summary=f"Would execute: {command}",
            output=f"[simulated] {command}",
        )
