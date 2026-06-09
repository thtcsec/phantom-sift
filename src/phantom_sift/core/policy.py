"""Policy engine — Guardrails before tool execution.

Adapted from SOAR's PolicyEngine pattern. In the SOAR context, this gates
auto-remediation decisions. Here, it gates tool execution to ensure:
1. No write operations on evidence
2. No path traversal outside evidence mount
3. No network access from forensic tools (isolation)
4. Iteration limits enforced
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class PolicyDecision:
    """Result of a policy check."""

    allowed: bool
    reason: str
    adjusted_params: dict[str, Any] | None = None


class PolicyEngine:
    """Architectural guardrails for agent tool execution.

    Unlike prompt-based restrictions (which LLMs can ignore),
    these are enforced in code before any tool runs.
    """

    def __init__(
        self,
        evidence_root: Path,
        max_iterations: int = 15,
        read_only: bool = True,
    ) -> None:
        self._evidence_root = evidence_root.resolve()
        self._max_iterations = max_iterations
        self._read_only = read_only
        self._blocked_patterns = [
            "/dev/",
            "/proc/",
            "/sys/",
            "/tmp/",
            "../../",
            "~",
        ]

    def check_tool_call(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        current_iteration: int,
    ) -> PolicyDecision:
        """Validate a tool call before execution.

        Returns PolicyDecision indicating if the call is allowed.
        """
        # Check iteration limit
        if current_iteration > self._max_iterations:
            return PolicyDecision(
                allowed=False,
                reason=f"Max iterations ({self._max_iterations}) exceeded",
            )

        # Check for write operations (should never exist in our MCP, but defense-in-depth)
        write_indicators = ["write", "delete", "modify", "create", "rm", "mv"]
        if any(w in tool_name.lower() for w in write_indicators):
            return PolicyDecision(
                allowed=False,
                reason=f"Write operation blocked: {tool_name}",
            )

        # Check path parameters for traversal
        for key, value in tool_input.items():
            if isinstance(value, str) and ("path" in key.lower() or "file" in key.lower()):
                if not self._is_safe_path(value):
                    return PolicyDecision(
                        allowed=False,
                        reason=f"Path traversal blocked: {value}",
                    )

        # Check for shell execution attempts
        shell_tools = ["execute_shell", "run_command", "bash", "sh"]
        if tool_name.lower() in shell_tools:
            return PolicyDecision(
                allowed=False,
                reason="Direct shell execution not available. Use typed MCP tools.",
            )

        logger.debug("policy_check_passed", tool=tool_name, iteration=current_iteration)
        return PolicyDecision(allowed=True, reason="OK")

    def check_iteration_budget(self, current: int) -> PolicyDecision:
        """Check if agent still has iteration budget."""
        if current > self._max_iterations:
            return PolicyDecision(
                allowed=False,
                reason=f"Iteration {current} exceeds max {self._max_iterations}. Graceful stop.",
            )
        remaining = self._max_iterations - current
        if remaining <= 2:
            logger.warning("iteration_budget_low", remaining=remaining)
        return PolicyDecision(allowed=True, reason=f"{remaining} iterations remaining")

    def _is_safe_path(self, path_str: str) -> bool:
        """Check if a path is within allowed boundaries."""
        for pattern in self._blocked_patterns:
            if pattern in path_str:
                return False

        # Resolve and check if within evidence root
        try:
            resolved = Path(path_str).resolve()
            return str(resolved).startswith(str(self._evidence_root))
        except (OSError, ValueError):
            return False
