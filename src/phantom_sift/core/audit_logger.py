"""Execution Logger — Structured agent execution trail.

Adapted from SOAR's AuditLogger pattern. Records every tool call,
LLM interaction, and self-correction with timestamps and token counts.

Output format: JSON Lines (.jsonl) — one event per line, append-only.
This directly satisfies hackathon requirement #8 (Agent Execution Logs).
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


class EventType(str, Enum):
    """Types of events in the execution log."""

    AGENT_START = "agent_start"
    AGENT_COMPLETE = "agent_complete"
    ITERATION_START = "iteration_start"
    ITERATION_COMPLETE = "iteration_complete"
    LLM_REQUEST = "llm_request"
    LLM_RESPONSE = "llm_response"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    SELF_CORRECTION = "self_correction"
    FINDING_CREATED = "finding_created"
    FINDING_REVISED = "finding_revised"
    ERROR = "error"
    POLICY_CHECK = "policy_check"


class ExecutionLogger:
    """Append-only execution log for agent transparency.

    Each entry includes:
    - Timestamp (ISO 8601 UTC)
    - Event type
    - Iteration number
    - Token usage (input/output)
    - Duration
    - Relevant data (tool name, finding ID, etc.)
    """

    def __init__(self, log_path: Path) -> None:
        self._log_path = log_path
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._start_time = time.time()
        self._total_input_tokens = 0
        self._total_output_tokens = 0
        self._total_tool_calls = 0

    def log(
        self,
        event_type: EventType,
        *,
        iteration: int = 0,
        input_tokens: int = 0,
        output_tokens: int = 0,
        duration_ms: float = 0,
        data: dict[str, Any] | None = None,
    ) -> None:
        """Append a structured event to the execution log."""
        self._total_input_tokens += input_tokens
        self._total_output_tokens += output_tokens
        if event_type == EventType.TOOL_CALL:
            self._total_tool_calls += 1

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event_type.value,
            "iteration": iteration,
            "tokens": {
                "input": input_tokens,
                "output": output_tokens,
                "cumulative_input": self._total_input_tokens,
                "cumulative_output": self._total_output_tokens,
            },
            "duration_ms": round(duration_ms, 2),
            "elapsed_total_s": round(time.time() - self._start_time, 2),
            "data": data or {},
        }

        with open(self._log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")

        logger.debug("execution_log_entry", event_type=event_type.value, iteration=iteration)

    def log_tool_call(
        self,
        *,
        iteration: int,
        tool_name: str,
        tool_input: dict[str, Any],
        call_id: str,
    ) -> None:
        """Log an outgoing MCP tool call."""
        self.log(
            EventType.TOOL_CALL,
            iteration=iteration,
            data={
                "tool_name": tool_name,
                "tool_input": tool_input,
                "call_id": call_id,
            },
        )

    def log_tool_result(
        self,
        *,
        iteration: int,
        tool_name: str,
        call_id: str,
        output_size: int,
        output_hash: str,
        duration_ms: float,
        success: bool,
    ) -> None:
        """Log a tool result received."""
        self.log(
            EventType.TOOL_RESULT,
            iteration=iteration,
            duration_ms=duration_ms,
            data={
                "tool_name": tool_name,
                "call_id": call_id,
                "output_size_bytes": output_size,
                "output_hash": output_hash,
                "success": success,
            },
        )

    def log_self_correction(
        self,
        *,
        iteration: int,
        finding_id: str,
        reason: str,
        action: str,
    ) -> None:
        """Log a self-correction event."""
        self.log(
            EventType.SELF_CORRECTION,
            iteration=iteration,
            data={
                "finding_id": finding_id,
                "reason": reason,
                "action": action,
            },
        )

    @property
    def stats(self) -> dict[str, Any]:
        """Current execution statistics."""
        return {
            "total_input_tokens": self._total_input_tokens,
            "total_output_tokens": self._total_output_tokens,
            "total_tokens": self._total_input_tokens + self._total_output_tokens,
            "total_tool_calls": self._total_tool_calls,
            "elapsed_seconds": round(time.time() - self._start_time, 2),
        }
