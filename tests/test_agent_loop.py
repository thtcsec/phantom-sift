"""Tests for the agent loop — integration-level validation.

Tests the loop mechanics without actual LLM calls (mocked).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from phantom_sift.agent.tool_dispatcher import (
    TOOL_REGISTRY,
    ToolDispatcher,
    get_anthropic_tool_definitions,
)
from phantom_sift.core.audit_logger import ExecutionLogger
from phantom_sift.core.policy import PolicyEngine


def test_tool_registry_complete():
    """All tools in the registry should be callable."""
    for name, func in TOOL_REGISTRY.items():
        assert callable(func), f"Tool {name} is not callable"


def test_anthropic_tool_definitions_valid():
    """Tool definitions should follow Anthropic schema."""
    tools = get_anthropic_tool_definitions()
    assert len(tools) > 0

    for tool in tools:
        assert "name" in tool
        assert "description" in tool
        assert "input_schema" in tool
        assert tool["input_schema"]["type"] == "object"
        assert "properties" in tool["input_schema"]
        assert "required" in tool["input_schema"]

        # Name must match registry
        assert tool["name"] in TOOL_REGISTRY, f"Tool {tool['name']} not in registry"


def test_tool_definitions_match_registry():
    """Every tool in registry should have an Anthropic definition."""
    definitions = get_anthropic_tool_definitions()
    defined_names = {t["name"] for t in definitions}

    for registry_name in TOOL_REGISTRY:
        assert registry_name in defined_names, (
            f"Tool {registry_name} in registry but missing Anthropic definition"
        )


def test_dispatcher_blocks_unknown_tool(tmp_path):
    """Dispatcher should reject calls to tools not in registry."""
    policy = PolicyEngine(evidence_root=tmp_path, max_iterations=10)
    log_path = tmp_path / "test.jsonl"
    logger = ExecutionLogger(log_path)
    dispatcher = ToolDispatcher(policy, logger)

    result = dispatcher.execute(
        tool_name="nonexistent_forensic_tool",
        tool_input={"path": str(tmp_path / "evidence.dd")},
        iteration=1,
    )

    assert "error" in result
    assert "Unknown tool" in result["error"]


def test_dispatcher_blocks_policy_violation(tmp_path):
    """Dispatcher should block calls that violate policy."""
    policy = PolicyEngine(evidence_root=tmp_path, max_iterations=10)
    log_path = tmp_path / "test.jsonl"
    logger = ExecutionLogger(log_path)
    dispatcher = ToolDispatcher(policy, logger)

    # Try to call with path traversal
    result = dispatcher.execute(
        tool_name="get_partition_table",
        tool_input={"image_path": "/tmp/../../etc/passwd"},
        iteration=1,
    )

    assert "error" in result or "BLOCKED" in result.get("error", "")


def test_dispatcher_blocks_after_max_iterations(tmp_path):
    """Dispatcher should block all calls after max iterations."""
    policy = PolicyEngine(evidence_root=tmp_path, max_iterations=5)
    log_path = tmp_path / "test.jsonl"
    logger = ExecutionLogger(log_path)
    dispatcher = ToolDispatcher(policy, logger)

    result = dispatcher.execute(
        tool_name="get_partition_table",
        tool_input={"image_path": str(tmp_path / "evidence.dd")},
        iteration=6,  # Over max
    )

    assert "error" in result or "BLOCKED" in result.get("error", "")


def test_dispatcher_logs_all_calls(tmp_path):
    """Every tool call should be logged to the execution log."""
    policy = PolicyEngine(evidence_root=tmp_path, max_iterations=10)
    log_path = tmp_path / "execution.jsonl"
    logger = ExecutionLogger(log_path)
    dispatcher = ToolDispatcher(policy, logger)

    # Call a tool (will fail because tool not found on system, but should still log)
    dispatcher.execute(
        tool_name="get_partition_table",
        tool_input={"image_path": str(tmp_path / "evidence.dd")},
        iteration=1,
    )

    # Check log file exists and has entries
    assert log_path.exists()
    with open(log_path) as f:
        lines = f.readlines()
    assert len(lines) >= 2  # tool_call + tool_result

    # Parse and verify structure
    for line in lines:
        entry = json.loads(line)
        assert "timestamp" in entry
        assert "event" in entry
        assert "iteration" in entry


def test_execution_logger_stats(tmp_path):
    """ExecutionLogger should track cumulative stats."""
    from phantom_sift.core.audit_logger import EventType, ExecutionLogger

    log_path = tmp_path / "stats.jsonl"
    logger = ExecutionLogger(log_path)

    logger.log(EventType.LLM_RESPONSE, iteration=1, input_tokens=100, output_tokens=50)
    logger.log(EventType.LLM_RESPONSE, iteration=2, input_tokens=200, output_tokens=80)
    logger.log(EventType.TOOL_CALL, iteration=1)
    logger.log(EventType.TOOL_CALL, iteration=2)
    logger.log(EventType.TOOL_CALL, iteration=3)

    stats = logger.stats
    assert stats["total_input_tokens"] == 300
    assert stats["total_output_tokens"] == 130
    assert stats["total_tokens"] == 430
    assert stats["total_tool_calls"] == 3
