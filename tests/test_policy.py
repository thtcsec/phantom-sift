"""Tests for the policy engine (architectural guardrails)."""

from pathlib import Path

from phantom_sift.core.policy import PolicyEngine


def test_read_only_tool_allowed():
    """Normal read-only tool calls should pass."""
    policy = PolicyEngine(evidence_root=Path("/mnt/evidence"), max_iterations=10)
    decision = policy.check_tool_call(
        tool_name="get_partition_table",
        tool_input={"image_path": "/mnt/evidence/disk.dd"},
        current_iteration=1,
    )
    assert decision.allowed is True


def test_write_tool_blocked():
    """Any tool with 'write' in name should be blocked."""
    policy = PolicyEngine(evidence_root=Path("/mnt/evidence"), max_iterations=10)
    decision = policy.check_tool_call(
        tool_name="write_file",
        tool_input={"path": "/mnt/evidence/malware.exe"},
        current_iteration=1,
    )
    assert decision.allowed is False
    assert "Write operation" in decision.reason


def test_shell_execution_blocked():
    """Direct shell execution should be blocked."""
    policy = PolicyEngine(evidence_root=Path("/mnt/evidence"), max_iterations=10)
    decision = policy.check_tool_call(
        tool_name="execute_shell",
        tool_input={"command": "rm -rf /"},
        current_iteration=1,
    )
    assert decision.allowed is False
    assert "shell execution" in decision.reason.lower()


def test_path_traversal_blocked():
    """Path traversal attempts should be blocked."""
    policy = PolicyEngine(evidence_root=Path("/mnt/evidence"), max_iterations=10)
    decision = policy.check_tool_call(
        tool_name="get_mft_entries",
        tool_input={"image_path": "/mnt/evidence/../../etc/passwd"},
        current_iteration=1,
    )
    assert decision.allowed is False
    assert "traversal" in decision.reason.lower()


def test_iteration_limit_enforced():
    """Exceeding max iterations should stop the agent."""
    policy = PolicyEngine(evidence_root=Path("/mnt/evidence"), max_iterations=10)
    decision = policy.check_tool_call(
        tool_name="vol_pslist",
        tool_input={"memory_path": "/mnt/evidence/mem.raw"},
        current_iteration=11,
    )
    assert decision.allowed is False
    assert "exceeded" in decision.reason.lower()


def test_iteration_budget_warning():
    """Low iteration budget should still allow but warn."""
    policy = PolicyEngine(evidence_root=Path("/mnt/evidence"), max_iterations=10)
    decision = policy.check_iteration_budget(current=9)
    assert decision.allowed is True
    assert "1 iterations remaining" in decision.reason
