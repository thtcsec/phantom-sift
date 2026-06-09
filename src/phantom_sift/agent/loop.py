"""Agent Loop — Core reasoning engine.

Adapted from SOAR's IncidentPipeline pattern:
  SOAR:  Event → Normalize → Correlate → Score → Decision → Playbook → Audit
  Agent: Evidence → Plan → Execute Tools → Evaluate → Self-Correct → Report

This is the main execution spine. It:
1. Plans which tools to run based on evidence type
2. Calls MCP tools and collects output
3. Evaluates findings for consistency
4. Self-corrects when inconsistencies detected
5. Produces structured findings with evidence chains
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from ..config import Settings
from ..core.audit_logger import EventType, ExecutionLogger
from ..core.evidence import EvidenceType, verify_evidence, verify_integrity_post_analysis
from ..core.findings import AnalysisResult, ForensicFinding
from ..core.policy import PolicyEngine
from .planner import AnalysisPlan, Planner
from .self_correction import SelfCorrector

logger = structlog.get_logger()


class AgentLoop:
    """Self-correcting forensic analysis agent.

    Architecture:
        Agent Loop (this) → Policy Gate → MCP Server → SIFT Tools
                                                    ↓
        Cloudflare AI Gateway ← LLM (Claude) ← Agent reasoning

    The agent CANNOT bypass the policy gate or call tools directly.
    All tool calls go through MCP which only exposes read-only functions.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._execution_logger = ExecutionLogger(settings.execution_log_path)
        self._policy = PolicyEngine(
            evidence_root=settings.evidence_mount_path,
            max_iterations=settings.agent_max_iterations,
            read_only=settings.evidence_read_only,
        )
        self._planner = Planner()
        self._self_corrector = SelfCorrector()
        self._findings: list[ForensicFinding] = []
        self._iteration = 0
        self._self_corrections = 0

    def run(
        self,
        case_path: Path,
        evidence_type: str,
        max_iterations: int,
    ) -> AnalysisResult:
        """Execute the full analysis loop.

        Returns AnalysisResult with findings, stats, and success/failure.
        """
        result = AnalysisResult(
            case_path=str(case_path),
            evidence_type=evidence_type,
        )

        self._execution_logger.log(
            EventType.AGENT_START,
            data={
                "case_path": str(case_path),
                "evidence_type": evidence_type,
                "max_iterations": max_iterations,
                "model": self._settings.agent_model,
            },
        )

        try:
            # Phase 1: Verify evidence integrity
            evidence = verify_evidence(case_path, evidence_type)  # type: ignore[arg-type]

            # Phase 2: Plan initial analysis
            plan = self._planner.create_plan(evidence_type)  # type: ignore[arg-type]

            # Phase 3: Execute reasoning loop
            for iteration in range(1, max_iterations + 1):
                self._iteration = iteration

                # Policy check: iteration budget
                budget_check = self._policy.check_iteration_budget(iteration)
                if not budget_check.allowed:
                    logger.warning("iteration_budget_exhausted", reason=budget_check.reason)
                    break

                self._execution_logger.log(
                    EventType.ITERATION_START,
                    iteration=iteration,
                    data={"plan_phase": plan.current_phase},
                )

                # Execute one reasoning step
                step_result = self._execute_step(plan, iteration)

                self._execution_logger.log(
                    EventType.ITERATION_COMPLETE,
                    iteration=iteration,
                    data={
                        "findings_count": len(self._findings),
                        "step_outcome": step_result.get("outcome", "unknown"),
                    },
                )

                # Self-correction check every N iterations
                if iteration % 3 == 0 and self._findings:
                    corrections = self._self_corrector.check(self._findings)
                    if corrections:
                        self._self_corrections += len(corrections)
                        for correction in corrections:
                            self._execution_logger.log_self_correction(
                                iteration=iteration,
                                finding_id=correction["finding_id"],
                                reason=correction["reason"],
                                action=correction["action"],
                            )

                # Check if analysis is complete
                if step_result.get("outcome") == "complete":
                    break

            # Phase 4: Verify evidence integrity preserved
            integrity_ok = verify_integrity_post_analysis(evidence)

            # Compile result
            result.findings = self._findings
            result.iterations_used = self._iteration
            result.self_corrections = self._self_corrections
            result.total_tool_calls = self._execution_logger.stats["total_tool_calls"]
            result.total_tokens = self._execution_logger.stats["total_tokens"]
            result.completed_at = datetime.now(timezone.utc)
            result.success = integrity_ok

            if not integrity_ok:
                result.error = "CRITICAL: Evidence integrity check failed post-analysis"

        except Exception as e:
            logger.error("agent_loop_failed", error=str(e))
            result.error = str(e)
            result.success = False
            self._execution_logger.log(
                EventType.ERROR,
                iteration=self._iteration,
                data={"error": str(e), "type": type(e).__name__},
            )

        self._execution_logger.log(
            EventType.AGENT_COMPLETE,
            iteration=self._iteration,
            data={
                "success": result.success,
                "findings_count": len(result.findings),
                "self_corrections": result.self_corrections,
                **self._execution_logger.stats,
            },
        )

        return result

    def _execute_step(self, plan: AnalysisPlan, iteration: int) -> dict[str, Any]:
        """Execute a single reasoning step.

        This is where the LLM is called to:
        1. Look at current findings and plan
        2. Decide which tool to call next
        3. Interpret tool output
        4. Update findings

        TODO: Wire to actual Anthropic client + MCP tool calls.
        Skeleton returns placeholder for init commit.
        """
        # Placeholder for LLM interaction
        # In full implementation:
        # 1. Build prompt with current state (findings, plan phase)
        # 2. Call Claude via CF AI Gateway
        # 3. Parse tool_use blocks
        # 4. Execute tool via MCP
        # 5. Feed result back to Claude
        # 6. Extract findings from response
        return {"outcome": "complete", "reason": "skeleton_implementation"}
