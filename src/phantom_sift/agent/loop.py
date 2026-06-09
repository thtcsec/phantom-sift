"""Agent Loop — Core reasoning engine (PRODUCTION).

Implements the full agent cycle:
  Evidence → Plan → [LLM reasons → Calls tools → Evaluates → Self-corrects] → Report

The agent uses Claude in tool-use mode. Each iteration:
1. Send current state (findings, plan phase, tool results) to Claude
2. Claude responds with either text (reasoning) or tool_use (action)
3. If tool_use: dispatch via ToolDispatcher (policy-gated)
4. Feed tool result back to Claude
5. Claude produces findings or requests next tool
6. Every 3 iterations: run self-correction checks
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from ..config import Settings
from ..core.audit_logger import EventType, ExecutionLogger
from ..core.evidence import verify_evidence, verify_integrity_post_analysis
from ..core.findings import (
    AnalysisResult,
    Confidence,
    EvidenceSource,
    FindingCategory,
    ForensicFinding,
)
from ..core.policy import PolicyEngine
from .llm_client import LLMClient, LLMResponse
from .planner import Planner
from .prompts import ANALYST_SYSTEM_PROMPT
from .self_correction import SelfCorrector
from .tool_dispatcher import ToolDispatcher, get_anthropic_tool_definitions

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
        self._llm = LLMClient(settings)
        self._dispatcher = ToolDispatcher(self._policy, self._execution_logger)
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
        """Execute the full analysis loop."""
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

            # Phase 3: Build initial message for Claude
            messages: list[dict[str, Any]] = [
                {
                    "role": "user",
                    "content": self._build_initial_prompt(case_path, evidence_type, plan),
                }
            ]

            tools = get_anthropic_tool_definitions()

            # Phase 4: Agent reasoning loop
            for iteration in range(1, max_iterations + 1):
                self._iteration = iteration

                # Policy check: iteration budget
                budget_check = self._policy.check_iteration_budget(iteration)
                if not budget_check.allowed:
                    logger.warning("iteration_budget_exhausted", reason=budget_check.reason)
                    # Ask Claude to finalize
                    messages.append({
                        "role": "user",
                        "content": "ITERATION BUDGET REACHED. Produce your final findings now. Summarize what you found and what remains uncertain.",
                    })
                    final_response = self._llm.chat(
                        messages=messages, tools=tools, system=ANALYST_SYSTEM_PROMPT
                    )
                    self._extract_findings_from_text(final_response.text_content, iteration)
                    break

                self._execution_logger.log(
                    EventType.ITERATION_START,
                    iteration=iteration,
                    data={"plan_phase": plan.current_phase, "findings_count": len(self._findings)},
                )

                # Call Claude
                response = self._llm.chat(
                    messages=messages, tools=tools, system=ANALYST_SYSTEM_PROMPT
                )

                self._execution_logger.log(
                    EventType.LLM_RESPONSE,
                    iteration=iteration,
                    input_tokens=response.input_tokens,
                    output_tokens=response.output_tokens,
                    duration_ms=response.duration_ms,
                    data={
                        "stop_reason": response.stop_reason,
                        "tool_calls_count": len(response.tool_calls),
                    },
                )

                # If Claude wants to use tools
                if response.has_tool_calls:
                    # Add assistant message to history
                    messages.append({
                        "role": "assistant",
                        "content": response.content_blocks,
                    })

                    # Execute each tool call
                    tool_results = []
                    for tool_call in response.tool_calls:
                        tool_name = tool_call["name"]
                        tool_input = tool_call["input"]
                        tool_use_id = tool_call["id"]

                        # Dispatch through policy gate
                        tool_output = self._dispatcher.execute(
                            tool_name=tool_name,
                            tool_input=tool_input,
                            iteration=iteration,
                        )

                        # Truncate large outputs for context window management
                        output_str = json.dumps(tool_output, default=str)
                        if len(output_str) > 15000:
                            output_str = output_str[:15000] + "\n... [TRUNCATED — output too large for context]"

                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": tool_use_id,
                            "content": output_str,
                        })

                    # Feed tool results back to Claude
                    messages.append({
                        "role": "user",
                        "content": tool_results,
                    })

                else:
                    # Claude responded with text only (reasoning/findings)
                    messages.append({
                        "role": "assistant",
                        "content": response.content_blocks,
                    })

                    # Check if Claude signaled completion
                    text = response.text_content
                    if "ANALYSIS_COMPLETE" in text:
                        self._extract_findings_from_text(text, iteration)
                        break

                    # Extract any findings from reasoning text
                    self._extract_findings_from_text(text, iteration)

                    # Prompt for next action
                    messages.append({
                        "role": "user",
                        "content": self._build_continuation_prompt(iteration, plan),
                    })

                # Self-correction check every 3 iterations
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
                        # Inform Claude about corrections
                        messages.append({
                            "role": "user",
                            "content": self._build_correction_prompt(corrections),
                        })

                self._execution_logger.log(
                    EventType.ITERATION_COMPLETE,
                    iteration=iteration,
                    data={
                        "findings_count": len(self._findings),
                        "stop_reason": response.stop_reason,
                    },
                )

            # Phase 5: Verify evidence integrity preserved
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

    # ─── Prompt Construction ──────────────────────────────────────────

    def _build_initial_prompt(self, case_path: Path, evidence_type: str, plan: Any) -> str:
        """Build the initial user message that kicks off analysis."""
        phase_info = plan.phases[0] if plan.phases else None
        phase_tools = ", ".join(phase_info.tools) if phase_info else "all"

        return f"""Analyze this forensic evidence and find evil.

## Evidence
- **Path:** {case_path}
- **Type:** {evidence_type}
- **Mount:** The evidence is mounted read-only. All paths you provide to tools should use the full path.

## Your Task
1. Start with {phase_info.name if phase_info else 'survey'}: {phase_info.description if phase_info else 'understand the evidence'}
2. Use the available forensic tools to investigate
3. Build findings with evidence chains
4. Self-correct if you find inconsistencies

## Analysis Plan
Phase 1: {phase_info.name if phase_info else 'survey'} — tools: {phase_tools}
Then: deeper analysis based on what you find.

## Output
When you have findings, output them as structured JSON in this format:
```json
{{
  "finding": {{
    "category": "malware_execution|persistence|lateral_movement|...",
    "confidence": "confirmed|high|medium|low",
    "title": "One-line summary",
    "description": "What you found with specifics",
    "iocs": ["indicator1", "indicator2"],
    "mitre_attack": ["T1234"],
    "timeline_position": "2026-01-15T14:30:00Z"
  }}
}}
```

When analysis is complete, include "ANALYSIS_COMPLETE" in your response.

Begin with your first tool call."""

    def _build_continuation_prompt(self, iteration: int, plan: Any) -> str:
        """Prompt to keep the agent working."""
        findings_summary = ""
        if self._findings:
            findings_summary = f"\n\nCurrent findings ({len(self._findings)}):\n"
            for f in self._findings[-3:]:  # Last 3
                findings_summary += f"- [{f.confidence.value}] {f.title}\n"

        return f"""Continue your analysis. Iteration {iteration}/{self._settings.agent_max_iterations}.
{findings_summary}
What should you investigate next? Use a tool or report findings.
If you believe analysis is complete, include "ANALYSIS_COMPLETE" in your response."""

    def _build_correction_prompt(self, corrections: list[dict[str, Any]]) -> str:
        """Inform the agent about self-correction results."""
        lines = ["⚠️ SELF-CORRECTION CHECK detected issues:\n"]
        for c in corrections:
            lines.append(f"- Finding `{c['finding_id']}`: {c['reason']} → Action: {c['action']}")
        lines.append("\nPlease review and adjust your analysis. Re-investigate if needed.")
        return "\n".join(lines)

    # ─── Finding Extraction ───────────────────────────────────────────

    def _extract_findings_from_text(self, text: str, iteration: int) -> None:
        """Parse structured findings from Claude's text response.

        Looks for JSON blocks with finding schema.
        """
        import re

        # Find JSON blocks with finding data
        pattern = r'```json\s*\n(.*?)\n\s*```'
        matches = re.findall(pattern, text, re.DOTALL)

        for match in matches:
            try:
                data = json.loads(match)
                finding_data = data.get("finding", data)

                # Map to our schema
                category_str = finding_data.get("category", "suspicious_activity")
                confidence_str = finding_data.get("confidence", "medium")

                try:
                    category = FindingCategory(category_str)
                except ValueError:
                    category = FindingCategory.SUSPICIOUS_ACTIVITY

                try:
                    confidence = Confidence(confidence_str)
                except ValueError:
                    confidence = Confidence.MEDIUM

                finding = ForensicFinding(
                    category=category,
                    confidence=confidence,
                    title=finding_data.get("title", "Untitled finding"),
                    description=finding_data.get("description", ""),
                    iocs=finding_data.get("iocs", []),
                    mitre_attack=finding_data.get("mitre_attack", []),
                    evidence_sources=[],  # Will be populated by tool call linkage
                )

                # Parse timeline
                timeline_str = finding_data.get("timeline_position")
                if timeline_str:
                    try:
                        finding.timeline_position = datetime.fromisoformat(
                            timeline_str.replace("Z", "+00:00")
                        )
                    except (ValueError, TypeError):
                        pass

                self._findings.append(finding)
                self._execution_logger.log(
                    EventType.FINDING_CREATED,
                    iteration=iteration,
                    data={
                        "finding_id": finding.finding_id,
                        "category": finding.category.value,
                        "confidence": finding.confidence.value,
                        "title": finding.title,
                    },
                )

                logger.info(
                    "finding_extracted",
                    finding_id=finding.finding_id,
                    category=category.value,
                    confidence=confidence.value,
                    title=finding.title,
                )

            except (json.JSONDecodeError, KeyError, TypeError) as e:
                logger.debug("finding_extraction_skipped", reason=str(e))
                continue
