"""Report Generator — Structured forensic report output.

Adapted from SOAR's report_generator pattern.
Produces both machine-readable (JSON) and human-readable (Markdown) reports.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..core.findings import AnalysisResult, Confidence, ForensicFinding


def generate_report(result: AnalysisResult, output_dir: Path) -> dict[str, Path]:
    """Generate analysis report in multiple formats.

    Returns paths to generated report files.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    # JSON report (machine-readable)
    json_path = output_dir / f"report_{timestamp}.json"
    json_report = result.model_dump(mode="json")
    json_path.write_text(json.dumps(json_report, indent=2, default=str))

    # Markdown report (human-readable)
    md_path = output_dir / f"report_{timestamp}.md"
    md_path.write_text(_render_markdown(result))

    return {"json": json_path, "markdown": md_path}


def _render_markdown(result: AnalysisResult) -> str:
    """Render analysis result as a Markdown report."""
    lines = [
        "# 👻 Phantom SIFT — Forensic Analysis Report\n",
        f"**Case:** `{result.case_path}`  ",
        f"**Evidence Type:** {result.evidence_type}  ",
        f"**Started:** {result.started_at.isoformat() if result.started_at else 'N/A'}  ",
        f"**Completed:** {result.completed_at.isoformat() if result.completed_at else 'N/A'}  ",
        "",
        "## Executive Summary\n",
        f"- **Total findings:** {len(result.findings)}",
        f"- **Confirmed (multi-source):** {len(result.confirmed_findings)}",
        f"- **Suspected hallucinations:** {len(result.suspected_hallucinations)}",
        f"- **Iterations used:** {result.iterations_used}",
        f"- **Self-corrections:** {result.self_corrections}",
        f"- **Total tool calls:** {result.total_tool_calls}",
        f"- **Total tokens:** {result.total_tokens:,}",
        "",
        "---\n",
        "## Findings\n",
    ]

    for i, finding in enumerate(result.findings, 1):
        confidence_emoji = {
            Confidence.CONFIRMED: "🟢",
            Confidence.HIGH: "🔵",
            Confidence.MEDIUM: "🟡",
            Confidence.LOW: "⚪",
            Confidence.HALLUCINATION_SUSPECTED: "🔴",
        }.get(finding.confidence, "⚪")

        lines.extend([
            f"### {i}. {confidence_emoji} {finding.title}\n",
            f"**Category:** {finding.category.value}  ",
            f"**Confidence:** {finding.confidence.value}  ",
            f"**Finding ID:** `{finding.finding_id}`  ",
            "",
            f"{finding.description}\n",
        ])

        if finding.evidence_sources:
            lines.append("**Evidence Sources:**\n")
            for src in finding.evidence_sources:
                lines.append(
                    f"- `{src.tool_name}` (call: `{src.tool_call_id}`) "
                    f"— {src.artifact_path or 'N/A'}"
                )
            lines.append("")

        if finding.iocs:
            lines.append(f"**IOCs:** `{'`, `'.join(finding.iocs)}`\n")

        if finding.mitre_attack:
            lines.append(f"**MITRE ATT&CK:** {', '.join(finding.mitre_attack)}\n")

        if finding.self_correction_note:
            lines.append(f"⚠️ **Self-correction:** {finding.self_correction_note}\n")

        lines.append("---\n")

    lines.extend([
        "## Audit Trail\n",
        f"Full execution log: `{result.case_id}_execution.jsonl`  ",
        "Every finding is traceable to specific tool executions via `call_id`.\n",
    ])

    return "\n".join(lines)
