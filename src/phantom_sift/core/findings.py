"""Forensic Finding schema — the primary output of the agent.

Adapted from SOAR's UnifiedIncident schema, redesigned for forensic artifacts.
Every finding must trace back to a specific tool execution.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Confidence(str, Enum):
    """Confidence level of a forensic finding."""

    CONFIRMED = "confirmed"  # Corroborated by 2+ tools/artifacts
    HIGH = "high"  # Strong single-source evidence
    MEDIUM = "medium"  # Plausible but needs corroboration
    LOW = "low"  # Inferred, not directly observed
    HALLUCINATION_SUSPECTED = "hallucination_suspected"  # Self-correction flagged this


class FindingCategory(str, Enum):
    """Category of forensic finding."""

    MALWARE_EXECUTION = "malware_execution"
    PERSISTENCE = "persistence"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    CREDENTIAL_ACCESS = "credential_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    INITIAL_ACCESS = "initial_access"
    COMMAND_AND_CONTROL = "command_and_control"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    BENIGN = "benign"


class EvidenceSource(BaseModel):
    """Link a finding to the exact tool execution that produced it."""

    tool_name: str = Field(description="MCP tool that produced this evidence")
    tool_call_id: str = Field(description="Unique ID of the tool call in execution log")
    raw_output_hash: str = Field(default="", description="SHA256 of raw tool output")
    artifact_path: str = Field(default="", description="Path within evidence (e.g., /Windows/Prefetch/)")
    offset: str = Field(default="", description="Byte offset or line number if applicable")
    timestamp_tool_called: datetime = Field(default_factory=datetime.utcnow)


class ForensicFinding(BaseModel):
    """A single forensic finding produced by the agent.

    Design principle: every claim must be traceable to tool output.
    """

    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    category: FindingCategory
    confidence: Confidence
    title: str = Field(description="One-line summary")
    description: str = Field(description="Detailed explanation of what was found")
    evidence_sources: list[EvidenceSource] = Field(
        default_factory=list,
        description="Tool executions that support this finding",
    )
    iocs: list[str] = Field(default_factory=list, description="Indicators of Compromise")
    mitre_attack: list[str] = Field(
        default_factory=list, description="MITRE ATT&CK technique IDs"
    )
    timeline_position: datetime | None = Field(
        default=None, description="When this activity occurred on the target system"
    )
    related_findings: list[str] = Field(
        default_factory=list, description="IDs of corroborating/related findings"
    )
    self_correction_note: str = Field(
        default="",
        description="If this finding was revised, explain what changed and why",
    )
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def is_corroborated(self) -> bool:
        """Finding supported by multiple evidence sources."""
        return len(self.evidence_sources) >= 2


class AnalysisResult(BaseModel):
    """Final output of an agent analysis run."""

    case_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:12])
    case_path: str
    evidence_type: str
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    findings: list[ForensicFinding] = Field(default_factory=list)
    iterations_used: int = 0
    self_corrections: int = 0
    total_tool_calls: int = 0
    total_tokens: int = 0
    success: bool = False
    error: str | None = None

    @property
    def confirmed_findings(self) -> list[ForensicFinding]:
        return [f for f in self.findings if f.confidence == Confidence.CONFIRMED]

    @property
    def suspected_hallucinations(self) -> list[ForensicFinding]:
        return [
            f for f in self.findings if f.confidence == Confidence.HALLUCINATION_SUSPECTED
        ]
