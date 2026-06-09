"""Self-Correction Engine — Detects and fixes agent mistakes.

Core hackathon requirement: the agent must 'recognize when something
doesn't add up and self-correct when it gets it wrong.'

This module checks findings for:
1. Temporal impossibilities (event B before event A, but A is prerequisite)
2. Contradictions between findings
3. Claims without evidence source (potential hallucinations)
4. Confidence downgrades when corroboration fails
"""

from __future__ import annotations

from typing import Any

import structlog

from ..core.findings import Confidence, FindingCategory, ForensicFinding

logger = structlog.get_logger()


class SelfCorrector:
    """Checks findings for logical consistency and flags issues.

    Returns correction actions that the agent loop applies.
    """

    def check(self, findings: list[ForensicFinding]) -> list[dict[str, Any]]:
        """Run all consistency checks on current findings.

        Returns list of correction actions to apply.
        """
        corrections: list[dict[str, Any]] = []

        corrections.extend(self._check_unsupported_claims(findings))
        corrections.extend(self._check_temporal_consistency(findings))
        corrections.extend(self._check_contradictions(findings))

        if corrections:
            logger.info("self_correction_triggered", count=len(corrections))

        return corrections

    def _check_unsupported_claims(
        self, findings: list[ForensicFinding]
    ) -> list[dict[str, Any]]:
        """Flag findings with no evidence sources (potential hallucinations).

        Rule: Any finding with confidence > LOW must have at least one
        evidence source linking it to a specific tool execution.
        """
        corrections = []
        for finding in findings:
            if finding.confidence in (Confidence.CONFIRMED, Confidence.HIGH, Confidence.MEDIUM):
                if not finding.evidence_sources:
                    corrections.append({
                        "finding_id": finding.finding_id,
                        "reason": "No evidence source for non-LOW confidence finding",
                        "action": "downgrade_to_hallucination_suspected",
                        "original_confidence": finding.confidence.value,
                    })
                    finding.confidence = Confidence.HALLUCINATION_SUSPECTED
                    finding.self_correction_note = (
                        "Downgraded: claimed evidence without tool execution backing it"
                    )
        return corrections

    def _check_temporal_consistency(
        self, findings: list[ForensicFinding]
    ) -> list[dict[str, Any]]:
        """Check that timeline positions are logically consistent.

        Example: If finding A says 'malware executed at 14:00' and finding B
        says 'malware downloaded at 15:00', that's a contradiction.
        """
        corrections = []
        timed_findings = [f for f in findings if f.timeline_position is not None]

        # Sort by timeline
        timed_findings.sort(key=lambda f: f.timeline_position)  # type: ignore[arg-type]

        # Look for causal impossibilities
        # (This is a skeleton — full implementation would use causal graph)
        for i, finding in enumerate(timed_findings):
            for related_id in finding.related_findings:
                related = next(
                    (f for f in timed_findings if f.finding_id == related_id), None
                )
                if related and related.timeline_position and finding.timeline_position:
                    # If this finding depends on related but happens before it
                    if (
                        "after" in finding.description.lower()
                        and finding.timeline_position < related.timeline_position
                    ):
                        corrections.append({
                            "finding_id": finding.finding_id,
                            "reason": f"Temporal contradiction with {related_id}",
                            "action": "flag_for_reinvestigation",
                        })

        return corrections

    def _check_contradictions(
        self, findings: list[ForensicFinding]
    ) -> list[dict[str, Any]]:
        """Detect directly contradicting findings.

        Example: Finding A says 'svchost.exe is legitimate' but Finding B
        says 'svchost.exe has injected code' — same IOC, opposite conclusions.
        """
        corrections = []

        # Separate benign from non-benign findings
        benign_findings = [f for f in findings if f.category == FindingCategory.BENIGN]
        malicious_findings = [f for f in findings if f.category != FindingCategory.BENIGN]

        # Check for shared IOCs between benign and malicious findings
        for b in benign_findings:
            for m in malicious_findings:
                shared_iocs = set(b.iocs) & set(m.iocs)
                if shared_iocs:
                    corrections.append({
                        "finding_id": b.finding_id,
                        "reason": f"Contradicts malicious finding {m.finding_id} on IOC {shared_iocs}",
                        "action": "reinvestigate_both",
                        "related_finding": m.finding_id,
                    })

        return corrections
