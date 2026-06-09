"""Tests for the self-correction engine."""

from phantom_sift.agent.self_correction import SelfCorrector
from phantom_sift.core.findings import (
    Confidence,
    EvidenceSource,
    FindingCategory,
    ForensicFinding,
)


def test_unsupported_claim_detected():
    """High-confidence finding without evidence source should be flagged."""
    corrector = SelfCorrector()
    findings = [
        ForensicFinding(
            category=FindingCategory.MALWARE_EXECUTION,
            confidence=Confidence.HIGH,
            title="Malware found",
            description="Something malicious",
            evidence_sources=[],  # No evidence!
        )
    ]

    corrections = corrector.check(findings)
    assert len(corrections) == 1
    assert corrections[0]["action"] == "downgrade_to_hallucination_suspected"
    assert findings[0].confidence == Confidence.HALLUCINATION_SUSPECTED


def test_supported_claim_passes():
    """Finding with evidence source should not be flagged."""
    corrector = SelfCorrector()
    findings = [
        ForensicFinding(
            category=FindingCategory.PERSISTENCE,
            confidence=Confidence.HIGH,
            title="Registry key found",
            description="Run key entry",
            evidence_sources=[
                EvidenceSource(tool_name="regripper", tool_call_id="c1")
            ],
        )
    ]

    corrections = corrector.check(findings)
    assert len(corrections) == 0


def test_low_confidence_no_evidence_ok():
    """LOW confidence findings without evidence are acceptable (inferred)."""
    corrector = SelfCorrector()
    findings = [
        ForensicFinding(
            category=FindingCategory.SUSPICIOUS_ACTIVITY,
            confidence=Confidence.LOW,
            title="Possible lateral movement",
            description="Inferred from timeline gap",
            evidence_sources=[],
        )
    ]

    corrections = corrector.check(findings)
    assert len(corrections) == 0


def test_contradiction_detected():
    """Conflicting benign + malicious findings on same IOC should be flagged."""
    corrector = SelfCorrector()
    findings = [
        ForensicFinding(
            category=FindingCategory.BENIGN,
            confidence=Confidence.MEDIUM,
            title="svchost.exe is legitimate",
            description="Standard Windows service",
            iocs=["svchost.exe"],
            evidence_sources=[
                EvidenceSource(tool_name="vol_pslist", tool_call_id="c1")
            ],
        ),
        ForensicFinding(
            category=FindingCategory.MALWARE_EXECUTION,
            confidence=Confidence.HIGH,
            title="svchost.exe injected",
            description="Malfind detected injected code",
            iocs=["svchost.exe"],
            evidence_sources=[
                EvidenceSource(tool_name="vol_malfind", tool_call_id="c2")
            ],
        ),
    ]

    corrections = corrector.check(findings)
    # Should flag the contradiction
    contradiction_corrections = [
        c for c in corrections if c["action"] == "reinvestigate_both"
    ]
    assert len(contradiction_corrections) >= 1
