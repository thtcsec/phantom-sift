"""Tests for ForensicFinding schema and AnalysisResult."""

from datetime import datetime, timezone

from phantom_sift.core.findings import (
    AnalysisResult,
    Confidence,
    EvidenceSource,
    FindingCategory,
    ForensicFinding,
)


def test_finding_creation():
    """Test basic finding creation with all fields."""
    finding = ForensicFinding(
        category=FindingCategory.MALWARE_EXECUTION,
        confidence=Confidence.HIGH,
        title="Suspicious process xmrig.exe executed",
        description="Process xmrig.exe found in prefetch with execution timestamp.",
        evidence_sources=[
            EvidenceSource(
                tool_name="analyze_prefetch",
                tool_call_id="call_001",
                artifact_path="/Windows/Prefetch/XMRIG.EXE-ABCD1234.pf",
            )
        ],
        iocs=["xmrig.exe", "pool.minexmr.com"],
        mitre_attack=["T1496"],
    )
    assert finding.finding_id  # Auto-generated
    assert finding.is_corroborated is False  # Only 1 source
    assert finding.confidence == Confidence.HIGH


def test_finding_corroborated():
    """Test that 2+ evidence sources = corroborated."""
    finding = ForensicFinding(
        category=FindingCategory.PERSISTENCE,
        confidence=Confidence.CONFIRMED,
        title="Registry Run key persistence",
        description="Malware registered in HKLM Run key.",
        evidence_sources=[
            EvidenceSource(tool_name="analyze_registry_hive", tool_call_id="call_010"),
            EvidenceSource(tool_name="get_amcache_entries", tool_call_id="call_011"),
        ],
    )
    assert finding.is_corroborated is True


def test_analysis_result_stats():
    """Test AnalysisResult correctly computes stats."""
    result = AnalysisResult(case_path="/evidence/disk.dd", evidence_type="disk")
    result.findings = [
        ForensicFinding(
            category=FindingCategory.MALWARE_EXECUTION,
            confidence=Confidence.CONFIRMED,
            title="Test",
            description="Test",
            evidence_sources=[
                EvidenceSource(tool_name="t1", tool_call_id="c1"),
                EvidenceSource(tool_name="t2", tool_call_id="c2"),
            ],
        ),
        ForensicFinding(
            category=FindingCategory.SUSPICIOUS_ACTIVITY,
            confidence=Confidence.HALLUCINATION_SUSPECTED,
            title="Suspicious",
            description="Flagged",
        ),
    ]

    assert len(result.confirmed_findings) == 1
    assert len(result.suspected_hallucinations) == 1


def test_finding_serialization():
    """Test finding can be serialized to JSON."""
    finding = ForensicFinding(
        category=FindingCategory.COMMAND_AND_CONTROL,
        confidence=Confidence.MEDIUM,
        title="C2 beacon detected",
        description="Periodic HTTP POST to suspicious domain.",
        iocs=["evil.example.com"],
        timeline_position=datetime(2026, 1, 15, 14, 30, 0, tzinfo=timezone.utc),
    )
    data = finding.model_dump(mode="json")
    assert data["category"] == "command_and_control"
    assert data["confidence"] == "medium"
    assert "evil.example.com" in data["iocs"]
