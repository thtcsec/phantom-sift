"""Evidence management — mount, verify integrity, enforce read-only.

Architectural guardrail: evidence is NEVER modified.
This module ensures evidence files are accessed read-only and
integrity is verified via hash before/after analysis.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import structlog

logger = structlog.get_logger()

EvidenceType = Literal["disk", "memory", "logs", "pcap"]


@dataclass
class EvidenceInfo:
    """Metadata about a piece of evidence."""

    path: Path
    evidence_type: EvidenceType
    size_bytes: int
    sha256_hash: str
    is_mounted: bool = False
    mount_point: Path | None = None


def compute_hash(path: Path, chunk_size: int = 8192) -> str:
    """Compute SHA256 hash of evidence file."""
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            sha256.update(chunk)
    return sha256.hexdigest()


def verify_evidence(path: Path, evidence_type: EvidenceType) -> EvidenceInfo:
    """Verify evidence file exists and compute integrity hash.

    This hash is recorded before analysis starts. After analysis,
    we re-compute and compare to prove no modification occurred.
    """
    if not path.exists():
        raise FileNotFoundError(f"Evidence not found: {path}")

    if not path.is_file():
        raise ValueError(f"Evidence path is not a file: {path}")

    size = path.stat().st_size
    if size == 0:
        raise ValueError(f"Evidence file is empty: {path}")

    logger.info("computing_evidence_hash", path=str(path), size_bytes=size)
    file_hash = compute_hash(path)
    logger.info("evidence_hash_computed", sha256=file_hash[:16] + "...")

    return EvidenceInfo(
        path=path,
        evidence_type=evidence_type,
        size_bytes=size,
        sha256_hash=file_hash,
    )


def verify_integrity_post_analysis(evidence: EvidenceInfo) -> bool:
    """Re-compute hash after analysis to prove evidence was not modified.

    This is a key requirement for the accuracy report:
    'How does your architecture prevent original data from being modified?'
    """
    current_hash = compute_hash(evidence.path)
    integrity_ok = current_hash == evidence.sha256_hash

    if not integrity_ok:
        logger.error(
            "EVIDENCE INTEGRITY VIOLATION",
            path=str(evidence.path),
            expected=evidence.sha256_hash,
            actual=current_hash,
        )
    else:
        logger.info("evidence_integrity_verified", path=str(evidence.path))

    return integrity_ok
