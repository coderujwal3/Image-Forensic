"""Unit tests for ImageEvidence core, integrity, and manifests."""

from pathlib import Path
import pytest
from forensic_image.core.constants import ImageFormat
from forensic_image.core.evidence import ImageEvidence
from forensic_image.core.exceptions import VerificationError


def test_evidence_instantiation_from_path(clean_jpeg_path: Path) -> None:
    evidence = ImageEvidence(clean_jpeg_path, operator="Special Agent Smith")
    assert evidence.filename == "clean_photo.jpg"
    assert evidence.format == ImageFormat.JPEG
    assert evidence.mime_type == "image/jpeg"
    assert evidence.dimensions == (800, 600)
    assert len(evidence.raw_bytes) > 0

    # Cryptographic hashes presence
    assert len(evidence.hashes.sha256) == 64
    assert len(evidence.hashes.md5) == 32
    assert len(evidence.hashes.sha1) == 40
    assert len(evidence.hashes.sha512) == 128
    assert evidence.hashes.size_bytes == clean_jpeg_path.stat().st_size
    assert evidence.evidence_id.startswith("EVID-")


def test_evidence_instantiation_from_bytes(clean_jpeg_path: Path) -> None:
    raw = clean_jpeg_path.read_bytes()
    evidence = ImageEvidence(raw, filename="memory_test.jpg")
    assert evidence.filename == "memory_test.jpg"
    assert evidence.format == ImageFormat.JPEG
    assert evidence.hashes.size_bytes == len(raw)


def test_evidence_immutability(clean_jpeg_path: Path) -> None:
    evidence = ImageEvidence(clean_jpeg_path)
    initial_bytes = evidence.raw_bytes
    initial_hash = evidence.hashes.sha256

    # Attempting to mutate returned bytes must not affect internal state
    raw_copy = bytearray(initial_bytes)
    raw_copy[0] = 0x00

    assert evidence.raw_bytes[0] == 0xFF  # Still JPEG SOI 0xFF
    assert evidence.hashes.sha256 == initial_hash


def test_evidence_verification(clean_jpeg_path: Path) -> None:
    evidence = ImageEvidence(clean_jpeg_path)
    correct_hash = evidence.hashes.sha256
    assert evidence.verify(correct_hash) is True

    # Bad hash must raise VerificationError
    bad_hash = "0" * 64
    with pytest.raises(VerificationError):
        evidence.verify(bad_hash)


def test_evidence_manifest_audit_events(clean_jpeg_path: Path) -> None:
    evidence = ImageEvidence(clean_jpeg_path, operator="Lead Investigator")
    report = evidence.analyze(operator="Lead Investigator")

    manifest = report.manifest
    assert manifest.evidence_id == evidence.evidence_id
    assert len(manifest.custody_chain) >= 2  # ACQUIRED and ANALYZED
    assert manifest.custody_chain[0].action == "ACQUIRED"
    assert manifest.custody_chain[-1].action == "ANALYZED"
    assert manifest.verify_manifest() is True
