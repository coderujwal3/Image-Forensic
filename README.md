# forensic-image

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)](https://www.python.org)

**`forensic-image`** is a professional-grade, evidence-driven digital image forensics, evidence preservation, and provenance analysis library for Python.

Designed for cybersecurity researchers, digital forensic investigators (DFIR), incident responders, OSINT researchers, and malware analysts, `forensic-image` moves beyond superficial EXIF viewing to scientifically analyze the structural, statistical, and compression characteristics of digital images.

---

## Core Forensic Philosophy

### 1. Evidence ≠ Interpretation
The library enforces a strict epistemic taxonomy across every finding:
* **`OBSERVED`**: Directly extracted from container headers, binary markers, or metadata tables without heuristic assumptions.
* **`DERIVED`**: Mathematically computed from observed data without statistical uncertainty (e.g. SHA-256 digest, aspect ratio).
* **`INFERRED`**: Scientific deduction backed by statistical models or reference profiles, clearly detailing **supporting evidence, confidence levels, and inherent limitations**.
* **`NOT_AVAILABLE`**: Transparently reports when an expected attribute (e.g. GPS coordinates) is stripped or absent.

### 2. Evidence Integrity & Chain of Custody
* Original evidence bytes are **immutable**.
* Primary evidence identifier is the **SHA-256** digest, calculated immediately upon ingestion.
* Automated chain-of-custody audit logging and evidence manifests.

### 3. Clear Separation Between Identity & Similarity
* **SHA-256 / MD5**: Exact byte-for-byte identity.
* **pHash / dHash / aHash / wHash**: Visual similarity metrics that survive re-encoding and metadata stripping.

### 4. Zero False Attribution
The library **never** claims that an observed quantization table "proves" an image came from a specific platform. Instead, it measures consistency scores against laboratory reference profiles and clearly states non-attribution caveats.

---

## Features

* **Binary Container Parsers**: Defensive, zero-crash stream parsers for JPEG (SOI, DQT, DHT, SOF0/1/2, SOS, DRI, EOI, APP markers), PNG (IHDR, iCCP, eXIf, tEXt, zTXt, iTXt, IDAT, IEND, CRC32 checks), and WebP (RIFF, VP8, VP8L, VP8X).
* **Trailing Payload Detection**: Flags unparsed binary overlays and payloads appended past container end markers (steganography, polyglots, RAR/ZIP appended archives).
* **Quantization & JPEG Forensics**: Extracts luminance/chrominance tables, calculates Mean Absolute Error (MAE) against standard Independent JPEG Group (IJG) tables, and estimates compression quality factors.
* **Chroma Subsampling Detection**: Identifies 4:4:4, 4:2:2, 4:2:0, 4:4:0, 4:1:1, and grayscale configurations directly from frame headers.
* **Metadata Forensics**: Safe TIFF IFD parser for EXIF, decimal GPS coordinate decoding, Defused XML parsing of Adobe XMP with modification history sequences (`xmpMM:History`), Photoshop 8BIM IPTC-NAA records, and ICC color profiles.
* **Thumbnail Forensics**: Extracts embedded EXIF/JFXX thumbnails, compares dimensions and perceptual hashes against the main image, and flags aspect ratio discrepancies and visual content divergence.
* **Recompression & Double Compression Indicators**: Statistical analysis of DCT coefficient histograms for periodic comb-filtering and first-digit Benford's Law divergences.
* **Tampering & Inconsistency Detection**: Flags mismatches between declared EXIF dimensions and actual decoded frames, orientation conflicts, temporal anomalies, and editing software signatures.
* **Screenshot Detection**: Matches image dimensions and aspect ratios against a comprehensive database of native mobile and desktop screen resolutions (iOS, Android, macOS, Windows).
* **Provenance Timeline Hypotheses**: Synthesizes an evidence-backed historical lifecycle hypothesis (`ORIGIN` → `SOFTWARE EDITING` → `RESAMPLING` → `RECOMPRESSION` → `SUPPLIED EVIDENCE`).
* **Experimental Pixel Forensics**: Error Level Analysis (ELA) and spatial noise variance analysis (explicitly labeled experimental with stated limitations).
* **Multi-Format Reporting**: ANSI rich terminal displays, canonical JSON, and interactive standalone HTML reports with dark/light mode.

---

## Installation

```bash
pip install forensic-image
```

For development and research:

```bash
git clone https://github.com/dfir/forensic-image.git
cd forensic-image
pip install -e ".[dev]"
```

---

## Quickstart

### Python API

```python
from forensic_image import analyze, verify, ImageEvidence

# 1. High-level analysis
report = analyze("evidence.jpg")

# 2. Inspect cryptographic digests & dimensions
print(f"SHA-256: {report.hashes.sha256}")
print(f"Dimensions: {report.file.width} x {report.file.height}")

# 3. Inspect metadata
if report.metadata.exif.is_present:
    print(f"Camera: {report.metadata.exif.make} {report.metadata.exif.model}")
    print(f"Capture Time: {report.metadata.exif.date_time_original}")

if report.metadata.exif.gps.has_coordinates:
    print(f"Coordinates: {report.metadata.exif.gps.latitude}, {report.metadata.exif.gps.longitude}")

# 4. Review forensic findings
for finding in report.findings.items:
    print(f"[{finding.status.value}] [{finding.severity.value}] {finding.title}")
    if finding.limitations:
        print(f"  Limitations: {finding.limitations}")

# 5. Export interactive HTML or JSON reports
report.save_html("forensic_report.html")
report.save_json("forensic_report.json")
```

### CLI

```bash
# Full interactive terminal analysis
forensic-image analyze evidence.jpg

# Export standalone HTML report
forensic-image analyze evidence.jpg --html report.html

# Inspect surviving metadata
forensic-image metadata evidence.jpg

# Inspect JPEG markers & quantization tables
forensic-image jpeg evidence.jpg

# Extract and inspect embedded thumbnail
forensic-image thumbnail evidence.jpg --extract thumb.jpg

# Side-by-side comparison of two images
forensic-image compare image1.jpg image2.jpg

# Verify cryptographic evidence integrity
forensic-image verify evidence.jpg --sha256 <expected_hash>
```

---

## Documentation

* [System Architecture](docs/ARCHITECTURE.md)
* [Forensic Methodology](docs/METHODOLOGY.md)
* [Forensic Limitations & Caveats](docs/LIMITATIONS.md)
* [CLI Reference](docs/CLI.md)
* [Research Framework](research/README.md)

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
