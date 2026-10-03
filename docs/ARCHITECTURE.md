# System Architecture: `forensic-image`

## High-Level Design Principles

The `forensic-image` library is architected from the ground up for **scientific rigor, evidence preservation, explainability, defensive parsing, and modular extensibility**.

```
                           ┌───────────────────────────────┐
                           │   Evidence Ingestion (Path)   │
                           └───────────────┬───────────────┘
                                           │
                                           ▼
                           ┌───────────────────────────────┐
                           │      ImageEvidence Core       │
                           │  - Immutable byte buffer      │
                           │  - Immediate SHA-256/MD5      │
                           │  - Chain-of-Custody Manifest  │
                           └───────────────┬───────────────┘
                                           │
                  ┌────────────────────────┼────────────────────────┐
                  ▼                        ▼                        ▼
       ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐
       │   Container Parser  │  │   Metadata Parser   │  │   Perceptual Hashes │
       │  - SafeBinaryReader │  │  - EXIF (TIFF IFD)  │  │  - pHash (2D DCT)   │
       │  - JPEG Markers/DQT │  │  - GPS Geolocation  │  │  - dHash (Gradient) │
       │  - PNG Chunks / CRC │  │  - Adobe XMP (Def)  │  │  - aHash (Average)  │
       │  - WebP RIFF / VP8X │  │  - IPTC-NAA / 8BIM  │  │  - wHash (Wavelet)  │
       │  - Trailing Payload │  │  - ICC Color Profile│  │  - Hamming Distance │
       └──────────┬──────────┘  └──────────┬──────────┘  └──────────┬──────────┘
                  │                        │                        │
                  └────────────────────────┼────────────────────────┘
                                           │
                                           ▼
                           ┌───────────────────────────────┐
                           │    Forensic Analysis Engine   │
                           │  - Quantization / Quality     │
                           │  - Chroma Subsampling (4:2:0) │
                           │  - Recompression / Benford    │
                           │  - Dimension / Cropping       │
                           │  - Tampering Inconsistencies  │
                           │  - Screenshot Resolution Match│
                           │  - Reference Profile Matcher  │
                           │  - Provenance Timeline Hypo   │
                           │  - Pixel Forensics (ELA) [Exp]│
                           └───────────────┬───────────────┘
                                           │
                                           ▼
                           ┌───────────────────────────────┐
                           │     Master ForensicReport     │
                           │  - Categorized Findings       │
                           │    (OBSERVED/DERIVED/INFERRED)│
                           │  - JSON / HTML / Terminal     │
                           └───────────────────────────────┘
```

## Modular Layering

### 1. Core Layer (`forensic_image.core`)
* **`evidence.py` (`ImageEvidence`)**: Immutable evidence container. Guarantees that evidence bytes are niemals mutated during analysis.
* **`reader.py` (`SafeBinaryReader`)**: Zero-crash bounded binary stream reader with strict bounds checking and memory allocation thresholds.
* **`manifest.py` (`EvidenceManifest`)**: Audit logging for chain-of-custody tracking.
* **`findings.py` (`Finding`, `FindingsList`)**: Strongly typed forensic findings enforcing epistemic status:
  - `OBSERVED`: Raw structural artifact.
  - `DERIVED`: Deterministic mathematical derivation.
  - `INFERRED`: Inductive hypothesis with limitations.
  - `NOT_AVAILABLE`: Missing metadata attribute.
* **`report.py` (`ForensicReport`)**: Master Pydantic model integrating all domains.

### 2. Format & Container Parsers (`forensic_image.formats`)
* **`detector.py`**: Magic byte detection for JPEG, PNG, WebP, TIFF, GIF, BMP, AVIF, HEIC.
* **`jpeg.py`**: Parser for ITU-T T.81 JPEG markers (SOI, EOI, DQT, DHT, SOF0/1/2, SOS, DRI, APP0-APP15). Detects trailing payload after EOI.
* **`png.py`**: Chunk parser for PNG format (IHDR, sRGB, iCCP, eXIf, tEXt, zTXt, iTXt, IDAT, IEND) with CRC-32 validation and trailing data detection.
* **`webp.py`**: RIFF WebP container parser with VP8X feature parsing.

### 3. Metadata Parsers (`forensic_image.metadata`)
* **`exif.py`**: Direct TIFF IFD parser handling both Big-Endian (`MM`) and Little-Endian (`II`), GPS decoding, and safe MakerNotes recognition.
* **`xmp.py`**: XML Entity Expansion (XXE) protected parser using `defusedxml`, extracting `xmpMM:History` modification sequences.
* **`iptc.py`**: Adobe Photoshop APP13 8BIM envelope and IPTC-NAA record 2 dataset decoder.
* **`icc.py`**: International Color Consortium profile header and tag table parser.
* **`thumbnail.py`**: Embedded thumbnail extraction, aspect ratio comparison, and perceptual similarity divergence check.

### 4. Forensic Analyzers (`forensic_image.forensics`)
Pluggable analyzers extending `BaseAnalyzer`:
* `QuantizationAnalyzer`: Compares observed tables against standard Independent JPEG Group (IJG) tables across quality factors 1-100.
* `SubsamplingAnalyzer`: Determines component sampling ratios (4:4:4, 4:2:2, 4:2:0, 4:4:0, 4:1:1).
* `RecompressionAnalyzer`: Detects periodic comb-filtering in DCT histograms and first-digit Benford's Law divergences.
* `TransformationAnalyzer`: Identifies spatial downscaling, camera sensor aspect ratio deviations, and common web bounding thresholds.
* `TamperingAnalyzer`: Flags dimension discrepancies between EXIF tags and decoded frames, software markers, and appended payloads.
* `ScreenshotAnalyzer`: Compares aspect ratios and exact dimensions against known mobile and desktop display resolutions.
* `ProvenanceAnalyzer`: Synthesizes an evidence-backed timeline hypothesis of processing steps.
* `PixelForensicAnalyzer`: Experimental Error Level Analysis (ELA) and noise variance estimation.

### 5. Hashing & Fingerprinting (`forensic_image.hashing`)
* **Cryptographic**: MD5, SHA-1, SHA-256, SHA-512.
* **Perceptual**: pHash (DCT-based), dHash (difference gradient), aHash (average), wHash (wavelet).

### 6. Reference Profiles (`forensic_image.profiles`)
Corpus of experimentally measured platform profiles (WhatsApp, Instagram, Twitter/X, Apple Camera, Photoshop, iOS Screenshots). Matcher computes normalized consistency score without making unwarranted attribution claims.

### 7. Reporting (`forensic_image.reporting`)
* **Terminal**: Rich-based console output with ASCII borders and evidence strength bars.
* **JSON**: Canonical machine-readable JSON.
* **HTML**: Self-contained interactive report with dark/light mode and collapsible sections.
