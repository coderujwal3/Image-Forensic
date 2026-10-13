# Forensic Limitations & Boundaries of Certainty

A digital forensic tool becomes scientifically trustworthy only when it clearly communicates its **inherent technical limitations**.

The `forensic-image` library adheres to the following explicit boundaries:

## 1. What Cannot Be Determined

### A. Stripped Metadata Cannot Be Reconstructed
* If EXIF, GPS, or XMP metadata has been removed from an image file, **it cannot be recovered from the remaining pixel payload**.
* The library reports `NOT_AVAILABLE` and explicitly notes that absent metadata cannot be hallucinated.

### B. Platform Attribution Cannot Be Established with Certainty
* Characteristics such as 1600px resizing, 4:2:0 subsampling, baseline encoding, and stripped EXIF are shared by numerous web services, CDNs, messaging apps, and email clients.
* Matching an image to a reference profile establishes **consistency**, not definitive provenance.

### C. Error Level Analysis (ELA) Is Not Proof of Forgery
* ELA highlights localized compression error residuals.
* Edges, high-contrast boundaries, saturated color transitions, and fine textures **naturally produce higher ELA error rates** in unmanipulated images.
* ELA is labeled **experimental** and must never be used alone to declare an image fraudulent.

### D. Single-Generation Recompression at Equal Quality
* Recompressing a JPEG at the identical quality factor ($Q_1 = Q_2$) using the same quantization matrix frequently leaves no detectable periodic artifacts in the DCT histogram.

### E. AI-Generated Images vs Camera Captures
* The library does not claim to magically detect "AI images" using ungrounded heuristics.
* Synthetic or generative images that lack camera metadata and match standard screen/web dimensions are reported as having `indeterminate origin` or consistent with synthetic/screen characteristics.

## 2. Defensive Security Model
Every input image processed by `forensic-image` is treated as **potentially hostile**.

The library mitigates common attack vectors:
1. **Decompression Bombs**: Dimensions exceeding `SecurityLimits.MAX_IMAGE_DIMENSION` (30,000px) or `SecurityLimits.MAX_TOTAL_PIXELS` (100 MP) are rejected before full memory allocation.
2. **Buffer Overflows / Invalid Offsets**: All segment parsing relies on `SafeBinaryReader`, which enforces strict upper bounds and raises `CorruptEvidenceError` on negative seeks or out-of-bounds reads.
3. **XML Entity Attacks (XXE)**: XMP parsing uses `defusedxml.ElementTree` to prevent external entity expansion and recursive entity bomb exploits.
4. **Infinite Loops**: Segment and chunk parsing enforce `SecurityLimits.MAX_SEGMENTS_COUNT = 10,000`.
5. **No Code Execution**: Embedded binary streams (such as MakerNotes or ICC profiles) are parsed as data tables only and never evaluated.
