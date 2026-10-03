# Forensic Methodology & Scientific Principles

## 1. Evidence vs. Interpretation

A foundational failure in automated forensic tooling is presenting an interpretive hypothesis as an absolute fact. `forensic-image` enforces a strict taxonomy:

| Status | Definition | Example |
| :--- | :--- | :--- |
| **`OBSERVED`** | Directly extracted from raw file bytes, container headers, or metadata tables without inference. | Quantization table DQT present; EXIF Make is "Apple". |
| **`DERIVED`** | Computed deterministically from observed facts via mathematical or logical operations without heuristic uncertainty. | SHA-256 digest; Image aspect ratio = 1.333; Total pixels = 3,145,728. |
| **`INFERRED`** | Inductive conclusion based on statistical models, heuristic profiles, or empirical matching. Subject to stated limitations. | Possible prior JPEG recompression; Characteristics consistent with Instagram profile. |
| **`NOT_AVAILABLE`**| An expected forensic field was stripped or absent in the supplied evidence. | No GPS coordinates present in EXIF. |
| **`UNKNOWN`** | Inconclusive or ambiguous forensic evidence. | Indeterminate origin for raw uncompressed image. |

## 2. Cryptographic Identity vs. Visual Similarity

* **Cryptographic Hashes (SHA-256, MD5, SHA-1)**:
  - Establish **exact byte-for-byte identity**.
  - A single bit flip changes the SHA-256 digest entirely (avalanche effect).
  - Used for evidence integrity and chain of custody.
* **Perceptual Hashes (pHash, dHash, aHash, wHash)**:
  - Establish **visual similarity** invariant to minor compression, resizing, or metadata stripping.
  - Expressed via Hamming distance and normalized similarity ($0.0 - 1.0$).
  - **Never** used as proof that two files are byte-identical.

## 3. JPEG Quantization & Quality Factor Estimation

The Independent JPEG Group (IJG) standard quality scaling algorithm maps quality $Q \in [1, 100]$ to a scaling factor $S$:
$$S = \begin{cases} \frac{5000}{Q} & \text{if } Q < 50 \\ 200 - 2Q & \text{if } Q \ge 50 \end{cases}$$

The scaled quantization table value $T[i]$ is computed as:
$$T[i] = \text{clamp}\left(\left\lfloor \frac{T_{50}[i] \cdot S + 50}{100} \right\rfloor, 1, 255\right)$$

The library computes the Mean Absolute Error (MAE) between the observed table and all $Q \in [1, 100]$. If $\text{MAE} = 0$, the encoder is using standard IJG quantization tables (libjpeg, Pillow, MozJPEG). If $\text{MAE} > 3.0$, the table represents custom camera firmware or proprietary encoder optimizations.

## 4. Recompression & Double Quantization Detection

When an image is double compressed at two distinct quality levels ($Q_1 \ne Q_2$), the rounding operations in quantization:
$$c' = \text{round}\left( \text{round}\left(\frac{c}{q_1}\right) \cdot \frac{q_1}{q_2} \right)$$
introduce periodic comb-filtering patterns in the histograms of Discrete Cosine Transform (DCT) AC coefficients.

The library evaluates:
1. **Histogram Periodicity**: Fast Fourier Transform (FFT) analysis on low-frequency AC coefficient distributions to identify periodic comb peaks.
2. **First-Digit Benford's Law Divergence**: Single-compressed natural images obey Benford's logarithmic distribution ($P(d) = \log_{10}(1 + 1/d)$). Double-compressed images exhibit measurable total variation divergence.

## 5. Platform Consistency vs. Source Attribution

The library rejects false attribution claims (e.g. *"This image came from WhatsApp"*). Instead, it compares observed features against laboratory profiles and reports:
> *"The observed characteristics are 88% consistent with reference profile 'WhatsApp Image Delivery'. This alone does not establish source attribution."*
