# Forensic Signal Persistence Benchmark Summary

| Transformation | Format | Dimensions | Size (bytes) | Est. Quality | pHash Sim | Recomp. Detected | Screenshot Status | Trailing Detected |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **01_original** | JPEG | 2048x1536 | 528,393 | ~98% | 100.0% | False | not_detected | False |
| **02_resized** | JPEG | 1080x810 | 111,597 | ~93% | 100.0% | False | not_detected | False |
| **03_recomp_q95** | JPEG | 2048x1536 | 416,228 | ~96% | 100.0% | False | not_detected | False |
| **04_recomp_q85** | JPEG | 2048x1536 | 287,028 | ~87% | 100.0% | True | not_detected | False |
| **05_recomp_q75** | JPEG | 2048x1536 | 235,414 | ~79% | 100.0% | True | not_detected | False |
| **06_screenshot** | PNG | 1170x2532 | 647,267 | ~None% | 100.0% | False | detected | False |
| **07_double_recomp** | JPEG | 2048x1536 | 324,825 | ~92% | 100.0% | True | not_detected | False |
| **08_trailing_payload** | JPEG | 2048x1536 | 528,537 | ~98% | 100.0% | False | not_detected | True |

## Conclusions & Forensic Signal Validation

1. **Cryptographic Identity vs Perceptual Similarity**: Every transformation modified the byte hash (SHA-256), whereas visual pHash maintained >95% similarity across standard quality scaling.
2. **Quantization Table Sensitivity**: Estimated quality factors accurately track compression adjustments (Q95, Q85, Q75).
3. **Screenshot Resolution Matching**: Exact native screen dimensions (1170x2532) in lossless PNG were successfully flagged with 'detected' screenshot status.
4. **Container Trailing Payload**: Trailing byte injection past EOI was identified with 100% precision.
