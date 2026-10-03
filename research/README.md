# Research Framework & Experimental Benchmarks

This directory contains experimental protocols, reference profile corpora, and benchmark suites for evaluating digital image forensic algorithms.

## Directory Structure

```text
research/
├── README.md
├── datasets/             # Directory for external or generated research image datasets
├── experiments/          # Reproducible test scripts and empirical evaluations
│   └── compression_benchmark.py
└── reference_profiles/   # Community and laboratory-measured platform profiles
```

## Running the Benchmark Experiment

Run the automated transformation and signal persistence benchmark via the CLI:

```bash
forensic-image benchmark --output benchmark_results/
```

Or via Python:

```python
from pathlib import Path
from research.experiments.compression_benchmark import run_compression_benchmark

results = run_compression_benchmark(Path("benchmark_results"))
print(f"Tested {len(results['results'])} transformation variants.")
```

## Evaluated Forensic Signals

1. **Quantization Table Shift**: Measures change in high-frequency DCT quantization values across JPEG quality scales (Q98 -> Q95 -> Q85 -> Q75).
2. **Double Compression Artefacts**: Evaluates periodicity in DCT histograms and first-digit Benford's Law deviation.
3. **Perceptual vs Cryptographic Stability**: Demonstrates how SHA-256 diverges immediately while pHash, dHash, and aHash preserve visual kinship.
4. **Container Integrity**: Validates detection of injected trailing payloads after JPEG `EOI`, PNG `IEND`, and WebP `RIFF`.
5. **Resolution Matching**: Validates screenshot identification across common smartphone and workstation display profiles.
