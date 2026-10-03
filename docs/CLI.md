# Command-Line Interface (CLI) Reference

The `forensic-image` command provides an investigator-oriented toolkit for examining image evidence directly from the terminal.

## Synopsis

```bash
forensic-image [OPTIONS] COMMAND [ARGS]...
```

## Commands

### `analyze`
Runs the full forensic investigation pipeline on an evidence file.

```bash
forensic-image analyze evidence.jpg
forensic-image analyze evidence.jpg --json
forensic-image analyze evidence.jpg --html report.html
forensic-image analyze evidence.jpg --pixel  # Enable experimental ELA
```

### `info`
Provides a rapid summary of container format, dimensions, file size, and primary cryptographic digests.

```bash
forensic-image info evidence.jpg
```

### `metadata`
Extracts and categorizes surviving EXIF, GPS, XMP history, IPTC editorial tags, and ICC color profile metadata.

```bash
forensic-image metadata evidence.jpg
forensic-image metadata evidence.jpg --json
```

### `jpeg`
Inspects JPEG binary structures, markers, chroma subsampling ratios, restart intervals, and quantization tables.

```bash
forensic-image jpeg evidence.jpg
```

### `hashes`
Computes cryptographic digests (SHA-256, MD5, SHA-1, SHA-512) and perceptual fingerprints (pHash, dHash, aHash, wHash).

```bash
forensic-image hashes evidence.jpg
```

### `thumbnail`
Extracts and compares embedded thumbnails with the primary image payload.

```bash
forensic-image thumbnail evidence.jpg
forensic-image thumbnail evidence.jpg --extract extracted_preview.jpg
```

### `compare`
Performs side-by-side forensic comparison between two images.

```bash
forensic-image compare original.jpg edited.jpg
```

### `report`
Exports structured reports in text, JSON, or HTML format.

```bash
forensic-image report evidence.jpg --format html --output case_001.html
forensic-image report evidence.jpg --format json --output case_001.json
```

### `verify`
Authenticates evidence file cryptographic integrity against an expected SHA-256 hash.

```bash
forensic-image verify evidence.jpg --sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### `manifest`
Outputs the forensic evidence manifest and chain-of-custody audit log as JSON.

```bash
forensic-image manifest evidence.jpg
```

### `benchmark`
Executes an empirical benchmark evaluating signal persistence across multi-generational transformations.

```bash
forensic-image benchmark --output benchmark_results/
```
