"""Command-Line Interface (CLI) for forensic-image toolkit."""

import json
import sys
from pathlib import Path
from typing import Optional
import click
import shutil
from rich.console import Console

from forensic_image.core.evidence import ImageEvidence
from forensic_image.hashing.perceptual import (
    hamming_distance,
    perceptual_similarity,
)
from forensic_image.reporting.html_reporter import HTMLReporter
from forensic_image.reporting.json_reporter import JSONReporter
from forensic_image.reporting.terminal import TerminalReporter
from forensic_image.version import TOOL_NAME, __version__

console = Console()

terminal_size = shutil.get_terminal_size(fallback=(80, 24))
@click.group(context_settings={"help_option_names": ["-h", "--help"], "terminal_width": terminal_size.columns, "max_content_width": terminal_size.columns})
@click.version_option(version=__version__, prog_name=TOOL_NAME)
def cli() -> None:
    """Professional-grade digital image forensics and evidence intelligence framework."""
    pass


@cli.command("analyze")
@click.argument("image_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--json", "as_json", is_flag=True, help="Output full report as JSON to stdout.")
@click.option("--html", "html_out", type=click.Path(path_type=Path), help="Save interactive HTML report to file.")
@click.option("--pixel", is_flag=True, help="Enable experimental pixel-level Error Level Analysis (ELA).")
@click.option("--operator", default="Forensic Analyst", help="Investigator name for custody manifest.")
def analyze_cmd(image_path: Path, as_json: bool, html_out: Optional[Path], pixel: bool, operator: str) -> None:
    """Executes full forensic investigation pipeline on an evidence file."""
    try:
        evidence = ImageEvidence(image_path, operator=operator)
        report = evidence.analyze(pixel=pixel, operator=operator)

        if html_out:
            report.save_html(str(html_out))
            console.print(f"[bold green]HTML forensic report saved to:[/] {html_out}")

        if as_json:
            click.echo(report.to_json())
        else:
            TerminalReporter().render(report)
    except Exception as e:
        console.print(f"[bold red]Forensic analysis error:[/] {str(e)}", file=sys.stderr)
        sys.exit(1)


@cli.command("info")
@click.argument("image_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def info_cmd(image_path: Path) -> None:
    """Quick forensic overview of an image file."""
    try:
        evidence = ImageEvidence(image_path)
        w, h = evidence.dimensions
        size_kb = round(evidence.hashes.size_bytes / 1024.0, 2)

        console.print(f"[bold cyan]File:[/] {evidence.filename}")
        console.print(f"[bold cyan]Format:[/] {evidence.format.value} ({evidence.mime_type})")
        console.print(f"[bold cyan]Dimensions:[/] {w} × {h}")
        console.print(f"[bold cyan]Size:[/] {size_kb} KB ({evidence.hashes.size_bytes:,} bytes)")
        console.print(f"[bold cyan]SHA-256:[/] {evidence.hashes.sha256}")
        console.print(f"[bold cyan]MD5:[/] {evidence.hashes.md5}")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {str(e)}", file=sys.stderr)
        sys.exit(1)


@cli.command("metadata")
@click.argument("image_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--json", "as_json", is_flag=True, help="Output metadata in JSON format.")
def metadata_cmd(image_path: Path, as_json: bool) -> None:
    """Extracts and displays EXIF, GPS, XMP, IPTC, and ICC metadata."""
    try:
        evidence = ImageEvidence(image_path)
        report = evidence.analyze(
            jpeg=False,
            similarity=False,
            quantization=False,
            subsampling=False,
            recompression=False,
            transformation=False,
            tampering=False,
            screenshot=False,
            pixel=False,
            profiles=False,
            provenance=False,
        )

        if as_json:
            click.echo(report.metadata.model_dump_json(indent=2))
        else:
            meta = report.metadata
            console.print("\n[bold cyan]─── EXIF METADATA ───[/]")
            if meta.exif.is_present:
                for k, v in [
                    ("Make", meta.exif.make),
                    ("Model", meta.exif.model),
                    ("Software", meta.exif.software),
                    ("DateTimeOriginal", meta.exif.date_time_original),
                    ("FocalLength", meta.exif.focal_length_mm),
                    ("FNumber", meta.exif.f_number),
                    ("ExposureTime", meta.exif.exposure_time),
                    ("ISO", meta.exif.iso),
                    ("Orientation", meta.exif.orientation),
                    ("Serial", meta.exif.camera_serial_number),
                ]:
                    if v is not None:
                        console.print(f"  [white]{k}:[/] [yellow]{v}[/]")
            else:
                console.print("  [dim]EXIF metadata absent.[/]")

            console.print("\n[bold cyan]─── GPS GEOLOCATION ───[/]")
            if meta.exif.gps.has_coordinates:
                console.print(f"  [white]Latitude:[/] [green]{meta.exif.gps.latitude}[/]")
                console.print(f"  [white]Longitude:[/] [green]{meta.exif.gps.longitude}[/]")
                console.print(f"  [white]Altitude:[/] [green]{meta.exif.gps.altitude_m} m[/]")
                console.print(f"  [white]Timestamp:[/] [green]{meta.exif.gps.timestamp}[/]")
            else:
                console.print("  [dim]GPS metadata absent.[/]")

            console.print("\n[bold cyan]─── ADOBE XMP ───[/]")
            if meta.xmp.is_present:
                console.print(f"  [white]Creator Tool:[/] {meta.xmp.creator_tool}")
                console.print(f"  [white]History Events:[/] {len(meta.xmp.history)}")
                for idx, ev in enumerate(meta.xmp.history, 1):
                    console.print(f"    {idx}. Action: {ev.action} | Agent: {ev.software_agent} | When: {ev.timestamp}")
            else:
                console.print("  [dim]XMP metadata absent.[/]")

            console.print("\n[bold cyan]─── ICC COLOR PROFILE ───[/]")
            if meta.icc.is_present:
                console.print(f"  [white]Description:[/] {meta.icc.description}")
                console.print(f"  [white]Device Class:[/] {meta.icc.device_class_name}")
                console.print(f"  [white]Color Space:[/] {meta.icc.color_space}")
            else:
                console.print("  [dim]ICC profile absent.[/]")

    except Exception as e:
        console.print(f"[bold red]Error:[/] {str(e)}", file=sys.stderr)
        sys.exit(1)


@cli.command("jpeg")
@click.argument("image_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def jpeg_cmd(image_path: Path) -> None:
    """Inspects JPEG binary structures, markers, and quantization tables."""
    try:
        evidence = ImageEvidence(image_path)
        report = evidence.analyze()

        if not report.jpeg:
            console.print("[yellow]Supplied evidence is not a JPEG container.[/]")
            return

        j = report.jpeg
        console.print(f"[bold cyan]JPEG Mode:[/] {'Progressive (SOF2)' if j.is_progressive else 'Baseline (SOF0)'}")
        console.print(f"[bold cyan]Quantization Tables Count:[/] {len(j.quantization_tables)}")
        console.print(f"[bold cyan]Huffman Tables Count:[/] {len(j.huffman_tables)}")
        console.print(f"[bold cyan]Restart Interval:[/] {j.restart_interval}")
        console.print(f"[bold cyan]Chroma Subsampling:[/] {report.subsampling.get('subsampling', 'Unknown')}")
        console.print(f"[bold cyan]Estimated Quality:[/] ~{report.quantization.get('estimated_quality', 'Unknown')}%")

        if j.has_trailing_data:
            console.print(
                f"[bold red]WARNING: Trailing data detected after EOI: {j.trailing_data_length} bytes at offset {j.trailing_data_offset}![/]"
            )

        console.print("\n[bold white]Segments & Markers Layout:[/]")
        for seg in j.segments[:25]:
            code_str = f"0x{seg.code:04X}" if seg.code else "-"
            console.print(f"  {seg.name:<10} {code_str:<8} Offset: {seg.offset:<8} Len: {seg.length:<8} {seg.description or ''}")

    except Exception as e:
        console.print(f"[bold red]Error:[/] {str(e)}", file=sys.stderr)
        sys.exit(1)


@cli.command("hashes")
@click.argument("image_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def hashes_cmd(image_path: Path) -> None:
    """Computes cryptographic digests and perceptual similarity hashes."""
    try:
        evidence = ImageEvidence(image_path)
        report = evidence.analyze()

        console.print("[bold cyan]─── CRYPTOGRAPHIC EVIDENCE DIGESTS ───[/]")
        console.print("  [dim]Exact byte-for-byte identification[/]")
        console.print(f"  [bold white]SHA-256:[/] [green]{report.hashes.sha256}[/]")
        console.print(f"  [bold white]MD5:[/]     [green]{report.hashes.md5}[/]")
        console.print(f"  [bold white]SHA-1:[/]   [green]{report.hashes.sha1}[/]")
        console.print(f"  [bold white]SHA-512:[/] [green]{report.hashes.sha512}[/]")
        console.print(f"  [bold white]Size:[/]    [green]{report.hashes.size_bytes:,} bytes[/]")

        console.print("\n[bold cyan]─── PERCEPTUAL SIMILARITY FINGERPRINTS ───[/]")
        console.print("  [dim]Visual similarity metrics (tolerate compression / format changes)[/]")
        console.print(f"  [bold white]pHash (DCT):[/]     [yellow]{report.similarity.phash or 'N/A'}[/]")
        console.print(f"  [bold white]dHash (Gradient):[/][yellow]{report.similarity.dhash or 'N/A'}[/]")
        console.print(f"  [bold white]aHash (Average):[/] [yellow]{report.similarity.ahash or 'N/A'}[/]")
        console.print(f"  [bold white]wHash (Wavelet):[/] [yellow]{report.similarity.whash or 'N/A'}[/]")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {str(e)}", file=sys.stderr)
        sys.exit(1)


@cli.command("thumbnail")
@click.argument("image_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--extract", type=click.Path(path_type=Path), help="Path to write extracted thumbnail bytes.")
def thumbnail_cmd(image_path: Path, extract: Optional[Path]) -> None:
    """Inspects embedded thumbnails and extracts thumbnail bytes."""
    try:
        evidence = ImageEvidence(image_path)
        report = evidence.analyze()
        thumb = report.thumbnail

        if not thumb.is_present:
            console.print("[yellow]No embedded thumbnail found in evidence.[/]")
            return

        console.print(f"[bold green]Embedded thumbnail detected![/]")
        console.print(f"  Source: {thumb.source_type}")
        console.print(f"  Dimensions: {thumb.width} × {thumb.height} (AR: {thumb.aspect_ratio})")
        console.print(f"  Byte Size: {thumb.byte_size} bytes")
        console.print(f"  Visual Similarity to Main: {thumb.visual_similarity_to_main}")
        console.print(f"  Discrepancy with Main: {'[bold red]YES[/]' if thumb.has_discrepancy else '[green]NO[/]'}")

        for r in thumb.discrepancy_reasons:
            console.print(f"    [red]• {r}[/]")

        if extract and report.metadata.exif.thumbnail_bytes:
            with open(extract, "wb") as f:
                f.write(report.metadata.exif.thumbnail_bytes)
            console.print(f"[bold green]Thumbnail extracted and saved to:[/] {extract}")

    except Exception as e:
        console.print(f"[bold red]Error:[/] {str(e)}", file=sys.stderr)
        sys.exit(1)


@cli.command("compare")
@click.argument("image1", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("image2", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def compare_cmd(image1: Path, image2: Path) -> None:
    """Performs side-by-side forensic comparison between two images."""
    try:
        ev1 = ImageEvidence(image1)
        ev2 = ImageEvidence(image2)
        r1 = ev1.analyze()
        r2 = ev2.analyze()

        console.print("\n[bold cyan]══════ FORENSIC COMPARISON ══════[/]")
        console.print(f"Image 1: [bold white]{ev1.filename}[/] ({ev1.hashes.size_bytes:,} bytes)")
        console.print(f"Image 2: [bold white]{ev2.filename}[/] ({ev2.hashes.size_bytes:,} bytes)")

        # Byte match
        exact_match = ev1.hashes.sha256 == ev2.hashes.sha256
        if exact_match:
            console.print("[bold green]✔ Byte Identity:[/] Exact match (identical SHA-256 digests)")
        else:
            console.print("[bold red]✘ Byte Identity:[/] Files are not byte-identical")

        # Perceptual match
        p1 = r1.similarity.phash
        p2 = r2.similarity.phash
        if p1 and p2:
            sim = perceptual_similarity(p1, p2)
            dist = hamming_distance(p1, p2)
            console.print(f"Perceptual Similarity (pHash): [bold yellow]{sim:.2%}[/] (Hamming distance: {dist} bits)")

        # Dimensions comparison
        w1, h1 = ev1.dimensions
        w2, h2 = ev2.dimensions
        if (w1, h1) == (w2, h2):
            console.print(f"Dimensions: Identical ({w1} × {h1})")
        else:
            console.print(f"[yellow]Dimensions Differ:[/] Image 1: {w1}×{h1} vs Image 2: {w2}×{h2}")

        # Metadata comparison
        m1 = r1.metadata.exif.is_present
        m2 = r2.metadata.exif.is_present
        console.print(f"EXIF Metadata: Image 1 ({'Present' if m1 else 'Absent'}), Image 2 ({'Present' if m2 else 'Absent'})")

    except Exception as e:
        console.print(f"[bold red]Error:[/] {str(e)}", file=sys.stderr)
        sys.exit(1)


@cli.command("report")
@click.argument("image_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--format", "fmt", type=click.Choice(["text", "json", "html"], case_sensitive=False), default="text")
@click.option("--output", "out_file", type=click.Path(path_type=Path), help="Output destination file.")
def report_cmd(image_path: Path, fmt: str, out_file: Optional[Path]) -> None:
    """Exports structured forensic report in text, JSON, or HTML format."""
    try:
        evidence = ImageEvidence(image_path)
        report = evidence.analyze()

        if fmt == "json":
            out_str = report.to_json()
        elif fmt == "html":
            out_str = HTMLReporter().render(report)
        else:
            out_str = TerminalReporter().render_to_string(report)

        if out_file:
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(out_str)
            console.print(f"[bold green]Report saved to:[/] {out_file}")
        else:
            click.echo(out_str)

    except Exception as e:
        console.print(f"[bold red]Error:[/] {str(e)}", file=sys.stderr)
        sys.exit(1)


@cli.command("verify")
@click.argument("image_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--sha256", required=True, help="Expected SHA-256 hexadecimal hash string.")
def verify_cmd(image_path: Path, sha256: str) -> None:
    """Verifies evidence file cryptographic integrity against expected SHA-256."""
    try:
        evidence = ImageEvidence(image_path)
        evidence.verify(sha256)
        console.print(f"[bold green]INTEGRITY VERIFIED:[/] File matches expected SHA-256 digest ({sha256}).")
    except Exception as e:
        console.print(f"[bold red]INTEGRITY VERIFICATION FAILED:[/] {str(e)}", file=sys.stderr)
        sys.exit(1)


@cli.command("manifest")
@click.argument("image_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def manifest_cmd(image_path: Path) -> None:
    """Outputs forensic evidence manifest and chain-of-custody audit log."""
    try:
        evidence = ImageEvidence(image_path)
        _ = evidence.analyze()  # Records analysis event
        click.echo(json.dumps(evidence._manifest.model_dump(), indent=2))
    except Exception as e:
        console.print(f"[bold red]Error:[/] {str(e)}", file=sys.stderr)
        sys.exit(1)


@cli.command("benchmark")
@click.option("--output", "out_dir", type=click.Path(path_type=Path), default=Path("benchmark_results"))
def benchmark_cmd(out_dir: Path) -> None:
    """Runs reproducible experimental benchmark across multi-generational transformations."""
    from research.experiments.compression_benchmark import run_compression_benchmark
    try:
        console.print("[bold cyan]Launching Forensic Benchmark Suite...[/]")
        run_compression_benchmark(out_dir)
        console.print(f"[bold green]Benchmark completed successfully. Results saved in:[/] {out_dir}")
    except Exception as e:
        console.print(f"[bold red]Benchmark error:[/] {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    cli()
