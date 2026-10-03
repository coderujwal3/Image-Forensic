"""Rich terminal reporter with ASCII forensic boxes and evidence strength meters."""

import io
from typing import Any
from rich.box import ROUNDED, DOUBLE_EDGE
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from forensic_image.core.constants import FindingStatus, Severity


class TerminalReporter:
    """Formats forensic reports for professional terminal presentation."""

    def __init__(self) -> None:
        self.console = Console(record=True, width=100)

    def render(self, report: Any) -> None:
        """Prints formatted report directly to terminal console."""
        self._build_display(report, self.console)

    def render_to_string(self, report: Any) -> str:
        """Captures rendered report as an ANSI string."""
        buf = io.StringIO()
        con = Console(file=buf, force_terminal=True, width=100)
        self._build_display(report, con)
        return buf.getvalue()

    def _build_display(self, report: Any, con: Console) -> None:
        # Title Banner
        title_text = Text("FORENSIC IMAGE INTELLIGENCE REPORT", style="bold cyan")
        subtitle = Text(f"ID: {report.manifest.evidence_id} | Created: {report.created_at}", style="dim")
        con.print(Panel(Text.assemble(title_text, "\n", subtitle), border_style="cyan", box=DOUBLE_EDGE))

        # 1. Evidence Overview Table
        ev_table = Table(title="Evidence Overview", box=ROUNDED, show_header=False, expand=True)
        ev_table.add_column("Property", style="bold white", width=22)
        ev_table.add_column("Value", style="green", no_wrap=False, overflow="fold")

        size_kb = round(report.file.size_bytes / 1024.0, 2)
        size_mb = round(size_kb / 1024.0, 2)
        size_str = f"{size_mb} MB ({report.file.size_bytes:,} bytes)" if size_mb >= 1.0 else f"{size_kb} KB ({report.file.size_bytes:,} bytes)"

        ev_table.add_row("File Basename", report.file.filename)
        ev_table.add_row("SHA-256 (Evidence ID)", report.hashes.sha256)
        ev_table.add_row("MD5", report.hashes.md5)
        ev_table.add_row("Container Format", f"{report.file.format} ({report.file.mime_type})")
        ev_table.add_row("File Size", size_str)
        dim_str = f"{report.file.width} × {report.file.height} ({report.file.megapixels} MP, AR: {report.file.aspect_ratio:.2f})"
        ev_table.add_row("Dimensions", dim_str)
        con.print(ev_table)

        # 2. Metadata Status Table
        meta_table = Table(title="Surviving Metadata & Containers", box=ROUNDED, expand=True)
        meta_table.add_column("Domain", style="bold white")
        meta_table.add_column("Status", justify="center")
        meta_table.add_column("Summary / Artifacts", style="yellow")

        # EXIF
        exif_stat = "[bold green]PRESENT[/]" if report.metadata.exif.is_present else "[dim red]ABSENT[/]"
        exif_summary = (
            f"Device: {report.metadata.exif.make or 'Unknown'} {report.metadata.exif.model or ''} | Date: {report.metadata.exif.date_time_original or 'None'}"
            if report.metadata.exif.is_present
            else "No surviving EXIF headers"
        )
        meta_table.add_row("EXIF", exif_stat, exif_summary)

        # GPS
        gps_stat = "[bold green]PRESENT[/]" if report.metadata.exif.gps.has_coordinates else "[dim red]ABSENT[/]"
        gps_summary = (
            f"Lat: {report.metadata.exif.gps.latitude}, Lon: {report.metadata.exif.gps.longitude} (Alt: {report.metadata.exif.gps.altitude_m}m)"
            if report.metadata.exif.gps.has_coordinates
            else "Stripped / Not available"
        )
        meta_table.add_row("GPS Geolocation", gps_stat, gps_summary)

        # XMP
        xmp_stat = "[bold green]PRESENT[/]" if report.metadata.xmp.is_present else "[dim red]ABSENT[/]"
        xmp_summary = (
            f"Tool: {report.metadata.xmp.creator_tool or 'Unknown'} | History events: {len(report.metadata.xmp.history)}"
            if report.metadata.xmp.is_present
            else "No XMP packet detected"
        )
        meta_table.add_row("Adobe XMP", xmp_stat, xmp_summary)

        # IPTC
        iptc_stat = "[bold green]PRESENT[/]" if report.metadata.iptc.is_present else "[dim red]ABSENT[/]"
        iptc_summary = (
            f"Headline: {report.metadata.iptc.headline or 'None'} | Creator: {report.metadata.iptc.byline_creator or 'None'}"
            if report.metadata.iptc.is_present
            else "No IPTC-NAA blocks"
        )
        meta_table.add_row("IPTC Editorial", iptc_stat, iptc_summary)

        # ICC
        icc_stat = "[bold green]PRESENT[/]" if report.metadata.icc.is_present else "[dim red]ABSENT[/]"
        icc_summary = (
            f"{report.metadata.icc.description or 'Custom profile'} ({report.metadata.icc.device_class_name or 'Unknown class'})"
            if report.metadata.icc.is_present
            else "Default sRGB / No ICC profile"
        )
        meta_table.add_row("ICC Color Profile", icc_stat, icc_summary)

        # Thumbnail
        thumb_stat = "[bold green]PRESENT[/]" if report.thumbnail.is_present else "[dim red]ABSENT[/]"
        thumb_summary = (
            f"{report.thumbnail.width}x{report.thumbnail.height} ({report.thumbnail.byte_size} bytes, AR: {report.thumbnail.aspect_ratio})"
            if report.thumbnail.is_present
            else "No embedded thumbnail"
        )
        meta_table.add_row("Embedded Thumbnail", thumb_stat, thumb_summary)
        con.print(meta_table)

        # 3. JPEG & Encoding Characteristics (if JPEG)
        if report.jpeg:
            jpeg_table = Table(title="JPEG Binary & Encoding Characteristics", box=ROUNDED, expand=True)
            jpeg_table.add_column("Property", style="bold white")
            jpeg_table.add_column("Value", style="cyan")

            prog_str = "Progressive (SOF2)" if report.jpeg.is_progressive else "Baseline Sequential (SOF0)"
            jpeg_table.add_row("Encoding Mode", prog_str)
            sub_str = report.subsampling.get("subsampling", "Unknown")
            jpeg_table.add_row("Chroma Subsampling", sub_str)
            est_q = report.quantization.get("estimated_quality", "Unknown")
            is_ijg = report.quantization.get("is_standard_ijg", False)
            q_str = f"~{est_q}% ({'Standard IJG Table' if is_ijg else 'Custom / Camera Table'})"
            jpeg_table.add_row("Estimated Quality", q_str)
            jpeg_table.add_row("Quantization Tables Count", str(len(report.jpeg.quantization_tables)))
            jpeg_table.add_row("Huffman Tables Count", str(len(report.jpeg.huffman_tables)))
            jpeg_table.add_row("Restart Interval (DRI)", str(report.jpeg.restart_interval))
            if report.jpeg.has_trailing_data:
                jpeg_table.add_row(
                    "[bold red]Trailing Payload Detected[/]",
                    f"[bold red]{report.jpeg.trailing_data_length} bytes after EOI at offset {report.jpeg.trailing_data_offset}[/]",
                )
            con.print(jpeg_table)

        # 4. Forensic Findings Table
        f_table = Table(title=f"Forensic Findings ({report.findings.count} Total)", box=ROUNDED, expand=True)
        f_table.add_column("Status", width=14, justify="center")
        f_table.add_column("Severity", width=10, justify="center")
        f_table.add_column("Finding Title & Evidence Basis")

        for f in report.findings.items:
            # Color status
            if f.status == FindingStatus.OBSERVED:
                status_styled = "[bold green]OBSERVED[/]"
            elif f.status == FindingStatus.DERIVED:
                status_styled = "[bold blue]DERIVED[/]"
            elif f.status == FindingStatus.INFERRED:
                status_styled = "[bold magenta]INFERRED[/]"
            elif f.status == FindingStatus.NOT_AVAILABLE:
                status_styled = "[dim white]NOT_AVAIL[/]"
            else:
                status_styled = f"[dim]{f.status.value}[/]"

            # Color severity
            if f.severity == Severity.CRITICAL:
                sev_styled = "[bold red on white]CRITICAL[/]"
            elif f.severity == Severity.HIGH:
                sev_styled = "[bold red]HIGH[/]"
            elif f.severity == Severity.MEDIUM:
                sev_styled = "[bold yellow]MEDIUM[/]"
            elif f.severity == Severity.LOW:
                sev_styled = "[cyan]LOW[/]"
            else:
                sev_styled = "[dim]INFO[/]"

            body = Text()
            body.append(f"{f.title}\n", style="bold")
            body.append(f"{f.description}\n", style="dim")
            if f.evidence:
                body.append("Evidence: " + " | ".join(f.evidence) + "\n", style="italic green")
            if f.limitations:
                body.append("Limitations: " + "; ".join(f.limitations), style="dim italic yellow")

            f_table.add_row(status_styled, sev_styled, body)
        con.print(f_table)

        # 5. Provenance Timeline Hypothesis
        prov = report.provenance
        if prov and prov.get("timeline_steps"):
            con.print("\n[bold cyan]HYPOTHESIZED PROCESSING SEQUENCE[/] [dim](Forensic Hypothesis, Not Established History)[/]")
            steps = prov.get("timeline_steps", [])
            for s in steps:
                con.print(f"  [bold yellow]Step {s.get('step_number')}:[/] [bold white]{s.get('stage_name')}[/]")
                con.print(f"    [dim]{s.get('description')}[/]")
                if s.get("step_number") < len(steps):
                    con.print("          [bold cyan]↓[/]")

        # 6. Evidence Strength Meter
        obs_c = report.findings.observed_count
        der_c = report.findings.derived_count
        inf_c = report.findings.inferred_count
        max_c = max(1, obs_c, der_c, inf_c)

        con.print("\n[bold white]Evidence Strength Breakdown[/]")
        con.print(f"  Observed:  {'█' * int((obs_c / max_c) * 20)} [green]({obs_c})[/]")
        con.print(f"  Derived:   {'█' * int((der_c / max_c) * 20)} [blue]({der_c})[/]")
        con.print(f"  Inferred:  {'█' * int((inf_c / max_c) * 20)} [magenta]({inf_c})[/]")
        con.print("-" * 100)
