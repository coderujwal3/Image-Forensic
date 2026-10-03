"""Professional DFIR HTML Report Generator with self-contained interactive components."""

import base64
import html
from typing import Any, Dict, List, Optional
from forensic_image.core.constants import FindingStatus, Severity


class HTMLReporter:
    """Generates standalone, responsive, high-assurance digital image forensic reports in HTML format."""

    def render(self, report: Any, title: Optional[str] = None) -> str:
        case_title = title or f"Forensic Analysis: {report.file.filename}"
        
        # Format sizes
        size_kb = round(report.file.size_bytes / 1024.0, 2)
        size_mb = round(size_kb / 1024.0, 2)
        size_str = f"{size_mb} MB ({report.file.size_bytes:,} bytes)" if size_mb >= 1.0 else f"{size_kb} KB ({report.file.size_bytes:,} bytes)"

        # Render quantization matrices if JPEG
        quant_html = self._render_quant_tables(report)

        # Render findings
        findings_html = self._render_findings(report.findings)

        # Render timeline
        timeline_html = self._render_timeline(report.provenance)

        # Render segments
        segments_html = self._render_segments(report.container_structure)

        # Render profiles
        profiles_html = self._render_profiles(report.profile_matches)

        # Render metadata tables
        exif_html = self._render_exif_table(report.metadata.exif)
        xmp_html = self._render_xmp_history(report.metadata.xmp)

        # Thumbnail base64 if present
        thumb_img_tag = ""
        if report.metadata.exif.thumbnail_bytes:
            b64_thumb = base64.b64encode(report.metadata.exif.thumbnail_bytes).decode("ascii")
            thumb_img_tag = f'<img src="data:image/jpeg;base64,{b64_thumb}" class="thumb-preview" alt="Embedded Thumbnail" />'

        html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(case_title)}</title>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --border-color: #30363d;
            --text-primary: #c9d1d9;
            --text-heading: #58a6ff;
            --text-muted: #8b949e;
            --accent-blue: #388bfd;
            --accent-green: #238636;
            --accent-red: #da3633;
            --accent-yellow: #d29922;
            --accent-purple: #8957e5;
        }}
        @media (prefers-color-scheme: light) {{
            :root {{
                --bg-primary: #f6f8fa;
                --bg-secondary: #ffffff;
                --bg-tertiary: #f0f2f5;
                --border-color: #d0d7de;
                --text-primary: #24292f;
                --text-heading: #0969da;
                --text-muted: #57606a;
                --accent-blue: #0969da;
                --accent-green: #1a7f37;
                --accent-red: #cf222e;
                --accent-yellow: #9a6700;
                --accent-purple: #8250df;
            }}
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 24px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }}
        h1 {{ color: var(--text-heading); font-size: 24px; margin-bottom: 8px; display: flex; align-items: center; gap: 12px; }}
        .header-meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; margin-top: 16px; }}
        .meta-item {{ font-size: 13px; }}
        .meta-label {{ color: var(--text-muted); text-transform: uppercase; font-size: 11px; font-weight: 600; letter-spacing: 0.5px; }}
        .meta-val {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; word-break: break-all; }}
        
        .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }}
        .metric-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
            text-align: center;
        }}
        .metric-val {{ font-size: 20px; font-weight: 700; color: var(--text-heading); margin-top: 4px; }}
        .metric-label {{ font-size: 12px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; }}

        .card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 24px;
        }}
        .card-title {{ font-size: 18px; font-weight: 600; color: var(--text-heading); margin-bottom: 16px; border-bottom: 1px solid var(--border-color); padding-bottom: 8px; }}

        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }}
        th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border-color); }}
        th {{ background: var(--bg-tertiary); color: var(--text-muted); font-weight: 600; font-size: 12px; text-transform: uppercase; }}
        tr:hover td {{ background: var(--bg-tertiary); }}

        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .status-observed {{ background: rgba(35, 134, 54, 0.2); color: #3fb950; border: 1px solid rgba(63, 185, 80, 0.4); }}
        .status-derived {{ background: rgba(56, 139, 253, 0.2); color: #58a6ff; border: 1px solid rgba(88, 166, 255, 0.4); }}
        .status-inferred {{ background: rgba(137, 87, 229, 0.2); color: #bc8cff; border: 1px solid rgba(188, 140, 255, 0.4); }}
        .status-not_available {{ background: rgba(139, 148, 158, 0.2); color: #8b949e; border: 1px solid rgba(139, 148, 158, 0.4); }}

        .sev-critical {{ background: #da3633; color: white; }}
        .sev-high {{ background: rgba(218, 54, 51, 0.2); color: #f85149; border: 1px solid rgba(248, 81, 73, 0.4); }}
        .sev-medium {{ background: rgba(210, 153, 34, 0.2); color: #e3b341; border: 1px solid rgba(227, 179, 65, 0.4); }}
        .sev-low {{ background: rgba(56, 139, 253, 0.15); color: #79c0ff; border: 1px solid rgba(121, 192, 255, 0.3); }}
        .sev-info {{ background: rgba(139, 148, 158, 0.15); color: #8b949e; border: 1px solid rgba(139, 148, 158, 0.3); }}

        .timeline-step {{
            position: relative;
            padding-left: 32px;
            padding-bottom: 24px;
            border-left: 2px solid var(--accent-blue);
            margin-left: 12px;
        }}
        .timeline-step:last-child {{ border-left: 2px solid transparent; padding-bottom: 0; }}
        .timeline-bullet {{
            position: absolute;
            left: -9px;
            top: 0;
            width: 16px;
            height: 16px;
            border-radius: 50%;
            background: var(--accent-blue);
            border: 3px solid var(--bg-secondary);
        }}
        .timeline-title {{ font-weight: 700; font-size: 14px; color: var(--text-heading); }}
        .timeline-desc {{ font-size: 13px; color: var(--text-primary); margin-top: 4px; }}
        .timeline-ev {{ font-size: 12px; color: var(--text-muted); font-style: italic; margin-top: 2px; }}

        .matrix-grid {{
            display: grid;
            grid-template-columns: repeat(8, 1fr);
            gap: 2px;
            max-width: 320px;
            margin-top: 8px;
            background: var(--border-color);
            padding: 2px;
            border-radius: 4px;
        }}
        .matrix-cell {{
            background: var(--bg-tertiary);
            text-align: center;
            font-size: 11px;
            font-family: ui-monospace, monospace;
            padding: 4px 2px;
        }}
        .thumb-preview {{
            max-width: 200px;
            max-height: 150px;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            margin-top: 8px;
        }}
        footer {{
            text-align: center;
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 40px;
            border-top: 1px solid var(--border-color);
            padding-top: 16px;
        }}
    </style>
</head>
<body>
<div class="container">
    <header>
        <h1>🔍 Forensic Image Intelligence Report</h1>
        <div class="header-meta">
            <div class="meta-item">
                <div class="meta-label">Evidence Identifier</div>
                <div class="meta-val">{html.escape(report.manifest.evidence_id)}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Target File</div>
                <div class="meta-val">{html.escape(report.file.filename)}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Primary SHA-256 Digest</div>
                <div class="meta-val">{report.hashes.sha256}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Acquisition & Tool</div>
                <div class="meta-val">{html.escape(report.manifest.environment.get('tool', 'forensic-image'))} v{html.escape(report.manifest.environment.get('tool_version', '0.1.0'))} (Python {html.escape(report.manifest.environment.get('python_version', '3'))})</div>
            </div>
        </div>
    </header>

    <div class="metrics-grid">
        <div class="metric-card">
            <div class="metric-label">Format</div>
            <div class="metric-val">{html.escape(report.file.format)}</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Dimensions</div>
            <div class="metric-val">{report.file.width} × {report.file.height}</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Resolution</div>
            <div class="metric-val">{report.file.megapixels} MP</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">File Size</div>
            <div class="metric-val">{size_str.split(' ')[0]} {size_str.split(' ')[1]}</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Findings Count</div>
            <div class="metric-val">{report.findings.count}</div>
        </div>
    </div>

    <!-- Forensic Findings -->
    <div class="card">
        <div class="card-title">⚖️ Forensic Findings & Observations</div>
        <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 12px;">
            Strict epistemic separation: <strong>OBSERVED</strong> (direct binary artifact) vs <strong>DERIVED</strong> (mathematically calculated) vs <strong>INFERRED</strong> (scientific hypothesis with stated limitations).
        </p>
        <table>
            <thead>
                <tr>
                    <th style="width: 120px;">Status</th>
                    <th style="width: 90px;">Severity</th>
                    <th>Finding Title & Evidence Basis</th>
                    <th>Limitations / Alternative Hypotheses</th>
                </tr>
            </thead>
            <tbody>
                {findings_html}
            </tbody>
        </table>
    </div>

    <!-- Hypothesized Processing Sequence -->
    {timeline_html}

    <!-- Metadata Section -->
    <div class="card">
        <div class="card-title">📋 Surviving Metadata Breakdown</div>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 20px;">
            <div>
                <h3 style="font-size: 14px; margin-bottom: 8px;">EXIF Header</h3>
                {exif_html}
            </div>
            <div>
                <h3 style="font-size: 14px; margin-bottom: 8px;">Geolocation (GPS)</h3>
                {self._render_gps_box(report.metadata.exif.gps)}
                
                <h3 style="font-size: 14px; margin: 16px 0 8px 0;">Embedded Thumbnail</h3>
                {thumb_img_tag or '<p style="font-size: 12px; color: var(--text-muted);">No embedded thumbnail located.</p>'}
                {self._render_thumb_details(report.thumbnail)}
            </div>
        </div>
        {xmp_html}
    </div>

    <!-- JPEG Forensics & Quantization -->
    {quant_html}

    <!-- Reference Profiles Consistency -->
    {profiles_html}

    <!-- Container Segments / Chunks -->
    {segments_html}

    <!-- Evidence Integrity & Custody -->
    <div class="card">
        <div class="card-title">🛡️ Evidence Integrity & Chain of Custody</div>
        <table>
            <thead>
                <tr>
                    <th>Hash Algorithm</th>
                    <th>Digest</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>SHA-256</td><td class="meta-val">{report.hashes.sha256}</td></tr>
                <tr><td>MD5</td><td class="meta-val">{report.hashes.md5}</td></tr>
                <tr><td>SHA-1</td><td class="meta-val">{report.hashes.sha1}</td></tr>
                <tr><td>SHA-512</td><td class="meta-val">{report.hashes.sha512}</td></tr>
                <tr><td>Perceptual pHash (DCT)</td><td class="meta-val">{report.similarity.phash or 'N/A'}</td></tr>
                <tr><td>Perceptual dHash (Diff)</td><td class="meta-val">{report.similarity.dhash or 'N/A'}</td></tr>
            </tbody>
        </table>
    </div>

    <footer>
        <p>Generated by <strong>forensic-image</strong> digital image forensics framework.</p>
        <p style="margin-top: 4px; font-size: 11px;">Reproducible forensic analysis. Evidence bytes were not modified during examination.</p>
    </footer>
</div>
</body>
</html>
"""
        return html_out

    def _render_findings(self, findings: Any) -> str:
        rows = []
        for f in findings.items:
            status_class = f"status-{f.status.value.lower()}"
            sev_class = f"sev-{f.severity.value.lower()}"
            
            ev_list = "".join(f"<li>{html.escape(e)}</li>" for e in f.evidence)
            ev_html = f'<ul style="margin: 4px 0 0 16px; font-size: 12px; color: var(--text-muted);">{ev_list}</ul>' if f.evidence else ""

            limit_list = "".join(f"<li>{html.escape(l)}</li>" for l in f.limitations)
            limit_html = f'<ul style="margin: 4px 0 0 16px; font-size: 12px; color: var(--accent-yellow);">{limit_list}</ul>' if f.limitations else "<span style='color: var(--text-muted); font-size: 11px;'>None stated</span>"

            conf_str = f" <small style='color: var(--text-muted);'>({int(f.confidence*100)}% conf)</small>" if f.confidence is not None else ""

            row = f"""
            <tr>
                <td><span class="badge {status_class}">{html.escape(f.status.value)}</span></td>
                <td><span class="badge {sev_class}">{html.escape(f.severity.value)}</span></td>
                <td>
                    <strong>{html.escape(f.title)}</strong>{conf_str}
                    <div style="font-size: 12px; margin-top: 2px;">{html.escape(f.description)}</div>
                    {ev_html}
                </td>
                <td>{limit_html}</td>
            </tr>
            """
            rows.append(row)
        return "\n".join(rows) if rows else "<tr><td colspan='4'>No findings generated.</td></tr>"

    def _render_timeline(self, prov: Dict[str, Any]) -> str:
        if not prov or not prov.get("timeline_steps"):
            return ""

        steps_html = []
        for s in prov.get("timeline_steps", []):
            ev_items = "".join(f"<li>{html.escape(e)}</li>" for e in s.get("evidence_basis", []))
            s_html = f"""
            <div class="timeline-step">
                <div class="timeline-bullet"></div>
                <div class="timeline-title">{html.escape(s.get('stage_name', ''))}</div>
                <div class="timeline-desc">{html.escape(s.get('description', ''))}</div>
                <ul class="timeline-ev">{ev_items}</ul>
            </div>
            """
            steps_html.append(s_html)

        return f"""
        <div class="card">
            <div class="card-title">⏳ Hypothesized Processing Sequence</div>
            <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 16px;">
                NOTE: This sequence is an evidence-based <strong>FORENSIC HYPOTHESIS</strong>, not established historical fact.
            </p>
            <div style="margin-top: 12px;">
                {"".join(steps_html)}
            </div>
        </div>
        """

    def _render_quant_tables(self, report: Any) -> str:
        if not report.jpeg or not report.jpeg.quantization_tables:
            return ""

        tables_html = []
        for tid, q_obj in report.jpeg.quantization_tables.items():
            name = "Luminance (Y / Table 0)" if tid == 0 else f"Chrominance (Table {tid})"
            cells = "".join(f'<div class="matrix-cell">{val}</div>' for val in q_obj.values_natural)
            est_q = report.quantization.get("table_qualities", {}).get(tid, "N/A")
            mae = report.quantization.get("mae_from_standard", {}).get(tid, 0.0)
            t_box = f"""
            <div style="margin-right: 24px;">
                <h4 style="font-size: 13px; margin-bottom: 4px;">{name}</h4>
                <div style="font-size: 11px; color: var(--text-muted);">Est. Quality: ~{est_q}% (IJG MAE: {mae:.2f})</div>
                <div class="matrix-grid">{cells}</div>
            </div>
            """
            tables_html.append(t_box)

        sub_str = report.subsampling.get("subsampling", "Unknown")
        prog_str = "Progressive" if report.jpeg.is_progressive else "Baseline Sequential"

        return f"""
        <div class="card">
            <div class="card-title">🔬 JPEG Quantization & Binary Forensics</div>
            <div style="margin-bottom: 12px; font-size: 13px;">
                <strong>Encoding:</strong> {prog_str} | 
                <strong>Chroma Subsampling:</strong> {sub_str} | 
                <strong>Restart Interval:</strong> {report.jpeg.restart_interval}
            </div>
            <div style="display: flex; flex-wrap: wrap;">
                {"".join(tables_html)}
            </div>
        </div>
        """

    def _render_exif_table(self, exif: Any) -> str:
        if not exif or not exif.is_present:
            return "<p style='font-size: 12px; color: var(--text-muted);'>EXIF metadata absent.</p>"

        rows = []
        fields = [
            ("Make", exif.make),
            ("Model", exif.model),
            ("Software", exif.software),
            ("Date/Time Original", exif.date_time_original),
            ("Date/Time Digitized", exif.date_time_digitized),
            ("Lens Make/Model", f"{exif.lens_make or ''} {exif.lens_model or ''}".strip() or None),
            ("Focal Length", f"{exif.focal_length_mm} mm" if exif.focal_length_mm else None),
            ("F-Number", f"f/{exif.f_number}" if exif.f_number else None),
            ("Exposure Time", exif.exposure_time),
            ("ISO", str(exif.iso) if exif.iso else None),
            ("Orientation", str(exif.orientation) if exif.orientation else None),
            ("Declared Dimensions", f"{exif.exif_image_width} × {exif.exif_image_height}" if exif.exif_image_width else None),
        ]
        for label, val in fields:
            if val:
                rows.append(f"<tr><td>{html.escape(label)}</td><td>{html.escape(str(val))}</td></tr>")

        return f"<table><tbody>{''.join(rows)}</tbody></table>" if rows else "<p style='font-size: 12px; color: var(--text-muted);'>No standard EXIF fields decoded.</p>"

    def _render_gps_box(self, gps: Any) -> str:
        if not gps or not gps.has_coordinates:
            return "<p style='font-size: 12px; color: var(--text-muted);'>GPS metadata stripped / absent.</p>"

        lat = gps.latitude
        lon = gps.longitude
        alt = f"{gps.altitude_m} m" if gps.altitude_m is not None else "N/A"
        time_str = gps.timestamp or "N/A"
        map_url = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}"

        return f"""
        <table>
            <tbody>
                <tr><td>Latitude</td><td>{lat}</td></tr>
                <tr><td>Longitude</td><td>{lon}</td></tr>
                <tr><td>Altitude</td><td>{alt}</td></tr>
                <tr><td>GPS Timestamp</td><td>{html.escape(time_str)}</td></tr>
                <tr><td>OpenStreetMap Link</td><td><a href="{map_url}" target="_blank" style="color: var(--accent-blue);">View on Map ↗</a></td></tr>
            </tbody>
        </table>
        """

    def _render_thumb_details(self, thumb: Any) -> str:
        if not thumb or not thumb.is_present:
            return ""
        discrepancy = "<span style='color: var(--accent-red); font-weight: 700;'>YES</span>" if thumb.has_discrepancy else "<span style='color: var(--accent-green);'>NO</span>"
        return f"""
        <div style="font-size: 12px; margin-top: 6px;">
            <div><strong>Source:</strong> {html.escape(thumb.source_type or 'Unknown')}</div>
            <div><strong>Dimensions:</strong> {thumb.width} × {thumb.height} (AR: {thumb.aspect_ratio})</div>
            <div><strong>Size:</strong> {thumb.byte_size} bytes</div>
            <div><strong>Discrepancy with Main:</strong> {discrepancy}</div>
        </div>
        """

    def _render_xmp_history(self, xmp: Any) -> str:
        if not xmp or not xmp.history:
            return ""

        rows = []
        for h_ev in xmp.history:
            row = f"""
            <tr>
                <td>{html.escape(h_ev.action or '')}</td>
                <td>{html.escape(h_ev.software_agent or '')}</td>
                <td>{html.escape(h_ev.timestamp or '')}</td>
                <td>{html.escape(h_ev.parameters or h_ev.changed or '')}</td>
            </tr>
            """
            rows.append(row)

        return f"""
        <div style="margin-top: 20px;">
            <h3 style="font-size: 14px; margin-bottom: 8px;">Adobe XMP Modification History Sequence (xmpMM:History)</h3>
            <table>
                <thead>
                    <tr><th>Action</th><th>Software Agent</th><th>Timestamp</th><th>Parameters / Changed</th></tr>
                </thead>
                <tbody>
                    {"".join(rows)}
                </tbody>
            </table>
        </div>
        """

    def _render_profiles(self, profiles: List[Any]) -> str:
        if not profiles:
            return ""

        rows = []
        for p in profiles[:5]:  # Top 5
            score_pct = int(p.consistency_score * 100)
            rows.append(f"""
            <tr>
                <td><strong>{html.escape(p.display_name)}</strong></td>
                <td><span class="badge" style="background: rgba(56, 139, 253, 0.2); color: var(--accent-blue);">{html.escape(p.category)}</span></td>
                <td><strong>{score_pct}%</strong></td>
                <td style="font-size: 12px;">{html.escape(p.interpretation)}</td>
            </tr>
            """)

        return f"""
        <div class="card">
            <div class="card-title">🎯 Platform Reference Profile Consistency</div>
            <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 8px;">
                Measures structural consistency against experimentally measured platform profiles. Does NOT constitute attribution.
            </p>
            <table>
                <thead>
                    <tr><th>Profile</th><th>Category</th><th>Consistency</th><th>Interpretation</th></tr>
                </thead>
                <tbody>
                    {"".join(rows)}
                </tbody>
            </table>
        </div>
        """

    def _render_segments(self, container: Any) -> str:
        if not container or not getattr(container, "segments", None):
            return ""

        rows = []
        for seg in container.segments[:30]:  # Limit display to 30
            code_str = f"0x{seg.code:04X}" if seg.code else "-"
            rows.append(f"""
            <tr>
                <td><strong>{html.escape(seg.name)}</strong></td>
                <td>{code_str}</td>
                <td>{seg.offset}</td>
                <td>{seg.length}</td>
                <td style="font-size: 12px; color: var(--text-muted);">{html.escape(seg.description or '')}</td>
            </tr>
            """)

        return f"""
        <div class="card">
            <div class="card-title">🧱 Container Segments & Binary Layout</div>
            <table>
                <thead>
                    <tr><th>Segment / Marker</th><th>Code</th><th>Offset</th><th>Length (bytes)</th><th>Description</th></tr>
                </thead>
                <tbody>
                    {"".join(rows)}
                </tbody>
            </table>
        </div>
        """
