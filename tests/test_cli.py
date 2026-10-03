"""Unit tests for CLI subcommands."""

from pathlib import Path
from click.testing import CliRunner
from forensic_image.cli.main import cli


def test_cli_info(clean_jpeg_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["info", str(clean_jpeg_path)])
    assert result.exit_code == 0
    assert "clean_photo.jpg" in result.output
    assert "SHA-256:" in result.output


def test_cli_hashes(clean_jpeg_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["hashes", str(clean_jpeg_path)])
    assert result.exit_code == 0
    assert "SHA-256:" in result.output
    assert "pHash" in result.output


def test_cli_analyze(clean_jpeg_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", str(clean_jpeg_path)])
    assert result.exit_code == 0
    assert "FORENSIC IMAGE INTELLIGENCE REPORT" in result.output


def test_cli_analyze_json(clean_jpeg_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", str(clean_jpeg_path), "--json"])
    assert result.exit_code == 0
    assert '"report_id":' in result.output


def test_cli_verify(clean_jpeg_path: Path) -> None:
    from forensic_image.core.evidence import ImageEvidence
    ev = ImageEvidence(clean_jpeg_path)
    correct_hash = ev.hashes.sha256

    runner = CliRunner()
    # Success
    res = runner.invoke(cli, ["verify", str(clean_jpeg_path), "--sha256", correct_hash])
    assert res.exit_code == 0
    assert "INTEGRITY VERIFIED" in res.output

    # Failure
    res_bad = runner.invoke(cli, ["verify", str(clean_jpeg_path), "--sha256", "badhash" * 8])
    assert res_bad.exit_code != 0
