import gzip
from pathlib import Path

from modules.analysis_router import choose_analysis
from modules.gzip_analyzer import analyze_gzip


def test_gzip_has_own_analysis_route():
    plan = choose_analysis(
        "GZIP Archive"
    )

    assert "gzip_analysis" in plan
    assert "archive_analysis" not in plan


def test_zip_still_uses_zip_analysis():
    plan = choose_analysis(
        "ZIP Archive"
    )

    assert "archive_analysis" in plan
    assert "gzip_analysis" not in plan


def test_gzip_payload_extraction(tmp_path):
    source = tmp_path / "payload.img.gz"

    raw_payload = (
        b"FALCONCTF-GZIP-TEST"
    )

    with gzip.open(source, "wb") as archive:
        archive.write(raw_payload)

    output_dir = tmp_path / "output"

    result = analyze_gzip(
        str(source),
        output_dir=str(output_dir)
    )

    assert result["valid"] is True
    assert result["saved_path"] is not None

    saved = Path(
        result["saved_path"]
    )

    assert saved.exists()
    assert saved.read_bytes() == raw_payload
