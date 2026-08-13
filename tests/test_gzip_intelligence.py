import gzip

from modules.challenge_classifier import classify_challenge
from modules.gzip_analyzer import analyze_gzip
from modules.recommendation_engine import generate_recommendations
from modules.solve_planner import generate_solve_plan


def make_gzip_jpeg_payload():
    return {
        "depth": 1,
        "source_encoding": "gzip",
        "encoded": "sample.jpg.gz",
        "payload_type": "JPEG Image",
        "confidence": 100,
        "route": "forensics",
        "reason": (
            "GZIP extraction revealed a known "
            "forensic payload."
        ),
        "preview": "Extracted GZIP payload",
        "saved_path": "output/sample.jpg",
    }


def test_gzip_jpeg_classifies_as_forensics():
    result = classify_challenge(
        "GZIP Archive",
        analysis_plan=[
            "hash_analysis",
            "strings_analysis",
            "gzip_analysis",
        ],
        encoding_results={
            "payloads": [
                make_gzip_jpeg_payload()
            ]
        },
    )

    assert result["category"] == "Forensics"

    assert result[
        "secondary_category"
    ] == "Archive"


def test_gzip_recommendations_do_not_claim_zip():
    recommendations = generate_recommendations(
        "GZIP Archive",
        {},
        score_result={"score": 25},
        encoding_results={
            "payloads": [
                make_gzip_jpeg_payload()
            ]
        },
    )

    assert any(
        "JPEG Image" in item
        for item in recommendations
    )

    assert any(
        "GZIP" in item
        for item in recommendations
    )

    assert not any(
        "archive structure" in item.lower()
        for item in recommendations
    )


def test_gzip_solve_plan_uses_inner_payload():
    steps = generate_solve_plan(
        "GZIP Archive",
        {},
        encoding_results={
            "payloads": [
                make_gzip_jpeg_payload()
            ]
        },
        classification_result={
            "category": "Forensics"
        },
    )

    actions = [
        step["action"]
        for step in steps
    ]

    assert (
        "Inspect the decoded forensic payload."
        in actions
    )

    assert (
        "Continue analysis of the extracted "
        "GZIP payload."
        in actions
    )

    assert (
        "Inspect the archive structure and "
        "nested files."
        not in actions
    )


def test_gzip_analyzer_routes_jpeg_to_forensics(
    tmp_path
):
    source = tmp_path / "image.jpg.gz"

    payload = (
        b"\xff\xd8\xff\xe0"
        b"\x00\x10JFIF\x00\x01"
        b"FALCONCTF-GZIP-INTELLIGENCE"
    )

    with gzip.open(source, "wb") as archive:
        archive.write(payload)

    result = analyze_gzip(
        str(source),
        output_dir=str(
            tmp_path / "output"
        ),
    )

    assert result["valid"] is True
    assert result["inner_type"] == "JPEG Image"
    assert result["inner_route"] == "forensics"
    assert result["inner_confidence"] == 100
