from modules.challenge_classifier import classify_challenge
from modules.scoring_engine import calculate_interest_score
from modules.recommendation_engine import generate_recommendations
from modules.solve_planner import generate_solve_plan
from modules.report_generator import generate_report


def build_zip_encoding_results():
    return {
        "base64": [],
        "hex": [],
        "decoded_flags": [],
        "recursive_layers": [],
        "payloads": [
            {
                "source_encoding": "base64",
                "payload_type": "ZIP Archive",
                "confidence": 100,
                "route": "archive_analysis",
                "reason": "Known file signature detected.",
                "preview": "PK TEST"
            }
        ]
    }


def test_payload_classification():
    result = classify_challenge(
        file_type="Unknown File Type",
        analysis_plan=[],
        findings={},
        encoding_results=build_zip_encoding_results(),
        archive_results={}
    )

    assert result["category"] == "Archive"
    assert result["confidence"] == 75
    assert result["secondary_category"] == "Encoding / Crypto"


def test_payload_scoring():
    result = calculate_interest_score(
        findings={},
        detected_flags=[],
        encoding_results=build_zip_encoding_results()
    )

    assert result["score"] == 25
    assert result["level"] == "MEDIUM"


def test_payload_recommendation():
    score_result = calculate_interest_score(
        findings={},
        detected_flags=[],
        encoding_results=build_zip_encoding_results()
    )

    recommendations = generate_recommendations(
        file_type="Unknown File Type",
        findings={},
        detected_flags=[],
        score_result=score_result,
        encoding_results=build_zip_encoding_results()
    )

    assert any(
        "decoded ZIP Archive" in item
        for item in recommendations
    )


def test_payload_solve_plan():
    classification = classify_challenge(
        file_type="Unknown File Type",
        analysis_plan=[],
        findings={},
        encoding_results=build_zip_encoding_results(),
        archive_results={}
    )

    plan = generate_solve_plan(
        file_type="Unknown File Type",
        findings={},
        detected_flags=[],
        encoding_results=build_zip_encoding_results(),
        archive_results={},
        classification_result=classification
    )

    assert plan[0]["priority"] == 95
    assert (
        plan[0]["action"]
        == "Analyze the decoded archive payload."
    )


def test_professional_report(tmp_path):
    test_file = tmp_path / "challenge.txt"
    test_file.write_text(
        "FalconCTF test",
        encoding="utf-8"
    )

    encoding_results = build_zip_encoding_results()

    classification = classify_challenge(
        file_type="Unknown File Type",
        analysis_plan=[],
        findings={},
        encoding_results=encoding_results,
        archive_results={}
    )

    score = calculate_interest_score(
        findings={},
        detected_flags=[],
        encoding_results=encoding_results
    )

    recommendations = generate_recommendations(
        file_type="Unknown File Type",
        findings={},
        detected_flags=[],
        score_result=score,
        encoding_results=encoding_results
    )

    solve_plan = generate_solve_plan(
        file_type="Unknown File Type",
        findings={},
        detected_flags=[],
        encoding_results=encoding_results,
        archive_results={},
        classification_result=classification
    )

    report_path = generate_report(
        file_path=str(test_file),
        file_type="Unknown File Type",
        hashes={},
        findings={},
        detected_flags=[],
        score_result=score,
        recommendations=recommendations,
        encoding_results=encoding_results,
        classification_result=classification,
        solve_plan=solve_plan,
        output_dir=str(tmp_path)
    )

    report_text = open(
        report_path,
        encoding="utf-8"
    ).read()

    assert "Challenge Classification" in report_text
    assert "Payload Intelligence" in report_text
    assert "ZIP Archive" in report_text
    assert "Interest Score" in report_text
    assert "Intelligent Solve Plan" in report_text
    assert "End of FalconCTF Report" in report_text


def test_no_intelligence_fallback():
    recommendations = generate_recommendations(
        file_type="Unknown File Type",
        findings={},
        detected_flags=[],
        score_result={"score": 0},
        encoding_results={}
    )

    assert any(
        "No strong indicators were detected"
        in item
        for item in recommendations
    )
