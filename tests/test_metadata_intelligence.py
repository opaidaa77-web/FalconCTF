from types import SimpleNamespace

from modules.encoding_analyzer import (
    analyze_encoded_data
)
from modules.metadata_analyzer import (
    analyze_metadata,
    get_metadata_text_values,
    parse_metadata_output
)
from modules.payload_inspector import inspect_payload


def test_parse_metadata_output_extracts_comment():
    metadata = parse_metadata_output(
        "File Type : JPEG\n"
        "Comment : 68656c6c6f\n"
    )

    assert metadata["File Type"] == "JPEG"
    assert metadata["Comment"] == "68656c6c6f"


def test_metadata_analyzer_returns_structured_data(
    monkeypatch,
    tmp_path
):
    sample = tmp_path / "sample.jpg"
    sample.write_bytes(b"fake")

    def fake_run(*args, **kwargs):
        return SimpleNamespace(
            returncode=0,
            stdout=(
                "File Type : JPEG\n"
                "Comment : 68656c6c6f\n"
            )
        )

    monkeypatch.setattr(
        "modules.metadata_analyzer.subprocess.run",
        fake_run
    )

    result = analyze_metadata(
        str(sample)
    )

    assert result["Comment"] == "68656c6c6f"


def test_metadata_hex_reaches_pem_intelligence():
    pem_text = (
        "-----BEGIN PRIVATE KEY-----\n"
        "ZmFrZS1jdGYta2V5\n"
        "-----END PRIVATE KEY-----\n"
    )

    metadata = {
        "Comment": pem_text.encode(
            "utf-8"
        ).hex()
    }

    sources = get_metadata_text_values(
        metadata
    )

    results = analyze_encoded_data(
        sources
    )

    payload_types = {
        payload["payload_type"]
        for payload in results["payloads"]
    }

    assert "PEM Private Key" in payload_types
    assert results["base64"] == []


def test_repeated_character_text_is_low_diversity():
    result = inspect_payload(
        b'"' * 24
    )

    assert result["payload_type"] == (
        "Low-Diversity Text"
    )
    assert result["confidence"] < 100
