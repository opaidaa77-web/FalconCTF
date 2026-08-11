from modules.payload_inspector import inspect_payload


def test_plain_text():
    result = inspect_payload(
        "FalconCTF normal readable text"
    )

    assert result["route"] == "text_analysis"


def test_flag_payload():
    result = inspect_payload(
        "FalconCTF{pytest_flag_test}"
    )

    assert result["route"] == "verify_flag"
    assert result["flags"]


def test_base64_payload():
    result = inspect_payload(
        "RmFsY29uQ1RGIHBheWxvYWQ="
    )

    assert result["route"] == "encoding_analysis"
    assert result["decoded_quality"] > 0


def test_rejected_base64_payload():
    result = inspect_payload(
        "AAECAwQFBgcICQ=="
    )

    assert result["route"] == "stop_recursive_decoding"
    assert result["decoded_quality"] == 0.0


def test_hex_payload():
    result = inspect_payload(
        "46616c636f6e435446207061796c6f6164"
    )

    assert result["route"] == "encoding_analysis"
    assert result["decoded_quality"] > 0


def test_zip_payload():
    result = inspect_payload(
        b"PK\x03\x04TEST-DATA"
    )

    assert result["route"] == "archive_analysis"
    assert result["confidence"] == 100


def test_elf_payload():
    result = inspect_payload(
        b"\x7fELFTEST-DATA"
    )

    assert result["route"] == "binary_analysis"
    assert result["confidence"] == 100


def test_png_payload():
    result = inspect_payload(
        b"\x89PNG\r\n\x1a\nTEST-DATA"
    )

    assert result["route"] == "forensics"
    assert result["confidence"] == 100


def test_two_word_plain_text():
    result = inspect_payload(
        "hello world"
    )

    assert result["payload_type"] == "Readable Text"
    assert result["route"] == "text_analysis"


def test_wrapped_base64_payload():
    result = inspect_payload(
        "RmFsY29u Q1RGIHBh eWxvYWQ="
    )

    assert result["payload_type"] == "Base64"
    assert result["route"] == "encoding_analysis"
