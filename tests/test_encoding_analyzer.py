import base64
from pathlib import Path

from modules.encoding_analyzer import analyze_encoded_data


def test_existing_base64_and_hex_fixture():
    fixture = Path(
        "tests/samples/encoded_test.txt"
    )

    strings = fixture.read_text(
        encoding="utf-8"
    ).splitlines()

    results = analyze_encoded_data(
        strings
    )

    base64_decoded = [
        item["decoded"]
        for item in results["base64"]
    ]

    hex_decoded = [
        item["decoded"]
        for item in results["hex"]
    ]

    assert "flag{encoded_test}" in base64_decoded
    assert "flag{hex_test}" in hex_decoded


def test_recursive_encoding_chain():
    flag = (
        "FalconCTF{pytest_recursive_test}"
    )

    layer3 = base64.b64encode(
        flag.encode()
    ).decode()

    layer2 = layer3.encode().hex()

    layer1 = base64.b64encode(
        layer2.encode()
    ).decode()

    results = analyze_encoded_data(
        [layer1]
    )

    layers = results[
        "recursive_layers"
    ]

    assert len(layers) >= 3

    assert layers[0]["type"] == "base64"
    assert layers[1]["type"] == "hex"
    assert layers[2]["type"] == "base64"

    assert flag in results[
        "decoded_flags"
    ]


def test_short_base64_zip_payload():
    raw_payload = (
        b"PK\x03\x04TEST"
    )

    encoded = base64.b64encode(
        raw_payload
    ).decode()

    results = analyze_encoded_data(
        [encoded]
    )

    payloads = results[
        "payloads"
    ]

    assert payloads

    assert any(
        payload["route"]
        == "archive_analysis"
        and payload["confidence"] == 100
        for payload in payloads
    )


def test_base64_zip_payload_type():
    raw_payload = (
        b"PK\x03\x04TEST-DATA"
    )

    encoded = base64.b64encode(
        raw_payload
    ).decode()

    results = analyze_encoded_data(
        [encoded]
    )

    assert any(
        payload["payload_type"]
        == "ZIP Archive"
        and payload["route"]
        == "archive_analysis"
        for payload in results["payloads"]
    )


def test_hex_elf_payload():
    raw_payload = (
        b"\x7fELFTEST-DATA"
    )

    encoded = raw_payload.hex()

    results = analyze_encoded_data(
        [encoded]
    )

    assert any(
        payload["route"]
        == "binary_analysis"
        and payload["confidence"] == 100
        for payload in results["payloads"]
    )


def test_empty_input():
    results = analyze_encoded_data(
        []
    )

    assert results["base64"] == []
    assert results["hex"] == []
    assert results["decoded_flags"] == []
    assert results["recursive_layers"] == []
    assert results["payloads"] == []


def test_decoded_payload_export(tmp_path):
    raw_payload = (
        b"PK\x03\x04FALCONCTF-DATA"
    )

    encoded = base64.b64encode(
        raw_payload
    ).decode()

    results = analyze_encoded_data(
        [encoded],
        save_payloads=True,
        output_dir=str(tmp_path)
    )

    exported = [
        payload
        for payload in results["payloads"]
        if payload.get("saved_path")
    ]

    assert exported

    saved_path = Path(
        exported[0]["saved_path"]
    )

    assert saved_path.exists()
    assert saved_path.suffix == ".zip"
    assert saved_path.read_bytes() == raw_payload
