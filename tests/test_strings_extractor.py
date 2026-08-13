from modules.strings_extractor import (
    LARGE_FILE_THRESHOLD,
    LARGE_FILE_SCAN_LIMIT,
    LARGE_FILE_MAX_STRINGS,
    extract_strings,
    get_string_scan_policy,
)


def test_extract_strings_respects_byte_limit(tmp_path):
    sample = tmp_path / "large_sample.bin"

    sample.write_bytes(
        b"VISIBLE\x00"
        + b"A" * 64
        + b"\x00HIDDEN"
    )

    results = extract_strings(
        str(sample),
        max_bytes=8
    )

    assert "VISIBLE" in results
    assert "HIDDEN" not in results


def test_extract_strings_respects_string_limit(tmp_path):
    sample = tmp_path / "strings.bin"

    sample.write_bytes(
        b"FIRST\x00SECOND\x00THIRD"
    )

    results = extract_strings(
        str(sample),
        max_strings=2
    )

    assert results == [
        "FIRST",
        "SECOND",
    ]


def test_large_file_scan_policy():
    policy = get_string_scan_policy(
        LARGE_FILE_THRESHOLD + 1
    )

    assert policy["limited"] is True
    assert policy["max_bytes"] == LARGE_FILE_SCAN_LIMIT
    assert policy["max_strings"] == LARGE_FILE_MAX_STRINGS
