import base64
import binascii
import re


# -------------------------------------------------
# Detection patterns
# -------------------------------------------------

FLAG_PATTERN = re.compile(
    r"[A-Za-z0-9_]{2,32}\{[^{}\r\n]{1,200}\}"
)

BASE64_PATTERN = re.compile(
    r"^[A-Za-z0-9+/]+={0,2}$"
)

HEX_PATTERN = re.compile(
    r"^[0-9A-Fa-f]+$"
)


# -------------------------------------------------
# General helpers
# -------------------------------------------------

def calculate_printable_ratio(data):
    """
    Calculate how much of a byte sequence is human-readable.

    A high ratio usually means the payload is text.
    A low ratio usually means the payload is binary data.
    """

    if not data:
        return 0.0

    printable_count = 0

    for byte in data:
        if (
            32 <= byte <= 126
            or byte in (9, 10, 13)
        ):
            printable_count += 1

    return printable_count / len(data)
def calculate_text_ratio(text):
    """
    Calculate how much of decoded Unicode text is readable.

    Unlike the byte-based printable ratio, this also works
    correctly with valid UTF-8 text containing non-ASCII
    characters.
    """

    if not text:
        return 0.0

    printable_count = 0

    for character in text:
        if (
            character.isprintable()
            or character in "\t\n\r"
        ):
            printable_count += 1

    return printable_count / len(text)

def decode_utf8(data):
    """
    Decode bytes as UTF-8.

    Strict decoding is used intentionally.
    Random binary data should not automatically be treated as text.
    """

    try:
        return data.decode("utf-8")

    except UnicodeDecodeError:
        return None


def normalize_text(text):
    """
    Remove whitespace from an encoding candidate.

    Base64 and hexadecimal strings may contain line breaks
    or spaces in real CTF challenges.
    """

    return "".join(
        text.split()
    )


def create_preview(data, limit=120):
    """
    Create a short safe preview for reports and terminal output.
    """

    text = decode_utf8(data)

    if text is not None:
        cleaned = text.replace(
            "\n",
            "\\n"
        )

        cleaned = cleaned.replace(
            "\r",
            "\\r"
        )

        if len(cleaned) > limit:
            return cleaned[:limit] + "..."

        return cleaned

    hex_preview = data[:40].hex()

    if len(data) > 40:
        hex_preview += "..."

    return hex_preview


# -------------------------------------------------
# Magic-byte detection
# -------------------------------------------------

def detect_magic_type(data):
    """
    Detect common CTF-relevant file formats using magic bytes.

    Returns:
        Dictionary containing:
            type
            route
            confidence
    """

    if data.startswith(
        b"\x89PNG\r\n\x1a\n"
    ):
        return {
            "type": "PNG Image",
            "route": "forensics",
            "confidence": 100
        }

    if data.startswith(
        b"\xff\xd8\xff"
    ):
        return {
            "type": "JPEG Image",
            "route": "forensics",
            "confidence": 100
        }

    if data.startswith(
        b"GIF87a"
    ) or data.startswith(
        b"GIF89a"
    ):
        return {
            "type": "GIF Image",
            "route": "forensics",
            "confidence": 100
        }

    if data.startswith(
        b"PK\x03\x04"
    ):
        return {
            "type": "ZIP Archive",
            "route": "archive_analysis",
            "confidence": 100
        }

    if data.startswith(
        b"\x7fELF"
    ):
        return {
            "type": "ELF Executable",
            "route": "binary_analysis",
            "confidence": 100
        }

    if data.startswith(
        b"%PDF-"
    ):
        return {
            "type": "PDF Document",
            "route": "forensics",
            "confidence": 100
        }

    if data.startswith(
        b"\x1f\x8b"
    ):
        return {
            "type": "GZIP Archive",
            "route": "archive_analysis",
            "confidence": 100
        }

    if data.startswith(
        b"7z\xbc\xaf\x27\x1c"
    ):
        return {
            "type": "7-Zip Archive",
            "route": "archive_analysis",
            "confidence": 100
        }

    if data.startswith(
        b"Rar!\x1a\x07"
    ):
        return {
            "type": "RAR Archive",
            "route": "archive_analysis",
            "confidence": 100
        }

    # -------------------------------------------------
    # Windows PE detection
    # -------------------------------------------------

    if data.startswith(
        b"MZ"
    ):
        if len(data) >= 64:
            pe_offset = int.from_bytes(
                data[60:64],
                byteorder="little"
            )

            if (
                pe_offset >= 0
                and pe_offset + 4 <= len(data)
                and data[
                    pe_offset:pe_offset + 4
                ] == b"PE\x00\x00"
            ):
                return {
                    "type": "PE Executable",
                    "route": "binary_analysis",
                    "confidence": 100
                }

        return {
            "type": "DOS / PE Candidate",
            "route": "binary_analysis",
            "confidence": 75
        }

    return None


# -------------------------------------------------
# Flag detection
# -------------------------------------------------

def detect_payload_flags(data):
    """
    Search readable payload content for flag-like strings.
    """

    text = decode_utf8(data)

    if text is None:
        return []

    return FLAG_PATTERN.findall(
        text
    )


# -------------------------------------------------
# Raw encoding-shape checks
# -------------------------------------------------

def has_base64_shape(text):
    """
    Check whether text structurally resembles Base64.

    Pure hexadecimal strings are intentionally excluded
    because they should be handled by the HEX analyzer.
    """

    cleaned = normalize_text(
        text
    )

    if len(cleaned) < 8:
        return False

    # Pure hexadecimal data gets priority over Base64.
    if (
        len(cleaned) % 2 == 0
        and HEX_PATTERN.fullmatch(cleaned)
    ):
        return False

    if not BASE64_PATTERN.fullmatch(
        cleaned
    ):
        return False

    return True


def has_hex_shape(text):
    """
    Check whether text structurally resembles hexadecimal data.
    """

    cleaned = normalize_text(
        text
    )

    if len(cleaned) < 8:
        return False

    if len(cleaned) % 2 != 0:
        return False

    if not HEX_PATTERN.fullmatch(
        cleaned
    ):
        return False

    return True


# -------------------------------------------------
# Decoded-payload quality
# -------------------------------------------------

def evaluate_decoded_quality(data):
    """
    Estimate whether decoded bytes are meaningful enough
    to justify another recursive decoding step.

    Strong evidence:
        - Flag detected
        - Known file signature
        - Valid readable UTF-8 text
        - Another clear encoding layer

    Binary data without a recognized signature is not treated
    as another text-encoding layer.
    """

    if not data:
        return 0.0

    # A detected flag is strong evidence.
    if detect_payload_flags(data):
        return 1.0

    # Known binary formats are also strong evidence.
    if detect_magic_type(data):
        return 1.0

    # Recursive text decoding should normally produce
    # meaningful UTF-8 text.
    text = decode_utf8(data)

    if text is None:
        return 0.0

    text_ratio = calculate_text_ratio(
        text
    )

    # Another clear encoding layer.
    if has_base64_shape(text):
        if text_ratio >= 0.95:
            return 0.95

        return 0.0

    if has_hex_shape(text):
        if text_ratio >= 0.95:
            return 0.95

        return 0.0

    # Normal readable text.
    if text_ratio >= 0.95:
        return 0.90

    if text_ratio >= 0.85:
        return 0.75

    return 0.0



# -------------------------------------------------
# Base64 validation
# -------------------------------------------------

def try_base64_decode(text):
    """
    Analyze a Base64-shaped candidate.

    The function distinguishes between:

        valid + meaningful Base64
        valid but low-quality Base64 candidate
        invalid Base64

    This allows FalconCTF to explicitly report rejected
    recursive-decoding candidates instead of silently
    accepting false positives.
    """

    if not has_base64_shape(
        text
    ):
        return None

    cleaned = normalize_text(
        text
    )

    padding_needed = (
        -len(cleaned)
    ) % 4

    padded = (
        cleaned
        + "=" * padding_needed
    )

    try:
        decoded = base64.b64decode(
            padded,
            validate=True
        )

    except (
        binascii.Error,
        ValueError
    ):
        return None

    if not decoded:
        return None

    quality = evaluate_decoded_quality(
        decoded
    )

    return {
        "accepted": quality >= 0.75,
        "decoded": decoded,
        "quality": quality
    }



# -------------------------------------------------
# Hex validation
# -------------------------------------------------

def try_hex_decode(text):
    """
    Attempt hexadecimal decoding.

    Like Base64, the result must pass quality validation.
    """

    if not has_hex_shape(
        text
    ):
        return None

    cleaned = normalize_text(
        text
    )

    try:
        decoded = bytes.fromhex(
            cleaned
        )

    except ValueError:
        return None

    if not decoded:
        return None

    quality = evaluate_decoded_quality(
        decoded
    )

    if quality < 0.60:
        return None

    return {
        "decoded": decoded,
        "quality": quality
    }


# -------------------------------------------------
# Main Payload Intelligence Engine
# -------------------------------------------------

def inspect_payload(payload):
    """
    Inspect one decoded payload and determine what it probably is.

    The function does not execute tools or automatically open files.
    It only analyzes the payload and recommends the next route.
    """

    if isinstance(
        payload,
        str
    ):
        raw_data = payload.encode(
            "utf-8"
        )

    elif isinstance(
        payload,
        bytes
    ):
        raw_data = payload

    else:
        raise TypeError(
            "payload must be str or bytes"
        )

    result = {
        "payload_type": "Unknown",
        "confidence": 0,
        "route": "manual_inspection",
        "reason": "",
        "printable_ratio": round(
            calculate_printable_ratio(
                raw_data
            ),
            3
        ),
        "flags": [],
        "preview": create_preview(
            raw_data
        ),
        "decoded_preview": None,
        "decoded_quality": None
    }

    # -------------------------------------------------
    # Flag detection
    # -------------------------------------------------

    flags = detect_payload_flags(
        raw_data
    )

    result["flags"] = flags

    if flags:
        result["payload_type"] = (
            "Flag Candidate"
        )

        result["confidence"] = 100

        result["route"] = (
            "verify_flag"
        )

        result["reason"] = (
            "A flag-like string was detected "
            "inside the payload."
        )

        return result

    # -------------------------------------------------
    # File signature detection
    # -------------------------------------------------

    magic_result = detect_magic_type(
        raw_data
    )

    if magic_result:
        result["payload_type"] = (
            magic_result["type"]
        )

        result["confidence"] = (
            magic_result["confidence"]
        )

        result["route"] = (
            magic_result["route"]
        )

        result["reason"] = (
            "Known file signature detected "
            "in the payload."
        )

        return result

    # -------------------------------------------------
    # Text-based inspection
    # -------------------------------------------------

    text = decode_utf8(
        raw_data
    )

    if text is not None:

        # ---------------------------------------------
        # Base64 candidate
        # ---------------------------------------------

        if has_base64_shape(
            text
        ):
            base64_result = try_base64_decode(
                text
            )

            if base64_result:
                decoded = base64_result[
                    "decoded"
                ]

                quality = base64_result[
                    "quality"
                ]

                # -------------------------------------
                # Accepted Base64
                # -------------------------------------

                if base64_result[
                    "accepted"
                ]:
                    result["payload_type"] = (
                        "Base64"
                    )

                    result["confidence"] = round(
                        quality * 100
                    )

                    result["route"] = (
                        "encoding_analysis"
                    )

                    result["reason"] = (
                        "Payload has valid Base64 structure "
                        "and its decoded content passed "
                        "quality validation."
                    )

                    result["decoded_preview"] = (
                        create_preview(
                            decoded
                        )
                    )

                    result["decoded_quality"] = round(
                        quality,
                        3
                    )

                    return result

                # -------------------------------------
                # Rejected Base64 false positive
                # -------------------------------------

                result["payload_type"] = (
                    "Rejected Base64 Candidate"
                )

                result["confidence"] = 90

                result["route"] = (
                    "stop_recursive_decoding"
                )

                result["reason"] = (
                    "The payload has valid Base64 syntax, "
                    "but the decoded bytes failed meaningful-data "
                    "quality checks. Recursive decoding was stopped "
                    "to reduce false positives."
                )

                result["decoded_preview"] = (
                    create_preview(
                        decoded
                    )
                )

                result["decoded_quality"] = round(
                    quality,
                    3
                )

                return result

        # ---------------------------------------------
        # Hex candidate
        # ---------------------------------------------

        hex_result = try_hex_decode(
            text
        )

        if hex_result:
            decoded = hex_result[
                "decoded"
            ]

            quality = hex_result[
                "quality"
            ]

            result["payload_type"] = (
                "Hex"
            )

            result["confidence"] = round(
                quality * 100
            )

            result["route"] = (
                "encoding_analysis"
            )

            result["reason"] = (
                "Payload has valid hexadecimal structure "
                "and its decoded content passed "
                "quality validation."
            )

            result["decoded_preview"] = (
                create_preview(
                    decoded
                )
            )

            result["decoded_quality"] = round(
                quality,
                3
            )

            return result

    # -------------------------------------------------
    # Readable text
    # -------------------------------------------------

    printable_ratio = (
        calculate_printable_ratio(
            raw_data
        )
    )

    if (
        text is not None
        and printable_ratio >= 0.85
    ):
        result["payload_type"] = (
            "Readable Text"
        )

        result["confidence"] = round(
            printable_ratio * 100
        )

        result["route"] = (
            "text_analysis"
        )

        result["reason"] = (
            "Payload is mostly human-readable text "
            "but no stronger encoding or file signature "
            "was confirmed."
        )

        return result

    # -------------------------------------------------
    # Mixed or binary payload
    # -------------------------------------------------

    if printable_ratio >= 0.50:
        result["payload_type"] = (
            "Mixed Data"
        )

        result["confidence"] = 60

        result["route"] = (
            "manual_inspection"
        )

        result["reason"] = (
            "Payload contains a mixture of printable "
            "and non-printable bytes."
        )

        return result

    result["payload_type"] = (
        "Binary / Low-Quality Data"
    )

    result["confidence"] = 70

    result["route"] = (
        "stop_recursive_decoding"
    )

    result["reason"] = (
        "Decoded payload has low readable-data quality. "
        "Further blind decoding may create false positives."
    )

    return result


# -------------------------------------------------
# Human-readable output
# -------------------------------------------------

def print_payload_result(result):
    """
    Display Payload Intelligence results.
    """

    print("\n" + "=" * 55)
    print("FalconCTF Payload Intelligence")
    print("=" * 55)

    print(
        "Payload Type :",
        result["payload_type"]
    )

    print(
        "Confidence   :",
        f"{result['confidence']}%"
    )

    print(
        "Next Route   :",
        result["route"]
    )

    print(
        "Printable    :",
        result["printable_ratio"]
    )

    print(
        "Reason       :",
        result["reason"]
    )

    print(
        "Preview      :",
        result["preview"]
    )

    if result["decoded_preview"]:
        print(
            "Decoded      :",
            result["decoded_preview"]
        )

    if result["decoded_quality"] is not None:
        print(
            "Decode Quality:",
            result["decoded_quality"]
        )

    if result["flags"]:
        print("\nDetected Payload Flags:")

        for flag in result["flags"]:
            print(
                " -",
                flag
            )
