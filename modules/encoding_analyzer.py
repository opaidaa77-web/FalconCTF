import base64
import hashlib
import binascii
import os
import re
from modules.payload_inspector import inspect_payload

MAX_ENCODING_DEPTH = 3


BINARY_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])"
    r"[01]{32,}"
    r"(?![A-Za-z0-9])"
)


BASE64_PATTERN = re.compile(
    r"(?<![A-Za-z0-9+/])"
    r"[A-Za-z0-9+/]{10,}={0,2}"
    r"(?![A-Za-z0-9+/=])"
)

HEX_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"(?:[0-9a-fA-F]{2}){4,}"
    r"(?![A-Za-z0-9_])"
)

FLAG_PATTERN = re.compile(
    r"[A-Za-z0-9_]+{[^{}\r\n]+}"
)


def add_unique(target_list, value):
    if value not in target_list:
        target_list.append(value)


def is_readable_text(text):
    if not text:
        return False

    printable = sum(
        1
        for char in text
        if char.isprintable() or char in "\r\n\t"
    )

    ratio = printable / len(text)

    return ratio >= 0.85


def normalize_binary_text(value):
    """
    Remove whitespace from a possible binary bitstream.
    """

    if not isinstance(value, str):
        return ""

    return "".join(
        value.split()
    )


def is_probable_binary(value):
    """
    Check whether a value looks like meaningful 8-bit
    binary-encoded data.

    The minimum length reduces false positives from short
    numbers that happen to contain only 0 and 1.
    """

    cleaned = normalize_binary_text(
        value
    )

    if len(cleaned) < 32:
        return False

    if len(cleaned) % 8 != 0:
        return False

    if not cleaned:
        return False

    if any(
        char not in "01"
        for char in cleaned
    ):
        return False

    # Require both bit values to reduce obvious noise.
    if "0" not in cleaned or "1" not in cleaned:
        return False

    return True


def get_binary_candidates(text):
    """
    Extract binary bitstreams.

    Supports both continuous bitstreams and streams wrapped
    across whitespace-separated lines/groups.
    """

    candidates = []

    cleaned = normalize_binary_text(
        text
    )

    # Entire input consists only of binary digits/whitespace.
    if is_probable_binary(cleaned):
        candidates.append(
            cleaned
        )

    # Also detect a standalone continuous binary sequence
    # embedded in surrounding text.
    for candidate in BINARY_PATTERN.findall(
        text
    ):
        if (
            is_probable_binary(candidate)
            and candidate not in candidates
        ):
            candidates.append(
                candidate
            )

    return candidates


def is_probable_hex(value):
    if len(value) < 8:
        return False

    # Long 0/1 bitstreams are binary encoding,
    # even though 0 and 1 are technically valid HEX digits.
    if is_probable_binary(value):
        return False

    if len(value) % 2 != 0:
        return False

    return bool(
        re.fullmatch(
            r"[0-9a-fA-F]+",
            value
        )
    )


def is_probable_base64(value):
    if len(value) < 12:
        return False

    # Binary bitstreams can also consist entirely of
    # characters accepted by the Base64 alphabet.
    if is_probable_binary(value):
        return False

    # Pure hexadecimal strings should be
    # handled as HEX, not Base64.
    if is_probable_hex(value):
        return False

    # "=" is only valid at the end.
    if not re.fullmatch(
        r"[A-Za-z0-9+/]+={0,2}",
        value
    ):
        return False

    # Remove existing padding before checking length.
    unpadded = value.rstrip("=")

    remainder = len(unpadded) % 4

    if remainder == 1:
        return False

    return True


def decode_binary_bytes(value):
    """
    Decode an 8-bit binary bitstream into raw bytes.
    """

    if not is_probable_binary(value):
        return None

    cleaned = normalize_binary_text(
        value
    )

    try:
        decoded_bytes = bytes(
            int(
                cleaned[index:index + 8],
                2
            )
            for index in range(
                0,
                len(cleaned),
                8
            )
        )

        if not decoded_bytes:
            return None

        return decoded_bytes

    except ValueError:
        return None


def decode_binary_candidate(value):
    """
    Decode binary data when the result is readable text.

    Raw binary payloads such as JPEG/ZIP/ELF are handled
    separately by Payload Intelligence.
    """

    decoded_bytes = decode_binary_bytes(
        value
    )

    if decoded_bytes is None:
        return None

    decoded_text = decoded_bytes.decode(
        "utf-8",
        errors="ignore"
    )

    if not is_readable_text(
        decoded_text
    ):
        return None

    return decoded_text


def decode_base64_bytes(value):
    if not is_probable_base64(value):
        return None

    try:
        value = value.rstrip("=")

        padding = (-len(value)) % 4

        padded_value = (
            value + ("=" * padding)
        )

        decoded_bytes = base64.b64decode(
            padded_value,
            validate=True
        )

        if not decoded_bytes:
            return None

        return decoded_bytes

    except (
        binascii.Error,
        ValueError
    ):
        return None


def decode_base64_candidate(value):
    decoded_bytes = decode_base64_bytes(
        value
    )

    if decoded_bytes is None:
        return None

    decoded_text = decoded_bytes.decode(
        "utf-8",
        errors="ignore"
    )

    if not is_readable_text(decoded_text):
        return None

    return decoded_text


def decode_hex_bytes(value):
    if not is_probable_hex(value):
        return None

    try:
        decoded_bytes = bytes.fromhex(
            value
        )

        if not decoded_bytes:
            return None

        return decoded_bytes

    except ValueError:
        return None


def decode_hex_candidate(value):
    decoded_bytes = decode_hex_bytes(
        value
    )

    if decoded_bytes is None:
        return None

    decoded_text = decoded_bytes.decode(
        "utf-8",
        errors="ignore"
    )

    if not is_readable_text(decoded_text):
        return None

    return decoded_text

def inspect_decoded_payload(decoded_bytes):
    if decoded_bytes is None:
        return None

    return inspect_payload(
        decoded_bytes
    )


def get_payload_extension(payload_result):
    payload_type = str(
        payload_result.get(
            "payload_type",
            ""
        )
    ).lower()

    extension_map = (
        ("zip archive", ".zip"),
        ("7-zip", ".7z"),
        ("rar", ".rar"),
        ("gzip", ".gz"),
        ("elf", ".elf"),
        ("pe executable", ".exe"),
        ("png", ".png"),
        ("jpeg", ".jpg"),
        ("gif", ".gif"),
        ("pdf", ".pdf")
    )

    for indicator, extension in extension_map:
        if indicator in payload_type:
            return extension

    return ".bin"


def save_decoded_payload(
    decoded_bytes,
    payload_result,
    source_encoding,
    depth,
    output_dir,
    saved_payload_paths
):
    route = str(
        payload_result.get(
            "route",
            ""
        )
    ).lower()

    savable_routes = {
        "archive_analysis",
        "binary_analysis",
        "forensics"
    }

    if route not in savable_routes:
        return None

    digest = hashlib.sha256(
        decoded_bytes
    ).hexdigest()

    if digest in saved_payload_paths:
        return saved_payload_paths[
            digest
        ]

    os.makedirs(
        output_dir,
        exist_ok=True
    )

    extension = get_payload_extension(
        payload_result
    )

    number = len(
        saved_payload_paths
    ) + 1

    filename = (
        f"decoded_payload_{number:03d}_"
        f"{source_encoding}_d{depth}"
        f"{extension}"
    )

    saved_path = os.path.join(
        output_dir,
        filename
    )

    with open(
        saved_path,
        "wb"
    ) as payload_file:
        payload_file.write(
            decoded_bytes
        )

    saved_payload_paths[
        digest
    ] = saved_path

    return saved_path

def extract_flags(text):
    return FLAG_PATTERN.findall(text)


def analyze_single_layer(text):
    findings = []

    # -------------------------------------------------
    # Binary
    # -------------------------------------------------

    binary_candidates = get_binary_candidates(
        text
    )

    for candidate in binary_candidates:
        decoded = decode_binary_candidate(
            candidate
        )

        if decoded is None:
            continue

        finding = {
            "type": "binary",
            "encoded": candidate,
            "decoded": decoded
        }

        if finding not in findings:
            findings.append(
                finding
            )

    # -------------------------------------------------
    # Base64
    # -------------------------------------------------

    base64_candidates = BASE64_PATTERN.findall(text)

    for candidate in base64_candidates:
        decoded = decode_base64_candidate(
            candidate
        )

        if decoded is None:
            continue

        finding = {
            "type": "base64",
            "encoded": candidate,
            "decoded": decoded
        }

        if finding not in findings:
            findings.append(finding)

    # -------------------------------------------------
    # HEX
    # -------------------------------------------------

    hex_candidates = HEX_PATTERN.findall(text)

    for candidate in hex_candidates:
        decoded = decode_hex_candidate(
            candidate
        )

        if decoded is None:
            continue

        finding = {
            "type": "hex",
            "encoded": candidate,
            "decoded": decoded
        }

        if finding not in findings:
            findings.append(finding)

    return findings


def analyze_encoded_data(
    strings,
    save_payloads=False,
    output_dir="output/decoded_payloads"
):
    results = {
        "binary": [],
        "base64": [],
        "hex": [],
        "decoded_flags": [],
        "recursive_layers": [],
        "payloads": []
    }

    visited = set()
    saved_payload_paths = {}

    def inspect_encoding_payloads(text, depth):
        # -------------------------------------------------
        # Binary payload inspection
        # -------------------------------------------------

        binary_candidates = get_binary_candidates(
            text
        )

        for candidate in binary_candidates:
            decoded_bytes = decode_binary_bytes(
                candidate
            )

            if decoded_bytes is None:
                continue

            payload_result = inspect_decoded_payload(
                decoded_bytes
            )

            if payload_result is None:
                continue

            saved_path = None

            if save_payloads:
                saved_path = save_decoded_payload(
                    decoded_bytes=decoded_bytes,
                    payload_result=payload_result,
                    source_encoding="binary",
                    depth=depth,
                    output_dir=output_dir,
                    saved_payload_paths=saved_payload_paths
                )

            payload_record = {
                "depth": depth,
                "source_encoding": "binary",
                "encoded": candidate,
                "payload_type": payload_result[
                    "payload_type"
                ],
                "confidence": payload_result[
                    "confidence"
                ],
                "route": payload_result[
                    "route"
                ],
                "reason": payload_result[
                    "reason"
                ],
                "preview": payload_result[
                    "preview"
                ],
                "saved_path": saved_path
            }

            if payload_record not in results[
                "payloads"
            ]:
                results["payloads"].append(
                    payload_record
                )

            for flag in payload_result.get(
                "flags",
                []
            ):
                add_unique(
                    results["decoded_flags"],
                    flag
                )

        # -------------------------------------------------
        # Base64 payload inspection
        # -------------------------------------------------

        base64_candidates = BASE64_PATTERN.findall(
            text
        )

        for candidate in base64_candidates:
            decoded_bytes = decode_base64_bytes(
                candidate
            )

            if decoded_bytes is None:
                continue

            payload_result = inspect_decoded_payload(
                decoded_bytes
            )

            if payload_result is None:
                continue

            saved_path = None

            if save_payloads:
                saved_path = save_decoded_payload(
                    decoded_bytes=decoded_bytes,
                    payload_result=payload_result,
                    source_encoding="base64",
                    depth=depth,
                    output_dir=output_dir,
                    saved_payload_paths=saved_payload_paths
                )

            payload_record = {
                "depth": depth,
                "source_encoding": "base64",
                "encoded": candidate,
                "payload_type": payload_result[
                    "payload_type"
                ],
                "confidence": payload_result[
                    "confidence"
                ],
                "route": payload_result[
                    "route"
                ],
                "reason": payload_result[
                    "reason"
                ],
                "preview": payload_result[
                    "preview"
                ]
            }
            payload_record["saved_path"] = saved_path

            if payload_record not in results[
                "payloads"
            ]:
                results["payloads"].append(
                    payload_record
                )

            for flag in payload_result.get(
                "flags",
                []
            ):
                add_unique(
                    results["decoded_flags"],
                    flag
                )

        # -------------------------------------------------
        # HEX payload inspection
        # -------------------------------------------------

        hex_candidates = HEX_PATTERN.findall(
            text
        )

        for candidate in hex_candidates:
            decoded_bytes = decode_hex_bytes(
                candidate
            )

            if decoded_bytes is None:
                continue

            payload_result = inspect_decoded_payload(
                decoded_bytes
            )

            if payload_result is None:
                continue

            saved_path = None

            if save_payloads:
                saved_path = save_decoded_payload(
                    decoded_bytes=decoded_bytes,
                    payload_result=payload_result,
                    source_encoding="hex",
                    depth=depth,
                    output_dir=output_dir,
                    saved_payload_paths=saved_payload_paths
                )

            payload_record = {
                "depth": depth,
                "source_encoding": "hex",
                "encoded": candidate,
                "payload_type": payload_result[
                    "payload_type"
                ],
                "confidence": payload_result[
                    "confidence"
                ],
                "route": payload_result[
                    "route"
                ],
                "reason": payload_result[
                    "reason"
                ],
                "preview": payload_result[
                    "preview"
                ]
            }
            payload_record["saved_path"] = saved_path

            if payload_record not in results[
                "payloads"
            ]:
                results["payloads"].append(
                    payload_record
                )

            for flag in payload_result.get(
                "flags",
                []
            ):
                add_unique(
                    results["decoded_flags"],
                    flag
                )

    def process_text(text, depth):
        if depth > MAX_ENCODING_DEPTH:
            return

        if not text:
            return

        # Prevent loops
        if text in visited:
            return

        visited.add(text)

        # -------------------------------------------------
        # Check current layer for flags
        # -------------------------------------------------

        for flag in extract_flags(text):
            add_unique(
                results["decoded_flags"],
                flag
            )

        # -------------------------------------------------
        # Stop recursion on confirmed terminal payloads
        # -------------------------------------------------

        current_payload = inspect_decoded_payload(
            text.encode("utf-8")
        )

        if (
            current_payload
            and current_payload["payload_type"].startswith(
                "PEM "
            )
        ):
            return

        # -------------------------------------------------
        # Payload Intelligence
        # -------------------------------------------------

        inspect_encoding_payloads(
            text,
            depth
        )

        # -------------------------------------------------
        # Traditional text-based encoding analysis
        # -------------------------------------------------

        findings = analyze_single_layer(
            text
        )

        for finding in findings:
            record = {
                "depth": depth,
                "type": finding["type"],
                "encoded": finding["encoded"],
                "decoded": finding["decoded"]
            }

            if record not in results[
                "recursive_layers"
            ]:
                results[
                    "recursive_layers"
                ].append(
                    record
                )

            simple_record = {
                "encoded": finding["encoded"],
                "decoded": finding["decoded"]
            }

            if finding["type"] == "binary":
                if simple_record not in results[
                    "binary"
                ]:
                    results["binary"].append(
                        simple_record
                    )

            elif finding["type"] == "base64":
                if simple_record not in results[
                    "base64"
                ]:
                    results["base64"].append(
                        simple_record
                    )

            elif finding["type"] == "hex":
                if simple_record not in results[
                    "hex"
                ]:
                    results["hex"].append(
                        simple_record
                    )

            # ---------------------------------------------
            # Check decoded result for flags
            # ---------------------------------------------

            for flag in extract_flags(
                finding["decoded"]
            ):
                add_unique(
                    results["decoded_flags"],
                    flag
                )

            # ---------------------------------------------
            # Analyze next textual encoding layer
            # ---------------------------------------------

            if depth < MAX_ENCODING_DEPTH:
                process_text(
                    finding["decoded"],
                    depth + 1
                )

    for text in strings:
        process_text(
            text,
            1
        )

    return results
