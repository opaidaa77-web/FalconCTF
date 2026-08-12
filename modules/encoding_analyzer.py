import base64
import hashlib
import binascii
import os
import re
from modules.payload_inspector import inspect_payload

MAX_ENCODING_DEPTH = 3


BASE64_PATTERN = re.compile(
    r"(?<![A-Za-z0-9+/])"
    r"[A-Za-z0-9+/]{10,}={0,2}"
    r"(?![A-Za-z0-9+/=])"
)

HEX_PATTERN = re.compile(
    r"(?<![0-9a-fA-F])"
    r"(?:[0-9a-fA-F]{2}){4,}"
    r"(?![0-9a-fA-F])"
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


def is_probable_hex(value):
    if len(value) < 8:
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

            if finding["type"] == "base64":
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

    def process_text(text, depth):
        if depth > MAX_ENCODING_DEPTH:
            return

        if not text:
            return

        # Prevent loops
        if text in visited:
            return

        visited.add(text)

        # Check current layer for flags
        for flag in extract_flags(text):
            add_unique(
                results["decoded_flags"],
                flag
            )

        findings = analyze_single_layer(text)

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
                ].append(record)

            simple_record = {
                "encoded": finding["encoded"],
                "decoded": finding["decoded"]
            }

            if finding["type"] == "base64":
                if simple_record not in results["base64"]:
                    results["base64"].append(
                        simple_record
                    )

            elif finding["type"] == "hex":
                if simple_record not in results["hex"]:
                    results["hex"].append(
                        simple_record
                    )

            # Check decoded result for flags
            for flag in extract_flags(
                finding["decoded"]
            ):
                add_unique(
                    results["decoded_flags"],
                    flag
                )

            # Analyze next encoding layer
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
