import base64
import binascii
import re


BASE64_PATTERN = re.compile(
    r"\b(?:[A-Za-z0-9+/]{4}){3,}"
    r"(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b"
)

HEX_PATTERN = re.compile(
    r"\b(?:[0-9a-fA-F]{2}){4,}\b"
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

    # Prevent pure hex strings from also being
    # interpreted as Base64.
    if is_probable_hex(value):
        return False

    if len(value) % 4 not in (0, 2, 3):
        return False

    return bool(
        re.fullmatch(
            r"[A-Za-z0-9+/]+={0,2}",
            value
        )
    )


def decode_base64_candidate(value):
    if not is_probable_base64(value):
        return None

    try:
        padding = (-len(value)) % 4

        padded_value = (
            value + ("=" * padding)
        )

        decoded_bytes = base64.b64decode(
            padded_value,
            validate=True
        )

        decoded_text = decoded_bytes.decode(
            "utf-8",
            errors="ignore"
        )

        if not is_readable_text(
            decoded_text
        ):
            return None

        return decoded_text

    except (
        binascii.Error,
        ValueError
    ):
        return None


def decode_hex_candidate(value):
    if not is_probable_hex(value):
        return None

    try:
        decoded_bytes = bytes.fromhex(
            value
        )

        decoded_text = decoded_bytes.decode(
            "utf-8",
            errors="ignore"
        )

        if not is_readable_text(
            decoded_text
        ):
            return None

        return decoded_text

    except ValueError:
        return None


def extract_flags(text):
    return FLAG_PATTERN.findall(
        text
    )


def analyze_encoded_data(strings):
    results = {
        "base64": [],
        "hex": [],
        "decoded_flags": []
    }

    for text in strings:
        if not text:
            continue

        # ---------------------------------------------
        # Base64 detection
        # ---------------------------------------------

        base64_candidates = (
            BASE64_PATTERN.findall(text)
        )

        for candidate in base64_candidates:
            if not is_probable_base64(
                candidate
            ):
                continue

            decoded = (
                decode_base64_candidate(
                    candidate
                )
            )

            if decoded is None:
                continue

            finding = {
                "encoded": candidate,
                "decoded": decoded
            }

            if (
                finding
                not in results["base64"]
            ):
                results[
                    "base64"
                ].append(finding)

            for flag in extract_flags(
                decoded
            ):
                add_unique(
                    results[
                        "decoded_flags"
                    ],
                    flag
                )

        # ---------------------------------------------
        # Hex detection
        # ---------------------------------------------

        hex_candidates = (
            HEX_PATTERN.findall(text)
        )

        for candidate in hex_candidates:
            if not is_probable_hex(
                candidate
            ):
                continue

            decoded = (
                decode_hex_candidate(
                    candidate
                )
            )

            if decoded is None:
                continue

            finding = {
                "encoded": candidate,
                "decoded": decoded
            }

            if (
                finding
                not in results["hex"]
            ):
                results[
                    "hex"
                ].append(finding)

            for flag in extract_flags(
                decoded
            ):
                add_unique(
                    results[
                        "decoded_flags"
                    ],
                    flag
                )

    return results
