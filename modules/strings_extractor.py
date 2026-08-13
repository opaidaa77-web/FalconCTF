import re


LARGE_FILE_THRESHOLD = 25 * 1024 * 1024
LARGE_FILE_SCAN_LIMIT = 8 * 1024 * 1024
LARGE_FILE_MAX_STRINGS = 5000


def get_string_scan_policy(file_size):
    """
    Return safe generic string-analysis limits.

    Large files are intentionally sampled instead of being
    exhaustively loaded and scanned by the generic pipeline.
    """

    if file_size > LARGE_FILE_THRESHOLD:
        return {
            "limited": True,
            "max_bytes": LARGE_FILE_SCAN_LIMIT,
            "max_strings": LARGE_FILE_MAX_STRINGS,
        }

    return {
        "limited": False,
        "max_bytes": None,
        "max_strings": None,
    }


def extract_strings(
    file_path,
    min_length=4,
    max_bytes=None,
    max_strings=None,
):
    try:
        with open(file_path, "rb") as file:
            if max_bytes is None:
                data = file.read()
            else:
                data = file.read(
                    max(0, int(max_bytes))
                )

        pattern = re.compile(
            rb"[\x20-\x7E]{"
            + str(min_length).encode()
            + rb",}"
        )

        results = []
        seen = set()

        for match in pattern.finditer(data):
            text = match.group(0).decode(
                "utf-8",
                errors="ignore",
            )

            if text in seen:
                continue

            seen.add(text)
            results.append(text)

            if (
                max_strings is not None
                and len(results) >= max_strings
            ):
                break

        return results

    except (
        FileNotFoundError,
        OSError,
        PermissionError,
    ):
        return []
