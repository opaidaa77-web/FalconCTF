import gzip
import os

from modules.hex_analyzer import detect_file_type


GZIP_CHUNK_SIZE = 1024 * 1024
MAX_GZIP_OUTPUT_SIZE = 512 * 1024 * 1024


def classify_inner_type(inner_type):
    """
    Route an extracted GZIP payload according
    to its detected inner file type.
    """

    value = str(
        inner_type
    ).lower()

    if any(
        indicator in value
        for indicator in (
            "png",
            "jpeg",
            "jpg",
            "gif",
            "pdf",
        )
    ):
        return (
            "forensics",
            100,
            "GZIP extraction revealed a known "
            "forensic payload."
        )

    if (
        "elf" in value
        or "pe executable" in value
    ):
        return (
            "binary_analysis",
            100,
            "GZIP extraction revealed a known "
            "executable payload."
        )

    if (
        "zip archive" in value
        or "gzip archive" in value
    ):
        return (
            "archive_analysis",
            100,
            "GZIP extraction revealed another "
            "compressed or archive payload."
        )

    return (
        "manual_inspection",
        40,
        "The GZIP payload was extracted successfully, "
        "but its inner file type requires deeper inspection."
    )


def analyze_gzip(
    file_path,
    output_dir="output/gzip_extracted",
    max_output_size=MAX_GZIP_OUTPUT_SIZE
):
    result = {
        "valid": False,
        "saved_path": None,
        "inner_type": "Unknown File Type",
        "inner_route": "manual_inspection",
        "inner_confidence": 0,
        "inner_reason": "",
        "bytes_written": 0,
        "reason": "",
    }

    if not os.path.isfile(file_path):
        result["reason"] = "File not found."
        return result

    output_name = os.path.basename(
        file_path
    )

    if output_name.lower().endswith(".gz"):
        output_name = output_name[:-3]

    if not output_name:
        output_name = "decoded_gzip_payload.bin"

    os.makedirs(
        output_dir,
        exist_ok=True
    )

    saved_path = os.path.join(
        output_dir,
        output_name
    )

    try:
        with gzip.open(
            file_path,
            "rb"
        ) as source:
            header = source.read(64)

            if not header:
                result["reason"] = (
                    "GZIP payload is empty."
                )
                return result

            result["inner_type"] = (
                detect_file_type(
                    header
                )
            )

            (
                result["inner_route"],
                result["inner_confidence"],
                result["inner_reason"],
            ) = classify_inner_type(
                result["inner_type"]
            )

            total = 0

            with open(
                saved_path,
                "wb"
            ) as destination:
                destination.write(
                    header
                )

                total += len(header)

                while True:
                    chunk = source.read(
                        GZIP_CHUNK_SIZE
                    )

                    if not chunk:
                        break

                    total += len(chunk)

                    if total > max_output_size:
                        destination.close()

                        try:
                            os.remove(
                                saved_path
                            )
                        except OSError:
                            pass

                        result["reason"] = (
                            "Decompressed payload exceeded "
                            "the configured safety limit."
                        )

                        return result

                    destination.write(
                        chunk
                    )

        result["valid"] = True
        result["saved_path"] = saved_path
        result["bytes_written"] = total
        result["reason"] = (
            "Valid GZIP stream extracted safely."
        )

        return result

    except (
        gzip.BadGzipFile,
        EOFError,
        OSError,
    ) as error:
        result["reason"] = str(error)

        try:
            if os.path.exists(saved_path):
                os.remove(saved_path)
        except OSError:
            pass

        return result
