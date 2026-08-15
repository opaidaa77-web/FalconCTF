import os
import subprocess


TEXT_METADATA_FIELDS = {
    "comment",
    "user comment",
    "image description",
    "description",
    "caption-abstract"
}


def parse_metadata_output(output):
    metadata = {}

    for line in output.splitlines():
        key, separator, value = line.partition(":")

        if not separator:
            continue

        key = key.strip()
        value = value.strip()

        if key and value:
            metadata[key] = value

    return metadata


def get_metadata_text_values(metadata):
    values = []

    for key, value in (metadata or {}).items():
        normalized_key = key.strip().lower()

        if (
            normalized_key in TEXT_METADATA_FIELDS
            and isinstance(value, str)
            and value.strip()
        ):
            values.append(value.strip())

    return values


def analyze_metadata(file_path):
    if not os.path.isfile(file_path):
        print("Error: File not found.")
        return {}

    print("\n" + "=" * 55)
    print("FalconCTF Metadata Analyzer")
    print("=" * 55)

    print("File :", os.path.basename(file_path))

    try:
        result = subprocess.run(
            ["exiftool", file_path],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            print("\nMetadata:")
            print(result.stdout.strip())

            return parse_metadata_output(
                result.stdout
            )

        print("\nCould not extract metadata.")
        return {}

    except FileNotFoundError:
        print("Error: exiftool is not installed.")
        return {}

    except OSError as error:
        print("Metadata analysis error:", error)
        return {}


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python3 metadata_analyzer.py <file>")
        sys.exit(1)

    analyze_metadata(sys.argv[1])
