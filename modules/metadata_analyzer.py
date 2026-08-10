import os
import subprocess


def analyze_metadata(file_path):
    if not os.path.isfile(file_path):
        print("Error: File not found.")
        return

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
        else:
            print("\nCould not extract metadata.")

    except FileNotFoundError:
        print("Error: exiftool is not installed.")

    except OSError as error:
        print("Metadata analysis error:", error)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python3 metadata_analyzer.py <file>")
        sys.exit(1)

    analyze_metadata(sys.argv[1])
