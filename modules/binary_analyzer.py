import os
import subprocess


def analyze_binary(file_path):
    if not os.path.isfile(file_path):
        print("Error: File not found.")
        return

    print("\n" + "=" * 55)
    print("FalconCTF Binary Analyzer")
    print("=" * 55)

    print("File :", file_path)

    try:
        file_result = subprocess.run(
            ["file", file_path],
            capture_output=True,
            text=True
        )

        print("\nFile Information:")
        print(file_result.stdout.strip())

        readelf_result = subprocess.run(
            ["readelf", "-h", file_path],
            capture_output=True,
            text=True
        )

        if readelf_result.returncode == 0:
            print("\nELF Header:")
            print(readelf_result.stdout.strip())
        else:
            print("\nNot a valid ELF file or readelf could not analyze it.")

    except FileNotFoundError as error:
        print("Required system tool not found:", error)

    except OSError as error:
        print("Binary analysis error:", error)
