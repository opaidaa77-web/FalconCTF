import os

from modules.hash_analyzer import calculate_hashes
from modules.hex_analyzer import detect_file_type
from modules.strings_extractor import extract_strings
from modules.interesting_strings import analyze_interesting_strings
from modules.analysis_router import choose_analysis


def smart_analyze(file_path):
    if not os.path.isfile(file_path):
        print("Error: File not found.")
        return

    print("\n" + "=" * 55)
    print("FalconCTF Smart Analysis Engine")
    print("=" * 55)

    print("File :", os.path.basename(file_path))
    print("Path :", os.path.abspath(file_path))
    print("Size :", os.path.getsize(file_path), "bytes")

    try:
        with open(file_path, "rb") as file:
            header = file.read(64)

        file_type = detect_file_type(header)

        print("\nDetected File Type:")
        print(file_type)
        analysis_plan = choose_analysis(file_type)

        print("\nRecommended Analysis Plan:")

        for analysis in analysis_plan:
            readable_name = analysis.replace("_", " ").title()
            print("[+]", readable_name)

        hashes = calculate_hashes(file_path)

        if hashes:
            print("\nHashes:")
            print("MD5    :", hashes["MD5"])
            print("SHA1   :", hashes["SHA1"])
            print("SHA256 :", hashes["SHA256"])

        strings = extract_strings(file_path)

        print("\nStrings Found:", len(strings))

        findings = analyze_interesting_strings(strings)

        print("\n" + "=" * 55)
        print("Interesting Findings")
        print("=" * 55)

        found_anything = False

        for category, items in findings.items():
            if items:
                found_anything = True
                print(f"\n{category.upper()}:")

                for item in items[:20]:
                    print(" -", item)

                if len(items) > 20:
                    print(f" ... and {len(items) - 20} more.")

        if not found_anything:
            print("\nNo obvious interesting findings detected.")

    except (OSError, PermissionError) as error:
        print("Analysis error:", error)
