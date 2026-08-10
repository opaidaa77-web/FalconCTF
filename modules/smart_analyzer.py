import os

from modules.hash_analyzer import calculate_hashes
from modules.hex_analyzer import detect_file_type, analyze_hex
from modules.strings_extractor import extract_strings
from modules.interesting_strings import analyze_interesting_strings
from modules.analysis_router import choose_analysis
from modules.binary_analyzer import analyze_binary
from modules.flag_detector import detect_flags
from modules.metadata_analyzer import analyze_metadata
from modules.scoring_engine import calculate_interest_score
from modules.report_generator import generate_report

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

        if "binary_analysis" in analysis_plan:
            analyze_binary(file_path)

        if "hex_analysis" in analysis_plan:
            analyze_hex(file_path)

        if "metadata_analysis" in analysis_plan:
            analyze_metadata(file_path)

        hashes = calculate_hashes(file_path)

        if hashes:
            print("\nHashes:")
            print("MD5    :", hashes["MD5"])
            print("SHA1   :", hashes["SHA1"])
            print("SHA256 :", hashes["SHA256"])

        strings = extract_strings(file_path)

        combined_text = "\n".join(strings)
        detected_flags = detect_flags(combined_text)

        print("\nStrings Found:", len(strings))

        if detected_flags:
            print("\nDetected Flags:")
            for flag in detected_flags:
                print(" -", flag)

        findings = analyze_interesting_strings(strings)

        score_result = calculate_interest_score(findings, detected_flags)

        print("\n" + "=" * 55)
        print("FalconCTF Interest Score")
        print("=" * 55)

        print("Score :", f"{score_result['score']}/100")
        print("Level :", score_result["level"])

        if score_result["reasons"]:
           print("\nReasons:")
        for reason in score_result["reasons"]:
            print(" [+]", reason)


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

        report_path = generate_report(
        file_path=file_path,
        file_type=file_type,
        hashes=hashes,
        findings=findings,
        detected_flags=detected_flags,
        score_result=score_result
        )

        print("\nReport Generated:")
        print(report_path)

    except (OSError, PermissionError) as error:
        print("Analysis error:", error)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python3 -m modules.smart_analyzer <file>")
        sys.exit(1)

    smart_analyze(sys.argv[1])
