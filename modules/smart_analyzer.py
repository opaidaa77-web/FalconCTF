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
from modules.archive_analyzer import analyze_archive
from modules.recommendation_engine import generate_recommendations


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

        # -------------------------------------------------
        # Run file-type specific analysis
        # -------------------------------------------------

        if "binary_analysis" in analysis_plan:
            analyze_binary(file_path)

        if "hex_analysis" in analysis_plan:
            analyze_hex(file_path)

        if "metadata_analysis" in analysis_plan:
            analyze_metadata(file_path)

        # -------------------------------------------------
        # Archive analysis
        # -------------------------------------------------

        archive_results = {
            "flags": [],
            "keywords": [],
            "interesting_files": [],
            "encrypted_files": []
        }

        if "archive_analysis" in analysis_plan:
            archive_results = analyze_archive(file_path)

        # -------------------------------------------------
        # Hash analysis
        # -------------------------------------------------

        hashes = calculate_hashes(file_path)

        if hashes:
            print("\nHashes:")
            print("MD5    :", hashes["MD5"])
            print("SHA1   :", hashes["SHA1"])
            print("SHA256 :", hashes["SHA256"])

        # -------------------------------------------------
        # Strings and flag detection
        # -------------------------------------------------

        strings = extract_strings(file_path)

        combined_text = "\n".join(strings)
        detected_flags = detect_flags(combined_text)

        for archive_flag in archive_results["flags"]:
            if archive_flag not in detected_flags:
                detected_flags.append(archive_flag)

        print("\nStrings Found:", len(strings))

        if detected_flags:
            print("\nDetected Flags:")

            for flag in detected_flags:
                print(" -", flag)

        # -------------------------------------------------
        # Interesting findings
        # -------------------------------------------------

        if "archive_analysis" in analysis_plan:
            findings = {
                "flags": [],
                "urls": [],
                "emails": [],
                "ips": [],
                "keywords": []
            }
        else:
            findings = analyze_interesting_strings(strings)

        # Merge archive keywords
        if archive_results["keywords"]:
            findings.setdefault("keywords", [])

            for keyword in archive_results["keywords"]:
                if keyword not in findings["keywords"]:
                    findings["keywords"].append(keyword)

        # Merge interesting archive files
        if archive_results["interesting_files"]:
            findings.setdefault("archive_files", [])

            for archive_file in archive_results["interesting_files"]:
                if archive_file not in findings["archive_files"]:
                    findings["archive_files"].append(archive_file)

        # Merge encrypted archive files
        if archive_results["encrypted_files"]:
            findings.setdefault("encrypted_files", [])

            for encrypted_file in archive_results["encrypted_files"]:
                if encrypted_file not in findings["encrypted_files"]:
                    findings["encrypted_files"].append(encrypted_file)

        # -------------------------------------------------
        # Interest scoring
        # -------------------------------------------------

        score_result = calculate_interest_score(
            findings,
            detected_flags
        )

        print("\n" + "=" * 55)
        print("FalconCTF Interest Score")
        print("=" * 55)

        print("Score :", f"{score_result['score']}/100")
        print("Level :", score_result["level"])

        if score_result["reasons"]:
            print("\nReasons:")

            for reason in score_result["reasons"]:
                print(" [+]", reason)

        # -------------------------------------------------
        # Interesting findings output
        # -------------------------------------------------

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
                    print(
                        f" ... and {len(items) - 20} more."
                    )

        if not found_anything:
            print(
                "\nNo obvious interesting findings detected."
            )

        # -------------------------------------------------
        # Recommendation Engine
        # -------------------------------------------------

        recommendations = generate_recommendations(
            file_type=file_type,
            findings=findings,
            detected_flags=detected_flags,
            score_result=score_result
        )

        print("\n" + "=" * 55)
        print("FalconCTF Recommended Next Steps")
        print("=" * 55)

        for index, recommendation in enumerate(
            recommendations,
            start=1
        ):
            print(f"[{index}] {recommendation}")

        # -------------------------------------------------
        # Report generation
        # -------------------------------------------------

        report_path = generate_report(
        file_path=file_path,
        file_type=file_type,
        hashes=hashes,
        findings=findings,
        detected_flags=detected_flags,
        score_result=score_result,
        recommendations=recommendations
        )

        print("\nReport Generated:")
        print(report_path)

    except (OSError, PermissionError) as error:
        print("Analysis error:", error)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print(
            "Usage: python3 -m modules.smart_analyzer <file>"
        )
        sys.exit(1)

    smart_analyze(sys.argv[1])
