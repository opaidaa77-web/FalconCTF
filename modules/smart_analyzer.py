import os
import sys
from getpass import getpass

from modules.hash_analyzer import calculate_hashes
from modules.hex_analyzer import detect_file_type, analyze_hex
from modules.strings_extractor import (
    extract_strings,
    get_string_scan_policy,
)
from modules.interesting_strings import analyze_interesting_strings
from modules.analysis_router import choose_analysis
from modules.binary_analyzer import analyze_binary
from modules.flag_detector import detect_flags
from modules.metadata_analyzer import (
    analyze_metadata,
    get_metadata_text_values
)
from modules.scoring_engine import calculate_interest_score
from modules.report_generator import generate_report
from modules.archive_analyzer import analyze_archive
from modules.gzip_analyzer import analyze_gzip
from modules.recommendation_engine import generate_recommendations
from modules.encoding_analyzer import analyze_encoded_data
from modules.challenge_classifier import classify_challenge
from modules.solve_planner import generate_solve_plan, print_solve_plan

def add_unique(target_list, value):
    if value not in target_list:
        target_list.append(value)


def smart_analyze(file_path, archive_password=None):
    if not os.path.isfile(file_path):
        print("Error: File not found.")
        return None

    print("\n" + "=" * 55)
    print("FalconCTF Smart Analysis Engine")
    print("=" * 55)

    print("File :", os.path.basename(file_path))
    print("Path :", os.path.abspath(file_path))
    print("Size :", os.path.getsize(file_path), "bytes")

    try:
        # -------------------------------------------------
        # File type detection
        # -------------------------------------------------

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
        # File-type specific analysis
        # -------------------------------------------------

        if "binary_analysis" in analysis_plan:
            analyze_binary(file_path)

        if "hex_analysis" in analysis_plan:
            analyze_hex(file_path)

        metadata_results = {}

        if "metadata_analysis" in analysis_plan:
            metadata_results = (
                analyze_metadata(file_path)
                or {}
            )

        # -------------------------------------------------
        # GZIP analysis
        # -------------------------------------------------

        gzip_results = None

        if "gzip_analysis" in analysis_plan:
            gzip_output_dir = os.path.join(
                "output",
                (
                    os.path.basename(
                        file_path
                    )
                    + "_extracted"
                )
            )

            gzip_results = analyze_gzip(
                file_path,
                output_dir=gzip_output_dir
            )

            print("\n" + "=" * 55)
            print("FalconCTF GZIP Analysis")
            print("=" * 55)

            if gzip_results["valid"]:
                print(
                    "[+] Valid GZIP stream detected"
                )
                print(
                    "[+] Inner Type :",
                    gzip_results["inner_type"]
                )
                print(
                    "[+] Extracted  :",
                    gzip_results["saved_path"]
                )
                print(
                    "[+] Size       :",
                    gzip_results["bytes_written"],
                    "bytes"
                )

            else:
                print(
                    "[-] GZIP analysis failed:",
                    gzip_results["reason"]
                )

        # -------------------------------------------------
        # Archive analysis
        # -------------------------------------------------

        archive_results = {
            "flags": [],
            "keywords": [],
            "interesting_files": [],
            "encrypted_files": [],
            "decrypted_files": []
        }

        if "archive_analysis" in analysis_plan:
            archive_results = analyze_archive(
                file_path,
                password=archive_password
            )

            if (
                archive_results["encrypted_files"]
                and archive_password is None
                and sys.stdin.isatty()
            ):
                print("\n" + "=" * 55)
                print("Encrypted ZIP Content Detected")
                print("=" * 55)

                print(
                    "[!] FalconCTF found encrypted content "
                    "inside this archive."
                )

                answer = input(
                    "[?] Do you want to enter a password? "
                    "[y/N]: "
                ).strip().lower()

                if answer in ("y", "yes"):
                    password_input = getpass(
                        "[?] ZIP password: "
                    )

                    if password_input:
                        print(
                            "\n[*] Re-analyzing archive "
                            "with supplied password..."
                        )

                        archive_results = analyze_archive(
                            file_path,
                            password=password_input
                        )

                        archive_password = password_input

                    else:
                        print(
                            "[!] Empty password supplied. "
                            "Continuing without decryption."
                        )

                else:
                    print(
                        "[*] Continuing without "
                        "decrypting protected content."
                    )

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
        # Strings
        # -------------------------------------------------

        file_size = os.path.getsize(
            file_path
        )

        string_policy = (
            get_string_scan_policy(
                file_size
            )
        )

        if string_policy["limited"]:
            print(
                "\n[!] Large File Safety Mode"
            )
            print(
                "[!] Generic strings and encoding "
                "analysis will be sampled."
            )
            print(
                "[!] Scan limit:",
                string_policy["max_bytes"],
                "bytes"
            )
            print(
                "[!] Maximum unique strings:",
                string_policy["max_strings"]
            )

        strings = extract_strings(
            file_path,
            max_bytes=string_policy[
                "max_bytes"
            ],
            max_strings=string_policy[
                "max_strings"
            ],
        )

        combined_text = "\n".join(strings)

        detected_flags = detect_flags(
            combined_text
        )

        # -------------------------------------------------
        # Automatic encoded-data analysis
        # -------------------------------------------------

        payload_output_dir = os.path.join(
            "output",
            (
                os.path.splitext(
                    os.path.basename(file_path)
                )[0]
                + "_decoded"
            )
        )

        encoding_sources = list(strings)

        for metadata_text in get_metadata_text_values(
            metadata_results
        ):
            if metadata_text not in encoding_sources:
                encoding_sources.append(
                    metadata_text
                )

        encoding_results = analyze_encoded_data(
            encoding_sources,
            save_payloads=True,
            output_dir=payload_output_dir
        )

        # -------------------------------------------------
        # Merge extracted GZIP payload intelligence
        # -------------------------------------------------

        if (
            gzip_results
            and gzip_results.get("valid")
            and gzip_results.get("saved_path")
        ):
            gzip_payload = {
                "depth": 1,
                "source_encoding": "gzip",
                "encoded": os.path.basename(
                    file_path
                ),
                "payload_type": gzip_results[
                    "inner_type"
                ],
                "confidence": gzip_results[
                    "inner_confidence"
                ],
                "route": gzip_results[
                    "inner_route"
                ],
                "reason": gzip_results[
                    "inner_reason"
                ],
                "preview": (
                    "Extracted GZIP payload: "
                    + gzip_results["saved_path"]
                ),
                "saved_path": gzip_results[
                    "saved_path"
                ],
            }

            if gzip_payload not in encoding_results[
                "payloads"
            ]:
                encoding_results[
                    "payloads"
                ].append(
                    gzip_payload
                )

        for decoded_flag in encoding_results[
            "decoded_flags"
        ]:
            add_unique(
                detected_flags,
                decoded_flag
            )

        for archive_flag in archive_results[
            "flags"
        ]:
            add_unique(
                detected_flags,
                archive_flag
            )

        print("\nStrings Found:", len(strings))

        # -------------------------------------------------
        # Base64 results
        # -------------------------------------------------

        if encoding_results["base64"]:
            print("\nDetected Base64 Data:")

            for finding in encoding_results[
                "base64"
            ][:10]:
                print(
                    " [+] Decoded:",
                    finding["decoded"]
                )

        # -------------------------------------------------
        # Hex results
        # -------------------------------------------------

        if encoding_results["hex"]:
            print("\nDetected Hex Data:")

            for finding in encoding_results[
                "hex"
            ][:10]:
                print(
                    " [+] Decoded:",
                    finding["decoded"]
                )

        # -------------------------------------------------
        # Recursive Encoding Chain
        # -------------------------------------------------

        if encoding_results.get(
            "recursive_layers"
        ):
            print("\n" + "=" * 55)
            print("FalconCTF Recursive Encoding Chain")
            print("=" * 55)

            for layer in encoding_results[
                "recursive_layers"
            ][:20]:
                print(
                    f"Depth {layer['depth']} | "
                    f"{layer['type'].upper()} -> "
                    f"{layer['decoded']}"
                )


        # -------------------------------------------------
        # Payload Intelligence
        # -------------------------------------------------

        if encoding_results.get(
            "payloads"
        ):
            print("\n" + "=" * 55)
            print("FalconCTF Payload Intelligence")
            print("=" * 55)

            for payload in encoding_results[
                "payloads"
            ][:20]:
                print(
                    "\nSource Encoding :",
                    payload["source_encoding"].upper()
                )

                print(
                    "Payload Type    :",
                    payload["payload_type"]
                )

                print(
                    "Confidence      :",
                    f"{payload['confidence']}%"
                )

                print(
                    "Next Route      :",
                    payload["route"]
                )

                print(
                    "Reason          :",
                    payload["reason"]
                )

                if payload.get("saved_path"):
                    print(
                        "Saved Payload   :",
                        payload["saved_path"]
                    )

        # -------------------------------------------------
        # Detected Flags
        # -------------------------------------------------

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
            findings = analyze_interesting_strings(
                strings
            )

        # -------------------------------------------------
        # Merge archive keywords
        # -------------------------------------------------

        if archive_results["keywords"]:
            findings.setdefault(
                "keywords",
                []
            )

            for keyword in archive_results[
                "keywords"
            ]:
                add_unique(
                    findings["keywords"],
                    keyword
                )

        # -------------------------------------------------
        # Merge interesting archive files
        # -------------------------------------------------

        if archive_results[
            "interesting_files"
        ]:
            findings.setdefault(
                "archive_files",
                []
            )

            for archive_file in archive_results[
                "interesting_files"
            ]:
                add_unique(
                    findings["archive_files"],
                    archive_file
                )

        # -------------------------------------------------
        # Merge encrypted archive files
        # -------------------------------------------------

        if archive_results[
            "encrypted_files"
        ]:
            findings.setdefault(
                "encrypted_files",
                []
            )

            for encrypted_file in archive_results[
                "encrypted_files"
            ]:
                add_unique(
                    findings["encrypted_files"],
                    encrypted_file
                )

        # -------------------------------------------------
        # Merge decrypted archive files
        # -------------------------------------------------

        if archive_results[
            "decrypted_files"
        ]:
            findings.setdefault(
                "decrypted_files",
                []
            )

            for decrypted_file in archive_results[
                "decrypted_files"
            ]:
                add_unique(
                    findings["decrypted_files"],
                    decrypted_file
                )

        # -------------------------------------------------
        # Merge Base64 findings
        # -------------------------------------------------

        if encoding_results["base64"]:
            findings.setdefault(
                "base64_decoded",
                []
            )

            for item in encoding_results[
                "base64"
            ]:
                add_unique(
                    findings["base64_decoded"],
                    item["decoded"]
                )

        # -------------------------------------------------
        # Merge Hex findings
        # -------------------------------------------------

        if encoding_results["hex"]:
            findings.setdefault(
                "hex_decoded",
                []
            )

            for item in encoding_results[
                "hex"
            ]:
                add_unique(
                    findings["hex_decoded"],
                    item["decoded"]
                )

        # -------------------------------------------------
        # Merge Recursive Encoding Chain
        # -------------------------------------------------

        if encoding_results.get(
            "recursive_layers"
        ):
            findings.setdefault(
                "encoding_chain",
                []
            )

            for layer in encoding_results[
                "recursive_layers"
            ]:
                chain_entry = (
                    f"Depth {layer['depth']} | "
                    f"{layer['type'].upper()} -> "
                    f"{layer['decoded']}"
                )

                add_unique(
                    findings["encoding_chain"],
                    chain_entry
                )


        # -------------------------------------------------
        # Merge Payload Intelligence
        # -------------------------------------------------

        if encoding_results.get(
            "payloads"
        ):
            findings.setdefault(
                "payload_intelligence",
                []
            )

            for payload in encoding_results[
                "payloads"
            ]:
                payload_entry = (
                    f"{payload['source_encoding'].upper()} -> "
                    f"{payload['payload_type']} | "
                    f"Confidence {payload['confidence']}% | "
                    f"Route: {payload['route']}"
                )

                if payload.get("saved_path"):
                    payload_entry += (
                        f" | Saved: "
                        f"{payload['saved_path']}"
                    )

                add_unique(
                    findings["payload_intelligence"],
                    payload_entry
                )


        # -------------------------------------------------
        # Challenge Classification
        # -------------------------------------------------

        classification_result = classify_challenge(
            file_type=file_type,
            analysis_plan=analysis_plan,
            findings=findings,
            encoding_results=encoding_results,
            archive_results=archive_results
        )

        print("\n" + "=" * 55)
        print("FalconCTF Challenge Classification")
        print("=" * 55)

        print(
            "Likely Category :",
            classification_result["category"]
        )

        print(
            "Confidence      :",
            f"{classification_result['confidence']}%"
        )

        if classification_result[
            "secondary_category"
        ]:
            print(
                "Secondary       :",
                classification_result[
                    "secondary_category"
                ],
                f"({classification_result['secondary_confidence']}%)"
            )

        if classification_result["reasons"]:
            print("\nClassification Reasons:")

            for reason in classification_result[
                "reasons"
            ]:
                print(
                    " [+]",
                    reason
                )

        # Store classification in findings
        findings.setdefault(
            "challenge_classification",
            []
        )

        add_unique(
            findings["challenge_classification"],
            (
                f"{classification_result['category']} "
                f"({classification_result['confidence']}%)"
            )
        )

        if classification_result[
            "secondary_category"
        ]:
            add_unique(
                findings["challenge_classification"],
                (
                    "Secondary: "
                    f"{classification_result['secondary_category']} "
                    f"({classification_result['secondary_confidence']}%)"
                )
            )

        # -------------------------------------------------
        # Interest scoring
        # -------------------------------------------------

        score_result = calculate_interest_score(
            findings,
            detected_flags,
            encoding_results=encoding_results
        )

        print("\n" + "=" * 55)
        print("FalconCTF Interest Score")
        print("=" * 55)

        print(
            "Score :",
            f"{score_result['score']}/100"
        )

        print(
            "Level :",
            score_result["level"]
        )

        if score_result["reasons"]:
            print("\nReasons:")

            for reason in score_result[
                "reasons"
            ]:
                print(
                    " [+]",
                    reason
                )

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

                print(
                    f"\n{category.upper()}:"
                )

                for item in items[:20]:
                    print(
                        " -",
                        item
                    )

                if len(items) > 20:
                    print(
                        f" ... and "
                        f"{len(items) - 20} more."
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
            score_result=score_result,
            encoding_results=encoding_results
        )

        print("\n" + "=" * 55)
        print("FalconCTF Recommended Next Steps")
        print("=" * 55)

        if recommendations:
            for index, recommendation in enumerate(
                recommendations,
                start=1
            ):
                print(
                    f"[{index}] {recommendation}"
                )

        else:
            print(
                "No additional recommendations generated."
            )
        # -------------------------------------------------
        # Intelligent Solve Planner
        # -------------------------------------------------

        solve_plan = generate_solve_plan(
        file_type=file_type,
        findings=findings,
        detected_flags=detected_flags,
        encoding_results=encoding_results,
        archive_results=archive_results,
        classification_result=classification_result
        )
        print_solve_plan(
            solve_plan
        )


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
            recommendations=recommendations,
            encoding_results=encoding_results,
            classification_result=classification_result,
            solve_plan=solve_plan
        )

        print("\nReport Generated:")
        print(report_path)

        # -------------------------------------------------
        # Return structured results
        # -------------------------------------------------

        return {
            "file_path": file_path,
            "file_type": file_type,
            "hashes": hashes,
            "findings": findings,
            "detected_flags": detected_flags,
            "encoding_results": encoding_results,
            "classification_result": classification_result,
            "score_result": score_result,
            "recommendations": recommendations,
            "solve_plan": solve_plan,
            "archive_results": archive_results,
            "report_path": report_path
        }

    except (
        OSError,
        PermissionError
    ) as error:
        print(
            "Analysis error:",
            error
        )

        return None


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        print(
            "Usage: python3 -m "
            "modules.smart_analyzer "
            "<file> [archive_password]"
        )

        sys.exit(1)

    target_file = sys.argv[1]

    password = None

    if len(sys.argv) == 3:
        password = sys.argv[2]

    smart_analyze(
        target_file,
        archive_password=password
    )
