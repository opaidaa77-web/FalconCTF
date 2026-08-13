import argparse
import os

from config.settings import *

from modules.system_info import get_system_info
from modules.file_analyzer import analyze_file
from modules.flag_detector import detect_flags
from modules.strings_extractor import extract_strings
from modules.base64_tool import encode_base64, decode_base64
from modules.interesting_strings import analyze_interesting_strings
from modules.hex_analyzer import analyze_hex
from modules.smart_analyzer import smart_analyze


LINE_WIDTH = 64


def normalize_file_path(file_path):
    """
    Normalize user-supplied file paths.

    Supports:
        - Home-directory expansion: ~/...
        - Environment variables: $HOME/...
        - Relative paths
        - Absolute paths
    """

    expanded = os.path.expandvars(
        os.path.expanduser(
            file_path.strip()
        )
    )

    return os.path.abspath(
        expanded
    )


# =========================================================
# Display helpers
# =========================================================

def print_separator(char="="):
    print(char * LINE_WIDTH)


def show_banner():
    print()
    print_separator()

    print(
        "                     FalconCTF Toolkit"
    )

    print(
        "              Intelligent CTF Analysis Framework"
    )

    print_separator()

    print(f"Version : {VERSION}")
    print(f"Author  : {AUTHOR}")

    print_separator()

    print(
        "Automated file analysis, flag detection, archive inspection,\n"
        "encoding analysis, payload intelligence, scoring,\n"
        "recommendations, solve planning and professional reports."
    )

    print_separator()


# =========================================================
# Shared analysis functions
# =========================================================

def run_strings_analysis(file_path):
    strings = extract_strings(
        file_path
    )

    if not strings:
        print(
            "\n[-] No readable strings found."
        )

        return

    print(
        f"\n[+] Strings Found: {len(strings)}"
    )

    print("\nFirst 50 strings:")
    print("-" * LINE_WIDTH)

    for string in strings[:50]:
        print(string)

    if len(strings) > 50:
        print(
            f"\n... and "
            f"{len(strings) - 50} more strings."
        )

    findings = analyze_interesting_strings(
        strings
    )

    print("\n" + "=" * LINE_WIDTH)
    print("Interesting Findings")
    print("=" * LINE_WIDTH)

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
            "\nNo interesting strings detected."
        )


# =========================================================
# Interactive menu
# =========================================================

def show_menu():
    print("\nMain Menu")
    print("-" * LINE_WIDTH)

    print(
        "[1] Smart Analysis        - Automated full analysis"
    )

    print(
        "[2] File Analyzer         - Basic file inspection"
    )

    print(
        "[3] Flag Detector         - Scan text for CTF flags"
    )

    print(
        "[4] Strings Extractor     - Extract readable strings"
    )

    print(
        "[5] Base64 Tool           - Encode / Decode Base64"
    )

    print(
        "[6] Hex Analyzer          - Inspect file hex/header data"
    )

    print(
        "[7] System Information    - Show environment details"
    )

    print("[8] Exit")

    print("-" * LINE_WIDTH)


def wait_for_enter():
    try:
        input(
            "\nPress Enter to return to the main menu..."
        )

    except (
        KeyboardInterrupt,
        EOFError
    ):
        pass


def run_smart_analysis_interactive():
    print("\nSmart Analysis")
    print("-" * LINE_WIDTH)

    file_path = input(
        "Enter challenge file path: "
    ).strip()

    if not file_path:
        print(
            "\n[-] No file path provided."
        )

        return

    file_path = normalize_file_path(
        file_path
    )

    smart_analyze(
        file_path
    )


def run_file_analyzer_interactive():
    print("\nFile Analyzer")
    print("-" * LINE_WIDTH)

    file_path = input(
        "Enter file path: "
    ).strip()

    if not file_path:
        print(
            "\n[-] No file path provided."
        )

        return

    file_path = normalize_file_path(
        file_path
    )

    analyze_file(
        file_path
    )


def run_flag_detector_interactive():
    print("\nFlag Detector")
    print("-" * LINE_WIDTH)

    text = input(
        "Enter text to scan: "
    )

    flags = detect_flags(
        text
    )

    if flags:
        print("\n[+] Flags Found:")

        for flag in flags:
            print(
                " -",
                flag
            )

    else:
        print(
            "\n[-] No obvious CTF flag pattern found."
        )


def run_strings_extractor_interactive():
    print("\nStrings Extractor")
    print("-" * LINE_WIDTH)

    file_path = input(
        "Enter file path: "
    ).strip()

    if not file_path:
        print(
            "\n[-] No file path provided."
        )

        return

    file_path = normalize_file_path(
        file_path
    )

    run_strings_analysis(
        file_path
    )


def run_base64_tool_interactive():
    print("\nBase64 Tool")
    print("-" * LINE_WIDTH)

    print("[1] Encode Base64")
    print("[2] Decode Base64")
    print("[3] Back")

    base64_choice = input(
        "\nSelect an option: "
    ).strip()

    if base64_choice == "1":
        text = input(
            "\nEnter text to encode: "
        )

        print(
            "\nEncoded Base64:"
        )

        print(
            encode_base64(text)
        )

    elif base64_choice == "2":
        text = input(
            "\nEnter Base64 text to decode: "
        )

        result = decode_base64(
            text
        )

        if result is not None:
            print(
                "\nDecoded Text:"
            )

            print(result)

        else:
            print(
                "\n[-] Invalid Base64 input."
            )

    elif base64_choice == "3":
        return

    else:
        print(
            "\n[-] Invalid Base64 option."
        )


def run_hex_analyzer_interactive():
    print("\nHex Analyzer")
    print("-" * LINE_WIDTH)

    file_path = input(
        "Enter file path: "
    ).strip()

    if not file_path:
        print(
            "\n[-] No file path provided."
        )

        return

    file_path = normalize_file_path(
        file_path
    )

    analyze_hex(
        file_path
    )


def interactive_menu():
    show_banner()

    while True:
        show_menu()

        try:
            choice = input(
                "\nSelect an option: "
            ).strip()

            if choice == "1":
                run_smart_analysis_interactive()
                wait_for_enter()

            elif choice == "2":
                run_file_analyzer_interactive()
                wait_for_enter()

            elif choice == "3":
                run_flag_detector_interactive()
                wait_for_enter()

            elif choice == "4":
                run_strings_extractor_interactive()
                wait_for_enter()

            elif choice == "5":
                run_base64_tool_interactive()
                wait_for_enter()

            elif choice == "6":
                run_hex_analyzer_interactive()
                wait_for_enter()

            elif choice == "7":
                get_system_info()
                wait_for_enter()

            elif choice == "8":
                print(
                    "\nExiting FalconCTF. Goodbye."
                )

                break

            else:
                print(
                    "\n[-] Invalid option. "
                    "Please choose 1-8."
                )

        except KeyboardInterrupt:
            print(
                "\n\n[!] Interrupted by user."
            )

        except EOFError:
            print(
                "\n\nExiting FalconCTF."
            )

            break


# =========================================================
# Command-line interface
# =========================================================

def build_parser():
    parser = argparse.ArgumentParser(
        prog="falconctf",
        description=(
            "FalconCTF - Intelligent CTF Analysis Framework"
        ),
        epilog=(
            "Example: falconctf analyze challenge.zip"
        )
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"FalconCTF {VERSION}"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        metavar="COMMAND"
    )

    # -----------------------------------------------------
    # Smart Analysis
    # -----------------------------------------------------

    analyze_parser = subparsers.add_parser(
        "analyze",
        help=(
            "Run FalconCTF intelligent analysis "
            "against a challenge file."
        )
    )

    analyze_parser.add_argument(
        "file",
        help="Challenge file to analyze."
    )

    analyze_parser.add_argument(
        "-p",
        "--password",
        help=(
            "Optional archive password."
        )
    )

    # -----------------------------------------------------
    # File Analyzer
    # -----------------------------------------------------

    file_parser = subparsers.add_parser(
        "file",
        help="Run basic file inspection."
    )

    file_parser.add_argument(
        "file",
        help="File to inspect."
    )

    # -----------------------------------------------------
    # Flag Detector
    # -----------------------------------------------------

    flag_parser = subparsers.add_parser(
        "flags",
        help="Search text for CTF flag patterns."
    )

    flag_parser.add_argument(
        "text",
        help="Text to scan."
    )

    # -----------------------------------------------------
    # Strings
    # -----------------------------------------------------

    strings_parser = subparsers.add_parser(
        "strings",
        help=(
            "Extract and analyze readable strings."
        )
    )

    strings_parser.add_argument(
        "file",
        help="File to analyze."
    )

    # -----------------------------------------------------
    # Base64
    # -----------------------------------------------------

    base64_parser = subparsers.add_parser(
        "base64",
        help="Encode or decode Base64 data."
    )

    base64_group = (
        base64_parser
        .add_mutually_exclusive_group(
            required=True
        )
    )

    base64_group.add_argument(
        "-e",
        "--encode",
        metavar="TEXT",
        help="Encode text as Base64."
    )

    base64_group.add_argument(
        "-d",
        "--decode",
        metavar="TEXT",
        help="Decode Base64 text."
    )

    # -----------------------------------------------------
    # Hex
    # -----------------------------------------------------

    hex_parser = subparsers.add_parser(
        "hex",
        help="Inspect file hex/header data."
    )

    hex_parser.add_argument(
        "file",
        help="File to inspect."
    )

    # -----------------------------------------------------
    # System
    # -----------------------------------------------------

    subparsers.add_parser(
        "system",
        help="Display FalconCTF environment information."
    )

    return parser


def cli():
    parser = build_parser()

    args = parser.parse_args()

    # Running without arguments keeps the original
    # interactive FalconCTF interface.
    if args.command is None:
        interactive_menu()
        return 0

    if args.command == "analyze":
        result = smart_analyze(
            normalize_file_path(
                args.file
            ),
            archive_password=args.password
        )

        return 0 if result is not None else 1

    if args.command == "file":
        analyze_file(
            normalize_file_path(
                args.file
            )
        )

        return 0

    if args.command == "flags":
        flags = detect_flags(
            args.text
        )

        if flags:
            for flag in flags:
                print(flag)

            return 0

        print(
            "No obvious CTF flag pattern found."
        )

        return 0

    if args.command == "strings":
        run_strings_analysis(
            normalize_file_path(
                args.file
            )
        )

        return 0

    if args.command == "base64":
        if args.encode is not None:
            print(
                encode_base64(
                    args.encode
                )
            )

            return 0

        decoded = decode_base64(
            args.decode
        )

        if decoded is None:
            print(
                "Error: Invalid Base64 input."
            )

            return 1

        print(decoded)

        return 0

    if args.command == "hex":
        analyze_hex(
            normalize_file_path(
                args.file
            )
        )

        return 0

    if args.command == "system":
        get_system_info()

        return 0

    parser.print_help()

    return 1


def main():
    return cli()


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
