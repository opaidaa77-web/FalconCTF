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


def print_separator(char="="):
    print(char * LINE_WIDTH)


def show_banner():
    print()
    print_separator()
    print("                     FalconCTF Toolkit")
    print("              Intelligent CTF Analysis Framework")
    print_separator()

    print(f"Version : {VERSION}")
    print(f"Author  : {AUTHOR}")

    print_separator()

    print(
        "Automated file analysis, flag detection, archive inspection,\n"
        "encoding analysis, scoring, recommendations and reports."
    )

    print_separator()


def show_menu():
    print("\nMain Menu")
    print("-" * LINE_WIDTH)

    print("[1] Smart Analysis        - Automated full analysis")
    print("[2] File Analyzer         - Basic file inspection")
    print("[3] Flag Detector         - Scan text for CTF flags")
    print("[4] Strings Extractor     - Extract readable strings")
    print("[5] Base64 Tool           - Encode / Decode Base64")
    print("[6] Hex Analyzer          - Inspect file hex/header data")
    print("[7] System Information    - Show environment details")
    print("[8] Exit")

    print("-" * LINE_WIDTH)


def wait_for_enter():
    try:
        input("\nPress Enter to return to the main menu...")
    except (KeyboardInterrupt, EOFError):
        pass


def run_smart_analysis():
    print("\nSmart Analysis")
    print("-" * LINE_WIDTH)

    file_path = input(
        "Enter challenge file path: "
    ).strip()

    if not file_path:
        print("\n[-] No file path provided.")
        return

    smart_analyze(file_path)


def run_file_analyzer():
    print("\nFile Analyzer")
    print("-" * LINE_WIDTH)

    file_path = input(
        "Enter file path: "
    ).strip()

    if not file_path:
        print("\n[-] No file path provided.")
        return

    analyze_file(file_path)


def run_flag_detector():
    print("\nFlag Detector")
    print("-" * LINE_WIDTH)

    text = input(
        "Enter text to scan: "
    )

    flags = detect_flags(text)

    if flags:
        print("\n[+] Flags Found:")

        for flag in flags:
            print(" -", flag)

    else:
        print(
            "\n[-] No obvious CTF flag pattern found."
        )


def run_strings_extractor():
    print("\nStrings Extractor")
    print("-" * LINE_WIDTH)

    file_path = input(
        "Enter file path: "
    ).strip()

    if not file_path:
        print("\n[-] No file path provided.")
        return

    strings = extract_strings(file_path)

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
            f"\n... and {len(strings) - 50} more strings."
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


def run_base64_tool():
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

        result = encode_base64(
            text
        )

        print(
            "\nEncoded Base64:"
        )

        print(result)

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


def run_hex_analyzer():
    print("\nHex Analyzer")
    print("-" * LINE_WIDTH)

    file_path = input(
        "Enter file path: "
    ).strip()

    if not file_path:
        print("\n[-] No file path provided.")
        return

    analyze_hex(file_path)


def run_system_info():
    print("\nSystem Information")
    print("-" * LINE_WIDTH)

    get_system_info()


def main():
    show_banner()

    while True:
        show_menu()

        try:
            choice = input(
                "\nSelect an option: "
            ).strip()

            if choice == "1":
                run_smart_analysis()
                wait_for_enter()

            elif choice == "2":
                run_file_analyzer()
                wait_for_enter()

            elif choice == "3":
                run_flag_detector()
                wait_for_enter()

            elif choice == "4":
                run_strings_extractor()
                wait_for_enter()

            elif choice == "5":
                run_base64_tool()
                wait_for_enter()

            elif choice == "6":
                run_hex_analyzer()
                wait_for_enter()

            elif choice == "7":
                run_system_info()
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


if __name__ == "__main__":
    main()
