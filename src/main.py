from config.settings import *
from modules.system_info import get_system_info
from modules.file_analyzer import analyze_file
from modules.flag_detector import detect_flags
from modules.strings_extractor import extract_strings
from modules.base64_tool import encode_base64, decode_base64
from modules.interesting_strings import analyze_interesting_strings
from modules.hex_analyzer import analyze_hex


def show_banner():
    print("=" * 50)
    print("              FalconCTF Toolkit")
    print("=" * 50)
    print("Version :", VERSION)
    print("Author  :", AUTHOR)
    print("=" * 50)


def show_menu():
    print("\n[1] System Information")
    print("[2] Analyze File")
    print("[3] Flag Detector")
    print("[4] Strings Extractor")
    print("[5] Base64 Tool")
    print("[6] Hex Analyzer")
    print("[7] Exit")


def main():
    show_banner()

    while True:
        show_menu()
        choice = input("\nSelect an option: ").strip()

        if choice == "1":
            print()
            get_system_info()

        elif choice == "2":
            file_path = input("\nEnter file path: ").strip()
            analyze_file(file_path)

        elif choice == "3":
            text = input("\nEnter text to scan: ")
            flags = detect_flags(text)

            if flags:
                print("\nFlags Found:")
                for flag in flags:
                    print("Found Flag :", flag)
            else:
                print("\nNo obvious flag pattern found.")

        elif choice == "4":
            file_path = input("\nEnter file path: ").strip()
            strings = extract_strings(file_path)

            if strings:
                print(f"\nStrings Found: {len(strings)}")

                for string in strings[:50]:
                    print(string)

                if len(strings) > 50:
                    print(f"\n... and {len(strings) - 50} more strings.")

                findings = analyze_interesting_strings(strings)

                print("\n" + "=" * 50)
                print("Interesting Findings")
                print("=" * 50)

                found_anything = False

                for category, items in findings.items():
                    if items:
                        found_anything = True
                        print(f"\n{category.upper()}:")

                        for item in items:
                            print(" -", item)

                if not found_anything:
                    print("\nNo interesting strings detected.")

            else:
                print("\nNo readable strings found.")

        elif choice == "5":
            print("\n[1] Encode Base64")
            print("[2] Decode Base64")

            base64_choice = input("\nSelect an option: ").strip()

            if base64_choice == "1":
                text = input("\nEnter text to encode: ")
                result = encode_base64(text)

                print("\nEncoded Base64:")
                print(result)

            elif base64_choice == "2":
                text = input("\nEnter Base64 text to decode: ")
                result = decode_base64(text)

                if result is not None:
                    print("\nDecoded Text:")
                    print(result)
                else:
                    print("\nInvalid Base64 input.")

            else:
                print("\nInvalid Base64 option.")

        elif choice == "6":
             file_path = input("\nEnter file path: ").strip()
             analyze_hex(file_path)



        elif choice == "7":
            print("\nExiting FalconCTF...")
            break

        else:
            print("\nInvalid option. Please choose 1-7.")


if __name__ == "__main__":
    main()
