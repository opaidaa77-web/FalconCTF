from config.settings import *
from modules.system_info import get_system_info
from modules.file_analyzer import analyze_file
from modules.flag_detector import detect_flags
from modules.strings_extractor import extract_strings

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
    print("[5] Exit")


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
            else:
                print("\nNo readable strings found.")

        elif choice == "5":
            print("\nExiting FalconCTF...")
            break

        else:
            print("\nInvalid option. Please choose 1-5.")


if __name__ == "__main__":
    main()
