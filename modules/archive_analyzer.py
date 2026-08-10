import os
import zipfile


def analyze_archive(file_path):
    print("\n" + "=" * 55)
    print("Archive Analysis")
    print("=" * 55)

    if not zipfile.is_zipfile(file_path):
        print("[-] File is not a valid ZIP archive.")
        return

    try:
        with zipfile.ZipFile(file_path, "r") as archive:
            members = archive.infolist()

            print("[+] Valid ZIP archive detected")
            print("[+] Files inside archive:", len(members))

            if not members:
                print("[-] Archive is empty.")
                return

            print("\nArchive Contents:")

            suspicious_extensions = {
                ".exe", ".dll", ".bin", ".sh", ".py",
                ".js", ".php", ".bat", ".ps1"
            }

            interesting_names = {
                "flag", "password", "passwd", "secret",
                "key", "token", "credential"
            }

            for member in members:
                name = member.filename
                size = member.file_size

                print(f" - {name} ({size} bytes)")

                lower_name = name.lower()
                extension = os.path.splitext(lower_name)[1]

                if extension in suspicious_extensions:
                    print(f"   [!] Interesting extension: {extension}")

                if any(keyword in lower_name for keyword in interesting_names):
                    print("   [!] Interesting filename detected")

    except (OSError, zipfile.BadZipFile) as error:
        print("[-] Archive analysis error:", error)
