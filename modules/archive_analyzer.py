import os
import re
import zipfile


MAX_FILE_SIZE = 1024 * 1024  # 1 MB per file


def analyze_archive(file_path):
    results = {
        "flags": [],
        "keywords": [],
        "interesting_files": [],
        "encrypted_files": []
    }

    print("\n" + "=" * 55)
    print("Archive Analysis")
    print("=" * 55)

    if not zipfile.is_zipfile(file_path):
        print("[-] File is not a valid ZIP archive.")
        return results

    suspicious_extensions = {
        ".exe", ".dll", ".bin", ".sh", ".py",
        ".js", ".php", ".bat", ".ps1"
    }

    interesting_names = {
        "flag", "password", "passwd", "secret",
        "key", "token", "credential"
    }

    flag_pattern = re.compile(
        r"[A-Za-z0-9_]+\{[^{}\r\n]+\}"
    )

    try:
        with zipfile.ZipFile(file_path, "r") as archive:
            members = archive.infolist()

            print("[+] Valid ZIP archive detected")
            print("[+] Entries inside archive:", len(members))

            if not members:
                print("[-] Archive is empty.")
                return results

            print("\nArchive Contents:")

            for member in members:
                name = member.filename

                if member.is_dir():
                    print(f" - {name} [directory]")
                    continue

                size = member.file_size
                lower_name = name.lower()
                extension = os.path.splitext(lower_name)[1]

                print(f" - {name} ({size} bytes)")

                if extension in suspicious_extensions:
                    print(f"   [!] Interesting extension: {extension}")

                    if name not in results["interesting_files"]:
                        results["interesting_files"].append(name)

                if any(keyword in lower_name for keyword in interesting_names):
                    print("   [!] Interesting filename detected")

                    if name not in results["interesting_files"]:
                        results["interesting_files"].append(name)

                if member.flag_bits & 0x1:
                    print("   [!] Encrypted file - content not scanned")
                    results["encrypted_files"].append(name)
                    continue

                if size > MAX_FILE_SIZE:
                    print("   [!] File too large - content scan skipped")
                    continue

                try:
                    raw_data = archive.read(member)
                    text = raw_data.decode("utf-8", errors="ignore")

                except (RuntimeError, OSError, zipfile.BadZipFile) as error:
                    print("   [-] Could not read file:", error)
                    continue

                flags = flag_pattern.findall(text)

                for flag in flags:
                    print(f"   [FLAG] {flag}")

                    if flag not in results["flags"]:
                        results["flags"].append(flag)

                lower_text = text.lower()

                for keyword in interesting_names:
                    if keyword in lower_text:
                        print(f"   [!] Sensitive content keyword: {keyword}")

                        finding = f"{name}: {keyword}"

                        if finding not in results["keywords"]:
                            results["keywords"].append(finding)

    except (OSError, zipfile.BadZipFile) as error:
        print("[-] Archive analysis error:", error)

    return results
