import os
import re
import zipfile
from io import BytesIO


MAX_FILE_SIZE = 1024 * 1024           # 1 MB per file
MAX_ARCHIVE_SIZE = 5 * 1024 * 1024   # 5 MB nested ZIP limit
MAX_DEPTH = 2


SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".bin", ".sh", ".py",
    ".js", ".php", ".bat", ".ps1"
}


INTERESTING_NAMES = {
    "flag", "password", "passwd", "secret",
    "key", "token", "credential"
}


FLAG_PATTERN = re.compile(
    r"[A-Za-z0-9_]+{[^{}\r\n]+}"
)


def add_unique(target_list, value):
    if value not in target_list:
        target_list.append(value)


def scan_text_content(text, display_name, results, indent="   "):
    flags = FLAG_PATTERN.findall(text)

    for flag in flags:
        print(f"{indent}[FLAG] {flag}")
        add_unique(results["flags"], flag)

    lower_text = text.lower()

    for keyword in INTERESTING_NAMES:
        if keyword in lower_text:
            print(
                f"{indent}[!] Sensitive content keyword: "
                f"{keyword}"
            )

            finding = f"{display_name}: {keyword}"

            add_unique(
                results["keywords"],
                finding
            )


def analyze_nested_zip(
    raw_data,
    parent_name,
    results,
    depth,
    password_bytes=None
):
    if depth >= MAX_DEPTH:
        print(
            "   [!] Nested ZIP found - "
            "max recursion depth reached"
        )
        return

    if len(raw_data) > MAX_ARCHIVE_SIZE:
        print(
            "   [!] Nested ZIP too large - skipped"
        )
        return

    try:
        nested_buffer = BytesIO(raw_data)

        if not zipfile.is_zipfile(nested_buffer):
            print("   [-] Nested ZIP is invalid")
            return

        nested_buffer.seek(0)

        with zipfile.ZipFile(
            nested_buffer,
            "r"
        ) as nested_archive:

            print(
                "   [+] Nested ZIP detected - analyzing"
            )

            for nested_member in nested_archive.infolist():

                nested_name = (
                    f"{parent_name} -> "
                    f"{nested_member.filename}"
                )

                if nested_member.is_dir():
                    print(
                        f"      - {nested_name} "
                        "[directory]"
                    )
                    continue

                nested_size = nested_member.file_size

                nested_lower_name = (
                    nested_member.filename.lower()
                )

                nested_extension = os.path.splitext(
                    nested_lower_name
                )[1]

                print(
                    f"      - {nested_name} "
                    f"({nested_size} bytes)"
                )

                if (
                    nested_extension
                    in SUSPICIOUS_EXTENSIONS
                ):
                    print(
                        "        [!] Interesting "
                        f"extension: {nested_extension}"
                    )

                    add_unique(
                        results["interesting_files"],
                        nested_name
                    )

                if any(
                    keyword in nested_lower_name
                    for keyword in INTERESTING_NAMES
                ):
                    print(
                        "        [!] Interesting "
                        "filename detected"
                    )

                    add_unique(
                        results["interesting_files"],
                        nested_name
                    )

                if nested_size > MAX_FILE_SIZE:
                    print(
                        "        [!] Nested file too "
                        "large - skipped"
                    )
                    continue

                # Encrypted nested file
                if nested_member.flag_bits & 0x1:

                    add_unique(
                        results["encrypted_files"],
                        nested_name
                    )

                    if password_bytes is None:
                        print(
                            "        [!] Encrypted "
                            "nested file - password "
                            "required"
                        )
                        continue

                    try:
                        nested_data = nested_archive.read(
                            nested_member,
                            pwd=password_bytes
                        )

                        print(
                            "        [+] Password accepted"
                        )

                    except RuntimeError:
                        print(
                            "        [-] Wrong password "
                            "or unsupported encryption"
                        )
                        continue

                    except (
                        OSError,
                        zipfile.BadZipFile
                    ) as error:
                        print(
                            "        [-] Could not "
                            "decrypt nested file:",
                            error
                        )
                        continue

                else:
                    try:
                        nested_data = nested_archive.read(
                            nested_member
                        )

                    except (
                        RuntimeError,
                        OSError,
                        zipfile.BadZipFile
                    ) as error:
                        print(
                            "        [-] Could not "
                            "read nested file:",
                            error
                        )
                        continue

                if nested_extension == ".zip":
                    analyze_nested_zip(
                        nested_data,
                        nested_name,
                        results,
                        depth + 1,
                        password_bytes
                    )
                    continue

                nested_text = nested_data.decode(
                    "utf-8",
                    errors="ignore"
                )

                scan_text_content(
                    nested_text,
                    nested_name,
                    results,
                    indent="        "
                )

    except (
        OSError,
        zipfile.BadZipFile
    ) as error:

        print(
            "   [-] Nested ZIP analysis error:",
            error
        )


def analyze_archive(file_path, password=None):

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
        print(
            "[-] File is not a valid ZIP archive."
        )
        return results

    password_bytes = None

    if password is not None:
        password_bytes = password.encode("utf-8")

    try:
        with zipfile.ZipFile(
            file_path,
            "r"
        ) as archive:

            members = archive.infolist()

            print(
                "[+] Valid ZIP archive detected"
            )

            print(
                "[+] Entries inside archive:",
                len(members)
            )

            if not members:
                print("[-] Archive is empty.")
                return results

            print("\nArchive Contents:")

            for member in members:

                name = member.filename

                if member.is_dir():
                    print(
                        f" - {name} [directory]"
                    )
                    continue

                size = member.file_size

                lower_name = name.lower()

                extension = os.path.splitext(
                    lower_name
                )[1]

                print(
                    f" - {name} ({size} bytes)"
                )

                if extension in SUSPICIOUS_EXTENSIONS:

                    print(
                        "   [!] Interesting "
                        f"extension: {extension}"
                    )

                    add_unique(
                        results["interesting_files"],
                        name
                    )

                if any(
                    keyword in lower_name
                    for keyword in INTERESTING_NAMES
                ):

                    print(
                        "   [!] Interesting "
                        "filename detected"
                    )

                    add_unique(
                        results["interesting_files"],
                        name
                    )

                if size > MAX_FILE_SIZE:
                    print(
                        "   [!] File too large - "
                        "content scan skipped"
                    )
                    continue

                # Encrypted file
                if member.flag_bits & 0x1:

                    add_unique(
                        results["encrypted_files"],
                        name
                    )

                    if password_bytes is None:

                        print(
                            "   [!] Encrypted file - "
                            "password required"
                        )

                        continue

                    try:
                        raw_data = archive.read(
                            member,
                            pwd=password_bytes
                        )

                        print(
                            "   [+] Password accepted"
                        )

                    except RuntimeError:

                        print(
                            "   [-] Wrong password or "
                            "unsupported encryption"
                        )

                        continue

                    except (
                        OSError,
                        zipfile.BadZipFile
                    ) as error:

                        print(
                            "   [-] Could not decrypt "
                            "file:",
                            error
                        )

                        continue

                else:

                    try:
                        raw_data = archive.read(
                            member
                        )

                    except (
                        RuntimeError,
                        OSError,
                        zipfile.BadZipFile
                    ) as error:

                        print(
                            "   [-] Could not read file:",
                            error
                        )

                        continue

                # Nested ZIP detection
                if extension == ".zip":

                    analyze_nested_zip(
                        raw_data,
                        name,
                        results,
                        0,
                        password_bytes
                    )

                    continue

                text = raw_data.decode(
                    "utf-8",
                    errors="ignore"
                )

                scan_text_content(
                    text,
                    name,
                    results
                )

    except (
        OSError,
        zipfile.BadZipFile
    ) as error:

        print(
            "[-] Archive analysis error:",
            error
        )

    return results
