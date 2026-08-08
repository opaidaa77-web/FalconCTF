import os
import hashlib
import mimetypes
from modules.flag_detector import detect_flags

def analyze_file(file_path):
    if not os.path.isfile(file_path):
        print("Error: File not found.")
        return

    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)
    mime_type, _ = mimetypes.guess_type(file_path)

    print("=" * 50)
    print("FalconCTF File Analyzer")
    print("=" * 50)

    print("File Name :", file_name)
    print("File Path :", os.path.abspath(file_path))
    print("File Size :", file_size, "bytes")
    print("MIME Type :", mime_type)

    with open(file_path, "rb") as file:
        data = file.read()

    md5_hash = hashlib.md5(data).hexdigest()
    sha1_hash = hashlib.sha1(data).hexdigest()
    sha256_hash = hashlib.sha256(data).hexdigest()

    print("MD5       :", md5_hash)
    print("SHA1      :", sha1_hash)
    print("SHA256    :", sha256_hash)
    text_data = data.decode("utf-8", errors="ignore")
    found_flags = detect_flags(text_data)

    print("\nFlag Detection:")
    if found_flags:
        for flag in found_flags:
            print("Found Flag :", flag)
    else:
        print("No obvious flag pattern found.")
