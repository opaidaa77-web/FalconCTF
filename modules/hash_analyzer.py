import hashlib
import os


def calculate_hashes(file_path):
    if not os.path.isfile(file_path):
        return None

    try:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as file:
            while True:
                chunk = file.read(4096)

                if not chunk:
                    break

                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

        return {
            "MD5": md5.hexdigest(),
            "SHA1": sha1.hexdigest(),
            "SHA256": sha256.hexdigest()
        }

    except (OSError, PermissionError):
        return None
