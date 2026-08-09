import os


def detect_file_type(data):
    signatures = {
        b"\x7fELF": "ELF Executable (Linux)",
        b"MZ": "PE Executable (Windows EXE/DLL)",
        b"\x89PNG\r\n\x1a\n": "PNG Image",
        b"\xff\xd8\xff": "JPEG Image",
        b"GIF87a": "GIF Image",
        b"GIF89a": "GIF Image",
        b"%PDF": "PDF Document",
        b"PK\x03\x04": "ZIP Archive",
        b"\x1f\x8b": "GZIP Archive",
    }

    for signature, file_type in signatures.items():
        if data.startswith(signature):
            return file_type

    return "Unknown File Type"


def analyze_hex(file_path, bytes_to_read=64):
    if not os.path.isfile(file_path):
        print("File not found.")
        return

    try:
        with open(file_path, "rb") as file:
            data = file.read(bytes_to_read)

        if not data:
            print("File is empty.")
            return

        print("\n" + "=" * 50)
        print("FalconCTF Hex Analyzer")
        print("=" * 50)

        print("File :", file_path)
        print("Bytes Read :", len(data))

        print("\nDetected File Type:")
        print(detect_file_type(data))

        print("\nHEX:")
        print(data.hex(" "))

        print("\nASCII:")
        ascii_output = ""

        for byte in data:
            if 32 <= byte <= 126:
                ascii_output += chr(byte)
            else:
                ascii_output += "."

        print(ascii_output)

        print("\nMagic Bytes:")
        magic = data[:8]
        print(magic.hex(" "))

    except PermissionError:
        print("Permission denied.")

    except OSError as error:
        print("Error reading file:", error)
