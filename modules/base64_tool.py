import base64
import binascii


def encode_base64(text):
    data = text.encode("utf-8")
    encoded = base64.b64encode(data)
    return encoded.decode("utf-8")


def decode_base64(text):
    try:
        decoded = base64.b64decode(text, validate=True)
        return decoded.decode("utf-8", errors="replace")

    except (binascii.Error, ValueError):
        return None
