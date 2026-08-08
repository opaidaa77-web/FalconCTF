import re


FLAG_PATTERNS = [
    r"\bpicoCTF\{[^}]+\}",
    r"\bHTB\{[^}]+\}",
    r"\bCTF\{[^}]+\}",
    r"\bflag\{[^}]+\}",
]



def detect_flags(text):
    found_flags = []

    for pattern in FLAG_PATTERNS:
        matches = re.findall(pattern, text, flags=re.IGNORECASE)

        for match in matches:
            if match not in found_flags:
                found_flags.append(match)

    return found_flags
