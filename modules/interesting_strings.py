import re


def analyze_interesting_strings(strings):
    results = {
        "flags": [],
        "urls": [],
        "emails": [],
        "ips": [],
        "keywords": []
    }

    keyword_list = [
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey"
]

    for text in strings:

        # Detect flags
        if re.search(r"[A-Za-z0-9_]+\{[^{}]+\}", text):
            results["flags"].append(text)

        # Detect URLs
        if re.search(r"https?://[^\s]+", text):
            results["urls"].append(text)

        # Detect email addresses
        if re.search(r"[\w.-]+@[\w.-]+\.\w+", text):
            results["emails"].append(text)

        # Detect IPv4 addresses
        if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
            results["ips"].append(text)

        # Detect interesting keywords
        lower_text = text.lower()

        for keyword in keyword_list:
            if keyword in lower_text:
                results["keywords"].append(text)
                break

    return results
