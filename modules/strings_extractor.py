import re


def extract_strings(file_path, min_length=4):
    try:
        with open(file_path, "rb") as file:
            data = file.read()

        pattern = rb"[\x20-\x7E]{" + str(min_length).encode() + rb",}"
        matches = re.findall(pattern, data)

        results = []

        for match in matches:
            text = match.decode("utf-8", errors="ignore")

            if text not in results:
                results.append(text)

        return results

    except FileNotFoundError:
        return []
