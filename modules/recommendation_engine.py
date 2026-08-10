def generate_recommendations(
    file_type,
    findings,
    detected_flags=None,
    score_result=None
):
    recommendations = []
    detected_flags = detected_flags or []
    score_result = score_result or {}

    def add(text):
        if text not in recommendations:
            recommendations.append(text)

    file_type_lower = file_type.lower()

    # Flag discovered
    if detected_flags:
        add(
            "Review and validate the detected CTF flag(s) "
            "before submission."
        )

    # Encrypted archive content
    if findings.get("encrypted_files"):
        add(
            "Encrypted archive content was detected. "
            "Obtain or identify the password and analyze "
            "the protected files."
        )

    # Interesting archive files
    if findings.get("archive_files"):
        add(
            "Inspect the interesting files discovered "
            "inside the archive."
        )

    # ELF / Linux binary
    if "elf" in file_type_lower:
        add(
            "Inspect readable strings, symbols and imported "
            "functions in the ELF binary."
        )
        add(
            "Continue with static reverse engineering if "
            "the flag is not directly exposed."
        )

    # Windows executable
    if "pe executable" in file_type_lower:
        add(
            "Inspect PE strings, imports and suspicious "
            "embedded data."
        )
        add(
            "Consider static reverse engineering if further "
            "analysis is required."
        )

    # Images
    if (
        "png" in file_type_lower
        or "jpeg" in file_type_lower
    ):
        add(
            "Inspect image metadata and search for hidden "
            "or appended data."
        )

    # PDF
    if "pdf" in file_type_lower:
        add(
            "Inspect PDF metadata, embedded strings and "
            "possible embedded objects."
        )

    # ZIP
    if "zip" in file_type_lower:
        add(
            "Review archive structure and nested files for "
            "hidden CTF artifacts."
        )

    # Interesting indicators
    if findings.get("urls"):
        add(
            "Review detected URLs for challenge-related "
            "context or indicators."
        )

    if findings.get("ips"):
        add(
            "Investigate detected IP addresses if they are "
            "relevant to the challenge."
        )

    if findings.get("emails"):
        add(
            "Review detected email addresses for possible "
            "challenge context."
        )

    if findings.get("keywords"):
        add(
            "Inspect the locations containing sensitive "
            "keywords such as flag, password, key or secret."
        )

    # High score
    score = score_result.get("score", 0)

    if score >= 50:
        add(
            "Prioritize this file because FalconCTF detected "
            "multiple high-interest indicators."
        )

    # Nothing obvious
    if not recommendations:
        add(
            "No strong indicators were detected. Continue "
            "with manual inspection and deeper analysis."
        )

    return recommendations
