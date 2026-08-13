def generate_recommendations(
    file_type,
    findings,
    detected_flags=None,
    score_result=None,
    encoding_results=None
):
    recommendations = []

    detected_flags = detected_flags or []
    score_result = score_result or {}
    encoding_results = encoding_results or {}

    def add(text):
        if text not in recommendations:
            recommendations.append(text)

    file_type_lower = file_type.lower()

    # -------------------------------------------------
    # Flag discovered
    # -------------------------------------------------

    if detected_flags:
        add(
            "Review and validate the detected "
            "CTF flag(s) before submission."
        )

    # -------------------------------------------------
    # Archive encryption state
    # -------------------------------------------------

    encrypted_files = set(
        findings.get("encrypted_files", [])
    )

    decrypted_files = set(
        findings.get("decrypted_files", [])
    )

    unresolved_encrypted = (
        encrypted_files - decrypted_files
    )

    if unresolved_encrypted:
        add(
            "Encrypted archive content remains locked. "
            "Obtain or identify the correct password and "
            "analyze the protected files."
        )

    if decrypted_files:
        add(
            "Encrypted archive content was successfully "
            "decrypted. Continue analyzing the recovered "
            "content."
        )

    # -------------------------------------------------
    # Encoded data
    # -------------------------------------------------

    if findings.get("base64_decoded"):
        add(
            "Base64 encoded content was successfully "
            "decoded. Review the decoded data for flags, "
            "secrets or additional encoded layers."
        )

    if findings.get("hex_decoded"):
        add(
            "Hex encoded content was successfully decoded. "
            "Inspect the decoded data for flags, secrets "
            "or additional encoded layers."
        )

    if (
        findings.get("base64_decoded")
        or findings.get("hex_decoded")
    ):
        add(
            "Check decoded content for nested or repeated "
            "encoding that may require another decoding pass."
        )

    # -------------------------------------------------
    # Decoded Payload Intelligence
    # -------------------------------------------------

    decoded_payloads = encoding_results.get(
        "payloads",
        []
    )

    for payload in decoded_payloads:
        route = str(
            payload.get(
                "route",
                ""
            )
        ).lower()

        payload_type = str(
            payload.get(
                "payload_type",
                "decoded payload"
            )
        )

        if route == "archive_analysis":
            add(
                f"Analyze the decoded {payload_type} and inspect "
                "its internal files, nested content and hidden artifacts."
            )

        elif route == "binary_analysis":
            add(
                f"Perform static analysis on the decoded {payload_type}, "
                "including strings, symbols, imports and program structure."
            )

        elif route == "forensics":
            add(
                f"Inspect the decoded {payload_type} for metadata, "
                "embedded content and hidden or appended data."
            )

        elif route == "encoding_analysis":
            add(
                "Continue decoding the recovered payload because "
                "another encoding layer was detected."
            )

        elif route == "verify_flag":
            add(
                "Validate the flag candidate recovered from "
                "the decoded payload before submission."
            )

        elif route == "stop_recursive_decoding":
            add(
                "Stop automatic recursive decoding for this payload "
                "and inspect it manually because its decoded quality "
                "is too low for reliable automatic processing."
            )

    # -------------------------------------------------
    # Interesting archive files
    # -------------------------------------------------

    if findings.get("archive_files"):
        add(
            "Inspect the interesting files discovered "
            "inside the archive."
        )

    # -------------------------------------------------
    # ELF
    # -------------------------------------------------

    if "elf" in file_type_lower:
        add(
            "Inspect readable strings, symbols and imported "
            "functions in the ELF binary."
        )

        add(
            "Continue with static reverse engineering if "
            "the flag is not directly exposed."
        )

    # -------------------------------------------------
    # PE
    # -------------------------------------------------

    if "pe executable" in file_type_lower:
        add(
            "Inspect PE strings, imports and suspicious "
            "embedded data."
        )

        add(
            "Consider static reverse engineering if further "
            "analysis is required."
        )

    # -------------------------------------------------
    # Images
    # -------------------------------------------------

    if (
        "png" in file_type_lower
        or "jpeg" in file_type_lower
    ):
        add(
            "Inspect image metadata and search for hidden "
            "or appended data."
        )

    # -------------------------------------------------
    # PDF
    # -------------------------------------------------

    if "pdf" in file_type_lower:
        add(
            "Inspect PDF metadata, embedded strings and "
            "possible embedded objects."
        )

    # -------------------------------------------------
    # ZIP
    # -------------------------------------------------

    if "gzip" in file_type_lower:
        add(
            "Continue analysis of the extracted GZIP "
            "payload using its detected inner file type."
        )

    elif "zip" in file_type_lower:
        add(
            "Review archive structure and nested files for "
            "hidden CTF artifacts."
        )

    # -------------------------------------------------
    # Indicators
    # -------------------------------------------------

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

    # -------------------------------------------------
    # Interest score
    # -------------------------------------------------

    score = score_result.get("score", 0)

    if score >= 50:
        add(
            "Prioritize this file because FalconCTF detected "
            "multiple high-interest indicators."
        )

    # -------------------------------------------------
    # Fallback
    # -------------------------------------------------

    if not recommendations:
        add(
            "No strong indicators were detected. Continue "
            "with manual inspection and deeper analysis."
        )

    return recommendations
