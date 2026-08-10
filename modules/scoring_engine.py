def calculate_interest_score(findings, detected_flags=None):
    score = 0
    reasons = []

    detected_flags = detected_flags or []

    # -------------------------------------------------
    # 1. CTF Flags
    # -------------------------------------------------

    if detected_flags:
        points = min(
            50,
            len(detected_flags) * 25
        )

        score += points

        reasons.append(
            f"Detected {len(detected_flags)} possible "
            f"CTF flag(s): +{points}"
        )

    flags = findings.get("flags", [])

    if flags and not detected_flags:
        points = min(
            40,
            len(flags) * 20
        )

        score += points

        reasons.append(
            f"Interesting flag-like pattern(s): +{points}"
        )

    # -------------------------------------------------
    # 2. Sensitive keywords
    # -------------------------------------------------

    keywords = findings.get("keywords", [])

    if keywords:
        points = min(
            25,
            len(keywords) * 10
        )

        score += points

        reasons.append(
            f"Sensitive keyword(s) detected: +{points}"
        )

    # -------------------------------------------------
    # 3. Archive intelligence
    # -------------------------------------------------

    archive_files = findings.get(
        "archive_files",
        []
    )

    if archive_files:
        points = min(
            15,
            len(archive_files) * 5
        )

        score += points

        reasons.append(
            f"Interesting archive file(s) detected: +{points}"
        )

    encrypted_files = set(
        findings.get(
            "encrypted_files",
            []
        )
    )

    decrypted_files = set(
        findings.get(
            "decrypted_files",
            []
        )
    )

    unresolved_encrypted = (
        encrypted_files - decrypted_files
    )

    if unresolved_encrypted:
        points = min(
            20,
            len(unresolved_encrypted) * 10
        )

        score += points

        reasons.append(
            f"Locked encrypted file(s) detected: +{points}"
        )

    if decrypted_files:
        points = min(
            10,
            len(decrypted_files) * 5
        )

        score += points

        reasons.append(
            f"Encrypted file(s) successfully decrypted: +{points}"
        )

    # -------------------------------------------------
    # 4. Encoding intelligence
    # -------------------------------------------------

    base64_decoded = findings.get(
        "base64_decoded",
        []
    )

    if base64_decoded:
        points = min(
            10,
            len(base64_decoded) * 3
        )

        score += points

        reasons.append(
            f"Base64 encoded content decoded: +{points}"
        )

    hex_decoded = findings.get(
        "hex_decoded",
        []
    )

    if hex_decoded:
        points = min(
            10,
            len(hex_decoded) * 3
        )

        score += points

        reasons.append(
            f"Hex encoded content decoded: +{points}"
        )

    encoding_chain = findings.get(
        "encoding_chain",
        []
    )

    if encoding_chain:
        depths = []

        for entry in encoding_chain:
            try:
                depth_text = entry.split("|")[0]

                depth = int(
                    depth_text
                    .replace("Depth", "")
                    .strip()
                )

                depths.append(depth)

            except (
                ValueError,
                IndexError
            ):
                continue

        max_depth = max(
            depths,
            default=1
        )

        points = min(
            15,
            max_depth * 5
        )

        score += points

        reasons.append(
            f"Recursive encoding chain detected "
            f"(depth {max_depth}): +{points}"
        )

    # Bonus when a real flag was recovered
    # through a recursive encoding chain.
    if detected_flags and encoding_chain:
        bonus = 5

        score += bonus

        reasons.append(
            f"Flag recovered through recursive decoding: +{bonus}"
        )

    # -------------------------------------------------
    # 5. Network / investigation indicators
    # -------------------------------------------------

    urls = findings.get("urls", [])

    if urls:
        points = min(
            10,
            len(urls) * 2
        )

        score += points

        reasons.append(
            f"URL indicator(s) detected: +{points}"
        )

    emails = findings.get("emails", [])

    if emails:
        points = min(
            8,
            len(emails) * 2
        )

        score += points

        reasons.append(
            f"Email indicator(s) detected: +{points}"
        )

    ips = findings.get("ips", [])

    if ips:
        points = min(
            12,
            len(ips) * 3
        )

        score += points

        reasons.append(
            f"IP address indicator(s) detected: +{points}"
        )

    # -------------------------------------------------
    # Final score
    # -------------------------------------------------

    score = min(score, 100)

    if score >= 75:
        level = "CRITICAL"

    elif score >= 50:
        level = "HIGH"

    elif score >= 25:
        level = "MEDIUM"

    elif score > 0:
        level = "LOW"

    else:
        level = "INFORMATIONAL"

    return {
        "score": score,
        "level": level,
        "reasons": reasons
    }
