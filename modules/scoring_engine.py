def calculate_interest_score(findings, detected_flags=None):
    score = 0
    reasons = []

    detected_flags = detected_flags or []

    # -------------------------------------------------
    # 1. CTF Flags - strongest indicator
    # -------------------------------------------------
    if detected_flags:
        points = min(50, len(detected_flags) * 25)
        score += points

        reasons.append(
            f"Detected {len(detected_flags)} possible "
            f"CTF flag(s): +{points}"
        )

    flags = findings.get("flags", [])

    if flags and not detected_flags:
        points = min(40, len(flags) * 20)
        score += points

        reasons.append(
            f"Interesting flag-like pattern(s): +{points}"
        )

    # -------------------------------------------------
    # 2. Sensitive keywords
    # -------------------------------------------------
    keywords = findings.get("keywords", [])

    if keywords:
        points = min(25, len(keywords) * 10)
        score += points

        reasons.append(
            f"Sensitive keyword(s) detected: +{points}"
        )

    # -------------------------------------------------
    # 3. Archive intelligence
    # -------------------------------------------------
    archive_files = findings.get("archive_files", [])

    if archive_files:
        points = min(15, len(archive_files) * 5)
        score += points

        reasons.append(
            f"Interesting archive file(s) detected: +{points}"
        )

    encrypted_files = findings.get("encrypted_files", [])

    if encrypted_files:
        points = min(20, len(encrypted_files) * 10)
        score += points

        reasons.append(
            f"Encrypted archive content detected: +{points}"
        )

    # -------------------------------------------------
    # 4. Network / investigation indicators
    # -------------------------------------------------
    urls = findings.get("urls", [])

    if urls:
        points = min(10, len(urls) * 2)
        score += points

        reasons.append(
            f"URL indicator(s) detected: +{points}"
        )

    emails = findings.get("emails", [])

    if emails:
        points = min(8, len(emails) * 2)
        score += points

        reasons.append(
            f"Email indicator(s) detected: +{points}"
        )

    ips = findings.get("ips", [])

    if ips:
        points = min(12, len(ips) * 3)
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
