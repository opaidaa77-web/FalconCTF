def classify_challenge(
    file_type,
    analysis_plan=None,
    findings=None,
    encoding_results=None,
    archive_results=None
):
    analysis_plan = analysis_plan or []
    findings = findings or {}
    encoding_results = encoding_results or {}
    archive_results = archive_results or {}

    scores = {
        "Reverse Engineering": 0,
        "Forensics": 0,
        "Archive": 0,
        "Encoding / Crypto": 0,
        "General Analysis": 0
    }

    reasons = {
        "Reverse Engineering": [],
        "Forensics": [],
        "Archive": [],
        "Encoding / Crypto": [],
        "General Analysis": []
    }

    file_type_lower = file_type.lower()

    # -------------------------------------------------
    # Reverse Engineering indicators
    # -------------------------------------------------

    if "elf" in file_type_lower:
        scores["Reverse Engineering"] += 70
        reasons["Reverse Engineering"].append(
            "ELF executable detected."
        )

    if "pe executable" in file_type_lower:
        scores["Reverse Engineering"] += 70
        reasons["Reverse Engineering"].append(
            "Windows PE executable detected."
        )

    if "binary_analysis" in analysis_plan:
        scores["Reverse Engineering"] += 20
        reasons["Reverse Engineering"].append(
            "Binary analysis was selected by the analysis router."
        )

    if "hex_analysis" in analysis_plan:
        scores["Reverse Engineering"] += 5
        reasons["Reverse Engineering"].append(
            "Low-level hexadecimal inspection is relevant."
        )

    # -------------------------------------------------
    # Forensics indicators
    # -------------------------------------------------

    if (
        "png" in file_type_lower
        or "jpeg" in file_type_lower
        or "jpg" in file_type_lower
    ):
        scores["Forensics"] += 70
        reasons["Forensics"].append(
            "Image file detected."
        )

    if "pdf" in file_type_lower:
        scores["Forensics"] += 60
        reasons["Forensics"].append(
            "PDF document detected."
        )

    if "metadata_analysis" in analysis_plan:
        scores["Forensics"] += 20
        reasons["Forensics"].append(
            "Metadata analysis is relevant to this file."
        )

    # -------------------------------------------------
    # Archive indicators
    # -------------------------------------------------

    if "zip" in file_type_lower:
        scores["Archive"] += 75
        reasons["Archive"].append(
            "ZIP archive detected."
        )

    if "archive_analysis" in analysis_plan:
        scores["Archive"] += 20
        reasons["Archive"].append(
            "Archive analysis was selected automatically."
        )

    if archive_results.get("interesting_files"):
        scores["Archive"] += 10
        reasons["Archive"].append(
            "Interesting files were discovered inside the archive."
        )

    if archive_results.get("encrypted_files"):
        scores["Archive"] += 10
        reasons["Archive"].append(
            "Encrypted archive content was detected."
        )

    # -------------------------------------------------
    # Encoding / Crypto indicators
    # -------------------------------------------------

    if encoding_results.get("base64"):
        scores["Encoding / Crypto"] += 30
        reasons["Encoding / Crypto"].append(
            "Base64 encoded content was detected."
        )

    if encoding_results.get("hex"):
        scores["Encoding / Crypto"] += 30
        reasons["Encoding / Crypto"].append(
            "Hex encoded content was detected."
        )

    recursive_layers = encoding_results.get(
        "recursive_layers",
        []
    )

    if recursive_layers:
        max_depth = max(
            (
                layer.get("depth", 1)
                for layer in recursive_layers
            ),
            default=1
        )

        scores["Encoding / Crypto"] += min(
            35,
            max_depth * 10
        )

        reasons["Encoding / Crypto"].append(
            f"Recursive encoding chain detected "
            f"with depth {max_depth}."
        )

    if encoding_results.get("decoded_flags"):
        scores["Encoding / Crypto"] += 20
        reasons["Encoding / Crypto"].append(
            "A flag was recovered from encoded data."
        )

    # -------------------------------------------------
    # Payload Intelligence indicators
    # -------------------------------------------------

    payloads = encoding_results.get(
        "payloads",
        []
    )

    payload_routes = {
        str(
            payload.get(
                "route",
                ""
            )
        ).lower()
        for payload in payloads
    }

    payload_sources = {
        str(
            payload.get(
                "source_encoding",
                ""
            )
        ).lower()
        for payload in payloads
    }

    if payloads:
        if (
            "base64" in payload_sources
            or "hex" in payload_sources
        ):
            scores[
                "Encoding / Crypto"
            ] += 30

            reasons[
                "Encoding / Crypto"
            ].append(
                "Encoded content produced a meaningful "
                "decoded payload."
            )

        if "archive_analysis" in payload_routes:
            scores["Archive"] += 75

            reasons["Archive"].append(
                "A decoded archive payload was detected."
            )

        if "binary_analysis" in payload_routes:
            scores[
                "Reverse Engineering"
            ] += 75

            reasons[
                "Reverse Engineering"
            ].append(
                "A decoded executable payload was detected."
            )

        if "forensics" in payload_routes:
            scores["Forensics"] += 70

            reasons["Forensics"].append(
                "A decoded forensic payload was detected."
            )

        if "encoding_analysis" in payload_routes:
            scores[
                "Encoding / Crypto"
            ] += 25

            reasons[
                "Encoding / Crypto"
            ].append(
                "Decoded data contains another encoding layer."
            )

        if "verify_flag" in payload_routes:
            scores[
                "Encoding / Crypto"
            ] += 20

            reasons[
                "Encoding / Crypto"
            ].append(
                "A flag candidate was recovered from "
                "decoded payload data."
            )

    # -------------------------------------------------
    # Findings-based indicators
    # -------------------------------------------------

    if findings.get("keywords"):
        scores["General Analysis"] += 10
        reasons["General Analysis"].append(
            "Sensitive keywords were detected."
        )

    if findings.get("urls"):
        scores["General Analysis"] += 5
        reasons["General Analysis"].append(
            "URL indicators were detected."
        )

    if findings.get("ips"):
        scores["General Analysis"] += 5
        reasons["General Analysis"].append(
            "IP address indicators were detected."
        )

    if findings.get("emails"):
        scores["General Analysis"] += 5
        reasons["General Analysis"].append(
            "Email indicators were detected."
        )

    # -------------------------------------------------
    # Select best category
    # -------------------------------------------------

    best_category = max(
        scores,
        key=scores.get
    )

    best_score = scores[
        best_category
    ]

    if best_score <= 0:
        best_category = "Unknown"
        confidence = 20
        best_reasons = [
            "No strong challenge category indicators were detected."
        ]

    else:
        confidence = min(
            100,
            best_score
        )

        best_reasons = reasons[
            best_category
        ]

    # -------------------------------------------------
    # Secondary category
    # -------------------------------------------------

    sorted_categories = sorted(
        scores.items(),
        key=lambda item: item[1],
        reverse=True
    )

    secondary_category = None
    secondary_score = 0

    if len(sorted_categories) > 1:
        second_name, second_score = (
            sorted_categories[1]
        )

        if (
            second_score >= 25
            and second_name != best_category
        ):
            secondary_category = second_name
            secondary_score = min(
                100,
                second_score
            )

    return {
        "category": best_category,
        "confidence": confidence,
        "reasons": best_reasons,
        "secondary_category": secondary_category,
        "secondary_confidence": secondary_score,
        "scores": scores
    }
