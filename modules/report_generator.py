import os
from datetime import datetime


def generate_report(
    file_path,
    file_type,
    hashes,
    findings,
    detected_flags,
    score_result,
    recommendations=None,
    encoding_results=None,
    classification_result=None,
    solve_plan=None,
    output_dir="reports"
):
    encoding_results = encoding_results or {}
    classification_result = classification_result or {}
    solve_plan = solve_plan or []

    os.makedirs(output_dir, exist_ok=True)

    base_name = os.path.basename(file_path)
    safe_name = base_name.replace(" ", "_")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    report_name = f"{safe_name}_{timestamp}_report.txt"
    report_path = os.path.join(output_dir, report_name)

    lines = []

    # -------------------------------------------------
    # Report Header
    # -------------------------------------------------

    lines.append("=" * 60)
    lines.append("FalconCTF Analysis Report")
    lines.append("=" * 60)
    lines.append("")

    lines.append(f"File Name : {base_name}")
    lines.append(f"File Path : {os.path.abspath(file_path)}")
    lines.append(f"File Type : {file_type}")
    lines.append(
        f"Generated : "
        f"{datetime.now().isoformat(timespec='seconds')}"
    )

    # -------------------------------------------------
    # Hashes
    # -------------------------------------------------

    lines.append("")
    lines.append("Hashes")
    lines.append("-" * 60)

    if hashes:
        lines.append(
            f"MD5    : {hashes.get('MD5', 'N/A')}"
        )

        lines.append(
            f"SHA1   : {hashes.get('SHA1', 'N/A')}"
        )

        lines.append(
            f"SHA256 : {hashes.get('SHA256', 'N/A')}"
        )

    else:
        lines.append("No hashes available.")

    # -------------------------------------------------
    # Challenge Classification
    # -------------------------------------------------

    lines.append("")
    lines.append("Challenge Classification")
    lines.append("-" * 60)

    if classification_result:
        lines.append(
            f"Primary   : "
            f"{classification_result.get('category', 'Unknown')} "
            f"({classification_result.get('confidence', 0)}%)"
        )

        secondary_category = classification_result.get(
            "secondary_category"
        )

        if secondary_category:
            lines.append(
                f"Secondary : "
                f"{secondary_category} "
                f"({classification_result.get('secondary_confidence', 0)}%)"
            )

        classification_reasons = classification_result.get(
            "reasons",
            []
        )

        if classification_reasons:
            lines.append("")
            lines.append("Reasons:")

            for reason in classification_reasons:
                lines.append(
                    f"[+] {reason}"
                )

    else:
        lines.append(
            "No challenge classification available."
        )

    # -------------------------------------------------
    # Payload Intelligence
    # -------------------------------------------------

    lines.append("")
    lines.append("Payload Intelligence")
    lines.append("-" * 60)

    payloads = encoding_results.get(
        "payloads",
        []
    )

    if payloads:
        for index, payload in enumerate(
            payloads[:50],
            start=1
        ):
            lines.append("")

            lines.append(
                f"[{index}] "
                f"{payload.get('payload_type', 'Unknown Payload')}"
            )

            lines.append(
                f"    Source Encoding : "
                f"{str(payload.get('source_encoding', 'unknown')).upper()}"
            )

            lines.append(
                f"    Confidence      : "
                f"{payload.get('confidence', 0)}%"
            )

            lines.append(
                f"    Route           : "
                f"{payload.get('route', 'manual_inspection')}"
            )

            reason = payload.get(
                "reason"
            )

            if reason:
                lines.append(
                    f"    Reason          : {reason}"
                )

            preview = payload.get(
                "preview"
            )

            if preview:
                lines.append(
                    f"    Preview         : {preview}"
                )

            saved_path = payload.get(
                "saved_path"
            )

            if saved_path:
                lines.append(
                    f"    Saved Payload   : {saved_path}"
                )

    else:
        lines.append(
            "No decoded payload intelligence available."
        )

    # -------------------------------------------------
    # Recursive Encoding Chain
    # -------------------------------------------------

    recursive_layers = encoding_results.get(
        "recursive_layers",
        []
    )

    if recursive_layers:
        lines.append("")
        lines.append("Recursive Encoding Chain")
        lines.append("-" * 60)

        for layer in recursive_layers[:50]:
            lines.append(
                f"Depth {layer.get('depth', '?')} | "
                f"{str(layer.get('type', 'unknown')).upper()} -> "
                f"{layer.get('decoded', '')}"
            )

    # -------------------------------------------------
    # Interest Score
    # -------------------------------------------------

    lines.append("")
    lines.append("Interest Score")
    lines.append("-" * 60)

    lines.append(
        f"Score : {score_result.get('score', 0)}/100"
    )

    lines.append(
        f"Level : "
        f"{score_result.get('level', 'INFORMATIONAL')}"
    )

    reasons = score_result.get("reasons", [])

    if reasons:
        lines.append("")
        lines.append("Reasons:")

        for reason in reasons:
            lines.append(f"[+] {reason}")

    # -------------------------------------------------
    # Detected Flags
    # -------------------------------------------------

    lines.append("")
    lines.append("Detected Flags")
    lines.append("-" * 60)

    if detected_flags:
        for flag in detected_flags:
            lines.append(f"- {flag}")

    else:
        lines.append("No CTF flags detected.")

    # -------------------------------------------------
    # Interesting Findings
    # -------------------------------------------------

    lines.append("")
    lines.append("Additional Interesting Findings")
    lines.append("-" * 60)

    found_anything = False

    reserved_findings = {
        "payload_intelligence",
        "challenge_classification",
        "encoding_chain"
    }

    for category, items in findings.items():

        if category in reserved_findings:
            continue

        if items:
            found_anything = True

            lines.append("")
            lines.append(f"{category.upper()}:")

            for item in items[:50]:
                lines.append(f"- {item}")

            if len(items) > 50:
                lines.append(
                    f"... and {len(items) - 50} more."
                )

    if not found_anything:
        lines.append(
            "No additional interesting findings detected."
        )

    # -------------------------------------------------
    # Recommended Next Steps
    # -------------------------------------------------

    lines.append("")
    lines.append("Recommended Next Steps")
    lines.append("-" * 60)

    recommendations = recommendations or []

    if recommendations:

        for index, recommendation in enumerate(
            recommendations,
            start=1
        ):
            lines.append(
                f"[{index}] {recommendation}"
            )

    else:
        lines.append(
            "No additional recommendations generated."
        )

    # -------------------------------------------------
    # Intelligent Solve Plan
    # -------------------------------------------------

    lines.append("")
    lines.append("Intelligent Solve Plan")
    lines.append("-" * 60)

    if solve_plan:
        for index, step in enumerate(
            solve_plan,
            start=1
        ):
            lines.append("")

            lines.append(
                f"[{index}] "
                f"{step.get('action', 'Manual inspection')}"
            )

            lines.append(
                f"    Priority : "
                f"{step.get('priority', 0)}"
            )

            lines.append(
                f"    Reason   : "
                f"{step.get('reason', 'No reason provided.')}"
            )

    else:
        lines.append(
            "No intelligent solve-plan steps generated."
        )

    # -------------------------------------------------
    # Report Footer
    # -------------------------------------------------

    lines.append("")
    lines.append("=" * 60)
    lines.append("End of FalconCTF Report")
    lines.append("=" * 60)

    # -------------------------------------------------
    # Save Report
    # -------------------------------------------------

    with open(
        report_path,
        "w",
        encoding="utf-8"
    ) as report_file:

        report_file.write(
            "\n".join(lines)
        )

    return report_path
