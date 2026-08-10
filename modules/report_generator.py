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
    output_dir="reports"
):
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
    lines.append("Interesting Findings")
    lines.append("-" * 60)

    found_anything = False

    for category, items in findings.items():

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
            "No obvious interesting findings detected."
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
