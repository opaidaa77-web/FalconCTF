def choose_analysis(file_type):
    file_type = file_type.lower()

    analysis_plan = []

    if "elf" in file_type:
        analysis_plan = [
            "hash_analysis",
            "strings_analysis",
            "flag_detection",
            "hex_analysis",
            "binary_analysis"
        ]

    elif "pe executable" in file_type:
        analysis_plan = [
            "hash_analysis",
            "strings_analysis",
            "flag_detection",
            "hex_analysis",
            "binary_analysis"
        ]

    elif "png" in file_type or "jpeg" in file_type:
        analysis_plan = [
            "hash_analysis",
            "strings_analysis",
            "flag_detection",
            "hex_analysis",
            "metadata_analysis"
        ]

    elif "pdf" in file_type:
        analysis_plan = [
            "hash_analysis",
            "strings_analysis",
            "flag_detection",
            "metadata_analysis"
        ]

    elif "gzip" in file_type:
        analysis_plan = [
            "hash_analysis",
            "strings_analysis",
            "gzip_analysis"
        ]

    elif "zip" in file_type:
        analysis_plan = [
            "hash_analysis",
            "strings_analysis",
            "archive_analysis"
        ]

    else:
        analysis_plan = [
            "hash_analysis",
            "strings_analysis",
            "flag_detection"
        ]

    return analysis_plan
