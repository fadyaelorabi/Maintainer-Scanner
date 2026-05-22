def detect_deprecated(version_data):
    if not version_data:
        return 0

    message = version_data.get("deprecated")

    if message:
        return 1

    return 0
