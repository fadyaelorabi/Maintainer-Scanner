def detect_deprecated(versions):

    for v in versions.values():

        if "deprecated" in v:
            return 1

    return 0