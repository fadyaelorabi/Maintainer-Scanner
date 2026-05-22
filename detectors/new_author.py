def detect_new_author(timeline, version_data):

    seen = set()

    current_author = version_data.get("_npmUser", {}).get("name")

    for v in timeline:

        # stop when we reach current version
        if v["version"] == version_data["version"]:
            break

        if "_npmUser" in v:
            seen.add(v["_npmUser"]["name"])

    #print("Current author:", current_author)
    #print("Previous authors:", seen)

    if current_author and current_author not in seen:
        return 1

    return 0
