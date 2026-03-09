def detect_new_author(timeline):

    seen = set()

    for v in timeline:

        if "_npmUser" not in v:
            continue

        author = v["_npmUser"]["name"]

        if author not in seen and len(seen) > 0:
            return 1

        seen.add(author)

    return 0