import requests

def check_missing_author(version):

    if "_npmUser" not in version:
        return 0

    username = version["_npmUser"]["name"]

    url = f"https://www.npmjs.com/~{username}"

    r = requests.get(url)

    if r.status_code == 404:
        return 1

    return 0