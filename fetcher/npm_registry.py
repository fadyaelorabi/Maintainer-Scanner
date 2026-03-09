import requests

session = requests.Session()

session.headers.update({
 "User-Agent":"depscan/1.0"
})

def fetch_package(name):

    url = f"https://registry.npmjs.org/{name}"

    try:
        r = session.get(url, timeout=5)

        if r.status_code != 200:
            return None

        return r.json()

    except requests.exceptions.RequestException:
        return None