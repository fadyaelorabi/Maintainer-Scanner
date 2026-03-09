from concurrent.futures import ThreadPoolExecutor

from fetcher.npm_registry import fetch_package
from engine.analyzer import analyze_package


def analyze_from_file(packages):

    def process(p):

        name = p["name"]
        version = p["version"]

        pkg = fetch_package(name)

        if not pkg:
            return None

        return analyze_package(name, version, pkg)

    with ThreadPoolExecutor(max_workers=10) as executor:

        results = list(executor.map(process, packages))

    return [r for r in results if r]