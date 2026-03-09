def get_version(pkg, version):

    versions = pkg["versions"]

    if version not in versions:
        return None

    return versions[version]