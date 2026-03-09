from detectors.missing_author import check_missing_author
from detectors.new_author import detect_new_author
from detectors.expired_domain import expired_domain
from detectors.deprecated import detect_deprecated
from detectors.unmaintained import detect_unmaintained
from detectors.maintainer_breach import check_breach
from utils.version_utils import get_version


def analyze_package(name, version, pkg):

    version_data = get_version(pkg, version)

    timeline = list(pkg["versions"].values())

    signals = {}

    signals["missing_author"] = check_missing_author(version_data)

    signals["new_author"] = detect_new_author(timeline)

    email = version_data["_npmUser"]["email"] if "_npmUser" in version_data else None

    signals["expired_domain"] = expired_domain(email)

    signals["deprecated"] = detect_deprecated(pkg["versions"])

    signals["unmaintained"] = detect_unmaintained(pkg["time"])

    # Get breach information
    breach_info = check_breach(email)

    signals["breached_maintainer"] = breach_info["breached"]

    return {
        "package": name,
        "version": version,
        "signals": signals,
        "latest_breach": breach_info["latest_breach"]
    }