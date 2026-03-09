from datetime import datetime, timezone
from dateutil import parser


def detect_unmaintained(time_data):

    last = time_data["modified"]

    last_date = parser.parse(last)

    if last_date.tzinfo is None:
        last_date = last_date.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)

    delta = now - last_date

    if delta.days > 730:
        return 1

    return 0