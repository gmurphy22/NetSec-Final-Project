"""
input checks. everything coming off the socket goes through here before it
touches auth, the database, or the relay.
"""

import re
import config

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_]+$")


def valid_username(u):
    return (
        isinstance(u, str)
        and config.MIN_USERNAME_LEN <= len(u) <= config.MAX_USERNAME_LEN
        and bool(_USERNAME_RE.match(u))
    )


def valid_display_name(d):
    if not isinstance(d, str):
        return False
    d = d.strip()
    # has to be printable, one line, and not too long
    return 1 <= len(d) <= config.MAX_DISPLAY_LEN and all(ord(c) >= 32 for c in d)


def valid_password(p):
    return isinstance(p, str) and config.MIN_PASSWORD_LEN <= len(p) <= config.MAX_PASSWORD_LEN


def clean_message(m):
    """cleans up a message, or gives back None if it's no good"""
    if not isinstance(m, str):
        return None
    m = m.replace("\r", " ").replace("\n", " ").strip()
    if not (1 <= len(m) <= config.MAX_MESSAGE_LEN):
        return None
    # strip control characters but leave tabs alone
    m = "".join(ch for ch in m if ord(ch) >= 32 or ch == "\t")
    return m or None
