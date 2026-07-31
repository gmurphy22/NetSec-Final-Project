"""
security log. writes out the events in the format the spec shows:

    2026-11-12 15:03:44
    Failed login
    User: alice
    IP: localhost

there's a lock on the write so two client threads can't end up writing half
an entry each.
"""

import datetime
import threading

import config


class SecurityLog:
    def __init__(self, path=config.LOG_FILE, echo=True):
        self.path = path
        self.echo = echo          # print a short version to the console too
        self._lock = threading.Lock()

    def log(self, event, user=None, ip="localhost", detail=None):
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = [ts, event]
        if user is not None:
            lines.append(f"User: {user}")
        lines.append(f"IP: {ip}")
        if detail:
            lines.append(f"Detail: {detail}")
        entry = "\n".join(lines) + "\n\n"
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(entry)
            if self.echo:
                summary = f"[LOG] {ts} | {event}"
                if user:
                    summary += f" | user={user}"
                if detail:
                    summary += f" | {detail}"
                print(summary)
