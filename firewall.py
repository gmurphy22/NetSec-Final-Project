"""
connection firewall that sits in front of the accept loop.

this started as the firewall.py from my vpn project, where it shelled out to
iptables to do the nat/masquerade on the server side and the dns leak rules on
the client side. that version needed root and worked at the kernel level, which
doesn't really work for a localhost chat server, so i kept the idea (decide who
gets to connect, throttle whoever is being abusive) and did it in python
instead.

what it stops:
  - anything not on localhost, since only 127.0.0.1 is on the allowlist
  - connection floods, with a per ip rate limit
  - login flooding, with a per ip failed login limit

same as the vpn version the blocks time out on their own and the object works
as a context manager.
"""

import time
import logging
import threading
import collections

import config

log = logging.getLogger("chat.firewall")


class ConnectionFirewall:
    def __init__(
        self,
        allowed_hosts=None,
        window=config.FW_WINDOW_SECONDS,
        max_conns=config.FW_MAX_CONNS_PER_WINDOW,
        max_login_fails=config.FW_MAX_LOGIN_FAILS_PER_WINDOW,
        block_seconds=config.FW_IP_BLOCK_SECONDS,
    ):
        self.allowed_hosts = set(allowed_hosts or config.ALLOWED_HOSTS)
        self.window = window
        self.max_conns = max_conns
        self.max_login_fails = max_login_fails
        self.block_seconds = block_seconds
        self._lock = threading.Lock()
        self._conns = collections.defaultdict(collections.deque)  # ip -> timestamps
        self._fails = collections.defaultdict(collections.deque)  # ip -> timestamps
        self._blocked = {}                                        # ip -> unblock time

    @staticmethod
    def _prune(dq, now, window):
        while dq and now - dq[0] > window:
            dq.popleft()

    def check_connection(self, ip):
        """should we take this connection? gives back (allowed, reason)"""
        now = time.time()
        with self._lock:
            # localhost only
            if ip not in self.allowed_hosts:
                return False, "host not in allowlist"

            # still serving a block?
            unblock = self._blocked.get(ip)
            if unblock is not None:
                if now < unblock:
                    return False, f"temporarily blocked ({int(unblock - now)}s left)"
                del self._blocked[ip]  # expired

            # rate limit per ip
            dq = self._conns[ip]
            self._prune(dq, now, self.window)
            dq.append(now)
            if len(dq) > self.max_conns:
                self._blocked[ip] = now + self.block_seconds
                log.warning("Connection flood from %s, blocking %ds", ip, self.block_seconds)
                return False, "connection rate limit exceeded"

            return True, "ok"

    def note_login_failure(self, ip):
        """log a bad login and block the ip if it's hammering us"""
        now = time.time()
        with self._lock:
            dq = self._fails[ip]
            self._prune(dq, now, self.window)
            dq.append(now)
            if len(dq) > self.max_login_fails:
                self._blocked[ip] = now + self.block_seconds
                log.warning("Login failure flood from %s, blocking %ds", ip, self.block_seconds)

    def is_blocked(self, ip):
        now = time.time()
        with self._lock:
            unblock = self._blocked.get(ip)
            return bool(unblock and now < unblock)

    def active_blocks(self):
        """{ip: seconds left}, mostly for the demo"""
        now = time.time()
        with self._lock:
            return {ip: int(t - now) for ip, t in self._blocked.items() if t > now}

    def __enter__(self):
        log.info(
            "Connection firewall active: allowlist=%s, max %d conns / %ds per IP",
            sorted(self.allowed_hosts), self.max_conns, self.window,
        )
        return self

    def __exit__(self, *_):
        log.info("Connection firewall shutting down")
