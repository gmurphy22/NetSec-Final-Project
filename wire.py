"""
the little protocol the client and server both use. one json object per line.
there's a byte cap on a single line so a client can't just spam bytes with no
newline and eat all the server's memory.
"""

import json
import config


def send_msg(sock, obj):
    """dump obj to json and send it as one line"""
    sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))


class LineReader:
    """buffers whatever comes off the socket and hands back one dict at a time"""

    def __init__(self, sock, max_bytes=config.MAX_LINE_BYTES):
        self.sock = sock
        self.max_bytes = max_bytes
        self._buf = b""

    def read_msg(self):
        """next message as a dict, or None if the other side hung up.

        throws ValueError on junk or oversized input so the caller can deal
        with it instead of the whole thing falling over.
        """
        while b"\n" not in self._buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                return None
            self._buf += chunk
            if len(self._buf) > self.max_bytes:
                self._buf = b""
                raise ValueError("message too large")
        line, self._buf = self._buf.split(b"\n", 1)
        text = line.decode("utf-8", errors="replace").strip()
        if not text:
            return {}
        obj = json.loads(text)              # json errors are ValueErrors already
        if not isinstance(obj, dict):
            raise ValueError("message must be a JSON object")
        return obj
