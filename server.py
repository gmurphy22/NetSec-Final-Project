"""
the chat server. tls, localhost only.

this is where all the pieces get bolted together:
  transport      tls sockets, so the traffic is encrypted and the server can
                 prove who it is
  auth           argon2id shadow passwords and account lockout (auth.py)
  session        random 256 bit tokens, checked on every command
  application    input validation and parameterised sql
  network        the connection firewall (firewall.py)
  logging        audit trail (security_log.py)

run it with:
    python server.py
"""

import ssl
import json
import socket
import logging
import threading

import config
import wire
import validation
import gen_cert
from database import UserDatabase
from auth import AuthManager
from firewall import ConnectionFirewall
from security_log import SecurityLog

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)


class ChatServer:
    def __init__(self):
        self.db = UserDatabase()
        self.auth = AuthManager(self.db)
        self.firewall = ConnectionFirewall()
        self.seclog = SecurityLog()
        self._ctx = None
        self._clients = {}                 # username -> (tls socket, display name)
        self._clients_lock = threading.Lock()

    # tls setup
    def _build_tls_context(self):
        gen_cert.generate(config.CERT_FILE, config.KEY_FILE)  # does nothing if it's there
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=config.CERT_FILE, keyfile=config.KEY_FILE)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2          # nothing older than 1.2
        return ctx

    # who's connected, needed for broadcasting
    def _add_client(self, username, sock, display):
        with self._clients_lock:
            self._clients[username] = (sock, display)

    def _remove_client(self, username):
        with self._clients_lock:
            self._clients.pop(username, None)

    def _broadcast(self, obj, exclude=None):
        with self._clients_lock:
            targets = list(self._clients.items())
        dead = []
        for uname, (sock, _disp) in targets:
            if uname == exclude:
                continue
            try:
                wire.send_msg(sock, obj)
            except OSError:
                dead.append(uname)
        for uname in dead:
            self._remove_client(uname)

    def _system(self, text, exclude=None):
        self._broadcast({"type": "system", "text": text}, exclude=exclude)

    # accept loop
    def start(self):
        self._ctx = self._build_tls_context()
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw.bind((config.HOST, config.PORT))
        raw.listen(50)
        print(f"Secure chat server listening on {config.HOST}:{config.PORT} (TLS)")
        with self.firewall:
            try:
                while True:
                    conn, addr = raw.accept()
                    ip = addr[0]
                    allowed, reason = self.firewall.check_connection(ip)
                    if not allowed:
                        self.seclog.log("Connection blocked", ip=ip, detail=reason)
                        self._safe_close(conn)
                        continue
                    threading.Thread(
                        target=self._handle, args=(conn, ip), daemon=True
                    ).start()
            except KeyboardInterrupt:
                print("\nShutting down.")
            finally:
                raw.close()

    @staticmethod
    def _safe_close(sock):
        try:
            sock.close()
        except OSError:
            pass

    # one of these per connection
    def _handle(self, conn, ip):
        # anything that isn't real tls dies on the handshake, which is fine
        try:
            tls = self._ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError) as e:
            self.seclog.log("TLS handshake failed", ip=ip, detail=str(e))
            self._safe_close(conn)
            return

        reader = wire.LineReader(tls)
        username = None
        token = None
        try:
            while True:
                try:
                    msg = reader.read_msg()
                except (ValueError, UnicodeDecodeError) as e:
                    # garbage or oversized input, tell them and hang up
                    self.seclog.log("Malformed input rejected", user=username, ip=ip, detail=str(e))
                    try:
                        wire.send_msg(tls, {"type": "error", "error": "malformed message"})
                    except OSError:
                        pass
                    break

                if msg is None:
                    break

                mtype = msg.get("type")
                if mtype == "register":
                    self._do_register(tls, ip, msg)
                elif mtype == "login":
                    username, token = self._do_login(tls, ip, msg)
                elif mtype == "send":
                    self._do_send(tls, ip, msg)
                elif mtype == "who":
                    self._do_who(tls, msg)
                elif mtype == "logout":
                    self._do_logout(tls, ip, msg)
                    username, token = None, None
                else:
                    wire.send_msg(tls, {"type": "error", "error": "unknown command"})
        except OSError:
            pass  # client disappeared on us
        finally:
            if username:
                self._remove_client(username)
                self._system(f"{self._display_of(username)} left the chat")
            if token:
                self.auth.destroy_session(token)
            if username:
                self.seclog.log("Disconnect", user=username, ip=ip)
            self._safe_close(tls)

    def _display_of(self, username):
        prof = self.db.get_user(username)
        return prof["display_name"] if prof else username

    # commands
    def _do_register(self, tls, ip, msg):
        u, p, d = msg.get("username"), msg.get("password"), msg.get("display_name")
        if not validation.valid_username(u):
            return wire.send_msg(tls, {"type": "register_result", "ok": False,
                                       "error": "username must be 3-32 chars: letters, digits, underscore"})
        if not validation.valid_password(p):
            return wire.send_msg(tls, {"type": "register_result", "ok": False,
                                       "error": f"password must be {config.MIN_PASSWORD_LEN}-{config.MAX_PASSWORD_LEN} characters"})
        if not validation.valid_display_name(d):
            return wire.send_msg(tls, {"type": "register_result", "ok": False,
                                       "error": "invalid display name"})
        try:
            user = self.auth.register(u, p, d.strip())
        except ValueError as e:
            self.seclog.log("Registration rejected", user=u, ip=ip, detail=str(e))
            return wire.send_msg(tls, {"type": "register_result", "ok": False, "error": str(e)})
        self.seclog.log("Account created", user=u, ip=ip)
        wire.send_msg(tls, {"type": "register_result", "ok": True, "user_id": user["user_id"]})

    def _do_login(self, tls, ip, msg):
        u, p = msg.get("username"), msg.get("password")
        if not validation.valid_username(u) or not isinstance(p, str):
            wire.send_msg(tls, {"type": "login_result", "ok": False, "error": "invalid credentials"})
            return None, None
        ok, reason = self.auth.verify_login(u, p)
        if not ok:
            self.firewall.note_login_failure(ip)
            self.seclog.log("Failed login", user=u, ip=ip, detail=reason)
            wire.send_msg(tls, {"type": "login_result", "ok": False, "error": reason})
            return None, None
        ts = self.db.update_last_login(u)
        token = self.auth.create_session(u)
        display = self._display_of(u)
        self._add_client(u, tls, display)
        self.seclog.log("Login success", user=u, ip=ip)
        wire.send_msg(tls, {"type": "login_result", "ok": True, "token": token,
                            "display_name": display, "last_login": ts})
        self._system(f"{display} joined the chat", exclude=u)
        return u, token

    def _do_send(self, tls, ip, msg):
        user = self.auth.session_user(msg.get("token"))
        if not user:
            return wire.send_msg(tls, {"type": "error", "error": "not authenticated"})
        text = validation.clean_message(msg.get("text"))
        if text is None:
            self.seclog.log("Malformed message rejected", user=user, ip=ip)
            return wire.send_msg(tls, {"type": "error", "error": "invalid message"})
        display = self._display_of(user)
        self.seclog.log("Message delivered", user=user, ip=ip, detail=f"{len(text)} chars")
        # skip the sender, their own client already printed it
        self._broadcast({"type": "message", "from": display, "text": text}, exclude=user)

    def _do_who(self, tls, msg):
        if not self.auth.session_user(msg.get("token")):
            return wire.send_msg(tls, {"type": "error", "error": "not authenticated"})
        with self._clients_lock:
            names = sorted(disp for (_s, disp) in self._clients.values())
        wire.send_msg(tls, {"type": "who", "users": names})

    def _do_logout(self, tls, ip, msg):
        token = msg.get("token")
        user = self.auth.session_user(token)
        if user:
            self._remove_client(user)
            self.auth.destroy_session(token)
            self._system(f"{self._display_of(user)} left the chat", exclude=user)
            self.seclog.log("Logout", user=user, ip=ip)
        wire.send_msg(tls, {"type": "logout_result", "ok": True})


if __name__ == "__main__":
    ChatServer().start()
