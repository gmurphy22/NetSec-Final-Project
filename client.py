"""
terminal client.

connects over tls and checks the server cert against cert.pem, so some other
process can't sit on the port and pretend to be the server. you can register or
log in, then whatever you type goes to everyone who's online.

once you're logged in:
    /who     see who's online
    /quit    log out and exit

run it from the same folder as the server so it can find cert.pem:
    python client.py
"""

import ssl
import sys
import socket
import getpass
import threading

import config
import wire


def make_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(config.CERT_FILE)   # trust our own self signed cert
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def connect():
    ctx = make_context()
    raw = socket.create_connection((config.HOST, config.PORT))
    return ctx.wrap_socket(raw, server_hostname="localhost")


def authenticate(tls, reader):
    """keeps asking until they log in. gives back (token, display name)."""
    while True:
        choice = input("[r]egister, [l]ogin, or [q]uit? ").strip().lower()
        if choice.startswith("q"):
            return None, None
        if choice.startswith("r"):
            u = input("  username: ").strip()
            d = input("  display name: ").strip()
            p = getpass.getpass("  password: ")
            wire.send_msg(tls, {"type": "register", "username": u, "password": p, "display_name": d})
            resp = reader.read_msg()
            if resp and resp.get("ok"):
                print("  Account created, now log in.\n")
            else:
                print("  Registration failed:", (resp or {}).get("error", "no response"), "\n")
        elif choice.startswith("l"):
            u = input("  username: ").strip()
            p = getpass.getpass("  password: ")
            wire.send_msg(tls, {"type": "login", "username": u, "password": p})
            resp = reader.read_msg()
            if resp and resp.get("ok"):
                print(f"  Logged in as {resp.get('display_name')}. "
                      f"Last login: {resp.get('last_login') or 'first time'}\n")
                return resp.get("token"), resp.get("display_name")
            print("  Login failed:", (resp or {}).get("error", "no response"), "\n")
        else:
            print("  Please choose r, l, or q.\n")


def main():
    try:
        tls = connect()
    except FileNotFoundError:
        print("cert.pem not found. Start the server once (it generates it), "
              "or run: python gen_cert.py")
        return
    except OSError as e:
        print(f"Could not connect to server at {config.HOST}:{config.PORT}: {e}")
        return

    reader = wire.LineReader(tls)
    print("Connected to secure chat server (TLS).\n")

    token, display = authenticate(tls, reader)
    if not token:
        tls.close()
        return

    print("Type a message and press Enter. Commands: /who  /quit\n")
    stop = threading.Event()

    # background thread just sits there printing whatever the server sends
    def receive():
        while not stop.is_set():
            try:
                m = reader.read_msg()
            except Exception:
                break
            if m is None:
                print("\n[disconnected by server]")
                stop.set()
                break
            t = m.get("type")
            if t == "message":
                print(f"{m.get('from')}: {m.get('text')}")
            elif t == "system":
                print(f"* {m.get('text')}")
            elif t == "who":
                print("Online:", ", ".join(m.get("users", [])) or "(nobody)")
            elif t == "error":
                print("[error]", m.get("error"))

    threading.Thread(target=receive, daemon=True).start()

    try:
        while not stop.is_set():
            try:
                line = input()
            except (EOFError, KeyboardInterrupt):
                break
            if not line.strip():
                continue
            if line.strip() == "/quit":
                wire.send_msg(tls, {"type": "logout", "token": token})
                break
            if line.strip() == "/who":
                wire.send_msg(tls, {"type": "who", "token": token})
                continue
            try:
                wire.send_msg(tls, {"type": "send", "token": token, "text": line})
            except OSError:
                break
    finally:
        stop.set()
        try:
            tls.close()
        except OSError:
            pass
        print("Goodbye.")


if __name__ == "__main__":
    main()
