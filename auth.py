"""
handles logins. shadow file for the credentials, argon2id for the hashing,
lockout after too many bad tries, and session tokens (when ur in).

passwords never get written down as plaintext. each user gets their own random
16 byte salt and the password gets hashed with argon2id, then one line goes in
the shadow file:

    username:salt_hex:password_hash_hex

on login i re-hash whatever they typed with their stored salt and compare with
hmac.compare_digest so the comparison takes the same time either way.

i went with argon2id instead of bcrypt or pbkdf2 because it's memory hard
"""

import os
import hmac
import time
import secrets
import threading

from argon2.low_level import hash_secret_raw, Type

import config


def _hash_password(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=config.ARGON2_TIME_COST,
        memory_cost=config.ARGON2_MEMORY_COST,
        parallelism=config.ARGON2_PARALLELISM,
        hash_len=config.ARGON2_HASH_LEN,
        type=Type.ID,
    )


class AuthManager:
    def __init__(self, db, shadow_path=config.SHADOW_FILE):
        self.db = db
        self.shadow_path = shadow_path
        self._lock = threading.Lock()
        self._shadow = {}        # username -> (salt_hex, hash_hex)
        self._sessions = {}      # token    -> username
        self._fail_counts = {}   # username -> how many fails in a row
        self._locked_until = {}  # username -> epoch seconds
        self._load_shadow()

    # shadow file
    def _load_shadow(self):
        if not os.path.exists(self.shadow_path):
            return
        with open(self.shadow_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.count(":") != 2:
                    continue
                user, salt_hex, hash_hex = line.split(":")
                self._shadow[user] = (salt_hex, hash_hex)

    def user_exists(self, username):
        return username in self._shadow

    def register(self, username, password, display_name):
        """makes the shadow entry and the profile row. ValueError if taken."""
        with self._lock:
            if username in self._shadow:
                raise ValueError("username already exists")
            salt = os.urandom(config.ARGON2_SALT_LEN)
            digest = _hash_password(password, salt)
            salt_hex, hash_hex = salt.hex(), digest.hex()
            with open(self.shadow_path, "a", encoding="utf-8") as f:
                f.write(f"{username}:{salt_hex}:{hash_hex}\n")
            self._shadow[username] = (salt_hex, hash_hex)
        # ok to write the db outside the lock, the name is already claimed
        return self.db.add_user(username, display_name)

    # login
    def verify_login(self, username, password):
        """gives back (ok, reason) and handles the lockout backoff"""
        with self._lock:
            now = time.time()
            locked_until = self._locked_until.get(username, 0)
            if now < locked_until:
                return False, f"account locked ({int(locked_until - now)}s remaining)"

            rec = self._shadow.get(username)
            if rec is None:
                # hash a throwaway anyway, otherwise a fast reply tells the
                # attacker the username doesn't exist
                _hash_password(password, b"\x00" * config.ARGON2_SALT_LEN)
                return False, "invalid credentials"

            salt_hex, hash_hex = rec
            digest = _hash_password(password, bytes.fromhex(salt_hex))
            if hmac.compare_digest(digest.hex(), hash_hex):
                self._fail_counts.pop(username, None)
                self._locked_until.pop(username, None)
                return True, "ok"

            # wrong password, count it and maybe lock the account
            n = self._fail_counts.get(username, 0) + 1
            self._fail_counts[username] = n
            if n >= config.MAX_FAILED_LOGINS:
                backoff = min(
                    config.LOCKOUT_BASE_SECONDS * (2 ** (n - config.MAX_FAILED_LOGINS)),
                    config.LOCKOUT_MAX_SECONDS,
                )
                self._locked_until[username] = now + backoff
                return False, f"too many failed attempts, locked {int(backoff)}s"
            return False, "invalid credentials"

    # sessions
    def create_session(self, username):
        token = secrets.token_hex(32)        # 256 bits from the csprng
        with self._lock:
            self._sessions[token] = username
        return token

    def session_user(self, token):
        if not token:
            return None
        with self._lock:
            return self._sessions.get(token)

    def destroy_session(self, token):
        with self._lock:
            self._sessions.pop(token, None)
