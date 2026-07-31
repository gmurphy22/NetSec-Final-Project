"""
sqlite storage for the profile stuff the spec asks for: user id, username,
display name, when the account was made, and last login. passwords are not in
here, those live in the shadow file (auth.py).

every query uses ? placeholders instead of string formatting so user input
can't turn into sql.
"""

import sqlite3
import threading
import uuid
import datetime

import config


def _now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class UserDatabase:
    def __init__(self, path=config.DB_FILE):
        self._lock = threading.Lock()
        # check_same_thread=False plus my own lock lets all the client threads
        # share the one connection
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id      TEXT PRIMARY KEY,
                    username     TEXT UNIQUE NOT NULL,
                    display_name TEXT NOT NULL,
                    created_at   TEXT NOT NULL,
                    last_login   TEXT
                )
                """
            )
            self._conn.commit()

    def add_user(self, username, display_name):
        user_id = uuid.uuid4().hex
        created = _now()
        with self._lock:
            self._conn.execute(
                "INSERT INTO users (user_id, username, display_name, created_at, last_login) "
                "VALUES (?, ?, ?, ?, ?)",
                (user_id, username, display_name, created, None),
            )
            self._conn.commit()
        return {
            "user_id": user_id,
            "username": username,
            "display_name": display_name,
            "created_at": created,
            "last_login": None,
        }

    def get_user(self, username):
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            )
            row = cur.fetchone()
        return dict(row) if row else None

    def update_last_login(self, username):
        ts = _now()
        with self._lock:
            self._conn.execute(
                "UPDATE users SET last_login = ? WHERE username = ?", (ts, username)
            )
            self._conn.commit()
        return ts
