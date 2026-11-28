"""Console users: password hashing and the bootstrap admin.

Passwords are stored as scrypt hashes (stdlib hashlib, no extra dependency):
    scrypt$<n>$<r>$<p>$<salt b64>$<hash b64>
"""
import base64
import hashlib
import hmac
import logging
import os
from typing import Any

import psycopg

logger = logging.getLogger("netwatch.control_plane.auth")

ROLES = ("viewer", "operator", "admin")
MIN_PASSWORD_LENGTH = 8
_N, _R, _P, _DKLEN = 2**14, 8, 1, 32


def hash_password(password: str) -> str:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=_DKLEN)
    return "$".join(
        ["scrypt", str(_N), str(_R), str(_P), base64.b64encode(salt).decode(), base64.b64encode(digest).decode()]
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, hash_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = base64.b64decode(hash_b64)
        digest = hashlib.scrypt(
            password.encode(),
            salt=base64.b64decode(salt_b64),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest, expected)


# Verifying against this when the user does not exist keeps response time independent of
# whether the username is valid.
_DUMMY_HASH = hash_password("timing-equalizer-not-a-real-password")


def check_credentials(stored_hash: str | None, password: str) -> bool:
    if stored_hash is None:
        verify_password(password, _DUMMY_HASH)
        return False
    return verify_password(password, stored_hash)


def seed_admin(db_dsn: str, username: str, password: str) -> bool:
    """Creates the bootstrap admin if it does not exist. Safe to run on both replicas at once."""
    with psycopg.connect(db_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO users (username, password_hash, role)
                VALUES (%s, %s, 'admin')
                ON CONFLICT (username) DO NOTHING;
                """,
                (username, hash_password(password)),
            )
            created = cur.rowcount == 1
        conn.commit()
    if created:
        logger.info("Created bootstrap admin user %r", username)
    return created


def load_user(conn: psycopg.Connection[Any], username: str) -> tuple[str, str, bool] | None:
    """Returns (password_hash, role, disabled) or None."""
    with conn.cursor() as cur:
        cur.execute("SELECT password_hash, role, disabled FROM users WHERE username = %s;", (username,))
        row = cur.fetchone()
    return (row[0], row[1], bool(row[2])) if row else None
