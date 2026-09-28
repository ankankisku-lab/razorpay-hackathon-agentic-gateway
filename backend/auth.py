"""API-key authentication.

The caller's identity used to be whatever user_id the request body
claimed; PolicyGate's USER_BINDING check could stop misattribution but
not impersonation. Now the HTTP layer derives the user from a secret key
and PolicyGate binds the mandate to THAT identity.

Issue a key:   python -m backend.auth issue <user_id>
Revoke a key:  python -m backend.auth revoke <api_key>
"""
import hashlib
import secrets
import sys
from typing import Optional

from backend.state_store import SQLiteStateStore

KEY_PREFIX = "agw_"


def hash_api_key(api_key: str) -> str:
    """Only this hash is stored, so a leaked database doesn't leak usable
    keys. Plain SHA-256, not bcrypt/argon2, on purpose: slow hashes exist
    to make brute-forcing LOW-entropy passwords expensive. These keys are
    256 random bits, which no amount of hashing speed makes guessable —
    and a fast deterministic hash is what lets the key be looked up
    directly by its hash."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def issue_api_key(store: SQLiteStateStore, user_id: str) -> str:
    """Returns the key exactly once; it can't be recovered later."""
    api_key = KEY_PREFIX + secrets.token_urlsafe(32)
    store.add_api_key(hash_api_key(api_key), user_id)
    return api_key


def resolve_api_key(store: SQLiteStateStore, api_key: Optional[str]) -> Optional[str]:
    if not api_key or not api_key.startswith(KEY_PREFIX):
        return None
    return store.lookup_api_key(hash_api_key(api_key))


def revoke_api_key(store: SQLiteStateStore, api_key: str) -> bool:
    return store.revoke_api_key(hash_api_key(api_key))


def _main(argv) -> int:
    usage = "usage: python -m backend.auth issue <user_id> | revoke <api_key>"
    if len(argv) != 2 or argv[0] not in ("issue", "revoke"):
        print(usage)
        return 2
    store = SQLiteStateStore()
    if argv[0] == "issue":
        print(issue_api_key(store, argv[1]))
        print(f"# API key for {argv[1]} — shown once; send it as 'Authorization: Bearer <key>'.", file=sys.stderr)
        return 0
    revoked = revoke_api_key(store, argv[1])
    print("revoked" if revoked else "no active key matched")
    return 0 if revoked else 1


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
