import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

from config import settings

# Reservation lifecycle. A rollback DELETES the row rather than setting a
# status — deleting is what frees the idempotency key, and freeing it is
# only ever safe on a confirmed outcome (see PolicyGate.rollback).
RESERVED = "RESERVED"                            # approved; Phase 2 in flight
AWAITING_CONFIRMATION = "AWAITING_CONFIRMATION"  # auto_execute=False pause
HELD = "HELD"                                    # ambiguous gateway outcome
COMMITTED = "COMMITTED"                          # final; key stays burned
OPEN_STATUSES = (RESERVED, AWAITING_CONFIRMATION, HELD)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id   TEXT PRIMARY KEY,
    spent_paise  INTEGER NOT NULL DEFAULT 0 CHECK (spent_paise >= 0)
);
CREATE TABLE IF NOT EXISTS reservations (
    idempotency_key TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL,
    mandate_id      TEXT NOT NULL,
    cart_id         TEXT NOT NULL,
    user_id         TEXT NOT NULL,
    amount_paise    INTEGER NOT NULL CHECK (amount_paise >= 0),
    currency        TEXT NOT NULL,
    expires_at      INTEGER NOT NULL,
    status          TEXT NOT NULL,
    order_id        TEXT,
    created_at      REAL NOT NULL,
    updated_at      REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reservations_status ON reservations (status);
CREATE TABLE IF NOT EXISTS orders (
    idempotency_key TEXT PRIMARY KEY,
    order_json      TEXT NOT NULL,
    created_at      REAL NOT NULL
);
"""


class SQLiteStateStore:
    """Durable replacement for PolicyGate's old in-memory dict/set and
    razorpay_gateway's in-memory order cache — the restart gap both of
    them documented as their highest-priority known limitation.

    A fresh connection per operation, not one shared connection: sqlite3
    connections aren't safe to share across threads by default, and a
    connection-per-call works identically whether the callers are
    threads in one process or several processes on one file.
    """

    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path is not None else Path(settings.state_db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as conn:
            # WAL lets readers proceed while a writer holds the lock —
            # without it every property read would queue behind a reserve.
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA)

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        # isolation_level=None disables the sqlite3 module's implicit
        # transactions, so the only transactions are the explicit
        # BEGIN IMMEDIATE ones in _write_transaction — no hidden BEGIN
        # quietly widening or narrowing what's atomic.
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def _write_transaction(self) -> Iterator[sqlite3.Connection]:
        """BEGIN IMMEDIATE takes SQLite's write lock up front, so every
        read inside the block sees state no other writer — thread or
        process — can change before COMMIT. A plain BEGIN would take it
        lazily at the first write, leaving exactly the read-then-write
        window the old in-memory race lived in."""
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    # --- Phase 1 --------------------------------------------------------

    def try_reserve(self, session_id: str, cap_paise: int, reservation: Dict[str, Any]) -> Tuple[str, int]:
        """Idempotency check, cap check and reservation as ONE atomic
        step. Returns ("OK" | "DUPLICATE" | "CAP_EXCEEDED", spent_paise),
        where spent_paise is the session total before this attempt."""
        key = reservation["idempotency_key"]
        amount = reservation["amount_paise"]
        now = time.time()
        with self._write_transaction() as conn:
            conn.execute("INSERT OR IGNORE INTO sessions (session_id) VALUES (?)", (session_id,))
            spent = conn.execute(
                "SELECT spent_paise FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone()["spent_paise"]

            if conn.execute("SELECT 1 FROM reservations WHERE idempotency_key = ?", (key,)).fetchone():
                return "DUPLICATE", spent

            if spent + amount > cap_paise:
                return "CAP_EXCEEDED", spent

            conn.execute("UPDATE sessions SET spent_paise = spent_paise + ? WHERE session_id = ?", (amount, session_id))
            conn.execute(
                """INSERT INTO reservations (idempotency_key, session_id, mandate_id, cart_id, user_id,
                       amount_paise, currency, expires_at, status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (key, session_id, reservation["mandate_id"], reservation["cart_id"], reservation["user_id"],
                 amount, reservation["currency"], reservation["expires_at"], RESERVED, now, now),
            )
            return "OK", spent

    # --- Phase 2 and reconciliation ---------------------------------------

    def transition(self, key: str, from_statuses: Tuple[str, ...], to_status: str, order_id: Optional[str] = None) -> bool:
        """Conditional status change — True only if THIS call moved the
        row. Two workers reconciling the same hold, or a webhook racing
        the synchronous path, can't both "win": the loser sees False and
        must not act (or write a ledger entry) on the transition."""
        placeholders = ",".join("?" for _ in from_statuses)
        with self._write_transaction() as conn:
            cur = conn.execute(
                f"""UPDATE reservations SET status = ?, order_id = COALESCE(?, order_id), updated_at = ?
                    WHERE idempotency_key = ? AND status IN ({placeholders})""",
                (to_status, order_id, time.time(), key, *from_statuses),
            )
            return cur.rowcount == 1

    def release(self, key: str, from_statuses: Tuple[str, ...] = OPEN_STATUSES) -> Optional[int]:
        """Deletes an open reservation and returns its amount to the
        session budget. None if nothing was released — including a
        COMMITTED row, which can never be rolled back."""
        placeholders = ",".join("?" for _ in from_statuses)
        with self._write_transaction() as conn:
            row = conn.execute(
                f"SELECT session_id, amount_paise FROM reservations WHERE idempotency_key = ? AND status IN ({placeholders})",
                (key, *from_statuses),
            ).fetchone()
            if row is None:
                return None
            conn.execute("DELETE FROM reservations WHERE idempotency_key = ?", (key,))
            conn.execute(
                "UPDATE sessions SET spent_paise = MAX(0, spent_paise - ?) WHERE session_id = ?",
                (row["amount_paise"], row["session_id"]),
            )
            return row["amount_paise"]

    # --- Reads --------------------------------------------------------------

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM reservations WHERE idempotency_key = ?", (key,)).fetchone()
        return dict(row) if row else None

    def list_by_status(self, status: str) -> List[Dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM reservations WHERE status = ? ORDER BY updated_at", (status,)).fetchall()
        return [dict(r) for r in rows]

    def open_amounts(self, session_id: str) -> Dict[str, int]:
        placeholders = ",".join("?" for _ in OPEN_STATUSES)
        with self._connection() as conn:
            rows = conn.execute(
                f"SELECT idempotency_key, amount_paise FROM reservations WHERE session_id = ? AND status IN ({placeholders})",
                (session_id, *OPEN_STATUSES),
            ).fetchall()
        return {r["idempotency_key"]: r["amount_paise"] for r in rows}

    def all_keys(self) -> Set[str]:
        # Global, not per session: idempotency keys are the reservations
        # table's primary key, so a key is burned everywhere once used.
        with self._connection() as conn:
            return {r[0] for r in conn.execute("SELECT idempotency_key FROM reservations")}

    def spent(self, session_id: str) -> int:
        with self._connection() as conn:
            row = conn.execute("SELECT spent_paise FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
        return row["spent_paise"] if row else 0

    # --- Created-order cache (Razorpay Orders have no idempotency) --------

    def get_cached_order(self, key: str) -> Optional[Dict[str, Any]]:
        with self._connection() as conn:
            row = conn.execute("SELECT order_json FROM orders WHERE idempotency_key = ?", (key,)).fetchone()
        return json.loads(row["order_json"]) if row else None

    def cache_order(self, key: str, order: Dict[str, Any]) -> None:
        with self._write_transaction() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO orders (idempotency_key, order_json, created_at) VALUES (?, ?, ?)",
                (key, json.dumps(order, default=str), time.time()),
            )
