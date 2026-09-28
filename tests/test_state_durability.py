"""Tier-2 guarantees: state survives restarts, concurrent requests are
serialized across threads AND processes, human-in-the-loop reservations
can be confirmed or cancelled, and held orders reconcile without a
webhook."""
import json
import os
import subprocess
import sys
import textwrap
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import backend.razorpay_gateway as gateway
from backend.exceptions import PolicyViolationError, RazorpayAmbiguousError, ReservationNotFoundError
from backend.ledger import _GENESIS_HASH, _calculate_hash
from backend.policy_gate import PolicyGate
from backend.reconciler import reconcile_once
from backend.signing import load_or_create_keypair
from backend.state_store import AWAITING_CONFIRMATION, COMMITTED, HELD, SQLiteStateStore
from backend.two_phase_commit import TwoPhaseCommitCoordinator
from config import settings
from tests.test_two_phase_commit import TEST_PRICE_PAISE, make_request

REPO_ROOT = Path(__file__).resolve().parent.parent


def _evaluate(gate: PolicyGate, req):
    return gate.evaluate(
        req.cart.model_dump(), req.mandate.model_dump(), req.signature,
        requester_user_id=req.user_id,
    )


def _held_request(coordinator: TwoPhaseCommitCoordinator):
    settings.allow_mock_gateway = True
    req = make_request(simulate_timeout=True)
    with pytest.raises(RazorpayAmbiguousError):
        coordinator.execute_transaction(req)
    return req


# --- Surviving a restart -----------------------------------------------------

def test_held_reservation_and_idempotency_survive_a_restart():
    db = settings.state_db_path
    before = TwoPhaseCommitCoordinator(PolicyGate(store=SQLiteStateStore(db)))
    req = _held_request(before)
    key = req.mandate.idempotency_key

    # A brand-new gate on the same file is what a restarted process sees.
    after = PolicyGate(store=SQLiteStateStore(db))
    assert after.get_reservation(key)["status"] == HELD
    assert after.reserved_amounts_paise == {key: TEST_PRICE_PAISE}
    assert after.session_spent_paise == TEST_PRICE_PAISE

    # The old in-memory set forgot this key on restart, so the same signed
    # request could be replayed. It must still be rejected.
    ok, reason, _ = _evaluate(after, req)
    assert not ok and "IDEMPOTENCY_REJECT" in reason


def test_created_order_cache_survives_a_restart(monkeypatch):
    db = settings.state_db_path
    calls = {"n": 0}

    def create(data):
        calls["n"] += 1
        return {"id": "order_once", "receipt": data["receipt"]}

    monkeypatch.setattr(gateway.razorpay_client.order, "create", create)
    payload = {"verified_total_paise": TEST_PRICE_PAISE, "currency": "INR", "cart_id": "crt_x"}

    first = gateway.create_razorpay_order(payload, "mnd_x", "idem_restart", order_cache=SQLiteStateStore(db))
    # "Restart": a new store object, same file. Razorpay Orders have no
    # server-side idempotency, so only this cache prevents a duplicate.
    second = gateway.create_razorpay_order(payload, "mnd_x", "idem_restart", order_cache=SQLiteStateStore(db))

    assert first["cached"] is False and second["cached"] is True
    assert second["order"]["id"] == "order_once"
    assert calls["n"] == 1


# --- Concurrency: threads in one process -------------------------------------

def test_concurrent_threads_cannot_exceed_session_cap():
    gate = PolicyGate(session_spend_cap_paise=3 * TEST_PRICE_PAISE)
    requests = [make_request() for _ in range(12)]

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda r: _evaluate(gate, r), requests))

    assert sum(1 for ok, _, _ in results if ok) == 3
    assert all("SESSION_CAP_REJECT" in reason for ok, reason, _ in results if not ok)
    assert gate.session_spent_paise == 3 * TEST_PRICE_PAISE


def test_concurrent_duplicates_of_one_request_reserve_exactly_once():
    gate = PolicyGate(session_spend_cap_paise=10_000_00)
    req = make_request()

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda r: _evaluate(gate, r), [req] * 8))

    assert sum(1 for ok, _, _ in results if ok) == 1
    assert all("IDEMPOTENCY_REJECT" in reason for ok, reason, _ in results if not ok)
    assert gate.session_spent_paise == TEST_PRICE_PAISE


# --- Concurrency: separate processes on one database / one ledger -----------

def _child_env(**extra) -> dict:
    """Children must use this test session's signing key and ledger, not
    the repo's real ones (paths are env-overridable pydantic settings)."""
    env = dict(os.environ)
    env.update({
        "SIGNING_PRIVATE_KEY_PATH": str(settings.signing_private_key_path),
        "SIGNING_PUBLIC_KEY_PATH": str(settings.signing_public_key_path),
        "LEDGER_PATH": str(settings.ledger_path),
        "LEDGER_CHECKPOINT_PATH": str(settings.ledger_checkpoint_path),
        "LEDGER_ARCHIVE_DIR": str(settings.ledger_archive_dir),
        "PYTHONPATH": str(REPO_ROOT),
    })
    env.update({k: str(v) for k, v in extra.items()})
    return env


_BARRIER = """
import os, time
from pathlib import Path
barrier = Path(os.environ["BARRIER_DIR"])
(barrier / f"{os.getpid()}.ready").touch()
deadline = time.time() + 120
while len(list(barrier.glob("*.ready"))) < int(os.environ["N_PROCS"]):
    assert time.time() < deadline, "barrier timeout"
    time.sleep(0.005)
"""


def _run_processes(code: str, n: int, tmp_path: Path, **env) -> list:
    barrier = tmp_path / "barrier"
    barrier.mkdir()
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", code], cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=_child_env(BARRIER_DIR=barrier, N_PROCS=n, **env),
        )
        for _ in range(n)
    ]
    outputs = []
    for p in procs:
        out, err = p.communicate(timeout=180)
        assert p.returncode == 0, err[-2000:]
        outputs.append(out)
    return outputs


def test_separate_processes_share_one_session_cap(tmp_path):
    """The per-process threading.Lock this replaced could never pass this:
    four processes, four gates, one budget that fits exactly three items."""
    load_or_create_keypair()  # children must find (not race to create) the key
    code = textwrap.dedent("""
        import json, os
        from backend.policy_gate import PolicyGate
        from backend.state_store import SQLiteStateStore
        from tests.test_two_phase_commit import TEST_PRICE_PAISE, make_request
        gate = PolicyGate(session_spend_cap_paise=3 * TEST_PRICE_PAISE, store=SQLiteStateStore(os.environ["STATE_DB"]))
        requests = [make_request() for _ in range(4)]
    """) + _BARRIER + textwrap.dedent("""
        results = [gate.evaluate(r.cart.model_dump(), r.mandate.model_dump(), r.signature,
                                 requester_user_id=r.user_id)[:2] for r in requests]
        print("RESULTS=" + json.dumps(results))
    """)
    db = tmp_path / "shared_state.db"
    SQLiteStateStore(db)  # create the schema once, up front

    outputs = _run_processes(code, 4, tmp_path, STATE_DB=db)
    results = [r for out in outputs for r in json.loads(out.split("RESULTS=")[1])]

    assert len(results) == 16
    assert sum(1 for ok, _ in results if ok) == 3
    assert all("SESSION_CAP_REJECT" in reason for ok, reason in results if not ok)
    assert SQLiteStateStore(db).spent("default") == 3 * TEST_PRICE_PAISE


def test_separate_processes_append_one_unbroken_ledger_chain(tmp_path):
    """Regression test for the forked chain found at block 144: several
    processes appending to one ledger file must produce a single chain,
    not interleaved forks."""
    load_or_create_keypair()
    ledger = tmp_path / "shared_ledger.jsonl"
    code = _BARRIER + textwrap.dedent("""
        from backend.ledger import build_entry, write_ledger_entry
        for i in range(25):
            assert write_ledger_entry(build_entry(f"mnd_{os.getpid()}", "MULTIPROCESS_TEST", i=i))["_persisted"]
    """)
    _run_processes(
        code, 4, tmp_path,
        LEDGER_PATH=ledger,
        LEDGER_CHECKPOINT_PATH=tmp_path / "checkpoint.json",
        LEDGER_ARCHIVE_DIR=tmp_path / "archive",
    )

    blocks = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert [b["index"] for b in blocks] == list(range(100))
    running = _GENESIS_HASH
    for b in blocks:
        assert b["previous_hash"] == running, f"fork at index {b['index']}"
        assert _calculate_hash(running, b) == b["block_hash"]
        running = b["block_hash"]


# --- Human-in-the-loop: confirm / cancel -------------------------------------

@pytest.fixture
def pending(monkeypatch):
    monkeypatch.setattr(gateway.razorpay_client.order, "create",
                        lambda data: {"id": "order_confirmed", "receipt": data["receipt"]})
    coordinator = TwoPhaseCommitCoordinator(PolicyGate(session_spend_cap_paise=10_000_00))
    req = make_request(auto_execute=False)
    result = coordinator.execute_transaction(req)
    assert result["status"] == "RESERVED"
    key = req.mandate.idempotency_key
    assert coordinator.policy_gate.get_reservation(key)["status"] == AWAITING_CONFIRMATION
    return coordinator, key, req.user_id


def test_confirm_runs_phase_two_and_commits(pending):
    coordinator, key, user = pending
    result = coordinator.confirm_reservation(key, user)

    assert result == {"status": "SUCCESS", "order_id": "order_confirmed", "amount_paise": TEST_PRICE_PAISE}
    row = coordinator.policy_gate.get_reservation(key)
    assert row["status"] == COMMITTED and row["order_id"] == "order_confirmed"


def test_confirm_twice_settles_only_once(pending):
    coordinator, key, user = pending
    coordinator.confirm_reservation(key, user)
    with pytest.raises(PolicyViolationError, match="RESERVATION_STATE_REJECT"):
        coordinator.confirm_reservation(key, user)


def test_cancel_releases_budget_and_frees_the_key(pending):
    coordinator, key, user = pending
    assert coordinator.cancel_reservation(key, user)["status"] == "CANCELLED"
    assert coordinator.policy_gate.get_reservation(key) is None
    assert coordinator.policy_gate.session_spent_paise == 0


def test_confirm_and_cancel_are_bound_to_the_mandate_user(pending):
    coordinator, key, _ = pending
    with pytest.raises(PolicyViolationError, match="USER_BINDING_REJECT"):
        coordinator.confirm_reservation(key, "usr_intruder")
    with pytest.raises(PolicyViolationError, match="USER_BINDING_REJECT"):
        coordinator.cancel_reservation(key, "usr_intruder")


def test_confirm_unknown_key_is_not_found(pending):
    coordinator, _, user = pending
    with pytest.raises(ReservationNotFoundError):
        coordinator.confirm_reservation("idem_does_not_exist", user)


def test_confirm_after_expiry_is_rejected_and_released(monkeypatch):
    coordinator = TwoPhaseCommitCoordinator(PolicyGate(session_spend_cap_paise=10_000_00))
    req = make_request(auto_execute=False, expires_at=int(time.time()) + 2)
    coordinator.execute_transaction(req)
    key = req.mandate.idempotency_key

    later = time.time() + 5
    monkeypatch.setattr(time, "time", lambda: later)
    with pytest.raises(PolicyViolationError, match="MANDATE_EXPIRED_REJECT"):
        coordinator.confirm_reservation(key, req.user_id)
    assert coordinator.policy_gate.get_reservation(key) is None


# --- Reconciler: resolving holds without a webhook ---------------------------

def test_reconciler_commits_hold_when_order_exists(monkeypatch):
    coordinator = TwoPhaseCommitCoordinator(PolicyGate(session_spend_cap_paise=10_000_00))
    key = _held_request(coordinator).mandate.idempotency_key
    monkeypatch.setattr(gateway.razorpay_client.order, "all",
                        lambda params: {"items": [{"id": "order_late", "receipt": params["receipt"]}]})

    assert reconcile_once(coordinator)["committed"] == 1
    row = coordinator.policy_gate.get_reservation(key)
    assert row["status"] == COMMITTED and row["order_id"] == "order_late"
    # A second pass, or a second worker, finds nothing left to do.
    assert reconcile_once(coordinator)["committed"] == 0


def test_reconciler_releases_hold_with_no_order_after_grace(monkeypatch):
    coordinator = TwoPhaseCommitCoordinator(PolicyGate(session_spend_cap_paise=10_000_00))
    key = _held_request(coordinator).mandate.idempotency_key
    monkeypatch.setattr(gateway.razorpay_client.order, "all", lambda params: {"items": []})

    assert reconcile_once(coordinator, held_grace_seconds=3600)["still_held"] == 1
    assert coordinator.policy_gate.get_reservation(key)["status"] == HELD

    assert reconcile_once(coordinator, now=time.time() + 3601, held_grace_seconds=3600)["released"] == 1
    assert coordinator.policy_gate.get_reservation(key) is None
    assert coordinator.policy_gate.session_spent_paise == 0


def test_reconciler_never_releases_when_lookup_fails(monkeypatch):
    coordinator = TwoPhaseCommitCoordinator(PolicyGate(session_spend_cap_paise=10_000_00))
    key = _held_request(coordinator).mandate.idempotency_key

    def boom(params):
        raise ConnectionError("razorpay unreachable")

    monkeypatch.setattr(gateway.razorpay_client.order, "all", boom)
    counts = reconcile_once(coordinator, now=time.time() + 10_000, held_grace_seconds=0)

    assert counts["lookup_failed"] == 1 and counts["released"] == 0
    assert coordinator.policy_gate.get_reservation(key)["status"] == HELD


def test_reconciler_releases_expired_unconfirmed_reservations():
    coordinator = TwoPhaseCommitCoordinator(PolicyGate(session_spend_cap_paise=10_000_00))
    req = make_request(auto_execute=False, expires_at=int(time.time()) + 2)
    coordinator.execute_transaction(req)

    assert reconcile_once(coordinator)["expired_confirmations"] == 0
    assert reconcile_once(coordinator, now=time.time() + 5)["expired_confirmations"] == 1
    assert coordinator.policy_gate.get_reservation(req.mandate.idempotency_key) is None
