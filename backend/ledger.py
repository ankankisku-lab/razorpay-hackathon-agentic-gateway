import hashlib
import json
import os
import shutil
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from filelock import FileLock, Timeout
from pydantic import ValidationError

from backend.schemas import LedgerBlock
from backend.signing import (
    load_or_create_keypair,
    get_public_key_hex,
    sign_hash,
    verify_hash_signature,
    public_key_from_hex,
)
from config import settings

# Two locks, because they guard different things. _LOCK serializes
# threads in this process over the module state below. _FILE_LOCK
# serializes PROCESSES over the ledger file itself: each process keeps
# its own in-memory chain head, so two processes appending to one file
# (the API and the dashboard, two uvicorn workers, a test run next to a
# running demo) used to each extend their own view of the chain and
# interleave their writes — which is exactly how the committed ledger
# ended up forked at block 144. Taking _FILE_LOCK and re-syncing from
# disk before every append makes the file, not process memory, the
# single source of truth for where the chain currently ends.
_LOCK = threading.Lock()
settings.ledger_path.parent.mkdir(parents=True, exist_ok=True)
_FILE_LOCK = FileLock(str(settings.ledger_path) + ".lock", timeout=30)

_GENESIS_HASH = "0" * 64
# No explicit genesis LedgerBlock is written — the sentinel hash above
# serves as block -1's hash. LedgerBlock.mandate_id documents 'ROOT' as
# the convention for a genesis block if one is ever wanted; this
# implementation doesn't require writing one, matching the simpler
# design that's already been proven correct.
_last_hash: str = _GENESIS_HASH
_segment_start_hash: str = _GENESIS_HASH
_next_index: int = 0
# How many bytes of the active ledger file this process has already
# read. Anything past it was appended by another process since.
_file_offset: int = 0

LEDGER_STREAM: List[dict] = []

_PRIVATE_KEY, _PUBLIC_KEY = load_or_create_keypair()
_PUBLIC_KEY_HEX = get_public_key_hex(_PUBLIC_KEY)


def _calculate_hash(prev_hash: str, block_payload: Dict[str, Any]) -> str:
    # signature/signer_public_key are written to the block AFTER
    # block_hash is computed (write_ledger_entry signs the hash itself,
    # so the signature can't exist before it) — excluding them here too,
    # not just previous_hash/block_hash, is what keeps write-time and
    # verify-time hashing from silently drifting apart.
    # _persisted/_error never actually reach a stored entry today (see
    # write_ledger_entry), but excluding them here too is cheap insurance
    # against a future refactor reintroducing the exact bug this project
    # already hit once: a field added before hashing that verify-time
    # hashing never saw.
    clean = {
        k: v for k, v in block_payload.items()
        if k not in (
            "previous_hash", "block_hash", "signature", "signer_public_key",
            "_persisted", "_error",
        )
    }
    serialized = json.dumps(clean, sort_keys=True, default=str)
    return hashlib.sha256(f"{prev_hash}:{serialized}".encode()).hexdigest()


def _read_checkpoint() -> Tuple[str, int]:
    if settings.ledger_checkpoint_path.exists():
        try:
            checkpoint = json.loads(settings.ledger_checkpoint_path.read_text())
            return checkpoint.get("last_hash", _GENESIS_HASH), checkpoint.get("next_index", 0)
        except (json.JSONDecodeError, OSError):
            pass
    return _GENESIS_HASH, 0


def _ingest(text: str) -> None:
    """Appends parsed blocks to LEDGER_STREAM and advances the chain head."""
    global _last_hash, _next_index
    for line_num, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            block = json.loads(line)
        except json.JSONDecodeError:
            # Not silent: a corrupt line is exactly what this ledger
            # exists to catch. A torn last write from a crash is the
            # realistic case and safe to skip past — but skipping with
            # zero trace would hide genuine corruption anywhere else in
            # the file, which defeats the point of a tamper-evident log.
            print(f"[LEDGER WARNING] Skipping unparseable line {line_num} in {settings.ledger_path}")
            continue
        LEDGER_STREAM.append(block)
        _last_hash = block.get("block_hash", _last_hash)
        _next_index = max(_next_index, block.get("index", -1) + 1)


def _load_existing_ledger() -> None:
    """Full (re)load: checkpoint first, then the whole active segment.
    Clears LEDGER_STREAM in place rather than rebinding it — app.py,
    mcp_server.py and the dashboard import the list object itself."""
    global _last_hash, _segment_start_hash, _next_index, _file_offset
    LEDGER_STREAM.clear()
    _segment_start_hash, _next_index = _read_checkpoint()
    _last_hash = _segment_start_hash
    _file_offset = 0
    if settings.ledger_path.exists():
        data = settings.ledger_path.read_bytes()
        _file_offset = len(data)
        _ingest(data.decode("utf-8"))


def _sync_from_disk_locked() -> None:
    """Catches this process up with blocks other processes appended.
    Caller must hold both locks. A checkpoint that moved, or a file
    shorter than what's already been read, means another process
    rotated the segment — only a full reload is safe then."""
    global _file_offset
    checkpoint_hash, _ = _read_checkpoint()
    if checkpoint_hash != _segment_start_hash:
        _load_existing_ledger()
        return
    size = settings.ledger_path.stat().st_size if settings.ledger_path.exists() else 0
    if size < _file_offset:
        _load_existing_ledger()
        return
    if size == _file_offset:
        return
    with open(settings.ledger_path, "rb") as f:
        f.seek(_file_offset)
        data = f.read()
    _file_offset += len(data)
    _ingest(data.decode("utf-8"))


with _LOCK, _FILE_LOCK:
    _load_existing_ledger()


def build_entry(
    mandate_id: str,
    event_type: str,
    order_id: Optional[str] = None,
    amount_paise: int = 0,
    **payload: Any,
) -> Dict[str, Any]:
    return {
        "timestamp": time.time(),
        "event_type": event_type,
        "mandate_id": mandate_id,
        "order_id": order_id,
        "amount_paise": amount_paise,
        "payload": payload,
    }


def _rotate_locked() -> None:
    global _last_hash, _segment_start_hash, _file_offset

    settings.ledger_archive_dir.mkdir(parents=True, exist_ok=True)
    stamp = f"{int(time.time())}_{uuid.uuid4().hex[:8]}"
    archive_path = settings.ledger_archive_dir / f"ledger_{stamp}.jsonl"
    meta_path = settings.ledger_archive_dir / f"ledger_{stamp}.meta.json"

    if settings.ledger_path.exists():
        try:
            os.replace(settings.ledger_path, archive_path)  # atomic on same filesystem
        except OSError:
            # os.replace requires source and destination on the same
            # filesystem — fails with EXDEV on some container/mounted-
            # volume setups. Falling back to copy+delete trades strict
            # atomicity (a crash between the two steps could briefly
            # leave both files present) for actually working there.
            shutil.copy2(settings.ledger_path, archive_path)
            settings.ledger_path.unlink(missing_ok=True)

    meta_path.write_text(json.dumps({
        "segment_start_hash": _segment_start_hash,
        "segment_end_hash": _last_hash,
        "block_count": len(LEDGER_STREAM),
        "rotated_at": time.time(),
    }, indent=2))

    # Atomic checkpoint write: temp file + os.replace, so a crash
    # mid-rotation can't leave a half-written, corrupt checkpoint behind.
    tmp = settings.ledger_checkpoint_path.with_suffix(".tmp")
    tmp.write_text(json.dumps({"last_hash": _last_hash, "next_index": _next_index}), encoding="utf-8")
    try:
        os.replace(tmp, settings.ledger_checkpoint_path)
    except OSError:
        shutil.copy2(tmp, settings.ledger_checkpoint_path)
        tmp.unlink(missing_ok=True)

    _segment_start_hash = _last_hash
    _file_offset = 0
    LEDGER_STREAM.clear()


def write_ledger_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Never raises — a ledger write failing must not be able to crash a
    real money transaction. Disk failure is reported via `_persisted` in
    the return value rather than thrown, so the caller decides whether
    that failure itself needs escalating.
    """
    global _last_hash, _next_index, _file_offset

    entry = {**entry}  # copy — never mutate the caller's dict

    try:
        with _LOCK, _FILE_LOCK:
            _sync_from_disk_locked()

            entry["index"] = _next_index
            entry["previous_hash"] = _last_hash
            entry["block_hash"] = _calculate_hash(_last_hash, entry)
            entry["signature"] = sign_hash(_PRIVATE_KEY, entry["block_hash"])
            entry["signer_public_key"] = _PUBLIC_KEY_HEX

            # Validates the fully-assembled block against the schema before
            # it's treated as real — catches a malformed entry here, at
            # write time, rather than during a later verify pass.
            try:
                LedgerBlock(**entry)
            except ValidationError as e:
                return {**entry, "_persisted": False, "_error": str(e)}

            # Disk first, memory second. The old order (memory, then disk)
            # meant a failed write left this process's chain head pointing
            # at a block that was never persisted, so every later block on
            # disk linked to a hash the file doesn't contain.
            try:
                with open(settings.ledger_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, default=str) + "\n")
            except OSError as e:
                print(f"[LEDGER WARNING] Failed to persist entry to disk: {e}")
                return {**entry, "_persisted": False, "_error": str(e)}

            LEDGER_STREAM.append(entry)
            _last_hash = entry["block_hash"]
            _next_index += 1
            _file_offset = settings.ledger_path.stat().st_size

            if _file_offset >= settings.ledger_max_bytes:
                try:
                    _rotate_locked()
                except OSError as e:
                    # The entry itself is safely on disk; only rotation
                    # failed, and the next write will simply try again.
                    print(f"[LEDGER WARNING] Rotation failed: {e}")
    except Timeout:
        print("[LEDGER WARNING] Timed out waiting for the ledger file lock.")
        return {**entry, "_persisted": False, "_error": "ledger file lock timeout"}

    try:
        print(f"[LEDGER] {json.dumps(entry, default=str)}")
    except Exception:
        print(f"[LEDGER] {entry}")

    return {**entry, "_persisted": True}


def _synced_snapshot() -> Tuple[List[dict], str]:
    """Verification must cover what's on disk, including blocks other
    processes wrote — not just this process's possibly-stale view."""
    with _LOCK, _FILE_LOCK:
        _sync_from_disk_locked()
        return list(LEDGER_STREAM), _segment_start_hash


def verify_chain() -> Tuple[bool, str]:
    """Proves internal consistency — nothing in the active segment was
    altered after the fact. Does NOT prove authenticity; see
    verify_signatures() for that separate property.

    Returns (bool, str), not a bare bool — `if verify_chain():` is
    ALWAYS True regardless of contents, since a non-empty tuple is
    truthy. Always unpack: `is_valid, msg = verify_chain()`.
    """
    try:
        blocks, running_hash = _synced_snapshot()
    except Timeout:
        return False, "Could not acquire the ledger file lock to verify."
    for block in blocks:
        if block.get("previous_hash") != running_hash:
            return False, f"Broken link at index {block.get('index')}: expected {running_hash}, got {block.get('previous_hash')}"
        recomputed = _calculate_hash(running_hash, block)
        if recomputed != block.get("block_hash"):
            return False, f"Tampered block at index {block.get('index')}: recomputed {recomputed} != stored {block.get('block_hash')}"
        running_hash = block["block_hash"]
    return True, "Chain intact and verified."


def verify_signatures() -> Tuple[bool, str]:
    """Proves authenticity — every block was genuinely produced by the
    holder of the private key matching its embedded public key. This is
    what makes the ledger non-repudiable, not verify_chain() alone: a
    forged final block can be made internally consistent (recompute its
    own hash to match), but forging a valid signature requires the
    private key. Same tuple-unpack rule as verify_chain().
    """
    try:
        blocks, _ = _synced_snapshot()
    except Timeout:
        return False, "Could not acquire the ledger file lock to verify."
    for block in blocks:
        block_hash = block.get("block_hash")
        signature = block.get("signature")
        signer_hex = block.get("signer_public_key")
        if not (block_hash and signature and signer_hex):
            return False, f"Missing signature fields at index {block.get('index')}."
        public_key = public_key_from_hex(signer_hex)
        if not verify_hash_signature(public_key, block_hash, signature):
            return False, f"Invalid signature at index {block.get('index')}."
    return True, "All signatures valid — ledger is non-repudiable."


def verify_archive(meta_path) -> Tuple[bool, str]:
    """Independently verifies one rotated-out segment against its own
    sidecar metadata, without touching LEDGER_STREAM or the active
    segment — proves old history on demand instead of holding it all in
    memory just in case."""
    meta = json.loads(meta_path.read_text())
    log_path = meta_path.with_suffix("").with_suffix(".jsonl")
    if not log_path.exists():
        return False, f"Log segment {log_path} missing."

    running_hash = meta["segment_start_hash"]
    for line in log_path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        block = json.loads(line)
        if block.get("previous_hash") != running_hash:
            return False, f"Archive broken at index {block.get('index')}."
        recomputed = _calculate_hash(running_hash, block)
        if recomputed != block.get("block_hash"):
            return False, f"Archive tampered at index {block.get('index')}."
        running_hash = block["block_hash"]

    if running_hash != meta["segment_end_hash"]:
        return False, "Archive end hash mismatch."
    return True, "Archive verified."
