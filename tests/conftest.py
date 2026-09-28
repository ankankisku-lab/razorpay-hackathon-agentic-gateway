import atexit
import shutil
import tempfile
from pathlib import Path

import pytest

from config import settings

# Module-level on purpose, not a fixture: pytest imports conftest.py
# before any test module, and backend.ledger reads settings.ledger_path
# and loads the signing key at IMPORT time. Only an override that runs
# before that import redirects it. Without this, tests appended to the
# real backend/ledger.jsonl — which is how the committed ledger ended up
# with a forked hash chain once another process (Streamlit) wrote to the
# same file.
_TEST_STATE_DIR = Path(tempfile.mkdtemp(prefix="gateway-tests-"))
atexit.register(shutil.rmtree, _TEST_STATE_DIR, ignore_errors=True)

settings.ledger_path = _TEST_STATE_DIR / "ledger.jsonl"
settings.ledger_checkpoint_path = _TEST_STATE_DIR / "ledger.checkpoint.json"
settings.ledger_archive_dir = _TEST_STATE_DIR / "ledger_archive"
settings.signing_private_key_path = _TEST_STATE_DIR / "keys" / "ledger_signing_key.pem"
settings.signing_public_key_path = _TEST_STATE_DIR / "keys" / "ledger_signing_key.pub.pem"


@pytest.fixture(autouse=True)
def _restore_mock_gateway_flag():
    """Several tests flip settings.allow_mock_gateway on to reach the
    simulated decline/timeout paths. It's a process-wide global, so
    without a reset every later test silently ran with mock mode on —
    test outcomes depended on execution order."""
    original = settings.allow_mock_gateway
    yield
    settings.allow_mock_gateway = original
