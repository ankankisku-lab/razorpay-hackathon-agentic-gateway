from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# File-relative, not CWD-relative — uvicorn, pytest, and a plain `python`
# invocation all have different working directories. Anchoring to
# __file__ means .env and every path below resolve the same way
# regardless of where the process was launched from.
BASE_DIR = Path(__file__).resolve().parent


class Settings(BaseSettings):
    """Required fields with no default raise at import time if unset —
    fail loud at startup, not mid-transaction on whichever request
    happens to need the missing key first.
    """
    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    groq_api_key: str = Field(..., alias="GROQ_API_KEY")
    planner_model: str = Field(default="openai/gpt-oss-120b", alias="PLANNER_MODEL")
    guard_model: str = Field(default="meta-llama/llama-prompt-guard-2-86m", alias="GUARD_MODEL")

    razorpay_key_id: str = Field(..., alias="RAZORPAY_KEY_ID")
    razorpay_key_secret: str = Field(..., alias="RAZORPAY_KEY_SECRET")
    razorpay_webhook_secret: str = Field(..., alias="RAZORPAY_WEBHOOK_SECRET")

    session_spend_cap_paise: int = Field(default=250_000, alias="SESSION_SPEND_CAP_PAISE")

    # Must default to False. This flag is what decides whether app.py
    # even registers the route that accepts SimulatedExecutionRequest —
    # a mock-gateway path reachable by accident in a real deployment
    # would defeat the entire point of keeping simulate_* fields out of
    # the production request schema.
    allow_mock_gateway: bool = Field(default=False, alias="ALLOW_MOCK_GATEWAY")

    ledger_max_bytes: int = Field(default=5_000_000, alias="LEDGER_MAX_BYTES")

    # Three paths, not one, because the ledger rotates: an active file,
    # a checkpoint recording where the hash chain left off (so a restart
    # continues the same chain instead of silently starting a new one),
    # and an archive directory for rotated-out segments. Defined here
    # rather than computed inside ledger.py so there's one source of
    # truth — two modules independently deriving "the same" path from
    # __file__ is how they quietly drift apart.
    ledger_path: Path = BASE_DIR / "backend" / "ledger.jsonl"
    ledger_checkpoint_path: Path = BASE_DIR / "backend" / "ledger.checkpoint.json"
    ledger_archive_dir: Path = BASE_DIR / "backend" / "ledger_archive"

    catalog_path: Path = BASE_DIR / "backend" / "catalog.json"
    index_path: Path = BASE_DIR / "retrieval" / "catalog.index"
    metadata_path: Path = BASE_DIR / "retrieval" / "catalog_meta.json"

    # Same reasoning as the ledger paths above — ledger.py needs these
    # to sign entries, and nothing else should ever need to know where
    # they live.
    signing_private_key_path: Path = BASE_DIR / "backend" / "keys" / "ledger_signing_key.pem"
    signing_public_key_path: Path = BASE_DIR / "backend" / "keys" / "ledger_signing_key.pub.pem"


# Instantiated once. Every other module imports `settings` from here
# rather than reading os.environ itself — that's what makes "fail loud
# on missing config" a startup-time guarantee instead of a race between
# whichever module happens to import first.
settings = Settings()


