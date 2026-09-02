from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


@dataclass
class Settings:
    llm_provider: str = field(default_factory=lambda: _env("WARDEN_LLM", "anthropic"))
    model: str = field(default_factory=lambda: _env("WARDEN_MODEL", "claude-sonnet-4-5"))
    anthropic_api_key: str = field(default_factory=lambda: _env("ANTHROPIC_API_KEY", ""))
    embeddings: str = field(default_factory=lambda: _env("WARDEN_EMBEDDINGS", "default"))

    data_dir: Path = field(default_factory=lambda: Path(_env("WARDEN_DATA_DIR", "data")))
    log_file: Path = field(default_factory=lambda: Path(_env("WARDEN_LOG_FILE", "data/sample_logs/auth.jsonl")))

    # detection tuning
    bf_threshold: int = field(default_factory=lambda: int(_env("WARDEN_BF_THRESHOLD", "10")))
    bf_window_sec: int = field(default_factory=lambda: int(_env("WARDEN_BF_WINDOW_SEC", "300")))
    travel_max_kmh: int = field(default_factory=lambda: int(_env("WARDEN_TRAVEL_MAX_KMH", "900")))
    travel_min_km: int = field(default_factory=lambda: int(_env("WARDEN_TRAVEL_MIN_KM", "500")))
    mfa_threshold: int = field(default_factory=lambda: int(_env("WARDEN_MFA_THRESHOLD", "5")))
    # empty = run every registered detection
    detections: list[str] = field(
        default_factory=lambda: [d.strip() for d in _env("WARDEN_DETECTIONS", "").split(",") if d.strip()]
    )

    auto_action_min_risk: int = field(default_factory=lambda: int(_env("WARDEN_AUTO_ACTION_MIN_RISK", "80")))
    # per-rule overrides, "rule:threshold,rule:threshold" (PB-005 allows 70 for spray)
    rule_thresholds: dict[str, int] = field(
        default_factory=lambda: {k: int(v) for k, v in (p.split(":") for p in _env("WARDEN_RULE_THRESHOLDS", "password_spray:70").split(",") if ":" in p)}
    )
    human_approval_actions: set[str] = field(
        default_factory=lambda: {a.strip() for a in _env("WARDEN_HUMAN_APPROVAL_ACTIONS", "lock_user").split(",") if a.strip()}
    )
    ip_safelist: set[str] = field(
        default_factory=lambda: {a.strip() for a in _env("WARDEN_IP_SAFELIST", "10.0.0.1,10.0.0.2").split(",") if a.strip()}
    )

    @property
    def knowledge_dir(self) -> Path:
        return self.data_dir / "knowledge"

    @property
    def attack_dir(self) -> Path:
        return self.data_dir / "attack"

    @property
    def eval_dir(self) -> Path:
        return self.data_dir / "eval"

    @property
    def chroma_dir(self) -> Path:
        return self.data_dir / "chroma"

    @property
    def state_dir(self) -> Path:
        return self.data_dir / "state"

    def __post_init__(self) -> None:
        if self.llm_provider == "anthropic" and not self.anthropic_api_key:
            # Fail soft: run offline rather than crash. Loud about it.
            print("[warden] ANTHROPIC_API_KEY not set, falling back to WARDEN_LLM=mock")
            self.llm_provider = "mock"


settings = Settings()
