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
    model: str = field(default_factory=lambda: _env("WARDEN_MODEL", "claude-opus-5"))
    proposal_model: str = field(default_factory=lambda: _env("WARDEN_PROPOSAL_MODEL", "claude-opus-5"))
    model_triage: str = field(default_factory=lambda: _env("WARDEN_MODEL_TRIAGE", "claude-sonnet-5"))
    llm_base_url: str = field(default_factory=lambda: _env("WARDEN_LLM_BASE_URL", ""))     # openai-compatible providers
    llm_api_key: str = field(default_factory=lambda: _env("WARDEN_LLM_API_KEY", ""))
    log_format: str = field(default_factory=lambda: _env("WARDEN_LOG_FORMAT", "text"))
    log_level: str = field(default_factory=lambda: _env("WARDEN_LOG_LEVEL", "info"))
    metrics_token: str = field(default_factory=lambda: _env("WARDEN_METRICS_TOKEN", ""))
    effort: str = field(default_factory=lambda: _env("WARDEN_EFFORT", "medium"))
    anthropic_api_key: str = field(default_factory=lambda: _env("ANTHROPIC_API_KEY", ""))
    # needed only when the key is not scoped to a workspace
    anthropic_workspace_id: str = field(default_factory=lambda: _env("ANTHROPIC_WORKSPACE_ID", ""))
    retrieval_mode: str = field(default_factory=lambda: _env("WARDEN_RETRIEVAL", "hybrid"))
    embeddings: str = field(default_factory=lambda: _env("WARDEN_EMBEDDINGS", "default"))

    data_dir: Path = field(default_factory=lambda: Path(_env("WARDEN_DATA_DIR", "data")))
    log_file: Path = field(default_factory=lambda: Path(_env("WARDEN_LOG_FILE", "data/sample_logs/auth.jsonl")))

    database_url: str = field(default_factory=lambda: _env("WARDEN_DATABASE_URL", ""))
    tenant: str = field(default_factory=lambda: _env("WARDEN_TENANT", "default"))

    # governance (warden/governance.py)
    redact: str = field(default_factory=lambda: _env("WARDEN_REDACT", ""))          # email,card,ssn,phone
    retention_events_days: int = field(default_factory=lambda: int(_env("WARDEN_RETENTION_EVENTS_DAYS", "90")))
    retention_cases_days: int = field(default_factory=lambda: int(_env("WARDEN_RETENTION_CASES_DAYS", "365")))
    retention_llm_days: int = field(default_factory=lambda: int(_env("WARDEN_RETENTION_LLM_DAYS", "365")))
    retention_audit_days: int = field(default_factory=lambda: int(_env("WARDEN_RETENTION_AUDIT_DAYS", "730")))
    verify_model: str = field(default_factory=lambda: _env("WARDEN_VERIFY_MODEL", ""))   # e.g. claude-haiku-4-5

    # dashboard / API auth (see warden/auth.py)
    auth_mode: str = field(default_factory=lambda: _env("WARDEN_AUTH", "none"))
    users: str = field(default_factory=lambda: _env("WARDEN_USERS", ""))
    trusted_proxies: str = field(default_factory=lambda: _env("WARDEN_TRUSTED_PROXIES", "127.0.0.1/32"))
    proxy_user_header: str = field(default_factory=lambda: _env("WARDEN_PROXY_USER_HEADER", "x-forwarded-user"))
    proxy_groups_header: str = field(default_factory=lambda: _env("WARDEN_PROXY_GROUPS_HEADER", "x-forwarded-groups"))
    proxy_default_role: str = field(default_factory=lambda: _env("WARDEN_PROXY_DEFAULT_ROLE", "viewer"))
    analyst_group: str = field(default_factory=lambda: _env("WARDEN_ANALYST_GROUP", "soc-analysts"))
    admin_group: str = field(default_factory=lambda: _env("WARDEN_ADMIN_GROUP", "soc-admins"))

    fp_prior_min_verdicts: int = field(default_factory=lambda: int(_env("WARDEN_FP_PRIOR_MIN_VERDICTS", "10")))
    exclusion_days: int = field(default_factory=lambda: int(_env("WARDEN_EXCLUSION_DAYS", "30")))
    otx_api_key: str = field(default_factory=lambda: _env("OTX_API_KEY", ""))
    hec_token: str = field(default_factory=lambda: _env("WARDEN_HEC_TOKEN", ""))
    hec_tokens: str = field(default_factory=lambda: _env("WARDEN_HEC_TOKENS", ""))    # "tenant:token,..."

    # detection tuning
    bf_threshold: int = field(default_factory=lambda: int(_env("WARDEN_BF_THRESHOLD", "10")))
    bf_window_sec: int = field(default_factory=lambda: int(_env("WARDEN_BF_WINDOW_SEC", "300")))
    spray_min_users: int = field(default_factory=lambda: int(_env("WARDEN_SPRAY_MIN_USERS", "5")))
    spray_max_per_user: float = field(default_factory=lambda: float(_env("WARDEN_SPRAY_MAX_PER_USER", "3")))
    stuffing_min_users: int = field(default_factory=lambda: int(_env("WARDEN_STUFFING_MIN_USERS", "8")))
    stuffing_min_ips: int = field(default_factory=lambda: int(_env("WARDEN_STUFFING_MIN_IPS", "4")))
    home_countries: str = field(default_factory=lambda: _env("WARDEN_HOME_COUNTRIES", "US"))
    dormant_days: int = field(default_factory=lambda: int(_env("WARDEN_DORMANT_DAYS", "60")))
    new_geo_min_history: int = field(default_factory=lambda: int(_env("WARDEN_NEW_GEO_MIN_HISTORY", "3")))
    lockout_storm_users: int = field(default_factory=lambda: int(_env("WARDEN_LOCKOUT_STORM_USERS", "5")))
    reset_cluster: int = field(default_factory=lambda: int(_env("WARDEN_RESET_CLUSTER", "3")))
    service_account_patterns: str = field(default_factory=lambda: _env("WARDEN_SERVICE_ACCOUNT_PATTERNS", "svc-*,svc_*,sa-*,*$"))
    privileged_groups: str = field(default_factory=lambda: _env(
        "WARDEN_PRIVILEGED_GROUPS",
        "Domain Admins,Enterprise Admins,Schema Admins,Administrators,Account Operators,Backup Operators,"
        "Server Operators,DnsAdmins,Group Policy Creator Owners,Global Administrator,Privileged Role Administrator,"
        "Security Administrator,Exchange Administrator,Okta Super Admins,Super Administrator,Organization Administrator,"
        "AdministratorAccess"))
    change_window: str = field(default_factory=lambda: _env("WARDEN_CHANGE_WINDOW", ""))
    history_days: int = field(default_factory=lambda: int(_env("WARDEN_HISTORY_DAYS", "90")))
    encryption_min_files: int = field(default_factory=lambda: int(_env("WARDEN_ENCRYPTION_MIN_FILES", "50")))
    beacon_min_connections: int = field(default_factory=lambda: int(_env("WARDEN_BEACON_MIN_CONNECTIONS", "8")))
    beacon_max_cv: float = field(default_factory=lambda: float(_env("WARDEN_BEACON_MAX_CV", "0.15")))
    dns_min_unique: int = field(default_factory=lambda: int(_env("WARDEN_DNS_MIN_UNIQUE", "30")))
    dns_txt_min: int = field(default_factory=lambda: int(_env("WARDEN_DNS_TXT_MIN", "50")))
    lateral_min_hosts: int = field(default_factory=lambda: int(_env("WARDEN_LATERAL_MIN_HOSTS", "5")))
    scan_min_targets: int = field(default_factory=lambda: int(_env("WARDEN_SCAN_MIN_TARGETS", "20")))
    exfil_bytes: int = field(default_factory=lambda: int(_env("WARDEN_EXFIL_BYTES", str(500 * 1024 * 1024))))
    aws_regions: str = field(default_factory=lambda: _env("WARDEN_AWS_REGIONS", "us-east-1,us-west-2"))
    email_domains: str = field(default_factory=lambda: _env("WARDEN_EMAIL_DOMAINS", "corp.example"))
    baseline_days: int = field(default_factory=lambda: int(_env("WARDEN_BASELINE_DAYS", "30")))
    baseline_min_days: int = field(default_factory=lambda: int(_env("WARDEN_BASELINE_MIN_DAYS", "7")))
    anomaly_min_z: float = field(default_factory=lambda: float(_env("WARDEN_ANOMALY_MIN_Z", "3")))
    peer_common: int = field(default_factory=lambda: int(_env("WARDEN_PEER_COMMON", "3")))
    peer_weight: float = field(default_factory=lambda: float(_env("WARDEN_PEER_WEIGHT", "0.25")))
    anomaly_threshold: float = field(default_factory=lambda: float(_env("WARDEN_ANOMALY_THRESHOLD", "8")))
    correlation_window_sec: int = field(default_factory=lambda: int(_env("WARDEN_CORRELATION_WINDOW_SEC", "7200")))
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
    # response connectors (warden/connectors): "action=connector,..."; unmapped actions use the mock
    connectors: str = field(default_factory=lambda: _env("WARDEN_CONNECTORS", ""))
    live_actions: bool = field(default_factory=lambda: _env("WARDEN_LIVE_ACTIONS", "0") in ("1", "true", "yes"))
    # actions that may auto-execute (on top of tickets/notifications), subject to rollback support
    auto_actions: set[str] = field(
        default_factory=lambda: {a.strip() for a in _env("WARDEN_AUTO_ACTIONS", "block_ip,isolate_host,disable_access_key").split(",") if a.strip()}
    )
    notify_targets: set[str] = field(
        default_factory=lambda: {a.strip() for a in _env("WARDEN_NOTIFY_TARGETS", "soc,oncall").split(",") if a.strip()}
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
        if self.llm_provider == "anthropic" and not self.anthropic_api_key and not os.environ.get("ANTHROPIC_AUTH_TOKEN"):
            # Fail soft: run offline rather than crash. Loud about it.
            print("[warden] ANTHROPIC_API_KEY not set, falling back to WARDEN_LLM=mock")
            self.llm_provider = "mock"


settings = Settings()
