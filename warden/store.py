"""Case persistence. JSON files on disk. Swap for Postgres when it matters."""
from __future__ import annotations

import json
from pathlib import Path

from .config import settings
from .models import Case


class CaseStore:
    def __init__(self, path: Path | None = None):
        self.dir = (path or settings.state_dir) / "cases"
        self.dir.mkdir(parents=True, exist_ok=True)

    def save(self, case: Case) -> None:
        (self.dir / f"{case.alert.id}.json").write_text(case.model_dump_json(indent=2))

    def get(self, alert_id: str) -> Case | None:
        p = self.dir / f"{alert_id}.json"
        return Case.model_validate_json(p.read_text()) if p.exists() else None

    def all(self) -> list[Case]:
        cases = [Case.model_validate_json(p.read_text()) for p in self.dir.glob("*.json")]
        return sorted(cases, key=lambda c: c.alert.ts, reverse=True)

    def exists(self, alert_id: str) -> bool:
        return (self.dir / f"{alert_id}.json").exists()
