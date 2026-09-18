import os

os.environ.setdefault("WARDEN_LLM", "mock")
os.environ.setdefault("WARDEN_EMBEDDINGS", "hash")
os.environ["WARDEN_LLM"] = "mock"
os.environ["WARDEN_EMBEDDINGS"] = "hash"

import pytest


@pytest.fixture(autouse=True)
def _isolated_data_dir(tmp_path, monkeypatch):
    """Nothing a test does may write into the repo's data/ (learned cases, reports, the DB).
    Tests that need repo fixtures read them by explicit path."""
    from warden.config import settings

    d = tmp_path / "warden-data"
    (d / "knowledge").mkdir(parents=True)
    monkeypatch.setattr(settings, "data_dir", d)
