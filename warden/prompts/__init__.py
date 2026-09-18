"""Versioned prompts. Each prompt is a markdown file with YAML-ish frontmatter:

    ---
    id: analyze
    version: "2026-09-18.1"
    changelog: [...]
    ---
    # system
    ...
    # user
    ... {placeholders} ...

The version is logged with every model call so an analysis can be replayed exactly.
Changing a prompt means bumping its version and adding a changelog line.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

DIR = Path(__file__).parent


@dataclass(frozen=True)
class Prompt:
    id: str
    version: str
    system: str
    user: str

    @property
    def tag(self) -> str:
        return f"{self.id}@{self.version}"


@lru_cache(maxsize=None)
def load(name: str) -> Prompt:
    text = (DIR / f"{name}.md").read_text()
    m = re.match(r"---\n(.*?)\n---\n(.*)", text, re.S)
    if not m:
        raise ValueError(f"prompt {name} is missing frontmatter")
    front, body = m.groups()
    version = re.search(r'^version:\s*"?([^"\n]+)"?', front, re.M).group(1)
    sections = dict(re.findall(r"^# (\w+)\n(.*?)(?=^# \w+\n|\Z)", body, re.S | re.M))
    return Prompt(id=name, version=version, system=sections["system"].strip(), user=sections["user"].strip())
