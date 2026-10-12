"""Config loading. All thresholds/weights come from configs/default.yaml."""
from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

import yaml

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_CONFIG_PATH = os.path.join(REPO_ROOT, "configs", "default.yaml")


def load_config(path: str | None = None) -> dict[str, Any]:
    path = path or os.environ.get("FRAUDMESH_CONFIG", DEFAULT_CONFIG_PATH)
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@lru_cache(maxsize=1)
def get_config() -> dict[str, Any]:
    return load_config()
