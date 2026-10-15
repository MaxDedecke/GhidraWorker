"""Paths and persistent settings."""

from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass, fields
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
REPO_DIR = PACKAGE_DIR.parent
SCRIPTS_DIR = PACKAGE_DIR / "ghidra_scripts"
STATIC_DIR = PACKAGE_DIR / "static"


def workspace_dir() -> Path:
    """Directory holding all projects and the settings file (``GW_WORKSPACE`` overrides it)."""
    return Path(os.environ.get("GW_WORKSPACE", REPO_DIR / "workspace")).resolve()


def tools_dir() -> Path:
    """Directory where Ghidra gets installed by the built-in installer."""
    return Path(os.environ.get("GW_TOOLS", REPO_DIR / "tools")).resolve()


@dataclass
class Settings:
    # Path to the Ghidra installation (the folder containing ``ghidraRun``). Empty = auto-detect.
    ghidra_dir: str = ""
    # JDK used to run Ghidra. Empty = JAVA_HOME / PATH.
    java_home: str = ""
    # Number of analyses running at the same time.
    max_parallel_jobs: int = 1
    # Ghidra's auto-analysis timeout per binary in seconds (0 = unlimited).
    analysis_timeout: int = 0
    # Number of CPU cores Ghidra may use (0 = all).
    max_cpu: int = 0
    # Max Java heap for headless Ghidra, e.g. "4G" (empty = Ghidra default).
    max_memory: str = ""
    # Enable slower but better analyzers (Decompiler Parameter ID, ...).
    thorough_analysis: bool = True
    # Start analysis right after a binary was added.
    auto_start: bool = True


_lock = threading.Lock()


def settings_path() -> Path:
    return workspace_dir() / "settings.json"


def load_settings() -> Settings:
    path = settings_path()
    if not path.exists():
        return Settings()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return Settings()
    known = {f.name for f in fields(Settings)}
    return Settings(**{k: v for k, v in data.items() if k in known})


def save_settings(settings: Settings) -> None:
    with _lock:
        path = settings_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(settings), indent=2), encoding="utf-8")
        tmp.replace(path)


def update_settings(changes: dict) -> Settings:
    current = asdict(load_settings())
    for f in fields(Settings):
        if f.name not in changes or changes[f.name] is None:
            continue
        value = changes[f.name]
        if f.type in ("int", int):
            value = max(0, int(value))
        elif f.type in ("bool", bool):
            value = bool(value)
        else:
            value = str(value).strip()
        current[f.name] = value
    settings = Settings(**current)
    settings.max_parallel_jobs = max(1, settings.max_parallel_jobs)
    save_settings(settings)
    return settings
