"""On-disk project store.

Every reverse-engineering project lives in its own folder below ``workspace/projects``::

    <id>/
      project.json      metadata + job status
      state.json        user work: function status, renames, notes
      input/            the original binary
      ghidra/           the Ghidra project (open it in the Ghidra GUI any time)
      analysis/         export produced by GhidraWorkerExport.java
      rebuild/          generated rebuild scaffold (your source tree)
      logs/             analysis logs
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import threading
import time
import uuid
from pathlib import Path
from typing import BinaryIO

from . import config
from .pe import read_pe_info

GHIDRA_PROJECT_NAME = "gw"
FUNCTION_STATUSES = ("todo", "progress", "done", "skip")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,80}$")
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_:]{0,200}$")


class ProjectError(Exception):
    pass


class NotFound(ProjectError):
    pass


def now() -> float:
    return round(time.time(), 3)


def slugify(text: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9]+", "-", text).strip("-").lower()
    return text[:40] or "projekt"


def safe_filename(name: str) -> str:
    name = Path(name.replace("\\", "/")).name
    name = re.sub(r"[^A-Za-z0-9._ -]+", "_", name).strip(" .")
    return name or "binary.exe"


def _read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".{uuid.uuid4().hex[:6]}.tmp")
    tmp.write_text(json.dumps(data, indent=1, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


class ProjectStore:
    def __init__(self, root: Path | None = None) -> None:
        self.root = (root or config.workspace_dir()) / "projects"
        self.root.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self._cache: dict[tuple[str, str], tuple[float, object]] = {}

    # ------------------------------------------------------------------ paths

    def path(self, pid: str) -> Path:
        if not _ID_RE.match(pid or ""):
            raise NotFound(pid)
        p = self.root / pid
        if not (p / "project.json").exists():
            raise NotFound(pid)
        return p

    def binary_path(self, pid: str) -> Path:
        meta = self.get(pid)
        return self.path(pid) / "input" / meta["binary"]["filename"]

    def analysis_dir(self, pid: str) -> Path:
        return self.path(pid) / "analysis"

    def rebuild_dir(self, pid: str) -> Path:
        return self.path(pid) / "rebuild"

    def ghidra_dir(self, pid: str) -> Path:
        return self.path(pid) / "ghidra"

    def log_path(self, pid: str) -> Path:
        return self.path(pid) / "logs" / "analysis.log"

    # ------------------------------------------------------------------ CRUD

    def create(self, filename: str, stream: BinaryIO, name: str | None = None) -> dict:
        filename = safe_filename(filename)
        display = (name or "").strip() or Path(filename).stem
        pid = f"{slugify(display)}-{uuid.uuid4().hex[:6]}"
        pdir = self.root / pid
        (pdir / "input").mkdir(parents=True)
        for sub in ("analysis", "rebuild", "logs", "ghidra"):
            (pdir / sub).mkdir()
        target = pdir / "input" / filename
        sha = hashlib.sha256()
        size = 0
        with open(target, "wb") as out:
            while True:
                chunk = stream.read(1 << 20)
                if not chunk:
                    break
                sha.update(chunk)
                size += len(chunk)
                out.write(chunk)
        if size == 0:
            shutil.rmtree(pdir, ignore_errors=True)
            raise ProjectError("Die Datei ist leer.")
        meta = {
            "id": pid,
            "name": display,
            "created": now(),
            "updated": now(),
            "binary": {
                "filename": filename,
                "size": size,
                "sha256": sha.hexdigest(),
                "pe": read_pe_info(target),
            },
            "status": "new",
            "job": None,
            "error": None,
            "analyzed": None,
            "notes": "",
            "tags": [],
        }
        _write_json(pdir / "project.json", meta)
        _write_json(pdir / "state.json", {"functions": {}})
        return meta

    def list(self) -> list[dict]:
        out = []
        for p in self.root.iterdir():
            meta = _read_json(p / "project.json", None)
            if meta:
                out.append(meta)
        out.sort(key=lambda m: m.get("updated", 0), reverse=True)
        return out

    def get(self, pid: str) -> dict:
        meta = _read_json(self.path(pid) / "project.json", None)
        if meta is None:
            raise NotFound(pid)
        return meta

    def update(self, pid: str, **changes) -> dict:
        with self.lock:
            meta = self.get(pid)
            meta.update(changes)
            meta["updated"] = now()
            _write_json(self.path(pid) / "project.json", meta)
            return meta

    def update_job(self, pid: str, **changes) -> dict:
        with self.lock:
            meta = self.get(pid)
            job = dict(meta.get("job") or {})
            job.update(changes)
            meta["job"] = job
            _write_json(self.path(pid) / "project.json", meta)
            return meta

    def delete(self, pid: str) -> None:
        with self.lock:
            shutil.rmtree(self.path(pid))
            for key in [k for k in self._cache if k[0] == pid]:
                del self._cache[key]

    # ------------------------------------------------------------------ user state

    def state(self, pid: str) -> dict:
        st = _read_json(self.path(pid) / "state.json", None) or {}
        st.setdefault("functions", {})
        return st

    def update_function(self, pid: str, address: str, changes: dict) -> dict:
        with self.lock:
            st = self.state(pid)
            entry = dict(st["functions"].get(address, {}))
            if "status" in changes and changes["status"] is not None:
                if changes["status"] not in FUNCTION_STATUSES:
                    raise ProjectError(f"Ungültiger Status: {changes['status']}")
                entry["status"] = changes["status"]
            if "notes" in changes and changes["notes"] is not None:
                entry["notes"] = str(changes["notes"])
            if "newName" in changes and changes["newName"] is not None:
                new_name = str(changes["newName"]).strip()
                if new_name and not _NAME_RE.match(new_name):
                    raise ProjectError(
                        "Ungültiger Funktionsname (erlaubt: Buchstaben, Ziffern, _ und ::)"
                    )
                entry["newName"] = new_name
            entry = {k: v for k, v in entry.items() if v not in ("", None)}
            if entry:
                entry["updated"] = now()
                st["functions"][address] = entry
            else:
                st["functions"].pop(address, None)
            _write_json(self.path(pid) / "state.json", st)
            self.update(pid)  # bump "updated"
            return entry

    def bulk_update_functions(self, pid: str, addresses: list[str], status: str) -> int:
        if status not in FUNCTION_STATUSES:
            raise ProjectError(f"Ungültiger Status: {status}")
        with self.lock:
            st = self.state(pid)
            for a in addresses:
                entry = dict(st["functions"].get(a, {}))
                entry["status"] = status
                entry["updated"] = now()
                st["functions"][a] = entry
            _write_json(self.path(pid) / "state.json", st)
            self.update(pid)
            return len(addresses)

    # ------------------------------------------------------------------ analysis data

    def analysis(self, pid: str, kind: str, default=None):
        """Load (and cache) one of the JSON files written by the Ghidra export script."""
        if kind not in ("program", "sections", "functions", "imports", "exports", "strings", "globals"):
            raise NotFound(kind)
        path = self.analysis_dir(pid) / f"{kind}.json"
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return default
        key = (pid, kind)
        cached = self._cache.get(key)
        if cached and cached[0] == mtime:
            return cached[1]
        data = _read_json(path, default)
        self._cache[key] = (mtime, data)
        return data

    def has_analysis(self, pid: str) -> bool:
        return (self.analysis_dir(pid) / "functions.json").exists()

    def functions(self, pid: str) -> list[dict]:
        """Functions from the analysis merged with the user's state."""
        funcs = self.analysis(pid, "functions", []) or []
        st = self.state(pid)["functions"]
        out = []
        for f in funcs:
            user = st.get(f["address"], {})
            merged = dict(f)
            merged["status"] = user.get("status") or default_status(f)
            merged["notes"] = user.get("notes", "")
            merged["newName"] = user.get("newName", "")
            merged["displayName"] = user.get("newName") or f["name"]
            out.append(merged)
        return out

    def summary(self, pid: str) -> dict:
        """Rebuild progress numbers shown on the dashboard."""
        if not self.has_analysis(pid):
            return {}
        funcs = self.functions(pid)
        relevant = [f for f in funcs if f["status"] != "skip"]
        counts = {s: 0 for s in FUNCTION_STATUSES}
        for f in funcs:
            counts[f["status"]] += 1
        total_bytes = sum(f["size"] for f in relevant) or 1
        done_bytes = sum(f["size"] for f in relevant if f["status"] == "done")
        program = self.analysis(pid, "program", {}) or {}
        return {
            "functions": len(funcs),
            "relevant": len(relevant),
            "counts": counts,
            "renamed": sum(1 for f in funcs if f["newName"]),
            # renames not yet written into the Ghidra project
            "pendingRenames": sum(1 for f in funcs if f["newName"] and f["newName"] != f["name"]),
            "progress": counts["done"] / len(relevant) if relevant else 0.0,
            "progressBytes": done_bytes / total_bytes,
            "imports": len(self.analysis(pid, "imports", []) or []),
            "strings": len(self.analysis(pid, "strings", []) or []),
            "format": program.get("executableFormat"),
            "language": program.get("language"),
            "compiler": program.get("compiler"),
        }


def default_status(func: dict) -> str:
    """Thunks and recognised library functions don't need to be rebuilt by hand."""
    if func.get("thunk") or func.get("library"):
        return "skip"
    return "todo"
