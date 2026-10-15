"""Locating, checking and installing Ghidra and a suitable JDK."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import threading
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import config

IS_WINDOWS = os.name == "nt"
GHIDRA_REPO = "NationalSecurityAgency/ghidra"
RELEASE_API = f"https://api.github.com/repos/{GHIDRA_REPO}/releases/latest"


# ---------------------------------------------------------------------------- detection


def _is_ghidra_dir(path: Path) -> bool:
    return (path / "support" / "analyzeHeadless").exists() or (
        path / "support" / "analyzeHeadless.bat"
    ).exists()


def find_ghidra(settings: config.Settings | None = None) -> Path | None:
    settings = settings or config.load_settings()
    candidates: list[Path] = []
    if settings.ghidra_dir:
        candidates.append(Path(settings.ghidra_dir).expanduser())
    if os.environ.get("GHIDRA_INSTALL_DIR"):
        candidates.append(Path(os.environ["GHIDRA_INSTALL_DIR"]).expanduser())
    tools = config.tools_dir()
    if tools.is_dir():
        candidates.append(tools / "ghidra")
        candidates.extend(sorted(tools.glob("ghidra_*"), reverse=True))
    for c in candidates:
        if c.is_dir() and _is_ghidra_dir(c):
            return c.resolve()
    return None


def read_properties(path: Path) -> dict[str, str]:
    props: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            props[k.strip()] = v.strip()
    except OSError:
        pass
    return props


def ghidra_info(ghidra_dir: Path) -> dict:
    props = read_properties(ghidra_dir / "Ghidra" / "application.properties")
    return {
        "version": props.get("application.version"),
        "release": props.get("application.release.name"),
        "java_min": props.get("application.java.min"),
    }


def headless_script(ghidra_dir: Path) -> Path:
    return ghidra_dir / "support" / ("analyzeHeadless.bat" if IS_WINDOWS else "analyzeHeadless")


def gui_script(ghidra_dir: Path) -> Path:
    return ghidra_dir / ("ghidraRun.bat" if IS_WINDOWS else "ghidraRun")


def find_java(settings: config.Settings | None = None) -> Path | None:
    settings = settings or config.load_settings()
    exe = "java.exe" if IS_WINDOWS else "java"
    for home in (settings.java_home, os.environ.get("JAVA_HOME", "")):
        if home:
            candidate = Path(home).expanduser() / "bin" / exe
            if candidate.exists():
                return candidate
    found = shutil.which("java")
    return Path(found) if found else None


_VERSION_RE = re.compile(r'version "(\d+)(?:\.(\d+))?')


def java_version(java: Path) -> int | None:
    try:
        out = subprocess.run(
            [str(java), "-version"], capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.SubprocessError):
        return None
    m = _VERSION_RE.search(out.stderr + out.stdout)
    if not m:
        return None
    major = int(m.group(1))
    if major == 1 and m.group(2):  # "1.8" style
        major = int(m.group(2))
    return major


@dataclass
class EnvStatus:
    ghidra_dir: str | None = None
    ghidra_version: str | None = None
    java: str | None = None
    java_version: int | None = None
    java_min: int | None = None
    javac: bool = False
    problems: list[str] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        return not self.problems

    def as_dict(self) -> dict:
        d = self.__dict__.copy()
        d["ready"] = self.ready
        return d


_status_cache: dict = {}


def check_environment(settings: config.Settings | None = None, use_cache: bool = True) -> EnvStatus:
    settings = settings or config.load_settings()
    key = (settings.ghidra_dir, settings.java_home, os.environ.get("JAVA_HOME"))
    if use_cache and _status_cache.get("key") == key:
        return _status_cache["status"]

    st = EnvStatus()
    gdir = find_ghidra(settings)
    if gdir is None:
        st.problems.append(
            "Ghidra wurde nicht gefunden. Unter Einstellungen automatisch installieren "
            "oder den Pfad zu einer Ghidra-Installation angeben."
        )
    else:
        st.ghidra_dir = str(gdir)
        info = ghidra_info(gdir)
        st.ghidra_version = info["version"]
        if info["java_min"] and info["java_min"].isdigit():
            st.java_min = int(info["java_min"])

    java = find_java(settings)
    if java is None:
        st.problems.append(
            "Kein Java gefunden. Ghidra benötigt ein JDK (z. B. Eclipse Temurin "
            f"{st.java_min or 21}+). JAVA_HOME setzen oder in den Einstellungen angeben."
        )
    else:
        st.java = str(java)
        st.java_version = java_version(java)
        st.javac = (java.parent / ("javac.exe" if IS_WINDOWS else "javac")).exists()
        need = st.java_min or 21
        if st.java_version is None:
            st.problems.append(f"Java-Version von {java} konnte nicht ermittelt werden.")
        elif st.java_version < need:
            st.problems.append(
                f"Java {st.java_version} ist zu alt – diese Ghidra-Version braucht JDK {need}+."
            )
        if not st.javac:
            st.problems.append(
                "Es wurde nur eine Java-Laufzeit (JRE) gefunden. Ghidra braucht ein JDK "
                "(mit javac), um die GhidraWorker-Skripte zu kompilieren."
            )

    _status_cache["key"] = key
    _status_cache["status"] = st
    return st


def invalidate_cache() -> None:
    _status_cache.clear()


def ghidra_env_vars(settings: config.Settings | None = None) -> dict[str, str]:
    """Environment for launching Ghidra so that it picks the configured JDK non-interactively."""
    settings = settings or config.load_settings()
    env = os.environ.copy()
    java = find_java(settings)
    if java is not None:
        home = java.resolve().parent.parent
        env["JAVA_HOME"] = str(home)
        env["PATH"] = str(home / "bin") + os.pathsep + env.get("PATH", "")
    return env


# ---------------------------------------------------------------------------- installation


class Installer:
    """Downloads the latest official Ghidra release (built from the GitHub repo) into tools/."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.state = {"running": False, "message": "", "progress": 0.0, "error": None}
        self._thread: threading.Thread | None = None

    def status(self) -> dict:
        with self.lock:
            return dict(self.state)

    def _set(self, **kw) -> None:
        with self.lock:
            self.state.update(kw)

    def start(self) -> bool:
        with self.lock:
            if self.state["running"]:
                return False
            self.state.update(running=True, message="Starte…", progress=0.0, error=None)
        self._thread = threading.Thread(target=self._run, daemon=True, name="ghidra-install")
        self._thread.start()
        return True

    def _run(self) -> None:
        try:
            path = install_latest(progress=lambda msg, p: self._set(message=msg, progress=p))
            settings = config.load_settings()
            settings.ghidra_dir = str(path)
            config.save_settings(settings)
            invalidate_cache()
            self._set(running=False, message=f"Ghidra installiert: {path}", progress=1.0)
        except Exception as exc:  # noqa: BLE001 - report everything to the UI
            self._set(running=False, error=str(exc), message="Installation fehlgeschlagen")


def latest_release_asset() -> tuple[str, str, int]:
    req = urllib.request.Request(RELEASE_API, headers={"Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.load(resp)
    for asset in data.get("assets", []):
        name = asset.get("name", "")
        if name.startswith("ghidra_") and name.endswith(".zip"):
            return name, asset["browser_download_url"], int(asset.get("size") or 0)
    raise RuntimeError(f"Kein Ghidra-ZIP im Release {data.get('tag_name')} gefunden")


def install_latest(progress=lambda msg, p: None, target: Path | None = None) -> Path:
    target = target or config.tools_dir()
    target.mkdir(parents=True, exist_ok=True)
    progress("Suche aktuelles Ghidra-Release auf GitHub…", 0.0)
    name, url, size = latest_release_asset()
    zip_path = target / name
    if not zip_path.exists() or (size and zip_path.stat().st_size != size):
        tmp = zip_path.with_suffix(".part")
        with urllib.request.urlopen(url, timeout=120) as resp, open(tmp, "wb") as out:
            total = size or int(resp.headers.get("Content-Length") or 0)
            done = 0
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                out.write(chunk)
                done += len(chunk)
                if total:
                    progress(f"Lade {name} … {done >> 20} / {total >> 20} MB", 0.9 * done / total)
        tmp.replace(zip_path)
    progress("Entpacke…", 0.92)
    root = extract_zip(zip_path, target)
    zip_path.unlink(missing_ok=True)
    progress("Fertig", 1.0)
    return root


def extract_zip(zip_path: Path, target: Path) -> Path:
    """Extract a Ghidra release zip (keeping unix exec bits) and return the Ghidra root dir."""
    target = target.resolve()
    roots: set[str] = set()
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            dest = (target / info.filename).resolve()
            if target != dest and target not in dest.parents:
                raise RuntimeError(f"Unsicherer Pfad im Archiv: {info.filename}")
            roots.add(info.filename.split("/", 1)[0])
            if info.is_dir():
                dest.mkdir(parents=True, exist_ok=True)
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(dest, "wb") as out:
                shutil.copyfileobj(src, out)
            mode = (info.external_attr >> 16) & 0o777
            if mode and not IS_WINDOWS:
                os.chmod(dest, mode | stat.S_IRUSR | stat.S_IWUSR)
    for r in sorted(roots):
        if _is_ghidra_dir(target / r):
            return target / r
    raise RuntimeError("Archiv enthält keine Ghidra-Installation")


def clone_source(target: Path | None = None) -> Path:
    """Clone the Ghidra source repository (handy for reading the API / building yourself)."""
    target = target or config.tools_dir() / "ghidra-src"
    if (target / ".git").exists():
        subprocess.run(["git", "-C", str(target), "pull", "--ff-only"], check=True)
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", "--depth", "1", f"https://github.com/{GHIDRA_REPO}", str(target)],
            check=True,
        )
    return target


def open_path(path: Path) -> None:
    """Open a file or folder with the OS default handler (Explorer, Finder, …)."""
    if IS_WINDOWS:
        os.startfile(str(path))  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)])
