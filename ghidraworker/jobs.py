"""Background job queue running Ghidra headless."""

from __future__ import annotations

import json
import os
import queue
import re
import shutil
import signal
import subprocess
import threading
import time
import traceback
from dataclasses import dataclass
from pathlib import Path

from . import config, ghidra_env, rebuild
from .projects import GHIDRA_PROJECT_NAME, NotFound, ProjectStore

JOB_TYPES = {
    # full import + auto-analysis + export (discards an existing Ghidra project)
    "analyze": "Analyse",
    # re-export from the existing Ghidra project, e.g. after working in the Ghidra GUI
    "export": "Export aktualisieren",
    # push renames from GhidraWorker into Ghidra, then re-export
    "sync": "Umbenennungen nach Ghidra übertragen",
}

# progress ranges (0..1) for the phases of a job
_PHASES = {
    "start": (0.0, 0.02),
    "import": (0.02, 0.06),
    "analysis": (0.06, 0.55),
    "export": (0.55, 0.62),
    "disassembly": (0.62, 0.68),
    "decompile": (0.68, 0.97),
    "rebuild": (0.97, 1.0),
}

_PHASE_LABELS = {
    "start": "Ghidra startet",
    "import": "Importiere Binärdatei",
    "analysis": "Auto-Analyse läuft",
    "export": "Exportiere Daten",
    "disassembly": "Exportiere Disassembly",
    "decompile": "Dekompiliere Funktionen",
    "rebuild": "Erzeuge Rebuild-Gerüst",
}

_PROGRESS_RE = re.compile(r"GW_PROGRESS (\w+) (\d+) (\d+)")


@dataclass
class Job:
    pid: str
    type: str
    queued: float


class JobRunner:
    def __init__(self, store: ProjectStore) -> None:
        self.store = store
        self.queue: queue.Queue[Job] = queue.Queue()
        self.lock = threading.Lock()
        self.active: dict[str, subprocess.Popen | None] = {}
        self.cancelled: set[str] = set()
        self.workers: list[threading.Thread] = []
        self._stop = threading.Event()

    # ------------------------------------------------------------------ lifecycle

    def start(self) -> None:
        self._recover()
        n = max(1, config.load_settings().max_parallel_jobs)
        for i in range(n):
            t = threading.Thread(target=self._worker, daemon=True, name=f"gw-worker-{i}")
            t.start()
            self.workers.append(t)

    def stop(self) -> None:
        self._stop.set()
        with self.lock:
            pids = list(self.active)
        for pid in pids:
            self.cancel(pid)

    def _recover(self) -> None:
        """Re-queue jobs that were queued and flag jobs interrupted by a server restart."""
        for meta in self.store.list():
            if meta.get("status") == "queued" and meta.get("job"):
                self.queue.put(Job(meta["id"], meta["job"].get("type", "analyze"), time.time()))
            elif meta.get("status") == "running":
                self.store.update(
                    meta["id"],
                    status="failed",
                    error="Abgebrochen: GhidraWorker wurde während der Analyse beendet.",
                )

    # ------------------------------------------------------------------ public API

    def submit(self, pid: str, job_type: str = "analyze") -> dict:
        if job_type not in JOB_TYPES:
            raise ValueError(job_type)
        meta = self.store.get(pid)
        if meta.get("status") in ("queued", "running"):
            raise RuntimeError("Für dieses Projekt läuft bereits ein Job.")
        if job_type != "analyze" and not self._ghidra_project_exists(pid):
            raise RuntimeError("Es gibt noch kein Ghidra-Projekt – bitte zuerst analysieren.")
        if job_type == "sync":
            renames = self._renames(pid)
            if not renames:
                raise RuntimeError("Es gibt keine Umbenennungen, die übertragen werden müssten.")
        with self.lock:
            self.cancelled.discard(pid)
        self.store.update(
            pid,
            status="queued",
            error=None,
            job={
                "type": job_type,
                "label": JOB_TYPES[job_type],
                "phase": "queued",
                "message": "Wartet auf freien Worker…",
                "progress": 0.0,
                "queued": time.time(),
                "started": None,
                "finished": None,
            },
        )
        self.queue.put(Job(pid, job_type, time.time()))
        return self.store.get(pid)

    def cancel(self, pid: str) -> bool:
        with self.lock:
            self.cancelled.add(pid)
            proc = self.active.get(pid)
        if proc is not None and proc.poll() is None:
            _kill_tree(proc)
            return True
        try:
            meta = self.store.get(pid)
        except NotFound:
            return False
        if meta.get("status") == "queued":
            self.store.update(pid, status="cancelled", error="Vom Benutzer abgebrochen.")
            return True
        return False

    def running(self) -> list[str]:
        with self.lock:
            return list(self.active)

    # ------------------------------------------------------------------ worker

    def _worker(self) -> None:
        while not self._stop.is_set():
            try:
                job = self.queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._run_job(job)
            except NotFound:
                pass  # project deleted while queued
            except Exception as exc:  # noqa: BLE001
                traceback.print_exc()
                try:
                    self.store.update(job.pid, status="failed", error=f"Interner Fehler: {exc}")
                except NotFound:
                    pass
            finally:
                with self.lock:
                    self.active.pop(job.pid, None)
                self.queue.task_done()

    def _ghidra_project_exists(self, pid: str) -> bool:
        return (self.store.ghidra_dir(pid) / f"{GHIDRA_PROJECT_NAME}.gpr").exists()

    def _renames(self, pid: str) -> dict[str, str]:
        funcs = {f["address"]: f["name"] for f in self.store.functions(pid)}
        out = {}
        for addr, entry in self.store.state(pid)["functions"].items():
            new = entry.get("newName")
            if new and funcs.get(addr) != new:
                out[addr] = new
        return out

    def build_command(self, pid: str, job_type: str) -> list[str]:
        settings = config.load_settings()
        gdir = ghidra_env.find_ghidra(settings)
        if gdir is None:
            raise RuntimeError("Ghidra ist nicht installiert/konfiguriert (siehe Einstellungen).")
        meta = self.store.get(pid)
        pdir = self.store.path(pid)
        cmd = [
            str(ghidra_env.headless_script(gdir)),
            str(self.store.ghidra_dir(pid)),
            GHIDRA_PROJECT_NAME,
        ]
        if job_type == "analyze":
            cmd += ["-import", str(self.store.binary_path(pid)), "-overwrite"]
        else:
            cmd += ["-process", meta["binary"]["filename"], "-noanalysis"]
        cmd += ["-scriptPath", str(config.SCRIPTS_DIR)]
        if job_type == "analyze":
            cmd += ["-preScript", "GhidraWorkerPrepare.java"]
            if settings.thorough_analysis:
                cmd.append("thorough")
            if settings.analysis_timeout:
                cmd += ["-analysisTimeoutPerFile", str(settings.analysis_timeout)]
        if job_type == "sync":
            renames_file = pdir / "logs" / "renames.json"
            renames_file.write_text(json.dumps(self._renames(pid)), encoding="utf-8")
            cmd += ["-postScript", "GhidraWorkerApplyRenames.java", str(renames_file)]
        cmd += ["-postScript", "GhidraWorkerExport.java", str(pdir / "analysis.new")]
        if settings.max_cpu:
            cmd += ["-max-cpu", str(settings.max_cpu)]
        return cmd

    def _run_job(self, job: Job) -> None:
        pid = job.pid
        with self.lock:
            if pid in self.cancelled:
                self.cancelled.discard(pid)
                return
            self.active[pid] = None
        meta = self.store.get(pid)
        if meta.get("status") != "queued":
            return

        settings = config.load_settings()
        env_status = ghidra_env.check_environment(settings, use_cache=False)
        if not env_status.ready:
            self.store.update(pid, status="failed", error=" ".join(env_status.problems))
            return

        pdir = self.store.path(pid)
        staging = pdir / "analysis.new"
        shutil.rmtree(staging, ignore_errors=True)
        if job.type == "analyze":
            # fresh import: start with an empty Ghidra project folder
            gproj = self.store.ghidra_dir(pid)
            shutil.rmtree(gproj, ignore_errors=True)
            gproj.mkdir(parents=True, exist_ok=True)

        cmd = self.build_command(pid, job.type)
        log_path = self.store.log_path(pid)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        started = time.time()
        self.store.update(pid, status="running", error=None)
        self.store.update_job(
            pid, phase="start", message=_PHASE_LABELS["start"], progress=0.0, started=started
        )

        env = ghidra_env.ghidra_env_vars(settings)
        if settings.max_memory:
            env["MAXMEM"] = settings.max_memory
        popen_kw: dict = {}
        if ghidra_env.IS_WINDOWS:
            popen_kw["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
        else:
            popen_kw["start_new_session"] = True

        with open(log_path, "w", encoding="utf-8", errors="replace") as log:
            log.write(f"# GhidraWorker {JOB_TYPES[job.type]} – {time.ctime(started)}\n")
            log.write("# " + " ".join(_quote(c) for c in cmd) + "\n\n")
            log.flush()
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                cwd=str(pdir),
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                **popen_kw,
            )
            with self.lock:
                self.active[pid] = proc
                cancelled = pid in self.cancelled
            if cancelled:
                _kill_tree(proc)
            tracker = _ProgressTracker(self.store, pid)
            ticker_stop = threading.Event()

            def tick() -> None:
                # keep the progress bar moving while Ghidra analyses silently
                while not ticker_stop.wait(2.0):
                    tracker.tick()

            ticker = threading.Thread(target=tick, daemon=True)
            ticker.start()
            assert proc.stdout is not None
            try:
                for line in proc.stdout:
                    log.write(line)
                    log.flush()
                    tracker.feed(line)
                rc = proc.wait()
            finally:
                ticker_stop.set()
            log.write(f"\n# Ghidra beendet mit Code {rc} nach {time.time() - started:.0f}s\n")

        with self.lock:
            was_cancelled = pid in self.cancelled
            self.cancelled.discard(pid)

        if was_cancelled:
            shutil.rmtree(staging, ignore_errors=True)
            self.store.update(pid, status="cancelled", error="Vom Benutzer abgebrochen.")
            self.store.update_job(pid, finished=time.time(), message="Abgebrochen")
            return

        if rc != 0 or not (staging / "functions.json").exists():
            shutil.rmtree(staging, ignore_errors=True)
            self.store.update(pid, status="failed", error=_diagnose(log_path, rc))
            self.store.update_job(pid, finished=time.time(), message="Fehlgeschlagen")
            return

        # swap in the new export atomically-ish
        final = self.store.analysis_dir(pid)
        old = pdir / "analysis.old"
        shutil.rmtree(old, ignore_errors=True)
        if final.exists():
            final.rename(old)
        staging.rename(final)
        shutil.rmtree(old, ignore_errors=True)

        self.store.update_job(pid, phase="rebuild", message=_PHASE_LABELS["rebuild"], progress=0.97)
        try:
            rebuild.generate(self.store, pid)
        except Exception as exc:  # noqa: BLE001 - analysis itself succeeded
            traceback.print_exc()
            with open(log_path, "a", encoding="utf-8") as log:
                log.write(f"\n# Rebuild-Gerüst konnte nicht erzeugt werden: {exc}\n")

        finished = time.time()
        self.store.update(pid, status="done", error=None, analyzed=finished)
        self.store.update_job(
            pid,
            phase="done",
            progress=1.0,
            finished=finished,
            message=f"Fertig in {_fmt_duration(finished - started)}",
        )


class _ProgressTracker:
    """Turns Ghidra's log output into a progress value for the UI."""

    def __init__(self, store: ProjectStore, pid: str) -> None:
        self.store = store
        self.pid = pid
        self.phase = "start"
        self.fraction = 0.0
        self.last_write = 0.0
        self.analysis_started = 0.0
        self.progress = 0.0
        self.lock = threading.Lock()

    def tick(self) -> None:
        with self.lock:
            if self.phase == "analysis" and self.analysis_started:
                self._feed_locked("")

    def feed(self, line: str) -> None:
        with self.lock:
            self._feed_locked(line)

    def _feed_locked(self, line: str) -> None:
        phase, fraction, detail = self.phase, self.fraction, None
        m = _PROGRESS_RE.search(line)
        if m:
            stage, done, total = m.group(1), int(m.group(2)), int(m.group(3))
            phase = stage if stage in _PHASES else "export"
            fraction = done / total if total else 1.0
            if stage in ("decompile", "disassembly"):
                detail = f"{done} / {total}"
        elif "IMPORTING:" in line:
            phase, fraction = "import", 0.0
        elif "ANALYZING all memory and code" in line:
            phase, fraction = "analysis", 0.0
            self.analysis_started = time.time()
        elif "REPORT: Analysis succeeded" in line or "ANALYSIS TIMING" in line:
            phase, fraction = "analysis", 1.0
        elif "Unable to lock project" in line or "LockException" in line:
            detail = "Projekt ist gesperrt – ist es noch in der Ghidra-GUI geöffnet?"
        else:
            if self.phase == "analysis" and self.analysis_started:
                # analysis gives no progress -> asymptotic approach based on elapsed time
                elapsed = time.time() - self.analysis_started
                fraction = min(0.95, elapsed / (elapsed + 60.0))
            else:
                return
        now = time.time()
        changed_phase = phase != self.phase
        self.phase, self.fraction = phase, fraction
        if not changed_phase and not detail and now - self.last_write < 0.5:
            return
        self.last_write = now
        lo, hi = _PHASES[phase]
        value = lo + (hi - lo) * fraction
        if value < self.progress:
            # export steps interleave with the long phases: never move the bar (or the
            # message) backwards, just keep showing the furthest phase reached
            return
        self.progress = value
        message = _PHASE_LABELS[phase] + (f" ({detail})" if detail else "")
        self.store.update_job(
            self.pid, phase=phase, progress=round(self.progress, 4), message=message
        )


def _diagnose(log_path: Path, rc: int) -> str:
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        text = ""
    hints = [
        ("Unable to lock project", "Das Ghidra-Projekt ist gesperrt – schließe es in der Ghidra-GUI."),
        ("No load spec found", "Ghidra erkennt das Dateiformat nicht."),
        ("Unable to prompt user for JDK", "Ghidra findet kein JDK – JAVA_HOME in den Einstellungen setzen."),
        ("UnsupportedClassVersionError", "Die Java-Version ist zu alt für diese Ghidra-Version."),
        ("OutOfMemoryError", "Zu wenig Arbeitsspeicher – in den Einstellungen 'Max. Speicher' erhöhen."),
        ("Script not found", "GhidraWorker-Skript nicht gefunden."),
        ("ERROR REPORT SCRIPT ERROR", "Das Export-Skript ist fehlgeschlagen (Details im Log)."),
    ]
    for needle, hint in hints:
        if needle in text:
            return f"{hint} (Exit-Code {rc})"
    errors = [l.strip() for l in text.splitlines() if l.startswith("ERROR")]
    tail = errors[-1] if errors else ""
    return f"Ghidra ist mit Exit-Code {rc} beendet worden. {tail}".strip()


def _kill_tree(proc: subprocess.Popen) -> None:
    try:
        if ghidra_env.IS_WINDOWS:
            subprocess.run(
                ["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                capture_output=True,
                check=False,
            )
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (OSError, ProcessLookupError):
        try:
            proc.kill()
        except OSError:
            pass


def _quote(s: str) -> str:
    return f'"{s}"' if " " in s else s


def _fmt_duration(secs: float) -> str:
    secs = int(secs)
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m {secs % 60}s"
    return f"{secs // 3600}h {secs % 3600 // 60}m"
