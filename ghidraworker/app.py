"""FastAPI application: REST API + the single page UI."""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import __version__, config, ghidra_env, rebuild
from .jobs import JOB_TYPES, JobRunner
from .projects import NotFound, ProjectError, ProjectStore


class FunctionUpdate(BaseModel):
    status: str | None = None
    notes: str | None = None
    newName: str | None = None


class BulkUpdate(BaseModel):
    addresses: list[str]
    status: str


class ProjectUpdate(BaseModel):
    name: str | None = None
    notes: str | None = None
    tags: list[str] | None = None


def create_app(store: ProjectStore | None = None, start_workers: bool = True) -> FastAPI:
    store = store or ProjectStore()
    runner = JobRunner(store)
    installer = ghidra_env.Installer()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        if start_workers:
            runner.start()
        yield
        runner.stop()

    app = FastAPI(title="GhidraWorker", version=__version__, lifespan=lifespan)
    app.state.store = store
    app.state.runner = runner

    def project_or_404(pid: str) -> dict:
        try:
            return store.get(pid)
        except NotFound:
            raise HTTPException(404, "Projekt nicht gefunden") from None

    def with_summary(meta: dict) -> dict:
        meta = dict(meta)
        try:
            meta["summary"] = store.summary(meta["id"])
        except NotFound:
            meta["summary"] = {}
        return meta

    # ------------------------------------------------------------------ system

    @app.get("/api/status")
    def status():
        settings = config.load_settings()
        env = ghidra_env.check_environment(settings)
        return {
            "version": __version__,
            "workspace": str(config.workspace_dir()),
            "environment": env.as_dict(),
            "installer": installer.status(),
            "running": runner.running(),
        }

    @app.get("/api/settings")
    def get_settings():
        return asdict(config.load_settings())

    @app.put("/api/settings")
    def put_settings(changes: dict):
        settings = config.update_settings(changes)
        ghidra_env.invalidate_cache()
        return {
            "settings": asdict(settings),
            "environment": ghidra_env.check_environment(settings, use_cache=False).as_dict(),
        }

    @app.post("/api/ghidra/install")
    def install_ghidra():
        if not installer.start():
            raise HTTPException(409, "Installation läuft bereits")
        return installer.status()

    @app.post("/api/ghidra/open")
    def open_ghidra():
        gdir = ghidra_env.find_ghidra()
        if not gdir:
            raise HTTPException(400, "Ghidra ist nicht installiert")
        _launch_gui(gdir, None)
        return {"ok": True}

    # ------------------------------------------------------------------ projects

    @app.get("/api/projects")
    def list_projects():
        return [with_summary(m) for m in store.list()]

    @app.post("/api/projects")
    def create_project(
        file: UploadFile = File(...),
        name: str = Form(""),
        autostart: str = Form(""),
    ):
        try:
            meta = store.create(file.filename or "binary.exe", file.file, name or None)
        except ProjectError as exc:
            raise HTTPException(400, str(exc)) from None
        start = autostart.lower() in ("1", "true", "yes") if autostart else config.load_settings().auto_start
        if start:
            meta = runner.submit(meta["id"], "analyze")
        return with_summary(meta)

    @app.get("/api/projects/{pid}")
    def get_project(pid: str):
        return with_summary(project_or_404(pid))

    @app.patch("/api/projects/{pid}")
    def patch_project(pid: str, body: ProjectUpdate):
        project_or_404(pid)
        changes = {k: v for k, v in body.model_dump().items() if v is not None}
        if "name" in changes and not changes["name"].strip():
            raise HTTPException(400, "Name darf nicht leer sein")
        return with_summary(store.update(pid, **changes))

    @app.delete("/api/projects/{pid}")
    def delete_project(pid: str):
        project_or_404(pid)
        runner.cancel(pid)
        if pid in runner.running():
            raise HTTPException(409, "Job wird gerade beendet – bitte gleich nochmal versuchen")
        store.delete(pid)
        return {"ok": True}

    @app.post("/api/projects/{pid}/jobs/{job_type}")
    def start_job(pid: str, job_type: str):
        project_or_404(pid)
        if job_type not in JOB_TYPES:
            raise HTTPException(404, "Unbekannter Job")
        try:
            return with_summary(runner.submit(pid, job_type))
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from None

    @app.post("/api/projects/{pid}/cancel")
    def cancel_job(pid: str):
        project_or_404(pid)
        return {"cancelled": runner.cancel(pid)}

    @app.get("/api/projects/{pid}/log", response_class=PlainTextResponse)
    def get_log(pid: str, tail: int = Query(400, ge=1, le=100000)):
        project_or_404(pid)
        path = store.log_path(pid)
        if not path.exists():
            return ""
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return "\n".join(lines[-tail:])

    # ------------------------------------------------------------------ analysis data

    @app.get("/api/projects/{pid}/data/{kind}")
    def get_data(pid: str, kind: str):
        project_or_404(pid)
        if kind == "functions":
            return store.functions(pid)
        try:
            data = store.analysis(pid, kind)
        except NotFound:
            raise HTTPException(404, "Unbekannter Datentyp") from None
        if data is None:
            raise HTTPException(404, "Noch keine Analyse vorhanden")
        return data

    @app.get("/api/projects/{pid}/types", response_class=PlainTextResponse)
    def get_types(pid: str):
        project_or_404(pid)
        path = store.analysis_dir(pid) / "types.h"
        if not path.exists():
            raise HTTPException(404, "Noch keine Analyse vorhanden")
        return path.read_text(encoding="utf-8", errors="replace")

    def _function(pid: str, address: str) -> dict:
        for f in store.functions(pid):
            if f["address"] == address:
                return f
        raise HTTPException(404, "Funktion nicht gefunden")

    @app.get("/api/projects/{pid}/functions/{address}")
    def get_function(pid: str, address: str):
        project_or_404(pid)
        f = _function(pid, address)
        adir = store.analysis_dir(pid)
        out = dict(f)
        for key, sub, ext in (("code", "decompiled", "c"), ("asm", "disassembly", "asm")):
            p = adir / sub / f"{f['file']}.{ext}"
            out[key] = p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""
        strings = store.analysis(pid, "strings", []) or []
        out["strings"] = [s for s in strings if f["fullName"] in s.get("usedBy", [])][:200]
        return out

    @app.put("/api/projects/{pid}/functions/{address}")
    def put_function(pid: str, address: str, body: FunctionUpdate):
        project_or_404(pid)
        _function(pid, address)
        try:
            store.update_function(pid, address, body.model_dump())
        except ProjectError as exc:
            raise HTTPException(400, str(exc)) from None
        return _function(pid, address)

    @app.post("/api/projects/{pid}/functions/bulk")
    def bulk_functions(pid: str, body: BulkUpdate):
        project_or_404(pid)
        try:
            n = store.bulk_update_functions(pid, body.addresses, body.status)
        except ProjectError as exc:
            raise HTTPException(400, str(exc)) from None
        return {"updated": n}

    # ------------------------------------------------------------------ rebuild

    @app.post("/api/projects/{pid}/rebuild")
    def regenerate(pid: str):
        project_or_404(pid)
        if not store.has_analysis(pid):
            raise HTTPException(409, "Noch keine Analyse vorhanden")
        return rebuild.generate(store, pid)

    @app.get("/api/projects/{pid}/rebuild")
    def rebuild_tree(pid: str):
        project_or_404(pid)
        root = store.rebuild_dir(pid)
        return {"root": str(root), "files": rebuild.tree(root)}

    @app.get("/api/projects/{pid}/rebuild/file", response_class=PlainTextResponse)
    def rebuild_file(pid: str, path: str):
        project_or_404(pid)
        try:
            p = rebuild.safe_child(store.rebuild_dir(pid), path)
        except ValueError:
            raise HTTPException(400, "Ungültiger Pfad") from None
        if not p.is_file():
            raise HTTPException(404, "Datei nicht gefunden")
        return p.read_text(encoding="utf-8", errors="replace")

    @app.get("/api/projects/{pid}/download/{what}")
    def download(pid: str, what: str):
        meta = project_or_404(pid)
        dirs = {
            "rebuild": store.rebuild_dir(pid),
            "analysis": store.analysis_dir(pid),
        }
        if what == "binary":
            return FileResponse(store.binary_path(pid), filename=meta["binary"]["filename"])
        if what not in dirs:
            raise HTTPException(404, "Unbekannter Download")
        data = rebuild.zip_dir(dirs[what], f"{pid}-{what}")
        return Response(
            data,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{pid}-{what}.zip"'},
        )

    @app.post("/api/projects/{pid}/open/{what}")
    def open_local(pid: str, what: str):
        """Open folders / the Ghidra project on the machine running GhidraWorker."""
        project_or_404(pid)
        targets = {
            "folder": store.path(pid),
            "rebuild": store.rebuild_dir(pid),
            "analysis": store.analysis_dir(pid),
        }
        try:
            if what == "ghidra":
                gdir = ghidra_env.find_ghidra()
                if not gdir:
                    raise HTTPException(400, "Ghidra ist nicht installiert")
                gpr = store.ghidra_dir(pid) / "gw.gpr"
                if not gpr.exists():
                    raise HTTPException(409, "Es gibt noch kein Ghidra-Projekt")
                _launch_gui(gdir, gpr)
            elif what in targets:
                ghidra_env.open_path(targets[what])
            else:
                raise HTTPException(404, "Unbekanntes Ziel")
        except OSError as exc:
            raise HTTPException(500, f"Konnte nicht geöffnet werden: {exc}") from None
        return {"ok": True}

    # ------------------------------------------------------------------ UI

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(config.STATIC_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=config.STATIC_DIR), name="static")
    return app


def _launch_gui(gdir: Path, project_file: Path | None) -> None:
    import subprocess

    cmd = [str(ghidra_env.gui_script(gdir))]
    if project_file is not None:
        cmd.append(str(project_file))
    kw: dict = {"env": ghidra_env.ghidra_env_vars(), "stdin": subprocess.DEVNULL}
    if ghidra_env.IS_WINDOWS:
        kw["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
    else:
        kw["start_new_session"] = True
    subprocess.Popen(cmd, **kw)
