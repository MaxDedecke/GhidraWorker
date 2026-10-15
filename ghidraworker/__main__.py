"""Command line entry point: ``python -m ghidraworker [serve|setup-ghidra|status]``."""

from __future__ import annotations

import argparse
import sys
import threading
import webbrowser

from . import __version__, config, ghidra_env


def _serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .app import create_app

    url = f"http://{'localhost' if args.host in ('127.0.0.1', '0.0.0.0') else args.host}:{args.port}/"
    print(f"GhidraWorker {__version__} – Workspace: {config.workspace_dir()}")
    env = ghidra_env.check_environment()
    if env.ready:
        print(f"Ghidra {env.ghidra_version}: {env.ghidra_dir}  |  Java {env.java_version}: {env.java}")
    else:
        for p in env.problems:
            print(f"  ! {p}")
    print(f"Oberfläche: {url}")
    if not args.no_browser:
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    uvicorn.run(create_app(), host=args.host, port=args.port, log_level="warning")
    return 0


def _setup(args: argparse.Namespace) -> int:
    if args.source:
        path = ghidra_env.clone_source()
        print(f"Ghidra-Quellcode: {path}")
    if not args.source_only:
        def progress(msg: str, p: float) -> None:
            print(f"\r[{int(p * 100):3d}%] {msg:<70}", end="", flush=True)

        path = ghidra_env.install_latest(progress=progress)
        print()
        settings = config.load_settings()
        settings.ghidra_dir = str(path)
        config.save_settings(settings)
        print(f"Ghidra installiert: {path}")
    return _status(args)


def _status(_args: argparse.Namespace) -> int:
    env = ghidra_env.check_environment(use_cache=False)
    for k, v in env.as_dict().items():
        print(f"{k:15} {v}")
    return 0 if env.ready else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ghidraworker", description="Reverse-Engineering-Verwaltung mit Ghidra")
    sub = parser.add_subparsers(dest="cmd")

    s = sub.add_parser("serve", help="Weboberfläche starten (Standard)")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--no-browser", action="store_true", help="Browser nicht automatisch öffnen")
    s.set_defaults(func=_serve)

    g = sub.add_parser("setup-ghidra", help="Aktuelles Ghidra-Release von GitHub installieren")
    g.add_argument("--source", action="store_true", help="zusätzlich das Ghidra-Repo (Quellcode) klonen")
    g.add_argument("--source-only", action="store_true", help="nur den Quellcode klonen")
    g.set_defaults(func=_setup)

    st = sub.add_parser("status", help="Ghidra/Java-Konfiguration prüfen")
    st.set_defaults(func=_status)

    args = parser.parse_args(argv)
    if not args.cmd:
        args = parser.parse_args(["serve", *(argv or sys.argv[1:])])
    if args.cmd == "setup-ghidra" and args.source_only:
        args.source = True
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
