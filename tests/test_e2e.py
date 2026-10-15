"""End-to-end test with a real Ghidra installation.

Runs only when Ghidra is available (GHIDRA_INSTALL_DIR) and a MinGW cross compiler can build
the small Windows test program in tests/fixtures/hello.c.
"""

import os
import shutil
import subprocess
import time

import pytest
from fastapi.testclient import TestClient

from conftest import FIXTURES
from ghidraworker import ghidra_env
from ghidraworker.app import create_app

MINGW = shutil.which("x86_64-w64-mingw32-gcc")
GHIDRA = os.environ.get("GHIDRA_INSTALL_DIR")

pytestmark = pytest.mark.skipif(
    not (GHIDRA and MINGW), reason="needs GHIDRA_INSTALL_DIR and x86_64-w64-mingw32-gcc"
)


@pytest.fixture(scope="module")
def hello_exe(tmp_path_factory):
    out = tmp_path_factory.mktemp("bin") / "hello.exe"
    subprocess.run([MINGW, "-O1", "-s", "-o", str(out), str(FIXTURES / "hello.c"), "-luser32"], check=True)
    return out


def wait_done(client, pid, timeout=600):
    end = time.time() + timeout
    while time.time() < end:
        meta = client.get(f"/api/projects/{pid}").json()
        if meta["status"] in ("done", "failed", "cancelled"):
            return meta
        time.sleep(1)
    raise TimeoutError


def test_full_pipeline(store, hello_exe, monkeypatch):
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", GHIDRA)
    ghidra_env.invalidate_cache()
    with TestClient(create_app(store)) as client:
        with open(hello_exe, "rb") as f:
            meta = client.post("/api/projects", files={"file": ("hello.exe", f)}, data={"autostart": "true"}).json()
        pid = meta["id"]
        meta = wait_done(client, pid)
        assert meta["status"] == "done", meta["error"]
        assert meta["summary"]["functions"] > 20

        funcs = client.get(f"/api/projects/{pid}/data/functions").json()
        main = next(f for f in funcs if "MessageBoxA" in " ".join(f["externalCalls"]) or
                    "MessageBoxA" in client.get(f"/api/projects/{pid}/functions/{f['address']}").json()["code"])
        client.put(f"/api/projects/{pid}/functions/{main['address']}", json={"newName": "app_main", "status": "done"})

        # push the rename into Ghidra and re-export
        client.post(f"/api/projects/{pid}/jobs/sync")
        meta = wait_done(client, pid)
        assert meta["status"] == "done", meta["error"]
        renamed = {f["address"]: f for f in client.get(f"/api/projects/{pid}/data/functions").json()}
        assert renamed[main["address"]]["name"] == "app_main"

        files = [x["path"] for x in client.get(f"/api/projects/{pid}/rebuild").json()["files"]]
        assert f"src/functions/{main['file']}_app_main.c" in files

        # the generated scaffold compiles (linking may still miss not yet ported callees)
        root = store.rebuild_dir(pid)
        src = root / "src" / "functions" / f"{main['file']}_app_main.c"
        r = subprocess.run([MINGW, "-std=c11", "-fsyntax-only", "-w", "-I", str(root / "include"), str(src)],
                           capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        r = subprocess.run([MINGW, "-std=c11", "-c", "-w", "-o", os.devnull, str(root / "src" / "gw_data.c")],
                           capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
