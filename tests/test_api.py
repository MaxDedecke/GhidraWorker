import io
import zipfile

import pytest
from fastapi.testclient import TestClient

from conftest import make_pe, write_fake_analysis
from ghidraworker.app import create_app


@pytest.fixture
def client(store):
    app = create_app(store, start_workers=False)
    with TestClient(app) as c:
        c.store = store
        yield c


def upload(client, name="prog.exe"):
    r = client.post("/api/projects", files={"file": (name, make_pe(), "application/octet-stream")},
                    data={"autostart": "false"})
    assert r.status_code == 200, r.text
    return r.json()


def test_index_and_static(client):
    assert "GhidraWorker" in client.get("/").text
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/fonts/Geist-Variable.woff2").status_code == 200


def test_status_reports_missing_ghidra(client):
    env = client.get("/api/status").json()["environment"]
    assert env["ready"] is False
    assert any("Ghidra" in p for p in env["problems"])


def test_project_lifecycle(client):
    meta = upload(client)
    pid = meta["id"]
    assert meta["status"] == "new"
    assert client.get("/api/projects").json()[0]["id"] == pid
    r = client.patch(f"/api/projects/{pid}", json={"name": "Neu", "notes": "hallo"})
    assert r.json()["name"] == "Neu" and r.json()["notes"] == "hallo"
    assert client.get(f"/api/projects/{pid}/data/functions").json() == []
    assert client.get(f"/api/projects/{pid}/data/strings").status_code == 404
    assert client.post(f"/api/projects/{pid}/jobs/export").status_code == 409
    assert client.post(f"/api/projects/{pid}/jobs/nope").status_code == 404
    assert client.get(f"/api/projects/{pid}/download/binary").content == make_pe()
    assert client.delete(f"/api/projects/{pid}").json() == {"ok": True}
    assert client.get(f"/api/projects/{pid}").status_code == 404


def test_invalid_project_id(client):
    assert client.get("/api/projects/..%2F..%2Fetc").status_code == 404
    assert client.get("/api/projects/UPPER").status_code == 404


def test_functions_and_rebuild_api(client):
    pid = upload(client)["id"]
    write_fake_analysis(client.store, pid)

    funcs = client.get(f"/api/projects/{pid}/data/functions").json()
    assert len(funcs) == 3
    f = client.get(f"/api/projects/{pid}/functions/140001100").json()
    assert "FUN_140001000(3);" in f["code"]
    assert f["strings"][0]["value"] == "hello"
    assert "RET" in f["asm"]
    assert client.get(f"/api/projects/{pid}/functions/deadbeef").status_code == 404

    r = client.put(f"/api/projects/{pid}/functions/140001000", json={"status": "done", "newName": "calc"})
    assert r.json()["displayName"] == "calc"
    assert client.put(f"/api/projects/{pid}/functions/140001000", json={"status": "x"}).status_code == 400

    r = client.post(f"/api/projects/{pid}/functions/bulk", json={"addresses": ["140001100"], "status": "progress"})
    assert r.json() == {"updated": 1}
    summary = client.get(f"/api/projects/{pid}").json()["summary"]
    assert summary["counts"]["done"] == 1 and summary["counts"]["progress"] == 1

    res = client.post(f"/api/projects/{pid}/rebuild").json()
    assert res["sources"] == 1
    files = [x["path"] for x in client.get(f"/api/projects/{pid}/rebuild").json()["files"]]
    assert "src/functions/140001000_calc.c" in files
    text = client.get(f"/api/projects/{pid}/rebuild/file", params={"path": "src/functions/140001000_calc.c"}).text
    assert "int calc(int param_1)" in text
    assert client.get(f"/api/projects/{pid}/rebuild/file", params={"path": "../project.json"}).status_code == 400

    z = zipfile.ZipFile(io.BytesIO(client.get(f"/api/projects/{pid}/download/rebuild").content))
    assert f"{pid}-rebuild/CMakeLists.txt" in z.namelist()
    assert "typedef" in client.get(f"/api/projects/{pid}/types").text


def test_settings_api(client):
    r = client.put("/api/settings", json={"max_cpu": 2, "auto_start": False})
    assert r.json()["settings"]["max_cpu"] == 2
    assert client.get("/api/settings").json()["auto_start"] is False
