import io
import json
import zipfile
from pathlib import Path

import pytest

from conftest import make_pe
from ghidraworker import config, ghidra_env, rebuild
from ghidraworker.jobs import JobRunner, _ProgressTracker
from ghidraworker.pe import PEImage, read_pe_info
from ghidraworker.projects import ProjectError, ProjectStore


# ------------------------------------------------------------------ PE


def test_read_pe_info_console_x64(tmp_path):
    p = tmp_path / "a.exe"
    p.write_bytes(make_pe(subsystem=3))
    info = read_pe_info(p)
    assert info["machine"] == "x64"
    assert info["bits"] == 64
    assert info["subsystem"] == "console"
    assert info["dll"] is False


def test_read_pe_info_gui_dll_x86(tmp_path):
    p = tmp_path / "a.dll"
    p.write_bytes(make_pe(subsystem=2, is64=False, dll=True))
    info = read_pe_info(p)
    assert (info["machine"], info["bits"], info["subsystem"], info["dll"]) == ("x86", 32, "windows", True)


def test_read_pe_info_not_pe(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"\x7fELF" + b"\0" * 100)
    assert read_pe_info(p) is None


def test_pe_image_reads_section_data(tmp_path):
    p = tmp_path / "a.exe"
    p.write_bytes(make_pe(data=bytes(range(32))))
    img = PEImage(p)
    assert img.image_base == 0x140000000
    assert img.read(0x140001004, 4) == bytes([4, 5, 6, 7])
    assert img.read(0x140001000 + 30, 8) is None  # runs past the raw data


# ------------------------------------------------------------------ project store


def test_create_and_list(store, project):
    assert project["binary"]["pe"]["machine"] == "x64"
    assert [p["id"] for p in store.list()] == [project["id"]]
    assert store.binary_path(project["id"]).exists()


def test_create_rejects_empty_file(store):
    with pytest.raises(ProjectError):
        store.create("empty.exe", io.BytesIO(b""))


def test_filename_is_sanitized(store):
    meta = store.create("..\\..\\evil name?.exe", io.BytesIO(b"MZ"))
    assert meta["binary"]["filename"] == "evil name_.exe"
    assert store.binary_path(meta["id"]).parent.name == "input"


def test_functions_default_status_and_updates(store, project):
    pid = project["id"]
    funcs = {f["address"]: f for f in store.functions(pid)}
    assert funcs["140001000"]["status"] == "todo"
    assert funcs["140001200"]["status"] == "skip"  # thunk
    store.update_function(pid, "140001000", {"status": "done", "newName": "double_it", "notes": "x2"})
    f = {f["address"]: f for f in store.functions(pid)}["140001000"]
    assert (f["status"], f["displayName"], f["notes"]) == ("done", "double_it", "x2")
    with pytest.raises(ProjectError):
        store.update_function(pid, "140001000", {"status": "bogus"})
    with pytest.raises(ProjectError):
        store.update_function(pid, "140001000", {"newName": "not valid!"})


def test_summary(store, project):
    pid = project["id"]
    store.update_function(pid, "140001000", {"status": "done", "newName": "a"})
    s = store.summary(pid)
    assert s["relevant"] == 2
    assert s["counts"]["done"] == 1
    assert s["progress"] == 0.5
    assert s["pendingRenames"] == 1


# ------------------------------------------------------------------ rebuild scaffold


def test_generate_scaffold(store, project):
    pid = project["id"]
    store.update_function(pid, "140001000", {"status": "done", "newName": "double_it"})
    res = rebuild.generate(store, pid)
    root = store.rebuild_dir(pid)
    assert res["sources"] == 1
    for rel in ("CMakeLists.txt", "PLAN.md", "src/main.c", "src/gw_data.c", "include/gw_rebuild.h",
                "include/gw_types.h", "include/gw_imports.h", "include/gw_globals.h", "include/gw_functions.h"):
        assert (root / rel).exists(), rel
    # renamed function file + rename applied in the callers
    fn = root / "src/functions/140001000_double_it.c"
    assert "int double_it(int param_1)" in fn.read_text()
    caller = (root / "src/functions/140001100_FUN_140001100.c").read_text()
    assert "double_it(3);" in caller
    assert not (root / "src/functions/140001200_Sleep.c").exists()  # thunk skipped
    sources = (root / "cmake/gw_sources.cmake").read_text()
    assert "140001000_double_it.c" in sources and "140001100" not in sources
    assert "set(GW_LIBRARIES kernel32)" in (root / "cmake/gw_libraries.cmake").read_text()
    protos = (root / "include/gw_functions.h").read_text()
    assert "int double_it(int param_1);" in protos


def test_globals_and_data(store, project):
    pid = project["id"]
    rebuild.generate(store, pid)
    root = store.rebuild_dir(pid)
    globals_h = (root / "include/gw_globals.h").read_text()
    assert "extern int DAT_140001010;" in globals_h
    assert "extern undefined weird[12];" in globals_h  # unknown type -> byte array
    assert "IMAGE_DOS_HEADER" not in globals_h  # header block skipped
    data = (root / "src/gw_data.c").read_text()
    # initial bytes of DAT_140001010 come from the .data section of the binary (bytes 0x11..0x14)
    assert "unsigned char DAT_140001010[4] = {" in data
    assert "0x11, 0x12, 0x13, 0x14," in data


def test_regenerate_keeps_user_edits(store, project):
    pid = project["id"]
    rebuild.generate(store, pid)
    root = store.rebuild_dir(pid)
    f = root / "src/functions/140001000_FUN_140001000.c"
    f.write_text("/* my cleaned up version */\n")
    cm = root / "CMakeLists.txt"
    cm.write_text(cm.read_text() + "\n# mine\n")
    store.update_function(pid, "140001000", {"newName": "renamed_later"})
    res = rebuild.generate(store, pid)
    assert f.read_text() == "/* my cleaned up version */\n"
    assert "# mine" in cm.read_text()
    # the edited file stays under its old name (no duplicate under the new name) and is reported
    assert not (root / "src/functions/140001000_renamed_later.c").exists()
    assert res["kept"] == ["src/functions/140001000_FUN_140001000.c"]
    assert "140001000_FUN_140001000.c" in (root / "PLAN.md").read_text()


def test_rename_moves_pristine_file(store, project):
    pid = project["id"]
    rebuild.generate(store, pid)
    store.update_function(pid, "140001000", {"newName": "better"})
    rebuild.generate(store, pid)
    root = store.rebuild_dir(pid)
    assert not (root / "src/functions/140001000_FUN_140001000.c").exists()
    assert (root / "src/functions/140001000_better.c").exists()


def test_tree_and_zip_skip_build_dir(store, project):
    pid = project["id"]
    rebuild.generate(store, pid)
    root = store.rebuild_dir(pid)
    (root / "build").mkdir()
    (root / "build" / "junk.o").write_bytes(b"x")
    paths = [f["path"] for f in rebuild.tree(root)]
    assert "PLAN.md" in paths and not any(p.startswith("build/") for p in paths)
    assert rebuild.MANIFEST not in paths
    names = zipfile.ZipFile(io.BytesIO(rebuild.zip_dir(root, "x"))).namelist()
    assert "x/PLAN.md" in names and not any("/build/" in n for n in names)


def test_safe_child(tmp_path):
    assert rebuild.safe_child(tmp_path, "a/b.c") == (tmp_path / "a/b.c").resolve()
    with pytest.raises(ValueError):
        rebuild.safe_child(tmp_path, "../etc/passwd")


def test_known_type_names():
    names = rebuild.known_type_names(
        "typedef struct _A A, *PA;\nstruct _A {\n int x;\n};\ntypedef int (*CB)(int);\nenum Color {\n};\n"
    )
    assert {"A", "PA", "_A", "CB", "Color", "undefined8", "code"} <= names


def test_sanitize_types():
    out = rebuild._sanitize_types("typedef unsigned char    bool;\ntypedef unsigned long DWORD;\n")
    assert "/* typedef unsigned char    bool;" in out
    assert "typedef unsigned long DWORD;" in out.splitlines()[1]


# ------------------------------------------------------------------ ghidra env


def _fake_ghidra(root: Path) -> Path:
    (root / "support").mkdir(parents=True)
    (root / "support" / "analyzeHeadless").write_text("#!/bin/sh\n")
    (root / "Ghidra").mkdir()
    (root / "Ghidra" / "application.properties").write_text(
        "application.version=12.1.4\napplication.java.min=21\n"
    )
    return root


def test_find_ghidra_via_settings(workspace, tmp_path):
    g = _fake_ghidra(tmp_path / "ghidra_x")
    assert ghidra_env.find_ghidra() is None
    config.update_settings({"ghidra_dir": str(g)})
    assert ghidra_env.find_ghidra() == g.resolve()
    assert ghidra_env.ghidra_info(g)["version"] == "12.1.4"


def test_extract_zip(tmp_path):
    z = tmp_path / "g.zip"
    with zipfile.ZipFile(z, "w") as zf:
        info = zipfile.ZipInfo("ghidra_1_PUBLIC/support/analyzeHeadless")
        info.external_attr = 0o755 << 16
        zf.writestr(info, "#!/bin/sh\n")
        zf.writestr("ghidra_1_PUBLIC/Ghidra/application.properties", "application.version=1\n")
    root = ghidra_env.extract_zip(z, tmp_path / "out")
    assert root.name == "ghidra_1_PUBLIC"
    if not ghidra_env.IS_WINDOWS:
        assert (root / "support" / "analyzeHeadless").stat().st_mode & 0o111


def test_extract_zip_rejects_traversal(tmp_path):
    z = tmp_path / "bad.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("../evil.txt", "x")
    with pytest.raises(RuntimeError):
        ghidra_env.extract_zip(z, tmp_path / "out")


def test_settings_roundtrip(workspace):
    s = config.update_settings({"max_parallel_jobs": 0, "thorough_analysis": False, "max_memory": " 8G "})
    assert s.max_parallel_jobs == 1 and s.thorough_analysis is False and s.max_memory == "8G"
    assert config.load_settings().max_memory == "8G"


# ------------------------------------------------------------------ jobs


def test_build_command(store, project, tmp_path):
    g = _fake_ghidra(tmp_path / "ghidra")
    config.update_settings({"ghidra_dir": str(g), "analysis_timeout": 600, "max_cpu": 4})
    runner = JobRunner(store)
    cmd = runner.build_command(project["id"], "analyze")
    assert cmd[0].endswith("analyzeHeadless" + (".bat" if ghidra_env.IS_WINDOWS else ""))
    assert "-import" in cmd and "-overwrite" in cmd
    assert cmd[cmd.index("-preScript") + 1:cmd.index("-preScript") + 3] == ["GhidraWorkerPrepare.java", "thorough"]
    assert cmd[cmd.index("-analysisTimeoutPerFile") + 1] == "600"
    assert cmd[cmd.index("-max-cpu") + 1] == "4"
    assert "GhidraWorkerExport.java" in cmd

    store.update_function(project["id"], "140001000", {"newName": "foo"})
    cmd = runner.build_command(project["id"], "sync")
    assert "-process" in cmd and "-noanalysis" in cmd and "-import" not in cmd
    renames = json.loads((store.path(project["id"]) / "logs" / "renames.json").read_text())
    assert renames == {"140001000": "foo"}


def test_submit_requires_ghidra_project(store, project):
    runner = JobRunner(store)
    with pytest.raises(RuntimeError):
        runner.submit(project["id"], "export")
    meta = runner.submit(project["id"], "analyze")
    assert meta["status"] == "queued"
    with pytest.raises(RuntimeError):
        runner.submit(project["id"], "analyze")
    assert runner.cancel(project["id"]) is True
    assert store.get(project["id"])["status"] == "cancelled"


def test_progress_tracker_is_monotonic(store, project):
    pid = project["id"]
    t = _ProgressTracker(store, pid)
    seen = []
    for line in ["INFO  IMPORTING: file", "INFO  ANALYZING all memory and code", "GW_PROGRESS export 6 8",
                 "GW_PROGRESS decompile 50 100", "GW_PROGRESS export 8 8"]:
        t.feed(line)
        seen.append(store.get(pid)["job"]["progress"])
    assert seen == sorted(seen)
    assert store.get(pid)["job"]["message"].startswith("Dekompiliere")
