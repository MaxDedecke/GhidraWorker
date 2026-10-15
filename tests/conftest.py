import io
import json
import struct
from pathlib import Path

import pytest

from ghidraworker.projects import ProjectStore


def make_pe(subsystem: int = 3, is64: bool = True, dll: bool = False, data: bytes = b"") -> bytes:
    """A minimal PE image: headers + one .data section (raw at 0x200, RVA 0x1000)."""
    pe_off = 0x80
    opt_size = 0xF0 if is64 else 0xE0
    buf = bytearray(0x200)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, pe_off)
    buf[pe_off : pe_off + 4] = b"PE\0\0"
    machine = 0x8664 if is64 else 0x14C
    chars = 0x0022 | (0x2000 if dll else 0)
    struct.pack_into("<HHIIIHH", buf, pe_off + 4, machine, 1, 0x60000000, 0, 0, opt_size, chars)
    opt = pe_off + 24
    struct.pack_into("<H", buf, opt, 0x20B if is64 else 0x10B)
    buf[opt + 2] = 14
    buf[opt + 3] = 30
    struct.pack_into("<I", buf, opt + 16, 0x1000)  # entry RVA
    if is64:
        struct.pack_into("<Q", buf, opt + 24, 0x140000000)
    else:
        struct.pack_into("<I", buf, opt + 28, 0x400000)
    struct.pack_into("<H", buf, opt + 0x44, subsystem)
    sec = opt + opt_size
    buf[sec : sec + 8] = b".data\0\0\0"
    raw = data or bytes(range(1, 33))
    struct.pack_into("<IIII", buf, sec + 8, len(raw), 0x1000, len(raw), 0x200)
    return bytes(buf) + raw


FUNCTIONS = [
    {
        "address": "140001000", "file": "140001000", "name": "FUN_140001000", "fullName": "FUN_140001000",
        "namespace": "Global", "signature": "int FUN_140001000(int param_1)",
        "cSignature": "int FUN_140001000(int param_1)", "callingConvention": "__fastcall",
        "returnType": "int", "paramCount": 1, "size": 40, "thunk": False, "thunkTarget": None,
        "thunkTargetExternal": False, "library": False, "nameSource": "DEFAULT", "decompiled": True,
        "decompileError": None, "lines": 6, "callers": ["140001100"], "callees": [], "externalCalls": [],
    },
    {
        "address": "140001100", "file": "140001100", "name": "FUN_140001100", "fullName": "FUN_140001100",
        "namespace": "Global", "signature": "void FUN_140001100(void)",
        "cSignature": "void FUN_140001100(void)", "callingConvention": "__fastcall",
        "returnType": "void", "paramCount": 0, "size": 80, "thunk": False, "thunkTarget": None,
        "thunkTargetExternal": False, "library": False, "nameSource": "DEFAULT", "decompiled": True,
        "decompileError": None, "lines": 8, "callers": [], "callees": ["140001000"],
        "externalCalls": ["KERNEL32.DLL::Sleep"],
    },
    {
        "address": "140001200", "file": "140001200", "name": "Sleep", "fullName": "Sleep",
        "namespace": "Global", "signature": "void Sleep(DWORD dwMilliseconds)",
        "cSignature": None, "callingConvention": "__stdcall",
        "returnType": "void", "paramCount": 1, "size": 6, "thunk": True, "thunkTarget": "KERNEL32.DLL::Sleep",
        "thunkTargetExternal": True, "library": False, "nameSource": "IMPORTED", "decompiled": True,
        "decompileError": None, "lines": 3, "callers": ["140001100"], "callees": [], "externalCalls": [],
    },
]

DECOMPILED = {
    "140001000": "\nint FUN_140001000(int param_1)\n\n{\n  return param_1 * 2 + DAT_140001010;\n}\n",
    "140001100": "\nvoid FUN_140001100(void)\n\n{\n  FUN_140001000(3);\n  Sleep(5);\n}\n",
    "140001200": "\nvoid Sleep(DWORD dwMilliseconds)\n\n{\n  Sleep(dwMilliseconds);\n}\n",
}


def write_fake_analysis(store: ProjectStore, pid: str) -> None:
    adir = store.analysis_dir(pid)
    (adir / "decompiled").mkdir(parents=True, exist_ok=True)
    (adir / "disassembly").mkdir(parents=True, exist_ok=True)
    files = {
        "program.json": {
            "name": "test.exe", "executableFormat": "Portable Executable (PE)", "language": "x86:LE:64:default",
            "compilerSpec": "windows", "compiler": "visualstudio:unknown", "imageBase": "140000000",
            "addressSize": 64, "ghidraVersion": "12.1.4", "md5": "x", "sha256": "y",
            "entryPoints": [{"address": "140001100", "name": "entry"}],
        },
        "sections": [
            {"name": ".text", "start": "140001000", "end": "140001fff", "size": 4096, "read": True,
             "write": False, "execute": True, "initialized": True},
            {"name": ".data", "start": "140001000", "end": "140001fff", "size": 4096, "read": True,
             "write": True, "execute": False, "initialized": True},
        ],
        "functions.json": FUNCTIONS,
        "imports.json": [
            {"library": "KERNEL32.DLL", "name": "Sleep", "originalName": None, "address": "EXTERNAL:00000001",
             "signature": "void Sleep(DWORD dwMilliseconds)", "refCount": 1, "usedBy": ["FUN_140001100"]},
            {"library": "MSVCRT.DLL", "name": "printf", "originalName": None, "address": "EXTERNAL:00000002",
             "signature": None, "refCount": 0, "usedBy": []},
        ],
        "exports.json": [{"name": "entry", "address": "140001100", "type": "Function"}],
        "strings.json": [{"address": "140003000", "value": "hello", "type": "string", "length": 6,
                          "refCount": 1, "usedBy": ["FUN_140001100"]}],
        "globals.json": [
            {"address": "140001010", "name": "DAT_140001010", "dataType": "int", "length": 4,
             "source": "DEFAULT", "block": ".data"},
            {"address": "140001014", "name": "weird", "dataType": "SomeUnknownStruct", "length": 12,
             "source": "USER_DEFINED", "block": ".data"},
            {"address": "140000000", "name": "IMAGE_DOS_HEADER_140000000", "dataType": "IMAGE_DOS_HEADER",
             "length": 64, "source": "IMPORTED", "block": "Headers"},
        ],
    }
    # the sections list above is stored under its own name
    (adir / "sections.json").write_text(json.dumps(files.pop("sections")), encoding="utf-8")
    for name, data in files.items():
        (adir / name).write_text(json.dumps(data), encoding="utf-8")
    (adir / "types.h").write_text(
        "typedef unsigned char   undefined;\ntypedef unsigned long    DWORD;\n"
        "typedef struct _POINT POINT;\nstruct _POINT {\n    int x;\n    int y;\n};\n",
        encoding="utf-8",
    )
    for addr, code in DECOMPILED.items():
        (adir / "decompiled" / f"{addr}.c").write_text(code, encoding="utf-8")
        (adir / "disassembly" / f"{addr}.asm").write_text(f"; asm {addr}\n  {addr}  c3  RET\n", encoding="utf-8")


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("GW_WORKSPACE", str(tmp_path / "ws"))
    monkeypatch.setenv("GW_TOOLS", str(tmp_path / "tools"))
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    return tmp_path / "ws"


@pytest.fixture
def store(workspace):
    return ProjectStore()


@pytest.fixture
def project(store):
    meta = store.create("test.exe", io.BytesIO(make_pe()), "Test Projekt")
    write_fake_analysis(store, meta["id"])
    return meta


FIXTURES = Path(__file__).parent / "fixtures"
