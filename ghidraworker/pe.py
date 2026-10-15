"""Tiny PE header reader (no dependencies) for facts Ghidra does not expose directly."""

from __future__ import annotations

import datetime as dt
import struct
from pathlib import Path

MACHINES = {
    0x014C: "x86",
    0x8664: "x64",
    0x01C0: "ARM",
    0x01C4: "ARMv7 (Thumb-2)",
    0xAA64: "ARM64",
    0x0200: "IA-64",
}

SUBSYSTEMS = {
    1: "native",
    2: "windows",  # GUI
    3: "console",
    7: "posix",
    9: "windows-ce",
    10: "efi-application",
    11: "efi-boot-driver",
    12: "efi-runtime-driver",
    14: "xbox",
    16: "windows-boot-application",
}


def read_pe_info(path: Path) -> dict | None:
    """Return basic PE header facts, or ``None`` if the file is not a PE image."""
    try:
        with open(path, "rb") as f:
            head = f.read(4096)
    except OSError:
        return None
    if len(head) < 0x40 or head[:2] != b"MZ":
        return None
    (pe_off,) = struct.unpack_from("<I", head, 0x3C)
    if pe_off + 0x18 > len(head):
        with open(path, "rb") as f:
            f.seek(pe_off)
            head = b"\0" * pe_off + f.read(1024)
    if head[pe_off : pe_off + 4] != b"PE\0\0":
        return None
    machine, nsections, timestamp, _, _, opt_size, characteristics = struct.unpack_from(
        "<HHIIIHH", head, pe_off + 4
    )
    opt = pe_off + 24
    if opt + 2 > len(head):
        return None
    (magic,) = struct.unpack_from("<H", head, opt)
    is64 = magic == 0x20B
    info = {
        "machine": MACHINES.get(machine, hex(machine)),
        "bits": 64 if is64 else 32,
        "sections": nsections,
        "timestamp": timestamp,
        "timestampIso": _iso(timestamp),
        "dll": bool(characteristics & 0x2000),
        "subsystem": None,
        "entryRva": None,
        "linkerVersion": None,
        "dotnet": False,
    }
    if opt_size >= 0x48 and opt + 0x48 <= len(head):
        major, minor = head[opt + 2], head[opt + 3]
        (entry_rva,) = struct.unpack_from("<I", head, opt + 16)
        (subsystem,) = struct.unpack_from("<H", head, opt + 0x44)
        info["linkerVersion"] = f"{major}.{minor}"
        info["entryRva"] = hex(entry_rva)
        info["subsystem"] = SUBSYSTEMS.get(subsystem, str(subsystem))
        # Data directory 14 = CLR runtime header (.NET assemblies)
        dd = opt + (0x70 if is64 else 0x60)
        clr = dd + 14 * 8
        if clr + 8 <= len(head):
            rva, size = struct.unpack_from("<II", head, clr)
            info["dotnet"] = bool(rva and size)
    return info


def _iso(ts: int) -> str | None:
    try:
        return dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


class PEImage:
    """Maps virtual addresses of a PE file to file contents (for initial values of globals)."""

    def __init__(self, path: Path) -> None:
        self.data = Path(path).read_bytes()
        d = self.data
        if d[:2] != b"MZ":
            raise ValueError("not a PE file")
        (pe_off,) = struct.unpack_from("<I", d, 0x3C)
        if d[pe_off : pe_off + 4] != b"PE\0\0":
            raise ValueError("not a PE file")
        _, nsections, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", d, pe_off + 4)
        opt = pe_off + 24
        (magic,) = struct.unpack_from("<H", d, opt)
        if magic == 0x20B:
            (self.image_base,) = struct.unpack_from("<Q", d, opt + 24)
        else:
            (self.image_base,) = struct.unpack_from("<I", d, opt + 28)
        self.sections = []
        sec = opt + opt_size
        for i in range(nsections):
            off = sec + 40 * i
            name = d[off : off + 8].rstrip(b"\0").decode("latin-1")
            vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", d, off + 8)
            self.sections.append((name, vaddr, max(vsize, raw_size), raw_ptr, raw_size))

    def read(self, va: int, length: int) -> bytes | None:
        """Bytes at virtual address ``va``; ``None`` if (partly) uninitialized/not in the file."""
        rva = va - self.image_base
        for _name, vaddr, vsize, raw_ptr, raw_size in self.sections:
            if vaddr <= rva < vaddr + vsize:
                start = rva - vaddr
                if start + length > raw_size:
                    return None  # .bss-like tail
                return self.data[raw_ptr + start : raw_ptr + start + length]
        if 0 <= rva and rva + length <= len(self.data) and not self.sections:
            return self.data[rva : rva + length]
        return None
