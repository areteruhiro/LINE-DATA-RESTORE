#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import ctypes
import ctypes.wintypes as wt
import hashlib
import json
import os
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
DEPS = ROOT / ".codex_deps"
if DEPS.exists():
    sys.path.insert(0, str(DEPS))

try:
    from Crypto.Cipher import AES
except Exception as exc: 
    raise SystemExit(
        "pycryptodome is required. Install with: "
        f"{sys.executable} -m pip install --target {DEPS} pycryptodome"
    ) from exc


SQLITE_HEADER = b"SQLite format 3\x00"
WX_PADDING = bytes.fromhex(
    "28BF4E5E4E758A4164004E56FFFA01082"
    "E2E00B6D0683E802F0CA9FE6453697A"
)


def default_output_root() -> Path:
    downloads = Path.home() / "Downloads"
    if downloads.exists():
        return downloads / "line_recovery_output"
    return Path.home() / "line_recovery_output"


def md5(data: bytes) -> bytes:
    return hashlib.md5(data).digest()


def rc4_crypt(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    key_len = len(key)
    for i in range(256):
        j = (j + s[i] + key[i % key_len]) & 0xFF
        s[i], s[j] = s[j], s[i]

    out = bytearray()
    i = j = 0
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) & 0xFF]
        out.append(b ^ k)
    return bytes(out)


def pad_passphrase(passphrase: bytes) -> bytes:
    p = bytearray(passphrase[:32])
    p.extend(WX_PADDING[: max(0, 32 - len(p))])
    return bytes(p[:32])


def derive_base_key_128(passphrase: bytes, *, line_variant: bool) -> bytes:
    padded = pad_passphrase(passphrase)

    inter_k = WX_PADDING
    for _ in range(51):
        inter_k = md5(inter_k)

    msg = passphrase[:32] if line_variant else padded
    for i in range(20):
        rc4_key = bytes(b ^ i for b in inter_k)
        msg = rc4_crypt(rc4_key, msg)
    inter_v = msg

    seed = (passphrase[:32] if line_variant else padded) + inter_v
    out = seed
    for _ in range(51):
        out = md5(out)
    return out


def page_key(base_key: bytes, page_no: int) -> bytes:
    return md5(base_key + struct.pack("<I", page_no) + b"sAlT")


def modmult(seed: int) -> int:
    a, b, c, m = 52774, 40692, 3791, 2147483399
    q = seed // a
    seed = b * (seed - a * q) - c * q
    if seed < 0:
        seed += m
    return seed


def page_iv(page_no: int, *, endian: str) -> bytes:
    seed = page_no + 1
    buf = bytearray()
    for _ in range(4):
        seed = modmult(seed)
        buf.extend(seed.to_bytes(4, endian))
    return md5(bytes(buf))


def parse_page_size(encrypted_db: bytes) -> int:
    if len(encrypted_db) < 24:
        raise ValueError("database is too small")
    page_size = int.from_bytes(encrypted_db[16:18], "big")
    if page_size == 1:
        return 65536
    if page_size < 512 or page_size > 65536 or page_size & (page_size - 1):
        raise ValueError(f"invalid wxSQLite3 page size marker: {page_size}")
    return page_size


def verify_first_page(encrypted_db: bytes, base_key: bytes) -> bool:
    if len(encrypted_db) < 32:
        return False
    key = page_key(base_key, 1)
    iv = page_iv(1, endian="little")
    cblock = encrypted_db[8:16] + encrypted_db[24:32]
    dec = AES.new(key, AES.MODE_CBC, iv).decrypt(cblock)
    recovered = dec[:8]
    return recovered == encrypted_db[16:24]


def decrypt_page(
    encrypted_page: bytes,
    page_no: int,
    base_key: bytes,
    *,
    iv_endian: str,
    final_page_count: int | None = None,
) -> bytes:
    key = page_key(base_key, page_no)
    if page_no == 1:
        out = bytearray(len(encrypted_page))
        out[0:16] = SQLITE_HEADER
        restored = bytearray(encrypted_page)
        restored[16:24] = encrypted_page[8:16]
        iv = page_iv(page_no, endian=iv_endian)
        out[16:] = AES.new(key, AES.MODE_CBC, iv).decrypt(restored[16:])
        return bytes(out)

    iv = page_iv(page_no, endian=iv_endian)
    return AES.new(key, AES.MODE_CBC, iv).decrypt(encrypted_page)


def decrypt_main_db(src: Path, dst: Path, base_key: bytes, *, iv_endian: str) -> tuple[int, int]:
    encrypted = src.read_bytes()
    page_size = parse_page_size(encrypted)
    page_count = (len(encrypted) + page_size - 1) // page_size
    if len(encrypted) % page_size:
        raise ValueError(f"{src.name}: length is not page-size aligned")

    out = bytearray(len(encrypted))
    for page_no in range(1, page_count + 1):
        offset = (page_no - 1) * page_size
        out[offset : offset + page_size] = decrypt_page(
            encrypted[offset : offset + page_size],
            page_no,
            base_key,
            iv_endian=iv_endian,
            final_page_count=page_count,
        )

    # Make the output standalone after WAL application/checkpointing.
    out[18] = 1
    out[19] = 1
    out[24:28] = (1).to_bytes(4, "big")
    out[28:32] = page_count.to_bytes(4, "big")
    dst.write_bytes(out)
    return page_size, page_count


def apply_wal(
    decrypted_db: Path,
    encrypted_wal: Path,
    base_key: bytes,
    *,
    iv_endian: str,
    page_size: int,
    page_count: int,
) -> tuple[int, int]:
    if not encrypted_wal.exists() or encrypted_wal.stat().st_size < 32:
        return 0, page_count

    data = encrypted_wal.read_bytes()
    wal_page_size = int.from_bytes(data[8:12], "big")
    if wal_page_size == 0:
        wal_page_size = 1024
    if wal_page_size != page_size:
        raise ValueError(
            f"WAL page size mismatch: db={page_size}, wal={wal_page_size}"
        )

    frame_size = 24 + page_size
    frames: list[tuple[int, int, int]] = []
    pos = 32
    while pos + frame_size <= len(data):
        header = data[pos : pos + 24]
        page_no = int.from_bytes(header[0:4], "big")
        commit_size = int.from_bytes(header[4:8], "big")
        frames.append((pos, page_no, commit_size))
        pos += frame_size

    base_bytes = decrypted_db.read_bytes()
    commits = [idx for idx, (_, _, commit) in enumerate(frames, 1) if commit]

    def build_candidate(
        limit_frame: int | None, *, truncate_on_commit: bool
    ) -> tuple[bytes, int, int]:
        db = bytearray(base_bytes)
        pending: list[tuple[int, bytes]] = []
        applied = 0
        final_count = page_count
        for idx, (frame_pos, page_no, commit_size) in enumerate(frames, 1):
            if limit_frame is not None and idx > limit_frame:
                break
            if page_no:
                enc_page = data[frame_pos + 24 : frame_pos + 24 + page_size]
                dec_page = decrypt_page(
                    enc_page,
                    page_no,
                    base_key,
                    iv_endian=iv_endian,
                    final_page_count=final_count,
                )
                pending.append((page_no, dec_page))

            if commit_size:
                for pgno, page in pending:
                    need = pgno * page_size
                    if len(db) < need:
                        db.extend(b"\x00" * (need - len(db)))
                    db[(pgno - 1) * page_size : pgno * page_size] = page
                    applied += 1
                pending.clear()
                final_count = commit_size
                if truncate_on_commit:
                    del db[commit_size * page_size :]

        header_count = final_count if truncate_on_commit else max(1, len(db) // page_size)
        db[18] = 1
        db[19] = 1
        db[24:28] = (1).to_bytes(4, "big")
        db[28:32] = header_count.to_bytes(4, "big")
        return bytes(db), applied, header_count

    def write_and_validate(candidate: bytes) -> dict:
        decrypted_db.write_bytes(candidate)
        return validate_sqlite(decrypted_db)

    candidates: list[tuple[int, bool | None]] = []
    candidates.append((len(frames), True))
    candidates.append((len(frames), False))
    candidates.extend((idx, True) for idx in commits)
    candidates.extend((idx, False) for idx in commits)

    best_bytes = base_bytes
    best_applied = 0
    best_count = page_count
    best_frame = 0 if validate_sqlite(decrypted_db).get("ok") else -1

    for frame_limit, truncate in candidates:
        cand_bytes, applied, count = build_candidate(
            frame_limit, truncate_on_commit=bool(truncate)
        )
        validation = write_and_validate(cand_bytes)
        if validation.get("ok") and frame_limit >= best_frame:
            best_bytes = cand_bytes
            best_applied = applied
            best_count = count
            best_frame = frame_limit

    decrypted_db.write_bytes(best_bytes)
    return best_applied, best_count


def validate_sqlite(path: Path) -> dict:
    result: dict = {"path": str(path), "ok": False}
    try:
        uri = path.resolve().as_uri() + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        try:
            tables = [
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                )
            ]
            quick_check = conn.execute("PRAGMA quick_check").fetchone()[0]
            result.update(
                ok=quick_check == "ok",
                quick_check=quick_check,
                table_count=len(tables),
                tables=tables[:50],
            )
            for table in (
                "_message",
                "_contact",
                "_chats",
                "_chat",
                "_groupchat",
                "_groupChat",
                "_profile",
            ):
                if table in tables:
                    result[f"{table}_rows"] = conn.execute(
                        f'SELECT COUNT(*) FROM "{table}"'
                    ).fetchone()[0]
        finally:
            conn.close()
    except Exception as exc:
        result.update(ok=False, error=str(exc))
    return result


def quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def safe_filename(name: str) -> str:
    return re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).strip(" .") or "table"


def csv_cell(value):
    if isinstance(value, bytes):
        return "0x" + value.hex()
    return value


def export_table(conn: sqlite3.Connection, table: str, dst: Path) -> int:
    cur = conn.execute(f"SELECT * FROM {quote_ident(table)}")
    cols = [d[0] for d in cur.description]
    count = 0
    with dst.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(cols)
        for row in cur:
            writer.writerow([csv_cell(value) for value in row])
            count += 1
    return count


def export_messages(sqlite_path: Path, export_dir: Path) -> dict:
    export_dir.mkdir(parents=True, exist_ok=True)
    summary: dict = {"sqlite": str(sqlite_path), "exports": {}, "schema": {}}
    conn = sqlite3.connect(sqlite_path)
    try:
        tables = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
        ]
        table_set = set(tables)
        for table in tables:
            columns = [
                {
                    "cid": row[0],
                    "name": row[1],
                    "type": row[2],
                    "notnull": row[3],
                    "default": row[4],
                    "pk": row[5],
                }
                for row in conn.execute(f"PRAGMA table_info({quote_ident(table)})")
            ]
            summary["schema"][table] = columns
            dst = export_dir / f"{sqlite_path.stem}__{safe_filename(table)}.csv"
            summary["exports"][table] = {
                "path": str(dst),
                "rows": export_table(conn, table, dst),
                "columns": [col["name"] for col in columns],
            }

        schema_path = export_dir / f"{sqlite_path.stem}__schema.json"
        schema_path.write_text(
            json.dumps(summary["schema"], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        summary["schema_path"] = str(schema_path)

        if {"_message", "_contact"}.issubset(table_set):
            msg_cols = {
                row[1] for row in conn.execute('PRAGMA table_info("_message")')
            }
            contact_cols = {
                row[1] for row in conn.execute('PRAGMA table_info("_contact")')
            }
            needed = {"_createdTime", "_from", "_to", "_chatId", "_text"}
            if needed.issubset(msg_cols) and {"_mid", "_displayName"}.issubset(
                contact_cols
            ):
                dst = export_dir / f"{sqlite_path.stem}_messages_joined.csv"
                query = """
                    SELECT
                        m._createdTime AS created_ms,
                        datetime(m._createdTime / 1000, 'unixepoch', 'localtime')
                            AS created_local,
                        COALESCE(c._displayName, m._from) AS sender,
                        m._from AS sender_mid,
                        m._to AS receiver_mid,
                        m._chatId AS chat_id,
                        m._text AS text
                    FROM _message AS m
                    LEFT JOIN _contact AS c ON c._mid = m._from
                    ORDER BY m._createdTime
                """
                cur = conn.execute(query)
                with dst.open("w", encoding="utf-8-sig", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow([d[0] for d in cur.description])
                    rows = 0
                    for row in cur:
                        writer.writerow(row)
                        rows += 1
                summary["exports"]["messages_joined"] = {
                    "path": str(dst),
                    "rows": rows,
                }
    finally:
        conn.close()
    return summary


PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wt.DWORD), ("HighPart", wt.LONG)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", wt.DWORD),
        ("Luid", LUID),
        ("Attributes", wt.DWORD),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_size_t),
        ("AllocationBase", ctypes.c_size_t),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.OpenProcess.restype = wt.HANDLE
kernel32.CloseHandle.argtypes = [wt.HANDLE]
kernel32.VirtualQueryEx.argtypes = [
    wt.HANDLE,
    ctypes.c_void_p,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t,
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.ReadProcessMemory.argtypes = [
    wt.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wt.BOOL
kernel32.GetCurrentProcess.restype = wt.HANDLE
advapi32.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
advapi32.LookupPrivilegeValueW.argtypes = [wt.LPCWSTR, wt.LPCWSTR, ctypes.POINTER(LUID)]
advapi32.AdjustTokenPrivileges.argtypes = [
    wt.HANDLE,
    wt.BOOL,
    ctypes.POINTER(TOKEN_PRIVILEGES),
    wt.DWORD,
    ctypes.c_void_p,
    ctypes.c_void_p,
]


def enable_debug_privilege() -> bool:
    token = wt.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        ctypes.byref(token),
    ):
        return False
    try:
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            return False
        tp = TOKEN_PRIVILEGES(1, luid, SE_PRIVILEGE_ENABLED)
        advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None)
        return ctypes.get_last_error() == 0
    finally:
        kernel32.CloseHandle(token)


@dataclass
class Proc:
    pid: int
    name: str
    path: str | None = None


def find_line_processes(scan_all_line: bool = False) -> list[Proc]:
    names = (
        "$_.ProcessName -like 'LINE*'"
        if scan_all_line
        else "$_.ProcessName -eq 'LINE'"
    )
    ps = (
        "Get-Process | Where-Object { "
        + names
        + " } | Select-Object Id,ProcessName,Path | ConvertTo-Json -Compress"
    )
    try:
        raw = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", ps],
            text=True,
            encoding="utf-8",
            errors="replace",
        ).strip()
    except Exception:
        return []
    if not raw:
        return []
    data = json.loads(raw)
    if isinstance(data, dict):
        data = [data]
    return [
        Proc(int(item["Id"]), item.get("ProcessName", ""), item.get("Path"))
        for item in data
    ]


ASCII_KEY_RE = re.compile(
    rb"(?:encryption_key|encryptionkey)\s*[:=]\s*\"?([0-9a-fA-F]{32})",
    re.I,
)
ASCII_MSE_RE = re.compile(rb"([0-9a-fA-F]{32})mse", re.I)
ASCII_CONTEXT_RE = re.compile(rb"[\x20-\x7e]{0,48}([0-9a-fA-F]{32})[\x20-\x7e]{0,48}")


def utf16_key_candidates(buf: bytes) -> Iterable[bytes]:
    for marker in ("encryption_key=", "encryptionkey="):
        needle = marker.encode("utf-16le")
        start = 0
        while True:
            idx = buf.lower().find(needle.lower(), start)
            if idx < 0:
                break
            after = buf[idx + len(needle) : idx + len(needle) + 96]
            chars = bytearray()
            for i in range(0, min(len(after), 64), 2):
                if i + 1 >= len(after) or after[i + 1] != 0:
                    break
                chars.append(after[i])
            m = re.match(rb"[0-9a-fA-F]{32}", bytes(chars))
            if m:
                yield m.group(0).lower()
            start = idx + 2


def candidates_from_buffer(buf: bytes) -> set[bytes]:
    found: set[bytes] = set()
    for regex in (ASCII_KEY_RE, ASCII_MSE_RE):
        for m in regex.finditer(buf):
            found.add(m.group(1).lower())
    for m in ASCII_CONTEXT_RE.finditer(buf):
        ctx = m.group(0).lower()
        if b"encryption" in ctx or b"mse" in ctx:
            found.add(m.group(1).lower())
    found.update(utf16_key_candidates(buf))
    return found


def is_readable_region(protect: int) -> bool:
    if protect & PAGE_GUARD or protect & PAGE_NOACCESS:
        return False
    return bool(protect & 0xF0 or protect & 0x06 or protect & 0x02)


def scan_process_memory(pid: int, *, max_candidates: int) -> tuple[set[bytes], dict]:
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    stats = {
        "pid": pid,
        "regions": 0,
        "readable_regions": 0,
        "bytes_read": 0,
        "read_failures": 0,
    }
    if not handle:
        stats["error"] = f"OpenProcess failed: {ctypes.get_last_error()}"
        return set(), stats

    found: set[bytes] = set()
    try:
        mbi = MEMORY_BASIC_INFORMATION()
        addr = 0
        max_addr = (1 << (ctypes.sizeof(ctypes.c_void_p) * 8)) - 1
        while addr < max_addr:
            res = kernel32.VirtualQueryEx(
                handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)
            )
            if not res:
                break
            base = int(mbi.BaseAddress)
            size = int(mbi.RegionSize)
            stats["regions"] += 1
            if mbi.State == MEM_COMMIT and is_readable_region(mbi.Protect):
                stats["readable_regions"] += 1
                carry = b""
                offset = 0
                chunk_size = 1024 * 1024
                while offset < size:
                    want = min(chunk_size, size - offset)
                    buf = ctypes.create_string_buffer(want)
                    nread = ctypes.c_size_t()
                    ok = kernel32.ReadProcessMemory(
                        handle,
                        ctypes.c_void_p(base + offset),
                        buf,
                        want,
                        ctypes.byref(nread),
                    )
                    if ok and nread.value:
                        data = carry + buf.raw[: nread.value]
                        stats["bytes_read"] += nread.value
                        found.update(candidates_from_buffer(data))
                        if len(found) >= max_candidates:
                            return found, stats
                        carry = data[-256:]
                        offset += want
                    else:
                        stats["read_failures"] += 1
                        if want > 4096:
                            chunk_size = max(4096, chunk_size // 2)
                        else:
                            offset += 4096
            next_addr = base + max(size, 0x1000)
            if next_addr <= addr:
                break
            addr = next_addr
    finally:
        kernel32.CloseHandle(handle)
    return found, stats


def snapshot_databases(line_data: Path, out_dir: Path) -> list[Path]:
    db_dir = line_data / "db"
    snap = out_dir / "snapshot"
    snap.mkdir(parents=True, exist_ok=True)
    copied: list[Path] = []
    for src in sorted(db_dir.glob("*.edb")):
        dst = snap / src.name
        shutil.copy2(src, dst)
        copied.append(dst)
        for suffix in ("-wal", "-shm"):
            side = src.with_name(src.name + suffix)
            if side.exists():
                shutil.copy2(side, snap / side.name)
    return copied


def key_byte_variants(candidate: bytes) -> list[tuple[str, bytes]]:
    variants = [("ascii", candidate)]
    try:
        raw = bytes.fromhex(candidate.decode("ascii"))
        variants.append(("rawhex", raw))
    except Exception:
        pass
    return variants


def mask_key(key: bytes) -> str:
    text = key.decode("ascii", errors="replace")
    return text[:4] + "..." + text[-4:]


def attempt_recovery(
    db_paths: list[Path], candidates: list[bytes], out_dir: Path
) -> tuple[list[dict], list[dict]]:
    decrypted_dir = out_dir / "decrypted"
    export_dir = out_dir / "exports"
    decrypted_dir.mkdir(parents=True, exist_ok=True)
    reports: list[dict] = []
    export_reports: list[dict] = []

    for db_path in db_paths:
        if db_path.name.startswith(("keep_", "chatStats_", "album_")):
            priority = "secondary"
        else:
            priority = "chat_candidate"
        db_report: dict = {
            "source": str(db_path),
            "name": db_path.name,
            "priority": priority,
            "attempts": [],
            "recovered": False,
        }
        encrypted = db_path.read_bytes()
        try:
            parse_page_size(encrypted)
        except Exception as exc:
            db_report["error"] = str(exc)
            reports.append(db_report)
            continue

        for candidate in candidates:
            for variant_name, pass_bytes in key_byte_variants(candidate):
                for line_variant in (True, False):
                    base_key = derive_base_key_128(pass_bytes, line_variant=line_variant)
                    if not verify_first_page(encrypted, base_key):
                        continue
                    for iv_endian in ("little", "big"):
                        out_sqlite = decrypted_dir / (
                            db_path.stem
                            + f".{variant_name}."
                            + ("line" if line_variant else "wx")
                            + f".{iv_endian}.sqlite"
                        )
                        attempt = {
                            "key": mask_key(candidate),
                            "passphrase_variant": variant_name,
                            "kdf": "line" if line_variant else "wx",
                            "iv_endian": iv_endian,
                            "output": str(out_sqlite),
                        }
                        try:
                            page_size, page_count = decrypt_main_db(
                                db_path, out_sqlite, base_key, iv_endian=iv_endian
                            )
                            frames, final_count = apply_wal(
                                out_sqlite,
                                db_path.with_name(db_path.name + "-wal"),
                                base_key,
                                iv_endian=iv_endian,
                                page_size=page_size,
                                page_count=page_count,
                            )
                            validation = validate_sqlite(out_sqlite)
                            attempt.update(
                                page_size=page_size,
                                page_count=final_count,
                                wal_frames_applied=frames,
                                validation=validation,
                            )
                            db_report["attempts"].append(attempt)
                            if validation.get("ok"):
                                db_report["recovered"] = True
                                db_report["selected_output"] = str(out_sqlite)
                                export_reports.append(
                                    export_messages(
                                        out_sqlite,
                                        export_dir / out_sqlite.stem,
                                    )
                                )
                                raise StopIteration
                        except StopIteration:
                            break
                        except Exception as exc:
                            attempt["error"] = str(exc)
                            db_report["attempts"].append(attempt)
                    if db_report["recovered"]:
                        break
                if db_report["recovered"]:
                    break
            if db_report["recovered"]:
                break
        reports.append(db_report)

    return reports, export_reports


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--line-data",
        default=os.path.expandvars(r"%LOCALAPPDATA%\LINE\Data"),
        type=Path,
    )
    parser.add_argument("--out", type=Path, default=default_output_root())
    parser.add_argument("--pid", type=int, action="append", default=[])
    parser.add_argument("--key", action="append", default=[], help="32-char hex key")
    parser.add_argument("--skip-memory", action="store_true")
    parser.add_argument("--scan-all-line", action="store_true")
    parser.add_argument("--max-candidates", type=int, default=5000)
    args = parser.parse_args()

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = args.out / stamp
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[+] Output: {out_dir}")
    print(f"[+] LINE data: {args.line_data}")
    db_paths = snapshot_databases(args.line_data, out_dir)
    print(f"[+] Snapshot .edb files: {len(db_paths)}")

    candidates: set[bytes] = {
        key.encode("ascii").lower()
        for key in args.key
        if re.fullmatch(r"[0-9a-fA-F]{32}", key)
    }
    mem_stats: list[dict] = []
    procs: list[Proc] = []
    if not args.skip_memory:
        enable_debug_privilege()
        if args.pid:
            procs = [Proc(pid, "manual") for pid in args.pid]
        else:
            procs = find_line_processes(args.scan_all_line)
        print("[+] Processes to scan: " + ", ".join(f"{p.name}:{p.pid}" for p in procs))
        for proc in procs:
            found, stats = scan_process_memory(proc.pid, max_candidates=args.max_candidates)
            stats["name"] = proc.name
            stats["path"] = proc.path
            mem_stats.append(stats)
            candidates.update(found)
            print(
                f"[+] PID {proc.pid}: found={len(found)}, "
                f"read={stats.get('bytes_read', 0) // (1024 * 1024)} MiB"
            )

    candidates = {c for c in candidates if re.fullmatch(rb"[0-9a-f]{32}", c)}
    ordered_candidates = sorted(candidates)
    print(f"[+] Unique passphrase candidates: {len(ordered_candidates)}")
    if ordered_candidates:
        print("[+] Candidate masks: " + ", ".join(mask_key(c) for c in ordered_candidates[:20]))

    reports, export_reports = attempt_recovery(db_paths, ordered_candidates, out_dir)

    report = {
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "line_data": str(args.line_data),
        "output": str(out_dir),
        "processes": [proc.__dict__ for proc in procs],
        "memory_scan": mem_stats,
        "candidate_count": len(ordered_candidates),
        "databases": reports,
        "exports": export_reports,
    }
    report_path = out_dir / "recovery_report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    recovered = [r for r in reports if r.get("recovered")]
    print(f"[+] Recovered databases: {len(recovered)}")
    for item in recovered:
        selected = item.get("selected_output")
        validation = item["attempts"][-1].get("validation", {})
        print(
            f"    {item['name']} -> {selected} "
            f"tables={validation.get('table_count')} "
            f"messages={validation.get('_message_rows', 'n/a')}"
        )
    print(f"[+] Report: {report_path}")
    return 0 if recovered else 2


if __name__ == "__main__":
    raise SystemExit(main())
