"""Import an NSP into the setup's loose ExeFS/RomFS cache using the player's NSTool and keys.

Why: NSP is a PFS0 container of NCAs, not a ready-to-use RomFS. The runtime stays unchanged; the setup validates the
result as any other dump. No keys or extractor binary are downloaded or distributed. CLI contract checked against
jakcron/nstool @ cfb826ca6c165fbcd816fd7949df88ef3d72a948 (MIT), README.md, SWITCH_KEYS.md and src/Settings.cpp;
no upstream implementation copied. Imported by prepare.py; use --source GAME.nsp [--nstool PATH --keys PATH]
[--base-nsp BASE.nsp] with the normal setup command. Encrypted NCA support depends on the supplied tool and keys.
"""

import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

from machine import Failed, emit

PROGRAM_ID = 0x0400C3F00006E000
MAX_FILES = 4096
MAX_STRINGS = 4 * 1024 * 1024
CACHE_DIR = "nsp-cache"


def is_nsp(path: Path) -> bool:
    """Detect the container by magic, including an NSP with a differently cased extension."""
    try:
        with path.open("rb") as f:
            return f.read(4) == b"PFS0"
    except OSError:
        return False


def entries(path: Path) -> list[tuple[str, int, int]]:
    """Bounded PFS0 index, with absolute data offsets. Reject unsafe names, duplicates and overlapping spans."""
    with path.open("rb") as f:
        size = os.fstat(f.fileno()).st_size
        head = f.read(16)
        if len(head) != 16 or head[:4] != b"PFS0":
            raise Failed("The NSP is not a PFS0 package")
        count, strings, reserved = struct.unpack_from("<III", head, 4)
        start = 16 + count * 24 + strings
        if reserved or not 0 < count <= MAX_FILES or strings > MAX_STRINGS or start > size:
            raise Failed("The NSP has an invalid or truncated file table")
        table, names = f.read(count * 24), f.read(strings)
        if len(table) != count * 24 or len(names) != strings:
            raise Failed("The NSP file table was truncated while reading")
        result, seen, spans = [], set(), []
        for i in range(count):
            off, length, name_off, padding = struct.unpack_from("<QQII", table, i * 24)
            end = names.find(b"\0", name_off)
            if padding or name_off >= strings or end < 0 or off + length > size - start:
                raise Failed("The NSP has an out-of-bounds file entry")
            try:
                name = names[name_off:end].decode("utf-8")
            except UnicodeDecodeError:
                raise Failed("The NSP has an invalid file name") from None
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or name in (".", "..") or name.lower() in seen:
                raise Failed("The NSP has unsafe or duplicate file names")
            seen.add(name.lower())
            result.append((name, start + off, length))
            if length:
                spans.append((off, off + length))
        spans.sort()
        if any(a[1] > b[0] for a, b in zip(spans, spans[1:])):
            raise Failed("The NSP has overlapping file entries")
        return result


def unpack_content(path: Path, dest: Path) -> tuple[list[Path], list[Path]]:
    """Stream only NCAs and tickets into a private staging directory; never load an NCA into Python memory."""
    index = entries(path)
    if any(n.lower().endswith(".ncz") for n, _, _ in index):
        raise Failed("Compressed NCZ content is not supported; select an uncompressed NSP")
    selected = [
        (n.lower(), o, s)
        for n, o, s in index
        if re.fullmatch(r"[0-9a-fA-F]{32}(?:\.cnmt)?\.(?:nca|tik)", n, re.IGNORECASE)
    ]
    if not selected or sum(n.endswith(".tik") for n, _, _ in selected) > 16:
        raise Failed("The NSP has no supported NCA content or too many tickets")
    dest.mkdir()
    total, done = sum(s for _, _, s in selected), 0
    with path.open("rb") as f:
        for name, off, length in selected:
            f.seek(off)
            with (dest / name).open("xb") as out:
                remaining = length
                while remaining:
                    block = f.read(min(16 * 1024 * 1024, remaining))
                    if not block:
                        raise Failed("The NSP was truncated while reading its content")
                    out.write(block)
                    remaining -= len(block)
                    done += len(block)
                    # SetupState uses a Windows 32-bit long: bytes overflow on a normal multi-GB NSP. MiB counts
                    # keep the same progress ratio and fit on both platforms.
                    emit("progress", (done + 1048575) // 1048576, (total + 1048575) // 1048576)
    return sorted(dest.glob("*.nca")), sorted(dest.glob("*.tik"))


def tool_run(tool: Path, keys: Path, tickets: list[Path], args: list[str]) -> str:
    """Keep tool output private: never copy key diagnostics into setup.log or the launcher's error text."""
    cmd = [str(tool), "-k", str(keys)]
    for ticket in tickets:
        cmd += ["--tik", str(ticket)]
    with tempfile.TemporaryFile(mode="w+b") as log:
        p = subprocess.run([*cmd, *args], stdout=log, stderr=subprocess.STDOUT)
        log.seek(0)
        metadata, error, warning = [], False, False
        # An extraction can print hundreds of thousands of paths. Scan all of it for failures, keeping only the
        # three header fields used for selection; a late warning must not be lost behind a truncated log prefix.
        while block := log.readline(65536):
            line = block.decode("utf-8", errors="replace")
            error |= bool(re.search(r"\[[^\]\n]*ERROR\]", line, re.IGNORECASE))
            warning |= "[WARNING]" in line or "not readable" in line.lower()
            if len(metadata) < 32 and re.match(r"\s*(?:Content Type|ProgID|Content Index):", line):
                metadata.append(line)
    if p.returncode or error:
        raise Failed(
            "NSTool could not read the NSP content. Check your keys, the base NSP for updates, and whether "
            "this NSTool build supports the package's NCA format."
        )
    return "".join(metadata) + ("\n[WARNING]" if warning else "")


def program(tool: Path, keys: Path, tickets: list[Path], ncas: list[Path]) -> Path:
    """Select MKW's Program 0 by its header, never by file size or directory order."""
    matches = []
    for nca in ncas:
        if nca.name.endswith(".cnmt.nca"):
            continue
        info = tool_run(tool, keys, tickets, ["-t", "nca", str(nca)])
        kind = re.search(r"^\s*Content Type:\s*(\w+)", info, re.MULTILINE)
        pid = re.search(r"^\s*ProgID:\s*0x([0-9a-fA-F]+)", info, re.MULTILINE)
        index = re.search(r"^\s*Content Index:\s*(\d+)", info, re.MULTILINE)
        if not kind or not pid or not index:
            raise Failed("NSTool did not return a readable NCA header; check its version and your keys")
        if kind[1] == "Program" and int(pid[1], 16) == PROGRAM_ID and int(index[1]) == 0:
            matches.append(nca)
    if len(matches) != 1:
        raise Failed(
            "Select an NSP containing exactly one Mario Kart World Program 0 NCA; "
            "supply an update's base separately with --base-nsp or MKW_NSP_BASE"
        )
    return matches[0]


def imported_source(
    src: Path, work: Path, runtime: Path, tool: Path | None = None, keys: Path | None = None, base: Path | None = None
) -> Path:
    """Convert once, publish only complete outputs, and retain the cache for linked RomFS and setup updates."""
    supplied = tool or os.environ.get("MKW_NSTOOL")
    bundled = runtime / "setup/nstool" / ("nstool.exe" if os.name == "nt" else "nstool")
    found = str(supplied) if supplied else str(bundled) if bundled.is_file() else shutil.which("nstool")
    if not found:
        raise Failed(
            "NSP import needs NSTool. Install it on PATH, place it in setup/nstool, "
            "or set MKW_NSTOOL to its executable path."
        )
    tool = Path(shutil.which(found) or found).absolute()
    keys = Path(keys or os.environ.get("MKW_NSP_KEYS") or Path.home() / ".switch/prod.keys").absolute()
    base_arg = base or os.environ.get("MKW_NSP_BASE")
    base = Path(base_arg).absolute() if base_arg else None
    if not tool.is_file() or not keys.is_file():
        raise Failed(
            "NSP import needs a valid NSTool executable and your own prod.keys "
            "(--keys, MKW_NSP_KEYS, or ~/.switch/prod.keys). No keys are supplied by the port."
        )
    if base and not is_nsp(base):
        raise Failed("The base NSP is missing or is not a PFS0 package")
    # Stat identity avoids hashing tens of GB on every launcher update; version checks still run on every setup.
    identity = ["nsp-import-v1"]
    for p in [src, tool, keys, *([base] if base else [])]:
        st = p.stat()
        identity.append((str(p.resolve()), st.st_size, st.st_mtime_ns))
    digest = hashlib.sha256(json.dumps(identity).encode()).hexdigest()
    root = work / CACHE_DIR
    root.mkdir(parents=True, exist_ok=True)
    cache = root / digest
    # Before recursive cleanup or moving a staged output, all resolved paths must remain inside the setup's work.
    if not root.resolve().is_relative_to(work.resolve()) or cache.is_symlink() or os.path.isjunction(cache):
        raise Failed("The NSP cache must be a directory inside setup-work")
    ready = cache / "ready.json"
    if ready.is_file() and (cache / "exefs/main").is_file() and (cache / "romfs").is_dir():
        return cache
    if cache.exists():
        shutil.rmtree(cache)
    emit("progress", 0, 0)
    with tempfile.TemporaryDirectory(prefix="import-", dir=root) as tmp:
        stage = Path(tmp)
        tickets, base_nca = [], None
        if base:
            ncas, ts = unpack_content(base, stage / "base")
            tickets += ts
            base_nca = program(tool, keys, tickets, ncas)
        ncas, ts = unpack_content(src, stage / "source")
        tickets += ts
        selected = program(tool, keys, tickets, ncas)
        output = stage / "output"
        output.mkdir()
        args = ["-t", "nca"]
        if base_nca:
            args += ["--basenca", str(base_nca)]
        args += ["--part0", str(output / "exefs"), "--part1", str(output / "romfs"), str(selected)]
        info = tool_run(tool, keys, tickets, args)
        main = output / "exefs/main"
        if re.search(r"not readable|\[WARNING\]", info, re.IGNORECASE) or not main.is_file():
            raise Failed(
                "NSTool did not extract complete ExeFS/RomFS. An update requires its base NSP "
                "(--base-nsp or MKW_NSP_BASE); check the keys and tool's NCA support too."
            )
        with main.open("rb") as f:
            magic = f.read(4)
        if magic != b"NSO0" or not (output / "romfs").is_dir() or not any((output / "romfs").iterdir()):
            raise Failed("NSP extraction produced no decrypted NSO or RomFS")
        (output / "ready.json").write_text(json.dumps({"format": 1}), encoding="utf-8")
        if not output.resolve().is_relative_to(root.resolve()) or not cache.resolve().is_relative_to(root.resolve()):
            raise Failed("The staged NSP output is outside the NSP cache")
        output.rename(cache)
    return cache
