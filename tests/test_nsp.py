"""Exercise NSP table validation, streamed import, update selection and failure/retry behavior with synthetic files.

No game content, keys or external extractor are needed: a fake NSTool process implements the documented CLI contract.
These tests do not establish compatibility with encrypted Switch 2 NCAs. Usage: uv run pytest tests/test_nsp.py.
"""

import json
import struct
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/prepare"))
import nsp  # noqa: E402


def package(path: Path, files: list[tuple[str, bytes]]) -> Path:
    names, table, data = bytearray(), bytearray(), bytearray()
    for name, value in files:
        table += struct.pack("<QQII", len(data), len(value), len(names), 0)
        names += name.encode() + b"\0"
        data += value
    path.write_bytes(b"PFS0" + struct.pack("<III", len(files), len(names), 0) + table + names + data)
    return path


def nca(number: int, kind: str = "Program", pid: int = nsp.PROGRAM_ID, patch: bool = False) -> tuple[str, bytes]:
    return f"{number:032x}.nca", json.dumps({"kind": kind, "pid": pid, "patch": patch}).encode()


@pytest.fixture
def backend(tmp_path: Path, monkeypatch):
    tool = tmp_path / "NSTool with spaces.exe"
    keys = tmp_path / "private.keys"
    tool.write_bytes(b"synthetic tool")
    keys.write_bytes(b"synthetic keyset; no real key material")
    calls = []

    def run(argv, *, stdout, stderr):
        assert stderr == subprocess.STDOUT and argv[:3] == [str(tool), "-k", str(keys)]
        calls.append(argv)
        info = json.loads(Path(argv[-1]).read_text())
        lines = f"  Content Type:    {info['kind']}\n  ProgID:          0x{info['pid']:016x}\n  Content Index:   0\n"
        if "--part0" in argv:
            if info["patch"] and "--basenca" not in argv:
                lines += "[WARNING] NCA Partition 1 not readable.\n"
            else:
                exefs = Path(argv[argv.index("--part0") + 1])
                romfs = Path(argv[argv.index("--part1") + 1])
                exefs.mkdir()
                romfs.mkdir()
                (exefs / "main").write_bytes(b"NSO0synthetic")
                (romfs / "synthetic.txt").write_text("synthetic test content")
        stdout.write(lines.encode())
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(nsp.subprocess, "run", run)
    return tool, keys, calls


def test_magic_and_streamed_content(tmp_path: Path) -> None:
    src = package(tmp_path / "Game Ñ.NSP", [("A" * 32 + ".NCA", b"content"), ("b" * 32 + ".tik", b"ticket")])
    assert nsp.is_nsp(src) and not nsp.is_nsp(tmp_path / "missing.nsp")
    archives, tickets = nsp.unpack_content(src, tmp_path / "out")
    assert [p.read_bytes() for p in archives] == [b"content"]
    assert [p.read_bytes() for p in tickets] == [b"ticket"]
    assert src.read_bytes().startswith(b"PFS0")


@pytest.mark.parametrize("name", ["../escape.nca", "C:\\escape.nca", "/escape.nca", ".", "..", "bad\nname"])
def test_unsafe_paths_are_rejected(tmp_path: Path, name: str) -> None:
    with pytest.raises(nsp.Failed, match="unsafe"):
        nsp.entries(package(tmp_path / "input.nsp", [(name, b"x")]))
    assert not (tmp_path / "escape.nca").exists()


@pytest.mark.parametrize("damage", ["header", "table", "name", "offset", "overlap", "duplicate", "count"])
def test_malformed_container(tmp_path: Path, damage: str) -> None:
    src = package(tmp_path / "input.nsp", [("a.nca", b"xx"), ("b.nca", b"yy")])
    data = bytearray(src.read_bytes())
    if damage == "header":
        data = data[:10]
    elif damage == "table":
        data = data[:25]
    elif damage == "name":
        struct.pack_into("<I", data, 32, 999)
    elif damage == "offset":
        struct.pack_into("<Q", data, 16, 2**63)
    elif damage == "overlap":
        struct.pack_into("<Q", data, 40, 1)
    elif damage == "duplicate":
        struct.pack_into("<I", data, 56, 0)
    else:
        struct.pack_into("<I", data, 4, 2**32 - 1)
    src.write_bytes(data)
    with pytest.raises(nsp.Failed):
        nsp.entries(src)


def test_ncz_refused(tmp_path: Path) -> None:
    src = package(tmp_path / "compressed.nsp", [("a" * 32 + ".ncz", b"compressed")])
    with pytest.raises(nsp.Failed, match="Compressed"):
        nsp.unpack_content(src, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_import_selects_header_and_reuses_cache(tmp_path: Path, backend) -> None:
    tool, keys, calls = backend
    src = package(
        tmp_path / "My Game Ñ.nsp", [nca(1, "Control"), nca(2, pid=1), nca(3), ("b" * 32 + ".tik", b"ticket")]
    )
    original = src.read_bytes()
    out = nsp.imported_source(src, tmp_path / "work", tmp_path, tool, keys)
    assert (out / "exefs/main").read_bytes().startswith(b"NSO0")
    assert (out / "romfs/synthetic.txt").is_file()
    assert json.loads((out / "ready.json").read_text()) == {"format": 1}
    assert "--tik" in calls[-1] and Path(calls[-1][-1]).stem == f"{3:032x}"
    assert not list(out.parent.glob("import-*"))  # temporary NCAs and tickets do not survive
    before = len(calls)
    assert nsp.imported_source(src, tmp_path / "work", tmp_path, tool, keys) == out
    assert len(calls) == before and src.read_bytes() == original
    keys.write_text("a different synthetic keyset")
    assert nsp.imported_source(src, tmp_path / "work", tmp_path, tool, keys) != out


def test_update_receives_base_nca(tmp_path: Path, backend) -> None:
    tool, keys, calls = backend
    src = package(tmp_path / "update.nsp", [nca(2, patch=True)])
    base = package(tmp_path / "base.nsp", [nca(1)])
    out = nsp.imported_source(src, tmp_path / "work", tmp_path, tool, keys, base)
    final = calls[-1]
    assert Path(final[final.index("--basenca") + 1]).stem == f"{1:032x}"
    assert Path(final[-1]).stem == f"{2:032x}"
    assert (out / "romfs").is_dir()


@pytest.mark.parametrize("files", [[nca(1, patch=True)], [nca(1), nca(2)], [nca(1, pid=1)]])
def test_incomplete_or_ambiguous_output_is_not_published(tmp_path: Path, backend, files) -> None:
    tool, keys, _ = backend
    src = package(tmp_path / "input.nsp", files)
    with pytest.raises(nsp.Failed):
        nsp.imported_source(src, tmp_path / "work", tmp_path, tool, keys)
    assert not list((tmp_path / "work").rglob("ready.json"))
    assert not list((tmp_path / "work" / nsp.CACHE_DIR).glob("import-*"))


def test_tool_failure_does_not_leak_output(tmp_path: Path, monkeypatch, backend, capsys) -> None:
    tool, keys, _ = backend

    def failed(argv, *, stdout, stderr):
        stdout.write(b"[ERROR] synthetic-private-key-value\n")
        return SimpleNamespace(returncode=0)  # false success must still be refused

    monkeypatch.setattr(nsp.subprocess, "run", failed)
    src = package(tmp_path / "input.nsp", [nca(1)])
    with pytest.raises(nsp.Failed) as error:
        nsp.imported_source(src, tmp_path / "work", tmp_path, tool, keys)
    captured = capsys.readouterr()
    assert "synthetic-private-key-value" not in str(error.value) + captured.out + captured.err
    assert not list((tmp_path / "work").rglob("ready.json"))


def test_missing_keys_fail_before_extracting(tmp_path: Path, backend) -> None:
    tool, _, calls = backend
    src = package(tmp_path / "input.nsp", [nca(1)])
    with pytest.raises(nsp.Failed, match="prod.keys"):
        nsp.imported_source(src, tmp_path / "work", tmp_path, tool, tmp_path / "missing.keys")
    assert not calls and not (tmp_path / "work").exists()


@pytest.mark.parametrize("returncode", [0, 1])
def test_late_tool_failure_is_not_hidden_by_large_output(tmp_path: Path, monkeypatch, backend, returncode: int) -> None:
    tool, keys, _ = backend

    def late_failure(argv, *, stdout, stderr):
        stdout.write(b"extracted-path\n" * 400000)
        stdout.write(b"[ERROR] synthetic-private-key-value\n")
        return SimpleNamespace(returncode=returncode)

    monkeypatch.setattr(nsp.subprocess, "run", late_failure)
    with pytest.raises(nsp.Failed, match="NSTool could not read"):
        nsp.tool_run(tool, keys, [], ["-t", "nca", "synthetic.nca"])


def test_cache_rebuilt_when_main_is_missing(tmp_path: Path, backend) -> None:
    tool, keys, calls = backend
    src = package(tmp_path / "input.nsp", [nca(1)])
    out = nsp.imported_source(src, tmp_path / "work", tmp_path, tool, keys)
    (out / "exefs/main").unlink()
    before = len(calls)
    assert nsp.imported_source(src, tmp_path / "work", tmp_path, tool, keys) == out
    assert len(calls) > before and (out / "exefs/main").is_file()


def test_setup_routes_nsp_through_importer(tmp_path: Path) -> None:
    src = package(tmp_path / "input.nsp", [nca(1)])
    game = tmp_path / "installation"
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools/prepare/prepare.py"),
            "--source",
            str(src),
            "--game",
            str(game),
            "--nstool",
            str(tmp_path / "missing-extractor"),
            "--keys",
            str(tmp_path / "missing.keys"),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1 and "NSP import needs" in result.stdout
    assert not (game / "exefs").exists() and not (game / "romfs").exists()
