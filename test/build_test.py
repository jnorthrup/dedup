#!/usr/bin/env python3
"""Build regressions in a disposable source copy; leaves local artifacts intact."""

import hashlib
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parent.parent


def run(directory, *command):
    result = subprocess.run(command, cwd=directory, text=True, capture_output=True)
    if result.returncode:
        raise AssertionError(
            f"{shlex.join(command)} failed ({result.returncode})\n"
            f"{result.stdout}\n{result.stderr}"
        )
    return result.stdout + result.stderr


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def modified(path):
    # Older make implementations compare only whole seconds.
    time.sleep(1.1)
    path.touch()


def check_builds(directory):
    def make(*arguments):
        return run(directory, "make", "-j2", *arguments)

    def mtime(path):
        return (directory / path).stat().st_mtime_ns

    make("dedup")
    release_hash = digest(directory / "dedup")
    release_mtime = mtime("build/release/dedup.o")
    executable_mtime = mtime("dedup")
    make("dedup")
    assert mtime("build/release/dedup.o") == release_mtime, "no-op rebuilt objects"
    assert mtime("dedup") == executable_mtime, "no-op replaced executable"

    make("check-build", "leaks-build")
    for mode, instrumented in (("release", False), ("check", True), ("leaks", False)):
        symbols = run(directory, "nm", f"build/{mode}/dedup.o")
        assert ("___asan_init" in symbols) == instrumented, f"wrong sanitizer mode: {mode}"
        assert (directory / f"build/{mode}/dedup").is_file()
    assert digest(directory / "dedup") == release_hash, "debug build replaced release"
    assert mtime("build/release/dedup.o") == release_mtime, "debug build reused release objects"
    make("dedup")
    assert mtime("dedup") == executable_mtime, "release was dirtied by debug builds"
    print("PASS: release, sanitizer and leaks builds remain separate; no-op builds stay unchanged", flush=True)

    before = {name: mtime(f"build/release/{name}.o") for name in ("clone", "dedup", "alist")}
    modified(directory / "clone.h")
    make("dedup")
    for name in ("clone", "dedup"):
        assert mtime(f"build/release/{name}.o") > before[name], f"header consumer not rebuilt: {name}"
    assert mtime("build/release/alist.o") == before["alist"], "unrelated object rebuilt"
    assert "clone.h" in (directory / "build/release/clone.d").read_text()
    print("PASS: changing a header rebuilds its consumers", flush=True)

    before = mtime("build/release/alist.o")
    time.sleep(1.1)
    make("dedup", "CFLAGS=-DDEDUP_BUILD_REGRESSION=1", "VERSION=build-regression")
    assert mtime("build/release/alist.o") > before, "changed flags did not rebuild"
    assert "build-regression" in run(directory, "./dedup", "--version")
    before = mtime("build/release/alist.o")
    time.sleep(1.1)
    make("dedup")
    assert mtime("build/release/alist.o") > before, "restoring flags reused stale objects"
    assert "build-regression" not in run(directory, "./dedup", "--version")
    print("PASS: flag/version changes and restoration invalidate cached objects", flush=True)

    # Exercise the selected binary through shell commands in the C suites and
    # through Python's --binary flag, including a pathname containing spaces.
    wrapper = directory / "selected binary"
    marker = directory / "selected-binary.log"
    selected = directory / "build/check/dedup"
    wrapper.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' invoked >> {shlex.quote(str(marker))}\n"
        f"exec {shlex.quote(str(selected))} \"$@\"\n"
    )
    wrapper.chmod(0o755)
    run(directory / "test", "make", "-j2", "check-fast", f"DEDUP_TEST_BINARY={wrapper}")
    assert marker.read_text().count("invoked") > 10, "tests ignored selected binary"
    before = mtime("test/runtime_dispatch_test.o")
    modified(directory / "signature.h")
    run(directory / "test", "make", "dedup_check", f"DEDUP_TEST_BINARY={wrapper}")
    assert mtime("test/runtime_dispatch_test.o") > before, "test header dependency was ignored"
    print("PASS: tests use the selected executable and rebuild for header changes", flush=True)


def main():
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).split(b"\0")
    with tempfile.TemporaryDirectory(prefix="dedup-build-regression-") as temporary:
        directory = Path(temporary)
        for item in tracked:
            if not item:
                continue
            relative = Path(os.fsdecode(item))
            source = ROOT / relative
            if source.is_file():
                destination = directory / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
        check_builds(directory)


if __name__ == "__main__":
    main()
