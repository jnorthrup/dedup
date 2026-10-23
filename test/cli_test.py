#!/usr/bin/env python3
"""Disposable CLI regressions; run after building dedup, with no disk images."""

import argparse
import ctypes
import errno
import fcntl
import os
from pathlib import Path
import pty
import pwd
import select
import struct
import subprocess
import sys
import tempfile
import termios
import time
import unittest


BINARY = Path(__file__).resolve().parent.parent / "dedup"
TIMEOUT = 15


class DedupCLI(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="dedup-cli-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def make_file(self, name, content=b"duplicate content\n"):
        path = self.directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def run_dedup(self, *arguments):
        return subprocess.run(
            [str(BINARY), *map(str, arguments)],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            cwd=self.directory,
        )

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def metrics(self, output):
        names = {"duplicates found", "entries pruned", "bytes saved", "already saved"}
        return {
            key: value
            for line in output.splitlines()
            for key, separator, value in [line.partition(": ")]
            if separator and key in names
        }

    def run_in_terminal(self, *arguments, width):
        """Capture a real tty while continuously draining its bounded buffer."""
        master, slave = pty.openpty()
        process = None
        output = bytearray()
        command = [str(BINARY), *map(str, arguments)]
        try:
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, width, 0, 0))
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=slave,
                stderr=slave,
                cwd=self.directory,
            )
            os.close(slave)
            slave = None
            deadline = time.monotonic() + TIMEOUT
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, TIMEOUT, bytes(output))
                readable, _, _ = select.select([master], [], [], min(remaining, 0.1))
                if not readable:
                    if process.poll() is not None:
                        break
                    continue
                try:
                    chunk = os.read(master, 65536)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    break
                if not chunk:
                    break
                output.extend(chunk)
            return subprocess.CompletedProcess(
                command,
                process.wait(timeout=max(0.1, deadline - time.monotonic())),
                output.decode(errors="replace"),
                "",
            )
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()
            os.close(master)
            if slave is not None:
                os.close(slave)

    def test_redirected_verbose_dry_run_reports_paths(self):
        origin = self.make_file("origin")
        duplicate = self.make_file("duplicate")
        before = {path: (path.stat().st_ino, path.read_bytes()) for path in [origin, duplicate]}
        result = self.run_dedup("-nPvl", "-t0", "--", origin, duplicate)
        self.assert_success(result)
        self.assertIn("would deduplicate", result.stdout)
        self.assertIn(str(origin), result.stdout)
        self.assertIn(str(duplicate), result.stdout)
        self.assertEqual(self.metrics(result.stdout)["duplicates found"], "1")
        for path, original in before.items():
            self.assertEqual((path.stat().st_ino, path.read_bytes()), original)

    def test_help_and_version_exit_successfully(self):
        for option, expected in [("--help", "usage:"), ("--version", "dedup")]:
            with self.subTest(option=option):
                result = self.run_dedup(option)
                self.assert_success(result)
                self.assertIn(expected, (result.stdout + result.stderr).lower())

    def test_invalid_numeric_options_are_rejected(self):
        path = self.make_file("input")
        for option, value in [
            ("-t", "garbage"), ("-d", "garbage"),
            ("-t", "1trailing"), ("-d", "1trailing"),
            ("-t", "-1"), ("-d", "-1"),
            ("-t", "256"), ("-d", "65536"),
            ("-t", "999999999999999999999999999999"),
            ("-d", "999999999999999999999999999999"),
        ]:
            with self.subTest(option=option, value=value):
                result = self.run_dedup("-nPl", option, value, "--", path)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertTrue(result.stderr)

    def test_unsupported_ignore_stops_before_scanning(self):
        origin = self.make_file("origin")
        duplicate = self.make_file("excluded")
        existing_summary = self.make_file("existing-summary", b"keep summary contents\n")
        before = {
            path: (path.stat().st_ino, path.read_bytes())
            for path in [origin, duplicate, existing_summary]
        }
        for option in ["--ignore", "-I"]:
            for threads in [0, 2]:
                for dry_run in [False, True]:
                    for summary in [self.directory / "new-summary", existing_summary]:
                        with self.subTest(option=option, threads=threads, dry_run=dry_run,
                                          summary=summary.name):
                            result = self.run_dedup(
                                "-nPvl" if dry_run else "-Pvl", "-t", threads,
                                "-S", summary, option, duplicate.name, "--", origin, duplicate
                            )
                            self.assertNotEqual(result.returncode, 0, result.stdout)
                            self.assertTrue(result.stderr)
                            self.assertFalse(result.stdout, "unsupported ignore option must stop scanning")
                            self.assertFalse((self.directory / "new-summary").exists())
                            for path, original in before.items():
                                self.assertEqual((path.stat().st_ino, path.read_bytes()), original)

    def test_summary_open_failure_stops_before_replacement(self):
        origin = self.make_file("origin")
        duplicate = self.make_file("duplicate")
        original_inode = duplicate.stat().st_ino
        result = self.run_dedup(
            "-Pl", "-S", self.directory / "missing" / "summary.txt", "--", origin, duplicate
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertTrue(result.stderr)
        self.assertEqual(duplicate.stat().st_ino, original_inode)
        self.assertEqual(duplicate.read_bytes(), origin.read_bytes())

    def test_existing_summary_path_is_never_truncated(self):
        origin = self.make_file("origin")
        duplicate = self.make_file("duplicate")
        before = {path: (path.stat().st_ino, path.read_bytes()) for path in [origin, duplicate]}
        for options in ["-nPl", "-Pl"]:
            with self.subTest(options=options):
                result = self.run_dedup(options, "-S", origin, "--", origin, duplicate)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertTrue(result.stderr)
                for path, original in before.items():
                    self.assertEqual((path.stat().st_ino, path.read_bytes()), original)

    def test_staging_collision_reports_failure_without_progress(self):
        for mode in ["-l", "-s"]:
            with self.subTest(mode=mode):
                origin = self.make_file("a-origin" + mode)
                duplicate = self.make_file("z-duplicate" + mode)
                staging = self.make_file(".~." + duplicate.name, b"keep existing staged data\n")
                before = {
                    path: (path.stat().st_ino, path.read_bytes())
                    for path in [origin, duplicate, staging]
                }
                result = self.run_dedup("-P", mode, "-t0", "--", origin, duplicate)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(str(duplicate), result.stderr)
                self.assertIn("exist", result.stderr.lower())
                self.assertNotIn("\x1b[", result.stderr)
                for path, original in before.items():
                    self.assertEqual((path.stat().st_ino, path.read_bytes()), original)

    def test_summary_inside_scan_is_not_an_input(self):
        header = b"DEDUP CLONING SUMMARY\n=====================\n\n"
        source = self.make_file("matches-summary-header", header)
        original_inode = source.stat().st_ino
        summary = self.directory / "summary.txt"
        result = self.run_dedup("-Pvl", "-t0", "-F", "raw", "-S", summary, "--", self.directory)
        self.assert_success(result)
        self.assertEqual(source.read_bytes(), header)
        self.assertEqual(source.stat().st_ino, original_inode)
        self.assertEqual(summary.read_bytes(), header + b"\nTotal cloning operations: 0\n")
        self.assertEqual(self.metrics(result.stdout), {
            "duplicates found": "0",
            "entries pruned": "0",
            "bytes saved": "0",
            "already saved": "0",
        })

    @unittest.skipUnless(sys.platform == "darwin", "clone integration requires macOS/APFS")
    def test_clone_preserves_content_and_rejects_near_collision(self):
        content = bytes(range(256)) * 512
        changed = bytearray(content)
        changed[len(changed) // 4] ^= 1  # Beyond the quick hash and between sampled positions.
        origin = self.make_file("a-origin", content)
        near_collision = self.make_file("near-collision", bytes(changed))
        duplicate = self.make_file("z-duplicate", content)
        before = {
            path: (path.stat().st_ino, path.read_bytes())
            for path in [origin, near_collision, duplicate]
        }

        dry_run = self.run_dedup("-nPC", "-t2", "-F", "raw", "--", origin, near_collision, duplicate)
        self.assert_success(dry_run)
        if "cloning not supported" in dry_run.stderr:
            self.skipTest("temporary directory does not support cloning")
        dry_metrics = self.metrics(dry_run.stdout)
        self.assertEqual(dry_metrics["duplicates found"], "0")
        self.assertEqual(dry_metrics["bytes saved"], "0")
        self.assertEqual(dry_metrics["already saved"], "0")
        for path, original in before.items():
            self.assertEqual((path.stat().st_ino, path.read_bytes()), original)

        result = self.run_dedup("-P", "-t2", "-F", "raw", "--", origin, near_collision, duplicate)
        self.assert_success(result)
        metrics = self.metrics(result.stdout)
        self.assertEqual(metrics["duplicates found"], "1")
        self.assertEqual(metrics["bytes saved"], str(len(content)))
        for path in [origin, near_collision]:
            self.assertEqual((path.stat().st_ino, path.read_bytes()), before[path])
        self.assertEqual(duplicate.read_bytes(), content)
        self.assertNotEqual(duplicate.stat().st_ino, before[duplicate][0])
        self.assertEqual(duplicate.stat().st_nlink, 1)

    def test_no_progress_in_wide_terminal_with_long_paths(self):
        directory = Path("segment-" + "a" * 90) / ("segment-" + "b" * 90)
        directory /= "segment-" + "c" * 90
        origin = self.make_file(directory / "origin")
        duplicate = self.make_file(directory / "duplicate")
        for width in [80, 400]:
            with self.subTest(width=width):
                result = self.run_in_terminal("-nPvl", "-t2", "--", origin, duplicate, width=width)
                self.assert_success(result)
                self.assertIn("would deduplicate", result.stdout)
                self.assertNotIn("\x1b[", result.stdout)
                self.assertNotIn("TOTL", result.stdout)
                self.assertNotIn("QUED", result.stdout)

        result = self.run_in_terminal("-nvl", "-t2", "--", origin, duplicate, width=400)
        self.assert_success(result)
        self.assertIn("TOTL", result.stdout)
        self.assertIn("QUED", result.stdout)

    def test_repeated_input_never_replaces_itself(self):
        modes = [[], ["-l"], ["-s"]] if sys.platform == "darwin" else [["-l"], ["-s"]]
        for mode in modes:
            for threads in [0, 2]:
                for dry_run in [False, True]:
                    with self.subTest(mode=mode, threads=threads, dry_run=dry_run):
                        name = "repeated-" + "-".join(mode or ["clone"]) + str(threads) + str(dry_run)
                        path = self.make_file(Path(name) / "file")
                        directory_alias = self.directory / (name + "-alias")
                        directory_alias.symlink_to(path.parent, target_is_directory=True)
                        before = (path.stat().st_ino, path.read_bytes())
                        result = self.run_dedup(
                            "-nP" if dry_run else "-P", *mode, "-t", threads, "-F", "raw", "--",
                            path, path, str(path.parent) + "/./file", path.parent,
                            directory_alias / "file", path.relative_to(self.directory),
                        )
                        self.assert_success(result)
                        self.assertFalse(path.is_symlink())
                        self.assertEqual((path.stat().st_ino, path.read_bytes()), before)
                        metrics = self.metrics(result.stdout)
                        self.assertEqual(metrics["duplicates found"], "0")
                        self.assertEqual(metrics["bytes saved"], "0")
                        self.assertEqual(metrics["already saved"], "0")

    def test_overlapping_roots_count_each_duplicate_once(self):
        modes = [[], ["-l"], ["-s"]] if sys.platform == "darwin" else [["-l"], ["-s"]]
        content = b"duplicate data for overlapping roots\n" * 256
        for mode in modes:
            for threads in [0, 2]:
                for dry_run in [False, True]:
                    with self.subTest(mode=mode, threads=threads, dry_run=dry_run):
                        name = "overlap-" + "-".join(mode or ["clone"]) + str(threads) + str(dry_run)
                        origin = self.make_file(Path(name) / "a-origin", content)
                        duplicate = self.make_file(Path(name) / "nested" / "z-duplicate", content)
                        before = {
                            path: (path.stat().st_ino, path.read_bytes())
                            for path in [origin, duplicate]
                        }
                        result = self.run_dedup(
                            "-nP" if dry_run else "-P", *mode, "-t", threads, "-F", "raw", "--",
                            origin.parent, duplicate.parent, origin, duplicate, origin.parent,
                        )
                        self.assert_success(result)
                        metrics = self.metrics(result.stdout)
                        if not mode and "cloning not supported" in result.stderr:
                            continue
                        self.assertEqual(metrics["duplicates found"], "1")
                        self.assertEqual(metrics["bytes saved"], str(len(content)))
                        self.assertEqual(metrics["already saved"], "0")
                        for path, original in before.items():
                            self.assertEqual(path.read_bytes(), original[1])
                            if dry_run:
                                self.assertEqual(path.stat().st_ino, original[0])

    @unittest.skipUnless(sys.platform == "darwin", "ACL integration requires macOS")
    def test_readable_file_with_denied_attributes_and_overlapping_roots(self):
        content = b"readable data with restricted metadata\n" * 2048
        origin = self.make_file("acl/a-origin", content)
        duplicate = self.make_file("acl/nested/z-denied", content)
        before = {
            path: (path.stat().st_ino, path.read_bytes())
            for path in [origin, duplicate]
        }
        case_alias = duplicate.with_name(duplicate.name.upper())
        case_alias_supported = case_alias.exists() and case_alias.samefile(duplicate)
        user = pwd.getpwuid(os.getuid()).pw_name
        subprocess.run(
            ["/bin/chmod", "+a", f"{user} deny readattr,readextattr", str(duplicate)],
            check=True, capture_output=True, text=True,
        )
        self.addCleanup(subprocess.run, ["/bin/chmod", "-N", str(duplicate)],
                        capture_output=True, check=False)
        with self.assertRaises(PermissionError):
            duplicate.stat()
        aliases = [duplicate.parent, str(duplicate.parent) + "/../nested"]
        if case_alias_supported:
            aliases.append(duplicate.parent.with_name(duplicate.parent.name.upper()))
            with case_alias.open("rb") as stream:
                resolved = fcntl.fcntl(stream.fileno(), fcntl.F_GETPATH, bytes(1024))
                self.assertEqual(
                    os.fsdecode(resolved.split(b"\0", 1)[0]),
                    str(duplicate.parent.resolve() / duplicate.name),
                )
        for threads in [0, 2]:
            with self.subTest(threads=threads):
                result = self.run_dedup(
                    "-nP", "-t", threads, "-F", "raw", "--",
                    origin.parent, duplicate.parent, *aliases, origin.parent,
                )
                self.assert_success(result)
                if "cloning not supported" in result.stderr:
                    self.skipTest("temporary directory does not support cloning")
                self.assertEqual(self.metrics(result.stdout), {
                    "duplicates found": "1",
                    "entries pruned": "0",
                    "bytes saved": str(len(content)),
                    "already saved": "0",
                })
                for path, original in before.items():
                    with path.open("rb") as stream:
                        self.assertEqual((os.fstat(stream.fileno()).st_ino, stream.read()), original)

    def test_repeated_hardlink_paths_preserve_shared_storage_count(self):
        origin = self.make_file("hardlinks/origin", b"shared hardlink data\n" * 256)
        alias = origin.parent / "alias"
        os.link(origin, alias)
        before = (origin.stat().st_ino, origin.read_bytes())
        modes = [[], ["-l"], ["-s"]] if sys.platform == "darwin" else [["-l"], ["-s"]]
        for mode in modes:
            for threads in [0, 2]:
                for dry_run in [False, True]:
                    with self.subTest(mode=mode, threads=threads, dry_run=dry_run):
                        result = self.run_dedup(
                            "-nP" if dry_run else "-P", *mode, "-t", threads, "-F", "raw", "--",
                            origin.parent, origin, alias, origin.parent,
                        )
                        self.assert_success(result)
                        if not mode and "cloning not supported" in result.stderr:
                            continue
                        metrics = self.metrics(result.stdout)
                        self.assertEqual(metrics["duplicates found"], "0")
                        self.assertEqual(metrics["bytes saved"], "0")
                        self.assertEqual(metrics["already saved"], str(len(before[1])))
                        for path in [origin, alias]:
                            self.assertFalse(path.is_symlink())
                            self.assertEqual((path.stat().st_ino, path.read_bytes()), before)

    @unittest.skipUnless(sys.platform == "darwin", "clone integration requires macOS/APFS")
    def test_repeated_clone_paths_preserve_shared_storage_count(self):
        origin = self.make_file("clones/origin", bytes(range(256)) * 512)
        clone = origin.parent / "clone"
        clonefile = ctypes.CDLL(None, use_errno=True).clonefile
        clonefile.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32]
        clonefile.restype = ctypes.c_int
        if clonefile(os.fsencode(origin), os.fsencode(clone), 0) != 0:
            error = ctypes.get_errno()
            if error in [errno.ENOTSUP, errno.EXDEV]:
                self.skipTest("temporary directory does not support cloning")
            self.fail(f"clonefile fixture failed: {os.strerror(error)}")
        alias = origin.parent / "hardlink"
        os.link(origin, alias)
        before = {
            path: (path.stat().st_ino, path.read_bytes())
            for path in [origin, alias, clone]
        }
        self.assertNotEqual(origin.stat().st_ino, clone.stat().st_ino)
        for threads in [0, 2]:
            for dry_run in [False, True]:
                with self.subTest(threads=threads, dry_run=dry_run):
                    result = self.run_dedup(
                        "-nP" if dry_run else "-P", "-t", threads, "-F", "raw", "--",
                        origin.parent, origin, clone, alias, origin.parent,
                    )
                    self.assert_success(result)
                    metrics = self.metrics(result.stdout)
                    self.assertEqual(metrics["duplicates found"], "0")
                    self.assertEqual(metrics["bytes saved"], "0")
                    self.assertEqual(metrics["already saved"], str(2 * len(before[origin][1])))
                    for path, original in before.items():
                        self.assertEqual((path.stat().st_ino, path.read_bytes()), original)

    def test_parallel_matches_serial_with_pruned_hardlinks(self):
        content_a = b"first duplicate group\n" * 256
        content_b = b"other duplicate group\n" * 256
        origin = self.make_file("origin", content_a)
        alias = self.directory / "hardlink"
        os.link(origin, alias)
        paths = [
            origin,
            alias,
            self.make_file("duplicate-a1", content_a),
            self.make_file("duplicate-a2", content_a),
            self.make_file("origin-b", content_b),
            self.make_file("duplicate-b", content_b),
        ]
        expected = None
        for threads in [0, 1, 4]:
            with self.subTest(threads=threads):
                result = self.run_dedup("-nPl", "-F", "raw", "-t", threads, "--", *paths)
                self.assert_success(result)
                metrics = self.metrics(result.stdout)
                self.assertEqual(metrics["duplicates found"], "3")
                self.assertEqual(metrics["entries pruned"], "1")
                self.assertEqual(metrics["bytes saved"], str(2 * len(content_a) + len(content_b)))
                if expected is None:
                    expected = metrics
                else:
                    self.assertEqual(metrics, expected)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--binary", type=Path, default=BINARY)
    options, test_arguments = parser.parse_known_args()
    BINARY = options.binary.resolve()
    if not BINARY.is_file():
        parser.error(f"dedup binary not found: {BINARY}; build it first or pass --binary")
    unittest.main(argv=[sys.argv[0], *test_arguments])
