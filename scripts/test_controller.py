#!/usr/bin/env python3
"""Compile and run headless controller state checks. No admin or network access."""
from pathlib import Path
import platform
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="netmoat-controller-tests-") as folder:
    executable = Path(folder) / "controller-tests"
    architecture = "arm64" if platform.machine() == "arm64" else "x86_64"
    subprocess.run(["/usr/bin/xcrun", "swiftc", "-parse-as-library", "-swift-version", "5",
                    "-DNETMOAT_TESTS", "-target", architecture + "-apple-macosx14.0",
                    str(root / "gui/NetMoat.swift"), str(root / "tests/controller_tests.swift"),
                    "-o", str(executable), "-framework", "SwiftUI", "-framework", "AppKit"], check=True)
    subprocess.run([str(executable)], check=True)
