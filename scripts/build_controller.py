#!/usr/bin/env python3
"""Build the local control app in one canonical location, with a custom icon."""
import argparse
from pathlib import Path
import plistlib
import platform
import shutil
import subprocess
import sys
import tempfile


def run(*args):
    subprocess.run([str(arg) for arg in args], check=True, stdout=subprocess.DEVNULL)


def build(output, replace=False):
    if sys.platform != "darwin":
        raise RuntimeError("The control app can only be built on macOS")
    root = Path(__file__).resolve().parents[1]
    output = output.expanduser().absolute()
    if output.suffix != ".app" or output.is_symlink():
        raise ValueError("Choose a regular .app destination")
    if output.exists():
        if not replace:
            raise FileExistsError("App already exists; use --replace after reviewing it")
        info = plistlib.loads((output / "Contents/Info.plist").read_bytes())
        if info.get("CFBundleIdentifier") != "io.github.lucasuiii.netmoat.controller":
            raise ValueError("Refusing to replace an app with a different identity")
    with tempfile.TemporaryDirectory(prefix="netmoat-controller-") as temp:
        temp = Path(temp)
        app = temp / "NetMoat.app"
        (app / "Contents/MacOS").mkdir(parents=True)
        (app / "Contents/Resources").mkdir()
        architecture = "arm64" if platform.machine() == "arm64" else "x86_64"
        run("/usr/bin/xcrun", "swiftc", "-parse-as-library", "-swift-version", "5",
            "-target", architecture + "-apple-macosx14.0", "-O",
            root / "gui/NetMoat.swift", "-o", app / "Contents/MacOS/NetMoat",
            "-framework", "SwiftUI", "-framework", "AppKit")
        iconset = temp / "NetMoat.iconset"
        iconset.mkdir()
        for points in [16, 32, 128, 256, 512]:
            for scale in [1, 2]:
                pixels = points * scale
                name = "icon_%dx%d%s.png" % (points, points, "@2x" if scale == 2 else "")
                run("/usr/bin/sips", "-z", pixels, pixels, root / "assets/netmoat-icon.png",
                    "--out", iconset / name)
        resources = app / "Contents/Resources"
        run("/usr/bin/iconutil", "-c", "icns", iconset, "-o", resources / "NetMoat.icns")
        path = app / "Contents/Info.plist"
        info = {"CFBundleIdentifier": "io.github.lucasuiii.netmoat.controller",
                     "CFBundleName": "NetMoat", "CFBundleDisplayName": "NetMoat",
                     "CFBundleExecutable": "NetMoat", "CFBundlePackageType": "APPL",
                     "CFBundleIconFile": "NetMoat.icns", "CFBundleVersion": "4",
                     "CFBundleShortVersionString": "0.4.0", "NSHighResolutionCapable": True,
                     "CFBundleDevelopmentRegion": "zh-Hans", "LSMinimumSystemVersion": "14.0",
                     "NSSystemAdministrationUsageDescription": "Manage the NetMoat network protection service."}
        path.write_bytes(plistlib.dumps(info))
        run("/usr/bin/codesign", "--force", "--deep", "--sign", "-", app)
        run("/usr/bin/codesign", "--verify", "--deep", "--strict", app)
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.exists():
            shutil.rmtree(output)
        shutil.copytree(app, output)
    print(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path.home() / "Applications/NetMoat.app")
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    build(args.output, args.replace)


if __name__ == "__main__":
    main()
