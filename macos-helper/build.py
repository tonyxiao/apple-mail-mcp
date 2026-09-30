#!/usr/bin/env python3
"""Compile an app hosting the selected CPython runtime in its native process."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import plistlib
import shlex
import shutil
import subprocess
import tempfile

IDENTIFIER = "com.tonyxiao.apple-mayo-mcp"
ROOT = Path(__file__).resolve().parent
QUERY = """
import json, sys, sysconfig
keys = ['INCLUDEPY', 'LIBDIR', 'LDLIBRARY', 'LIBS', 'SYSLIBS', 'PYTHONFRAMEWORK', 'DESTSHARED']
data = {key: sysconfig.get_config_var(key) for key in keys}
data.update(stdlib=sysconfig.get_path('stdlib'), prefix=sys.base_prefix)
print(json.dumps(data))
"""


def build(python: Path, site_packages: Path, output: Path) -> None:
    if not python.is_absolute() or not site_packages.is_absolute() or not output.is_absolute():
        raise ValueError("python, site-packages and output must be absolute paths")
    if not site_packages.is_dir() or not (site_packages / "email_mcp").is_dir():
        raise ValueError("site-packages must contain the installed email_mcp package (not editable .pth)")
    if output.exists() or output.is_symlink():
        raise ValueError("output already exists; build a new app before replacing an installed app")
    config = json.loads(subprocess.check_output([str(python), "-I", "-c", QUERY], text=True))
    stdlib = Path(config["stdlib"])
    dynload = Path(config["DESTSHARED"] or stdlib / "lib-dynload")
    if not (stdlib / "encodings").is_dir() or not dynload.is_dir():
        raise ValueError("selected Python must provide a stdlib and lib-dynload directory")
    if config["PYTHONFRAMEWORK"]:
        library = Path(config["prefix"]) / config["PYTHONFRAMEWORK"]
    else:
        library = Path(config["LIBDIR"]) / config["LDLIBRARY"]
    if not library.is_file():
        raise ValueError("selected Python does not expose an embeddable framework or shared library")
    contents = output / "Contents"
    macos = contents / "MacOS"
    macos.mkdir(parents=True)
    (contents / "Info.plist").write_bytes((ROOT / "Info.plist.in").read_bytes())
    compiler = shlex.split(os.environ.get("CC", "cc"))
    with tempfile.TemporaryDirectory(prefix="apple-mail-helper-build-") as scratch:
        header = Path(scratch) / "runtime.h"
        header.write_text("\n".join(
            f"#define {key} {json.dumps(str(value))}" for key, value in {
                "HELPER_PYTHON_HOME": config["prefix"],
                "HELPER_STDLIB": stdlib, "HELPER_DYNLOAD": dynload,
                "HELPER_SITE_PACKAGES": site_packages,
            }.items()) + "\n")
        subprocess.run(compiler + ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
            "-I" + config["INCLUDEPY"], "-I" + scratch, str(ROOT / "launcher.c"),
            str(library), "-Wl,-rpath," + str(library.parent),
            *shlex.split(config["LIBS"] or ""), *shlex.split(config["SYSLIBS"] or ""),
            "-o", str(macos / "apple-mayo-mcp")], check=True)
        # Ad-hoc CPython and wheel extensions have no shared Apple Team ID.
        # Keep hardened DYLD environment restrictions; relax only team validation.
        entitlements = Path(scratch) / "entitlements.plist"
        entitlements.write_bytes(plistlib.dumps({
            "com.apple.security.cs.disable-library-validation": True,
        }))
        signer = shutil.which("codesign") or "/usr/bin/codesign"
        subprocess.run([signer, "--force", "--sign", "-", "--identifier", IDENTIFIER,
                        "--options", "runtime", "--entitlements", str(entitlements),
                        "--timestamp=none", str(output)], check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--site-packages", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build(args.python, args.site_packages, args.output)


if __name__ == "__main__":
    main()
