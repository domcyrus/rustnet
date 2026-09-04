#!/usr/bin/env python3
"""Validate the opt-in Linux example and inspect built DEB, RPM and tar assets."""

import argparse
import configparser
import gzip
import io
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parent.parent
UNIT = Path("resources/packaging/linux/systemd/rustnet-headless.service")
DOCS = ("SERVICE.md", "SERVICE.zh-CN.md", "SERVICE.ja.md")
PAYLOADS = (*DOCS, str(UNIT))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def output(*command):
    return subprocess.check_output(command)


def check_sources():
    unit = configparser.ConfigParser(interpolation=None, strict=True)
    unit.optionxform = str
    unit.read(ROOT / UNIT)
    expected = {
        "User": "root",
        "UnsetEnvironment": "SUDO_UID SUDO_GID SUDO_USER",
        "ExecStart": "/usr/bin/rustnet --headless --interface any --refresh-interval 5000 --output jsonl",
        "KillSignal": "SIGTERM",
        "TimeoutStopSec": "30s",
        "UMask": "0077",
        "StateDirectory": "rustnet",
        "StateDirectoryMode": "0700",
        "StandardOutput": "append:/var/lib/rustnet/headless.jsonl",
        "StandardError": "journal",
        "CapabilityBoundingSet": "CAP_NET_RAW CAP_BPF CAP_PERFMON CAP_SETUID CAP_SETGID",
        "AmbientCapabilities": "CAP_SETUID",
        "NoNewPrivileges": "yes",
        "PrivateTmp": "yes",
        "ProtectHome": "yes",
        "ProtectSystem": "strict",
        "ReadWritePaths": "/var/lib/rustnet",
    }
    for key, value in expected.items():
        require(unit["Service"].get(key) == value, f"unexpected systemd {key}")
    require("--no-sandbox" not in unit["Service"]["ExecStart"], "sandbox disabled")
    require("--no-uid-drop" not in unit["Service"]["ExecStart"], "UID drop disabled")

    metadata = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["metadata"]
    for package_format in ("deb", "generate-rpm"):
        entries = metadata[package_format]["assets"]
        assets = {
            entry["source"] if isinstance(entry, dict) else entry[0]: entry
            for entry in entries
        }
        for source in PAYLOADS:
            require(source in assets, f"{package_format} omits {source}")
            entry = assets[source]
            dest = entry["dest"] if isinstance(entry, dict) else entry[1]
            mode = entry["mode"] if isinstance(entry, dict) else entry[2]
            require(dest.lstrip("/").startswith("usr/share/doc/"), f"active asset: {dest}")
            require(mode == "644", f"unsafe documentation mode: {source}")
        for source, entry in assets.items():
            if source.endswith(".service"):
                dest = entry["dest"] if isinstance(entry, dict) else entry[1]
                require("/share/doc/" in dest, f"active service installed: {dest}")

    require(str(UNIT) in (ROOT / "debian/examples").read_text().splitlines(), "Debian example missing")
    for name in DOCS:
        require(name in (ROOT / "debian/docs").read_text().splitlines(), f"Debian omits {name}")
        require((ROOT / name).is_file(), f"missing {name}")
        require("sudo install -d -m 0700 -o root -g root /var/lib/rustnet" in (ROOT / name).read_text(), f"{name} omits first-start directory setup")
    spec = (ROOT / "rpm/rustnet.spec").read_text()
    require(f"%doc {UNIT}" in spec, "native RPM example is not documentation")
    require("%doc " + " ".join(DOCS) in spec, "native RPM translations missing")
    require("STOPSIGNAL SIGTERM" in (ROOT / "Dockerfile").read_text(), "Docker stop signal missing")

    if shutil.which("systemd-analyze"):
        with tempfile.TemporaryDirectory(prefix="rustnet-unit-") as directory:
            path = Path(directory) / UNIT.name
            # Validate directives even where the built executable is not installed.
            path.write_text((ROOT / UNIT).read_text().replace("ExecStart=/usr/bin/rustnet", "ExecStart=/bin/true"))
            subprocess.run(["systemd-analyze", "verify", str(path)], check=True)


def tar_members(data):
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        return {
            member.name.removeprefix("./"): (member.mode, archive.extractfile(member).read())
            for member in archive.getmembers()
            if member.isfile()
        }


def check_contents(members, label, package):
    for name in members:
        require(".." not in PurePosixPath(name).parts, f"unsafe path in {label}: {name}")
        if package and name.endswith(".service"):
            require(name.lstrip("/").startswith("usr/share/doc/"), f"active service in {label}: {name}")
    for source in PAYLOADS:
        name = Path(source).name
        candidates = [key for key in members if PurePosixPath(key).name in (name, name + ".gz")]
        require(len(candidates) == 1, f"{label} must contain exactly one {name}")
        key = candidates[0]
        mode, contents = members[key]
        require(stat.S_IMODE(mode) == 0o644, f"wrong mode in {label}: {key}")
        if key.endswith(".gz"):
            contents = gzip.decompress(contents)
        require(contents == (ROOT / source).read_bytes(), f"stale {name} in {label}")
        if package:
            require(key.lstrip("/").startswith("usr/share/doc/"), f"non-documentation payload: {key}")


def check_scripts(contents, label):
    text = contents.decode(errors="replace")
    require(
        not re.search(r"\b(?:systemctl|invoke-rc\.d|deb-systemd-invoke)\b[^\n]*rustnet-headless", text),
        f"{label} mutates the example service",
    )


def check_artifact(path):
    path = path.resolve()
    if path.suffix == ".deb":
        members = tar_members(output("dpkg-deb", "--fsys-tarfile", str(path)))
        check_contents(members, path.name, package=True)
        for name, (_, contents) in tar_members(output("dpkg-deb", "--ctrl-tarfile", str(path))).items():
            if name in ("preinst", "postinst", "prerm", "postrm"):
                check_scripts(contents, path.name)
    elif path.suffix == ".rpm":
        listing = output("rpm", "-qp", "--qf", "[%{FILENAMES}\t%{FILEMODES}\n]", str(path)).decode()
        cpio = output("rpm2cpio", str(path))
        members = {}
        for line in listing.splitlines():
            name, mode = line.split("\t")
            require(".." not in PurePosixPath(name).parts, f"unsafe RPM path: {name}")
            if name.endswith(".service") or PurePosixPath(name).name in DOCS:
                contents = subprocess.check_output(
                    ["cpio", "--extract", "--to-stdout", "--quiet", "." + name, name], input=cpio
                )
                members[name] = (int(mode), contents)
        check_contents(members, path.name, package=True)
        check_scripts(output("rpm", "-qp", "--scripts", str(path)), path.name)
    elif path.name.endswith(".tar.gz"):
        check_contents(tar_members(path.read_bytes()), path.name, package=False)
    else:
        raise ValueError(f"unsupported artifact: {path}")
    print(f"verified {path.name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", nargs="*", type=Path)
    args = parser.parse_args()
    check_sources()
    for path in args.artifacts:
        check_artifact(path)
    print("Linux service packaging checks passed")


if __name__ == "__main__":
    main()
