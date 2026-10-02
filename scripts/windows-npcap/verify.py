"""Windows-only Npcap runtime regression checks. See README.md for prerequisites."""

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import time


DLLS = ("Packet.dll", "wpcap.dll")


def pe_machine(path):
    with open(path, "rb") as stream:
        if stream.read(2) != b"MZ":
            raise RuntimeError(f"Not a PE image: {path}")
        stream.seek(0x3C)
        offset = struct.unpack("<I", stream.read(4))[0]
        stream.seek(offset)
        if stream.read(4) != b"PE\0\0":
            raise RuntimeError(f"Invalid PE signature: {path}")
        return struct.unpack("<H", stream.read(2))[0]


def windows_api():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel.GetSystemDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    kernel.GetSystemDirectoryW.restype = wintypes.UINT
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    psapi.EnumProcessModules.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    psapi.EnumProcessModules.restype = wintypes.BOOL
    psapi.GetModuleFileNameExW.argtypes = [
        wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD,
    ]
    psapi.GetModuleFileNameExW.restype = wintypes.DWORD
    return kernel, psapi


def module_paths(kernel, psapi, handle):
    modules = (wintypes.HMODULE * 2048)()
    needed = wintypes.DWORD()
    if not psapi.EnumProcessModules(handle, modules, ctypes.sizeof(modules),
                                    ctypes.byref(needed)):
        raise ctypes.WinError(ctypes.get_last_error())
    if needed.value > ctypes.sizeof(modules):
        raise RuntimeError("Module enumeration buffer is too small")
    paths = set()
    for module in modules[:needed.value // ctypes.sizeof(wintypes.HMODULE)]:
        name = ctypes.create_unicode_buffer(32768)
        length = psapi.GetModuleFileNameExW(handle, module, name, len(name))
        if not length or length >= len(name):
            raise ctypes.WinError(ctypes.get_last_error())
        paths.add(os.path.normcase(os.path.realpath(name.value)))
    return paths


def run_case(kernel, psapi, executable, root, marker, expected, state,
             placement, names, arguments):
    label = f"{placement}-{'-'.join(names) or 'clean'}-{arguments[0][2:]}"
    case = root / label
    app, cwd, path = (case / name for name in ("app", "cwd", "path"))
    for directory in (app, cwd, path):
        directory.mkdir(parents=True)
    program = app / "rustnet.exe"
    shutil.copy2(executable, program)
    locations = {"app": app, "cwd": cwd, "path": path}
    for location in (locations.values() if placement == "all"
                     else [locations.get(placement)]):
        if location:
            for name in names:
                shutil.copy2(marker, location / name)
    signal = case / "marker.txt"
    environment = dict(os.environ, RUSTNET_DLL_MARKER=str(signal))
    environment["PATH"] = str(path) + os.pathsep + environment.get("PATH", "")
    seen = set()
    with open(case / "stdout.txt", "wb") as stdout, \
            open(case / "stderr.txt", "wb") as stderr:
        process = subprocess.Popen([str(program), *arguments], cwd=cwd,
                                   env=environment, stdout=stdout, stderr=stderr)
        handle = kernel.OpenProcess(0x0400 | 0x0010, False, process.pid)
        try:
            if not handle and process.poll() is None:
                raise ctypes.WinError(ctypes.get_last_error())
            deadline = time.monotonic() + 30
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"{label}: startup/shutdown timed out")
                if handle:
                    try:
                        seen.update(module_paths(kernel, psapi, handle))
                    except OSError:
                        # The loader can change the module list during startup
                        # or exit. Successful startup must still yield both DLLs.
                        pass
                time.sleep(0.01)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
            if handle:
                kernel.CloseHandle(handle)
    (case / "modules.json").write_text(json.dumps(sorted(seen), indent=2))
    validate_result({
        "label": label,
        "marker_executed": signal.exists(),
        "modules": seen,
        "returncode": process.returncode,
        "stdout": (case / "stdout.txt").read_text(encoding="utf-8", errors="replace"),
        "stderr": (case / "stderr.txt").read_text(encoding="utf-8", errors="replace"),
    }, expected, state, arguments)
    print(f"PASS {label}", flush=True)


def validate_result(result, expected, state, arguments):
    label = result["label"]
    if result["marker_executed"]:
        raise RuntimeError(f"{label}: marker DLL executed")
    npcap = {name: {p for p in result["modules"] if Path(p).name.lower() == name.lower()}
             for name in DLLS}
    for name, paths in npcap.items():
        if paths - {expected[name]}:
            raise RuntimeError(f"{label}: unexpected {name} module: {paths}")
    if arguments[0] in ("--help", "--version"):
        if result["returncode"] or any(npcap.values()):
            raise RuntimeError(f"{label}: help/version failed or loaded Npcap")
    elif state == "absent":
        if result["returncode"] == 0 or "Npcap is not installed" not in result["stderr"]:
            raise RuntimeError(f"{label}: expected the missing Npcap diagnostic")
        if any(npcap.values()):
            raise RuntimeError(f"{label}: Npcap loaded on the absent-runtime host")
    else:
        if result["returncode"] or any(not paths for paths in npcap.values()):
            raise RuntimeError(f"{label}: capture failed or both modules were not observed")
        snapshot = json.loads(result["stdout"])
        runtime = snapshot.get("runtime", {})
        if (snapshot.get("type") != "snapshot" or runtime.get("status") != "stopped"
                or runtime.get("capture_status") != "healthy"):
            raise RuntimeError(f"{label}: expected a completed headless snapshot")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("--npcap", choices=("installed", "absent"), required=True)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("Run on Windows with Python and MSVC matching the executable architecture")
    executable = args.executable.resolve(strict=True)
    if pe_machine(executable) != pe_machine(sys.executable):
        parser.error("Python and rustnet.exe must have the same PE architecture")
    kernel, psapi = windows_api()
    system = ctypes.create_unicode_buffer(32768)
    length = kernel.GetSystemDirectoryW(system, len(system))
    if not length or length >= len(system):
        raise ctypes.WinError(ctypes.get_last_error())
    expected = {name: os.path.normcase(os.path.realpath(Path(system.value) / "Npcap" / name))
                for name in DLLS}
    for name, path in expected.items():
        if Path(path).exists() != (args.npcap == "installed"):
            parser.error(f"{name} does not match --npcap {args.npcap}: {path}")

    # Keep evidence after failures and successes. Never change system DLLs.
    root = Path(tempfile.mkdtemp(prefix="rustnet-npcap-"))
    print(f"Evidence: {root}", flush=True)
    (root / "build.json").write_text(json.dumps({
        "executable": str(executable),
        "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "windows": sys.getwindowsversion().platform_version,
        "npcap": args.npcap,
        "expected_modules": expected,
        "module_sha256": {name: hashlib.sha256(Path(path).read_bytes()).hexdigest()
                          for name, path in expected.items() if Path(path).exists()},
    }, indent=2))
    imports = subprocess.run(["dumpbin", "/imports", str(executable)],
                             capture_output=True, text=True, check=True).stdout
    (root / "imports.txt").write_text(imports)
    validator = (Path(__file__).resolve().parents[2]
                 / ".github/actions/build-rustnet/verify_windows_imports.py")
    subprocess.run([sys.executable, "-B", str(validator)], input=imports,
                   text=True, check=True)
    marker = root / "marker.dll"
    source = Path(__file__).with_name("marker.c").resolve()
    subprocess.run(["cl", "/nologo", "/LD", "/MT", str(source),
                    f"/Fe{marker}", f"/Fo{root / 'marker.obj'}"], cwd=root, check=True)
    if pe_machine(marker) != pe_machine(executable):
        raise RuntimeError("Use an MSVC developer prompt matching rustnet.exe architecture")
    signal = root / "positive-control.txt"
    subprocess.run([sys.executable, "-c", "import ctypes,sys; ctypes.WinDLL(sys.argv[1])",
                    str(marker)], env=dict(os.environ, RUSTNET_DLL_MARKER=str(signal)),
                   check=True, timeout=10)
    if not signal.exists():
        raise RuntimeError("Marker positive control failed")

    capture = ["--headless", "--duration", "3", "--output", "json",
               "--no-geoip", "--no-resolve-dns"]
    cases = [("clean", (), capture)]
    for placement in ("app", "cwd", "path", "all"):
        for names in (("wpcap.dll",), ("Packet.dll",), DLLS):
            cases.append((placement, names, capture))
    cases.extend(("all", DLLS, [flag]) for flag in ("--help", "--version"))
    failures = []
    for placement, names, arguments in cases:
        try:
            run_case(kernel, psapi, executable, root, marker, expected, args.npcap,
                     placement, names, arguments)
        except (OSError, RuntimeError, ValueError) as error:
            failures.append(str(error))
            print(f"FAIL {error}", flush=True)
    (root / "result.json").write_text(json.dumps({"failures": failures}, indent=2))
    return bool(failures)


if __name__ == "__main__":
    sys.exit(main())
