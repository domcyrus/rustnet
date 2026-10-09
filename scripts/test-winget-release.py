"""Exercise the published Windows installers without Npcap or a terminal."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import urllib.request
import winreg

import yaml

sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')
ARCH = sys.argv[1]
ROOT = Path('winget-test-results').resolve()
ROOT.mkdir(exist_ok=True)
MANIFEST = ROOT / 'manifest'
MANIFEST.mkdir(exist_ok=True)
REF = 'b3a0e2946f3e796308759fc6f8f2b06b9f70c6f5'
RESULTS = []


def download(url, path):
    with urllib.request.urlopen(url, timeout=90) as response:
        path.write_bytes(response.read())


def run(label, command, expected=0, files=False):
    print(f'{label}: {command}', flush=True)
    if files:
        stdout_path = ROOT / f'{label}.stdout.txt'
        stderr_path = ROOT / f'{label}.stderr.txt'
        with stdout_path.open('wb') as stdout, stderr_path.open('wb') as stderr:
            proc = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stdout,
                                  stderr=stderr, timeout=600, cwd=ROOT)
        stdout, stderr = stdout_path.read_bytes(), stderr_path.read_bytes()
    else:
        proc = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                              timeout=600, cwd=ROOT)
        stdout, stderr = proc.stdout, proc.stderr
        (ROOT / f'{label}.stdout.txt').write_bytes(stdout)
        (ROOT / f'{label}.stderr.txt').write_bytes(stderr)
    output = stdout.decode('utf-8', errors='replace')
    error = stderr.decode('utf-8', errors='replace')
    RESULTS.append({'test': label, 'command': command, 'exit_code': proc.returncode})
    (ROOT / 'results.json').write_text(json.dumps(RESULTS, indent=2))
    print(f'Exit: {proc.returncode}\n{output[:2000]}\n{error[:2000]}', flush=True)
    allowed = [expected] if isinstance(expected, int) else expected
    assert proc.returncode in allowed, f'{label}: unexpected exit {proc.returncode}'
    return output, error


def smoke(stage, exe):
    data = exe.read_bytes()
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    machine = struct.unpack_from('<H', data, pe + 4)[0]
    assert machine == {'x86': 0x14c, 'x64': 0x8664}[ARCH]
    for files in [False, True]:
        mode = 'files' if files else 'pipes'
        for flag in ['--version', '-V', '--help', '-h']:
            label = f'{stage}-{mode}-{flag.lstrip("-")}'
            output, error = run(label, [str(exe), flag], files=files)
            assert not error.strip(), f'{label}: stderr is not empty'
            if flag in ['--version', '-V']:
                assert output.strip() == 'rustnet 1.7.0', repr(output)
            else:
                assert '--headless' in output and '--interface' in output
        output, error = run(f'{stage}-{mode}-no-args', [str(exe)], expected=1, files=files)
        assert 'interactive mode requires a terminal' in error
        assert not output.strip()
    output, error = run(f'{stage}-missing-npcap', [str(exe), '--headless', '--duration', '1'], expected=1)
    assert 'npcap' in error.lower() and 'npcap.com' in error.lower(), error
    assert 'panicked' not in error.lower()
    found = []
    for view in [winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY]:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                           r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                           0, winreg.KEY_READ | view) as key:
            for i in range(winreg.QueryInfoKey(key)[0]):
                with winreg.OpenKey(key, winreg.EnumKey(key, i)) as entry:
                    try:
                        name = winreg.QueryValueEx(entry, 'DisplayName')[0]
                    except FileNotFoundError:
                        continue
                    if name.lower() == 'rustnet':
                        found.append({field: winreg.QueryValueEx(entry, field)[0]
                                      for field in ['DisplayName', 'DisplayVersion', 'Publisher']})
    assert found and all(x['DisplayVersion'] == '1.7.0' and x['Publisher'] == 'domcyrus' for x in found), found
    (ROOT / f'{stage}-registry.json').write_text(json.dumps(found, indent=2))


for suffix in ['installer.yaml', 'locale.en-US.yaml', 'yaml']:
    name = f'domcyrus.RustNet.{suffix}'
    url = f'https://raw.githubusercontent.com/domcyrus/winget-pkgs/{REF}/manifests/d/domcyrus/RustNet/1.7.0/{name}'
    download(url, MANIFEST / name)
manifest = yaml.safe_load((MANIFEST / 'domcyrus.RustNet.installer.yaml').read_text())
installer = next(item for item in manifest['Installers'] if item['Architecture'] == ARCH)
assert manifest['InstallationMetadata']['Files'][0]['InvocationParameter'] == '--version'
msi = ROOT / f'rustnet-{ARCH}.msi'
download(installer['InstallerUrl'], msi)
assert hashlib.sha256(msi.read_bytes()).hexdigest().upper() == installer['InstallerSha256']
for directory in ['System32', 'SysWOW64']:
    for name in ['wpcap.dll', 'Packet.dll', 'Npcap/wpcap.dll', 'Npcap/Packet.dll']:
        path = Path(os.environ['WINDIR']) / directory / name
        assert not path.exists(), f'Npcap/WinPcap is installed: {path}'
print('Verified installer hash and absence of Npcap/WinPcap DLLs', flush=True)
program_files = os.environ['ProgramFiles' if ARCH == 'x64' else 'ProgramFiles(x86)']
exe = Path(program_files) / 'Rustnet' / 'rustnet.exe'
assert not exe.exists(), f'RustNet already installed: {exe}'
winget = os.environ['WINGET_EXE']
run('winget-version', [winget, '--version'])
run('winget-validate', [winget, 'validate', '--manifest', str(MANIFEST)])
run('msi-install', ['msiexec.exe', '/i', str(msi), '/qn', '/norestart', '/L*v', str(ROOT / 'msi-install.log')], expected=[0, 3010])
smoke('msi', exe)
run('msi-uninstall', ['msiexec.exe', '/x', str(msi), '/qn', '/norestart', '/L*v', str(ROOT / 'msi-uninstall.log')], expected=[0, 3010])
assert not exe.exists()
run('winget-local-manifests', [winget, 'settings', '--enable', 'LocalManifestFiles'])
run('winget-install', [winget, 'install', '--manifest', str(MANIFEST), '--architecture', ARCH,
                       '--silent', '--disable-interactivity',
                       '--accept-source-agreements', '--accept-package-agreements', '--verbose-logs'])
smoke('winget', exe)
run('winget-uninstall', [winget, 'uninstall', '--name', 'Rustnet', '--exact', '--silent',
                         '--disable-interactivity', '--accept-source-agreements'])
assert not exe.exists()
summary = f'## Windows {ARCH} release validation\n\nPassed {len(RESULTS)} command checks against the published v1.7.0 MSI and PR commit `{REF}`.\n\n- MSI and winget installation/uninstallation passed.\n- Winget manifest validation passed.\n- Correct executable architecture and installed registry version.\n- Help/version succeeded with pipes and files, with no Npcap installed.\n- No-argument execution reproduced the validator terminal error.\n- Headless execution reported Npcap installation instructions.\n'
(ROOT / 'summary.md').write_text(summary)
with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as target:
    target.write(summary)
