#!/usr/bin/env python3
"""Build a deterministic binary distribution and SHA-256 checksums offline."""
import hashlib
from pathlib import Path
import re
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
version = re.search(r'VERSION = "([^"]+)"', (ROOT / 'src/main/java/com/nullfuscator/obf/core/BuildInfo.java').read_text()).group(1)
destination = ROOT / 'build/release'
destination.mkdir(parents=True, exist_ok=True)
jar = destination / f'nullfuscator-{version}.jar'
subprocess.run([sys.executable, str(ROOT / 'scripts/build.py'), '--output', str(jar)], check=True)
files = {jar.name: jar, **{p.name: p for p in (ROOT / 'LICENSE', ROOT / 'THIRD_PARTY_NOTICES.md', ROOT / 'README.md', ROOT / 'CHANGELOG.md')}}
for folder in ('bin', 'config', 'licenses', 'docs'):
    for path in sorted((ROOT / folder).rglob('*')):
        if path.is_file():
            files[path.relative_to(ROOT).as_posix()] = path
archive = destination / f'nullfuscator-{version}.zip'
with zipfile.ZipFile(archive, 'w') as output:
    for name, path in sorted(files.items()):
        entry = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
        entry.create_system = 3
        entry.external_attr = (0o100755 << 16) if path.name == 'nullfuscator' else (0o100644 << 16)
        output.writestr(entry, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
(destination / 'SHA256SUMS').write_text(''.join(
    hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.name + '\n' for p in (jar, archive)), encoding='utf-8')
print(f'Release files: {destination}')
