#!/usr/bin/env python3
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def build(output):
    dependencies = sorted((ROOT / "libs").glob("*.jar"))
    if not dependencies:
        raise RuntimeError("Missing dependencies: expected JARs in libs/")
    pinned = dict(line.split()[::-1] for line in (ROOT / "libs/SHA256SUMS").read_text().splitlines())
    if {p.name for p in dependencies} != set(pinned):
        raise RuntimeError("Dependency inventory differs from libs/SHA256SUMS")
    for dependency in dependencies:
        if hashlib.sha256(dependency.read_bytes()).hexdigest() != pinned[dependency.name]:
            raise RuntimeError(f"Dependency checksum mismatch: {dependency.name}")
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".nullfuscator-build-", dir=output.parent) as directory:
        work = Path(directory)
        classes = work / "classes"
        classes.mkdir()
        sources = sorted((ROOT / "src/main/java").rglob("*.java"))
        args = ["--release", "17", "-encoding", "UTF-8", "-cp",
                os.pathsep.join(map(str, dependencies)), "-d", str(classes), *map(str, sources)]
        argfile = work / "javac.args"
        argfile.write_text("\n".join('"' + a.replace("\\", "\\\\").replace('"', '\\"') + '"'
                                     for a in args), encoding="utf-8")
        subprocess.run(["javac", "@" + str(argfile)], check=True, cwd=ROOT)
        entries = {}
        for dependency in dependencies:
            with zipfile.ZipFile(dependency) as jar:
                for item in jar.infolist():
                    name = item.filename
                    upper = name.upper()
                    if item.is_dir() or upper == "META-INF/MANIFEST.MF" or name == "module-info.class":
                        continue
                    if upper.startswith("META-INF/") and (upper.endswith((".SF", ".RSA", ".DSA", ".EC"))
                                                           or upper.startswith("META-INF/SIG-")):
                        continue
                    data = jar.read(item)
                    if name in entries and entries[name] != data:
                        raise RuntimeError(f"Conflicting dependency resource: {name}")
                    entries[name] = data
        for path in sorted(classes.rglob("*.class")):
            name = path.relative_to(classes).as_posix()
            if name in entries:
                raise RuntimeError(f"Application/dependency class collision: {name}")
            entries[name] = path.read_bytes()
        for resource in [ROOT / "LICENSE", ROOT / "THIRD_PARTY_NOTICES.md", *sorted((ROOT / "licenses").glob("*.txt"))]:
            entries["META-INF/" + resource.relative_to(ROOT).as_posix()] = resource.read_bytes()
        for preset in sorted((ROOT / "config").glob("*.hocon")):
            entries["presets/" + preset.name] = preset.read_bytes()
        manifest = b"Manifest-Version: 1.0\r\nMain-Class: com.nullfuscator.obf.core.Main\r\n\r\n"
        staged = work / "obfuscator.jar"
        with zipfile.ZipFile(staged, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as jar:
            for name, data in [("META-INF/MANIFEST.MF", manifest), *sorted(entries.items())]:
                entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                entry.create_system = 3
                entry.external_attr = 0o100644 << 16
                jar.writestr(entry, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        os.replace(staged, output)
    print(f"Built {output}")
    print(f"SHA-256 {hashlib.sha256(output.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "build/nullfuscator-obf.jar")
    build(parser.parse_args().output)
