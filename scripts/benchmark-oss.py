#!/usr/bin/env python3
"""Benchmark NULLFUSCATOR and three open-source JVM obfuscators on one corpus.

The corpus is recreated from the repository's historical, source-only test
fixture at COMMIT.  Third-party tools are deliberately passed in as paths, so
the benchmark never silently changes the version being measured.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "c7c31fe4d8f384eb4e84502d4ea1aabbb1bc6020"
MAIN_CLASS = "com.math.matrix.MatrixSimdApp"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def median(values):
    return statistics.median(values)


def command_version(command):
    result = subprocess.run(command, text=True, capture_output=True)
    return (result.stdout + result.stderr).strip().splitlines()[0]


def run_measured(command, output, cwd, timeout):
    """Run a process and sample the aggregate RSS of it and its descendants."""
    started = time.perf_counter()
    with output.open("wb") as stream:
        process = subprocess.Popen(command, cwd=cwd, stdout=stream,
                                   stderr=subprocess.STDOUT)
        peak_kib = 0
        while process.poll() is None:
            pids, pending = {process.pid}, [process.pid]
            while pending:
                parent = pending.pop()
                try:
                    children = (Path("/proc") / str(parent) / "task" / str(parent) /
                                "children").read_text().split()
                    for child in map(int, children):
                        if child not in pids:
                            pids.add(child)
                            pending.append(child)
                except (FileNotFoundError, ProcessLookupError):
                    pass
            current_kib = 0
            for pid in pids:
                try:
                    for line in (Path("/proc") / str(pid) / "status").read_text(
                            encoding="ascii").splitlines():
                        if line.startswith("VmRSS:"):
                            current_kib += int(line.split()[1])
                            break
                except (FileNotFoundError, ProcessLookupError):
                    pass
            peak_kib = max(peak_kib, current_kib)
            time.sleep(0.01)
        code = process.wait()
    return {"exitCode": code, "seconds": time.perf_counter() - started,
            "peakRssMiB": peak_kib / 1024.0}


def historic_corpus(destination):
    """Merge all historic generated classes into the exact 1,233-class fixture."""
    listing = subprocess.check_output(
        ["git", "ls-tree", "-r", "--name-only", COMMIT, "--", "JarTest/gen_src"],
        cwd=ROOT, text=True).splitlines()
    classes = [item for item in listing if "/build/" in item and item.endswith(".class")]
    if len(classes) != 1233:
        raise RuntimeError(f"Expected 1233 historical classes, found {len(classes)}")
    manifest = "Manifest-Version: 1.0\r\nMain-Class: " + MAIN_CLASS + "\r\n\r\n"
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.writestr("META-INF/MANIFEST.MF", manifest)
        names = set()
        for source in classes:
            name = source.split("/build/", 1)[1]
            if name in names:
                raise RuntimeError(f"Duplicate class entry in corpus: {name}")
            names.add(name)
            archive.writestr(name, subprocess.check_output(
                ["git", "show", f"{COMMIT}:{source}"], cwd=ROOT))
    return {"classCount": len(classes), "sha256": sha256(destination),
            "bytes": destination.stat().st_size}


def class_names(path):
    with zipfile.ZipFile(path) as archive:
        return {name[:-6] for name in archive.namelist() if name.endswith(".class")}


def string_constants(data):
    if data[:4] != b"\xca\xfe\xba\xbe":
        return set()
    count = int.from_bytes(data[8:10], "big")
    pos, utf8, string_references, index = 10, {}, [], 1
    while index < count:
        tag = data[pos]
        pos += 1
        if tag == 1:
            length = int.from_bytes(data[pos:pos + 2], "big")
            pos += 2
            value = data[pos:pos + length]
            pos += length
            try:
                text = value.decode("utf-8")
                utf8[index] = text
            except UnicodeDecodeError:
                pass
        elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
            pos += 4
        elif tag in (5, 6):
            pos += 8
            index += 1
        elif tag == 8:
            string_references.append(int.from_bytes(data[pos:pos + 2], "big"))
            pos += 2
        elif tag in (7, 16, 19, 20):
            pos += 2
        elif tag == 15:
            pos += 3
        else:
            raise ValueError(f"Unknown class constant-pool tag {tag}")
        index += 1
    return {utf8[item] for item in string_references
            if item in utf8 and len(utf8[item]) >= 4}


def strings(path):
    result = set()
    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            if name.endswith(".class"):
                result.update(string_constants(archive.read(name)))
    return result


def validate(output, expected):
    if not output.is_file() or not zipfile.is_zipfile(output):
        return {"verified": False, "reason": "tool did not write a readable JAR"}
    result = subprocess.run(["java", "-Xverify:all", "-jar", str(output)],
                            text=True, capture_output=True, timeout=90)
    # The fixture emits elapsed timings.  They are intentionally excluded from
    # the semantic oracle; deterministic results remain compared byte-for-byte.
    stable = lambda text: "\n".join(line for line in text.splitlines()
                                    if "Standard:" not in line and "Blocked:" not in line)
    actual = stable(result.stdout)
    semantic = (result.returncode == 0 and actual == stable(expected))
    return {"verified": semantic, "exitCode": result.returncode,
            "stdoutSha256": hashlib.sha256(actual.encode()).hexdigest(),
            "stderr": result.stderr[-2000:] if not semantic else ""}


def write_proguard(path, corpus, output, java_home):
    path.write_text("\n".join([
        f"-injars {corpus}", f"-outjars {output}",
        f"-libraryjars {java_home / 'jmods/java.base.jmod'}(!**.jar;!module-info.class)",
        "-dontshrink", "-dontoptimize", "-dontwarn", "-ignorewarnings",
        f"-keep public class {MAIN_CLASS} {{ public static void main(java.lang.String[]); }}",
        "-keepattributes *", "-printmapping proguard.map",
    ]) + "\n", encoding="utf-8")


def write_yguard(path, corpus, output, yguard, ant):
    path.write_text(f'''<project default="obfuscate">
  <taskdef name="yguard" classname="com.yworks.yguard.YGuardTask" classpath="{yguard}"/>
  <target name="obfuscate">
    <yguard><inoutpair in="{corpus}" out="{output}"/>
      <rename mainclass="{MAIN_CLASS}" logfile="yguard-renaming.xml"><keep>
        <method name="void main(java.lang.String[])" class="{MAIN_CLASS}"/>
      </keep></rename>
    </yguard>
  </target>
</project>\n''', encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skidfuscator", type=Path, required=True)
    parser.add_argument("--skid-java", type=Path, required=True,
                        help="Java 17 executable; Skidfuscator CE needs matching jmods")
    parser.add_argument("--skid-jmods", type=Path, required=True)
    parser.add_argument("--proguard", type=Path, required=True)
    parser.add_argument("--yguard", type=Path, required=True)
    parser.add_argument("--ant", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=4)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--artifacts-dir", type=Path,
                        help="Optional directory to retain one output JAR per successful variant")
    parser.add_argument("--only", action="append", default=[],
                        help="Variant name to run; repeat to select several")
    args = parser.parse_args()
    if args.runs < 1 or args.warmup < 0:
        raise SystemExit("--runs must be >= 1 and --warmup must be >= 0")
    for path in (args.skidfuscator, args.skid_java, args.skid_jmods, args.proguard, args.yguard, args.ant):
        if not path.exists():
            raise SystemExit(f"Missing tool path: {path}")
    subprocess.run([sys.executable, str(ROOT / "scripts/build.py")], check=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.artifacts_dir:
        args.artifacts_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="nullfuscator-oss-benchmark-") as temp:
        work = Path(temp)
        corpus = work / "corpus.jar"
        corpus_info = historic_corpus(corpus)
        expected_run = subprocess.check_output(["java", "-Xverify:all", "-jar", str(corpus)], text=True)
        original_classes, original_strings = class_names(corpus), strings(corpus)
        null_rename = work / "nullfuscator-rename.hocon"
        null_rename.write_text("""sourceStrip { enabled:false }
classRenamer { enabled:true, renameMain:false }
methodRenamer { enabled:true, renameVirtual:false, renamePublic:false }
fieldRenamer { enabled:true }
""", encoding="utf-8")
        proguard_cfg = work / "proguard.pro"
        yguard_xml = work / "yguard.xml"
        variants = {
            "nullfuscator-rename": lambda out: ["java", "-Xmx2g", "-jar", str(ROOT / "build/nullfuscator-obf.jar"), "--input", str(corpus), "--output", str(out), "--config", str(null_rename), "--seed", "1337", "--no-mapping"],
            "nullfuscator-light": lambda out: ["java", "-Xmx2g", "-jar", str(ROOT / "build/nullfuscator-obf.jar"), "--input", str(corpus), "--output", str(out), "--config", str(ROOT / "config/light.hocon"), "--seed", "1337", "--no-mapping"],
            "nullfuscator-full": lambda out: ["java", "-Xmx3g", "-jar", str(ROOT / "build/nullfuscator-obf.jar"), "--input", str(corpus), "--output", str(out), "--config", str(ROOT / "config/full.hocon"), "--seed", "1337", "--no-mapping"],
            "proguard-rename": lambda out: (write_proguard(proguard_cfg, corpus, out, args.skid_java.parent.parent), [str(args.proguard), "@" + str(proguard_cfg)])[1],
            "yguard-rename": lambda out: (write_yguard(yguard_xml, corpus, out, args.yguard, args.ant), ["java", "-cp", os.pathsep.join([str(args.ant), str(args.ant.parent / "ant-launcher.jar"), str(args.yguard)]), "org.apache.tools.ant.Main", "-f", str(yguard_xml)])[1],
            "skidfuscator-ce-default": lambda out: [str(args.skid_java), "-Xmx3g", "-jar", str(args.skidfuscator), "obfuscate", "--notrack", "--runtime=" + str(args.skid_jmods), "--output=" + str(out), str(corpus)],
        }
        unknown = set(args.only) - set(variants)
        if unknown:
            raise SystemExit("Unknown variants: " + ", ".join(sorted(unknown)))
        if args.only:
            variants = {name: variants[name] for name in args.only}
        result = {
            "schemaVersion": 1, "corpus": corpus_info, "mainClass": MAIN_CLASS,
            "corpusRunSha256": hashlib.sha256(expected_run.encode()).hexdigest(),
            "runs": args.runs, "warmup": args.warmup,
            "environment": {"java": command_version(["java", "-version"]), "platform": sys.platform},
            "tools": {name: str(path) for name, path in vars(args).items() if name not in {"runs", "warmup", "output"}},
            "variants": {},
        }
        for name, make_command in variants.items():
            samples, final_output = [], work / (name + ".jar")
            for run in range(args.warmup + args.runs):
                output = work / f"{name}-{run}.jar"
                log = work / f"{name}-{run}.log"
                sample = run_measured(make_command(output), log, work, timeout=1800)
                sample["outputExists"] = output.is_file()
                if sample["exitCode"] != 0:
                    sample["diagnostics"] = log.read_text(errors="replace")[-4000:]
                if run >= args.warmup:
                    samples.append(sample)
                    if output.is_file(): shutil.copy2(output, final_output)
            successful = [sample for sample in samples if sample["exitCode"] == 0 and final_output.is_file()]
            entry = {"samples": samples}
            if successful:
                entry.update({"buildSecondsMedian": median([s["seconds"] for s in successful]),
                              "peakRssMiBMedian": median([s["peakRssMiB"] for s in successful]),
                              "outputBytes": final_output.stat().st_size,
                              "outputRatio": final_output.stat().st_size / corpus.stat().st_size,
                              "classNamesLeft": len(original_classes & class_names(final_output)),
                              "originalStringsLeft": len(original_strings & strings(final_output)),
                              "validation": validate(final_output, expected_run)})
                if args.artifacts_dir:
                    shutil.copy2(final_output, args.artifacts_dir / f"{name}.jar")
            else:
                entry["validation"] = {"verified": False, "reason": "all measured runs failed"}
            result["variants"][name] = entry
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
