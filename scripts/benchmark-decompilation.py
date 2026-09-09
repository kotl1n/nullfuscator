#!/usr/bin/env python3
"""Measure decompilation and recompilation of benchmark JAR artifacts.

The input directory should contain input.jar and one JAR for each obfuscator.
Both decompilers are invoked on every JAR, then their emitted Java files are
compiled with the requested JDK.  The JSON output records raw diagnostics so
that a zero exit status is never mistaken for successful recovery.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import time


def run(command, timeout):
    started = time.perf_counter()
    completed = subprocess.run(command, text=True, capture_output=True,
                               timeout=timeout)
    return {
        "exitCode": completed.returncode,
        "seconds": time.perf_counter() - started,
        "stdout": completed.stdout[-4000:],
        "stderr": completed.stderr[-4000:],
    }


def source_metrics(directory):
    sources = sorted(directory.rglob("*.java"))
    text = "\n".join(source.read_text(encoding="utf-8", errors="replace")
                     for source in sources)
    markers = (
        "Could not be decompiled",
        "could not be decompiled",
        "Decompiler error",
        "decompiler error",
        "Couldn't be decompiled",
    )
    return {
        "javaFiles": len(sources),
        "sourceBytes": len(text.encode()),
        "embeddedErrorMarkers": sum(text.count(marker) for marker in markers),
        "sources": sources,
    }


def compile_sources(java, metrics, output, timeout):
    sources = metrics.pop("sources")
    if not sources:
        return {"exitCode": None, "reason": "decompiler produced no Java files"}
    source_list = output.parent / "sources.txt"
    source_list.write_text("\n".join(map(str, sources)) + "\n", encoding="utf-8")
    output.mkdir(parents=True, exist_ok=True)
    result = run([str(java), "--release", "21", "-encoding", "UTF-8", "-d",
                  str(output), "@" + str(source_list)], timeout)
    diagnostics = result["stdout"] + "\n" + result["stderr"]
    total = re.search(r"of (\d+) total", diagnostics)
    final = re.search(r"\n(\d+) errors?\s*$", diagnostics)
    if total:
        result["reportedErrors"] = int(total.group(1))
    elif final:
        result["reportedErrors"] = int(final.group(1))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--cfr", type=Path, required=True)
    parser.add_argument("--vineflower", type=Path, required=True)
    parser.add_argument("--javac", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args()
    jars = sorted(args.artifacts_dir.glob("*.jar"))
    if not jars:
        raise SystemExit("No JAR artifacts found")
    report = {"schemaVersion": 1, "tools": {"cfr": str(args.cfr),
              "vineflower": str(args.vineflower), "javac": str(args.javac)},
              "artifacts": {}}
    output_root = args.output.parent / (args.output.stem + "-sources")
    for jar in jars:
        entry = {}
        for name, command in {
            "cfr": ["java", "-jar", str(args.cfr), str(jar), "--outputdir"],
            "vineflower": ["java", "-jar", str(args.vineflower), "--log=ERROR", str(jar)],
        }.items():
            source_dir = output_root / jar.stem / name
            source_dir.mkdir(parents=True, exist_ok=True)
            decompile = run(command + [str(source_dir)], args.timeout)
            metrics = source_metrics(source_dir)
            compile_result = compile_sources(args.javac, metrics,
                                             output_root / jar.stem / (name + "-classes"),
                                             args.timeout)
            entry[name] = {"decompile": decompile, "source": metrics,
                           "compile": compile_result}
        report["artifacts"][jar.stem] = entry
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
