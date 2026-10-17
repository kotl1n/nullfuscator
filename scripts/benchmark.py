#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
JAR = ROOT / "build/nullfuscator-obf.jar"
PROFILES = ("light", "balanced", "strong", "full")
RUNS = 3


def run(command, cwd=None):
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return result


def timed(command, cwd=None):
    process = subprocess.Popen(command, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    started = time.monotonic()
    peak_rss = 0
    while process.poll() is None:
        try:
            status = Path(f"/proc/{process.pid}/status").read_text(encoding="utf-8")
            match = re.search(r"VmHWM:\s+(\d+) kB", status)
            if match:
                peak_rss = max(peak_rss, int(match.group(1)))
        except FileNotFoundError:
            pass
        time.sleep(0.005)
    stdout, stderr = process.communicate()
    if process.returncode:
        raise RuntimeError(stdout + stderr)
    return time.monotonic() - started, peak_rss, subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def median(values):
    return statistics.median(values)


def write_fixture(directory, warmup_rounds=20_000, rounds=100_000):
    methods = []
    calls = []
    for number in range(8):
        methods.append(f"""    static int k{number}(int x, int y) {{
        int a = (x + {number * 17 + 3}) * (y - {number * 13 + 5});
        int b = (a ^ (x << {number % 7})) & (y | {number * 101 + 11});
        return (b + a) ^ (b >>> {number % 11 + 1});
    }}""")
        calls.append(f"BenchKernel.k{number}(x + {number}, y - {number})")
    methods.append("    static long padding() { long value = 0;"
                   + "".join(f" value += {number}L;" for number in range(1200)) + " return value; }")
    (directory / "BenchKernel.java").write_text("public final class BenchKernel {\n"
                                                 + "\n".join(methods) + "\n}\n", encoding="utf-8")
    (directory / "BenchMain.java").write_text(f"""public final class BenchMain {{
    static int run(int rounds) {{
        int value = 1;
        for (int i = 0; i < rounds; i++) {{
            int x = value + i * 31;
            int y = value ^ (i * 17);
            value ^= { ' ^ '.join(calls) };
        }}
        return value;
    }}
    public static void main(String[] args) {{
        run({warmup_rounds});
        long start = System.nanoTime();
        int value = run({rounds});
        long elapsed = System.nanoTime() - start;
        System.out.println(value + " " + elapsed);
    }}
}}\n""", encoding="utf-8")


def runtime_samples(artifact, expected=None):
    values = []
    launches = []
    rss = []
    checksum = expected
    for _ in range(RUNS):
        seconds, peak_rss, result = timed(["java", "-Xverify:all", "-jar", artifact])
        value, nanos = result.stdout.strip().split()
        values.append(int(nanos) / 1_000_000)
        launches.append(seconds * 1000)
        rss.append(peak_rss / 1024)
        if checksum is None:
            checksum = value
        if value != checksum:
            raise RuntimeError(f"{artifact}: expected checksum {checksum}, got {value}")
    return {"checksum": checksum, "launch_ms": median(launches), "kernel_ms": median(values), "process_rss_mib": median(rss)}


def main():
    global JAR, RUNS, PROFILES
    parser = argparse.ArgumentParser(description="Measure verified output size and runtime against the input checksum")
    parser.add_argument("--jar", type=Path, default=JAR)
    parser.add_argument("--runs", type=int, default=RUNS)
    parser.add_argument("--profiles", nargs="+", choices=PROFILES, default=PROFILES)
    parser.add_argument("--warmup-rounds", type=int, default=20_000,
                        help="kernel rounds before timing in each fresh JVM")
    parser.add_argument("--rounds", type=int, default=100_000,
                        help="kernel rounds measured in each fresh JVM")
    args = parser.parse_args()
    if args.warmup_rounds < 0 or args.rounds < 1:
        parser.error("--warmup-rounds must be nonnegative and --rounds must be positive")
    if args.runs < 1:
        parser.error("--runs must be positive")
    JAR, RUNS, PROFILES = args.jar.resolve(), args.runs, args.profiles
    if not JAR.is_file():
        if JAR != ROOT / "build/nullfuscator-obf.jar":
            parser.error(f"JAR does not exist: {JAR}")
        run(["python3", ROOT / "scripts/build.py"])
    with tempfile.TemporaryDirectory(prefix="nullfuscator-benchmark-") as raw:
        work = Path(raw)
        write_fixture(work, args.warmup_rounds, args.rounds)
        run(["javac", "--release", "17", "BenchKernel.java", "BenchMain.java"], work)
        input_jar = work / "input.jar"
        run(["jar", "--create", "--file", input_jar, "--main-class", "BenchMain", "BenchKernel.class", "BenchMain.class"], work)
        results = {"environment": {"java": run(["java", "-version"]).stderr.splitlines()[0], "runs": RUNS,
                                    "warmup_rounds": args.warmup_rounds, "rounds": args.rounds},
                   "input_bytes": input_jar.stat().st_size,
                   "baseline": runtime_samples(input_jar), "profiles": {}}
        for profile in PROFILES:
            output = work / f"{profile}.jar"
            wall = []
            memory = []
            protected = []
            for _ in range(RUNS):
                seconds, rss, result = timed(["java", "-Xmx1g", "-jar", JAR, "--input", input_jar,
                                              "--output", output, "--config", ROOT / "config" / f"{profile}.hocon",
                                              "--seed", "20260910", "--no-mapping", "--verbose"])
                wall.append(seconds * 1000)
                memory.append(rss / 1024)
                match = re.search(r"semanticCore: protected=(\d+) methods", result.stderr)
                protected.append(int(match.group(1)) if match else 0)
            with zipfile.ZipFile(output) as archive:
                classes = [item for item in archive.infolist() if item.filename.endswith(".class")]
                class_bytes = sum(item.file_size for item in classes)
            results["profiles"][profile] = {"obfuscation_ms": median(wall), "obfuscator_rss_mib": median(memory),
                                             "output_bytes": output.stat().st_size, "class_bytes": class_bytes, "classes": len(classes), "semantic_core_methods": median(protected),
                                             **runtime_samples(output, results["baseline"]["checksum"])}
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
