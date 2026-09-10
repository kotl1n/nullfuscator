#!/usr/bin/env python3
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import tempfile
import time

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


def write_fixture(directory):
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
        run(20_000);
        long start = System.nanoTime();
        int value = run(100_000);
        long elapsed = System.nanoTime() - start;
        System.out.println(value + " " + elapsed);
    }}
}}\n""", encoding="utf-8")


def runtime_samples(artifact):
    values = []
    launches = []
    rss = []
    for _ in range(RUNS):
        seconds, peak_rss, result = timed(["java", "-Xverify:all", "-jar", artifact])
        value, nanos = result.stdout.strip().split()
        values.append(int(nanos) / 1_000_000)
        launches.append(seconds * 1000)
        rss.append(peak_rss / 1024)
        if not value:
            raise RuntimeError("benchmark produced no result")
    return {"launch_ms": median(launches), "kernel_ms": median(values), "process_rss_mib": median(rss)}


def main():
    if not JAR.is_file():
        run(["python3", ROOT / "scripts/build.py"])
    with tempfile.TemporaryDirectory(prefix="nullfuscator-benchmark-") as raw:
        work = Path(raw)
        write_fixture(work)
        run(["javac", "--release", "17", "BenchKernel.java", "BenchMain.java"], work)
        input_jar = work / "input.jar"
        run(["jar", "--create", "--file", input_jar, "--main-class", "BenchMain", "BenchKernel.class", "BenchMain.class"], work)
        results = {"environment": {"java": run(["java", "-version"]).stderr.splitlines()[0], "runs": RUNS},
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
            results["profiles"][profile] = {"obfuscation_ms": median(wall), "obfuscator_rss_mib": median(memory),
                                             "output_bytes": output.stat().st_size, "semantic_core_methods": median(protected),
                                             **runtime_samples(output)}
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
