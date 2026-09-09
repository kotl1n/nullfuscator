#!/usr/bin/env python3
"""Run an explicit CI performance gate against a representative executable JAR."""
from pathlib import Path
import argparse
import json
import statistics
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def timed(command, **kwargs):
    started = time.perf_counter()
    result = subprocess.run(command, **kwargs)
    return result, time.perf_counter() - started


def timed_with_rss(command):
    """Measure one process without inheriting peak RSS from earlier children."""
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        started = time.perf_counter()
        process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
        peak_kib = 0
        status = Path(f"/proc/{process.pid}/status")
        while process.poll() is None:
            try:
                for line in status.read_text(encoding="ascii").splitlines():
                    if line.startswith("VmRSS:"):
                        peak_kib = max(peak_kib, int(line.split()[1]))
                        break
            except (FileNotFoundError, ProcessLookupError):
                pass
            time.sleep(0.01)
        elapsed = time.perf_counter() - started
        stdout.seek(0)
        stderr.seek(0)
        result = subprocess.CompletedProcess(command, process.returncode,
                stdout.read().decode(errors="replace"), stderr.read().decode(errors="replace"))
        return result, elapsed, peak_kib / 1024.0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--obfuscator", type=Path, default=ROOT / "build/nullfuscator-obf.jar")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--max-build-seconds", type=float, required=True)
    parser.add_argument("--max-peak-rss-mib", type=float, required=True)
    parser.add_argument("--max-output-ratio", type=float, required=True)
    parser.add_argument("--max-startup-ms", type=float)
    parser.add_argument("--startup-runs", type=int, default=5)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    failures = []
    with tempfile.TemporaryDirectory(prefix="nullfuscator-benchmark-") as temp:
        output = Path(temp) / "output.jar"
        command = ["java", "-jar", str(args.obfuscator), "--input", str(args.input),
                   "--output", str(output), "--config", str(args.config),
                   "--seed", str(args.seed), "--no-mapping"]
        build, build_seconds, peak_rss_mib = timed_with_rss(command)
        if build.returncode:
            raise RuntimeError(build.stdout + build.stderr)
        output_ratio = output.stat().st_size / max(1, args.input.stat().st_size)

        startup_ms = None
        if args.max_startup_ms is not None:
            samples = []
            for _ in range(max(1, args.startup_runs)):
                run, elapsed = timed(["java", "-Xverify:all", "-jar", str(output)],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                if run.returncode:
                    raise RuntimeError(run.stderr.decode(errors="replace"))
                samples.append(elapsed * 1000.0)
            startup_ms = statistics.median(samples)

        if build_seconds > args.max_build_seconds:
            failures.append(f"buildSeconds {build_seconds:.3f} > {args.max_build_seconds:.3f}")
        if peak_rss_mib > args.max_peak_rss_mib:
            failures.append(f"peakRssMiB {peak_rss_mib:.1f} > {args.max_peak_rss_mib:.1f}")
        if output_ratio > args.max_output_ratio:
            failures.append(f"outputRatio {output_ratio:.3f} > {args.max_output_ratio:.3f}")
        if startup_ms is not None and startup_ms > args.max_startup_ms:
            failures.append(f"startupMedianMs {startup_ms:.1f} > {args.max_startup_ms:.1f}")

        report = {
            "schemaVersion": 1,
            "input": str(args.input),
            "config": str(args.config),
            "buildSeconds": round(build_seconds, 6),
            "peakRssMiB": round(peak_rss_mib, 3),
            "outputBytes": output.stat().st_size,
            "outputRatio": round(output_ratio, 6),
            "startupMedianMs": None if startup_ms is None else round(startup_ms, 3),
            "passed": not failures,
            "failures": failures,
        }
        encoded = json.dumps(report, indent=2) + "\n"
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(encoded, encoding="utf-8")
        print(encoded, end="")
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
