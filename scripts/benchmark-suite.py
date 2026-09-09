#!/usr/bin/env python3
"""Collect reproducible medians for one input JAR and explicitly named profiles."""
from pathlib import Path
import argparse
import hashlib
import json
import platform
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def median(values):
    values = sorted(values)
    middle = len(values) // 2
    return values[middle] if len(values) % 2 else (values[middle - 1] + values[middle]) / 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--profile", action="append", required=True,
                        help="NAME=HOCON path; repeat for each profile")
    parser.add_argument("--runs", type=int, default=4)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--obfuscator", type=Path, default=ROOT / "build/nullfuscator-obf.jar")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.runs < 1 or args.warmup < 0:
        raise SystemExit("--runs must be >= 1 and --warmup must be >= 0")

    profiles = {}
    for item in args.profile:
        name, separator, value = item.partition("=")
        if not separator or not name or not value:
            raise SystemExit("--profile must have NAME=HOCON form")
        if name in profiles:
            raise SystemExit(f"duplicate profile: {name}")
        profiles[name] = Path(value)

    data = {
        "schemaVersion": 1,
        "input": str(args.input),
        "inputSha256": digest(args.input),
        "obfuscator": str(args.obfuscator),
        "obfuscatorSha256": digest(args.obfuscator),
        "seed": args.seed,
        "runs": args.runs,
        "warmup": args.warmup,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "javaVersion": subprocess.check_output(["java", "-version"], stderr=subprocess.STDOUT,
                                                  text=True).splitlines()[0],
        "profiles": {},
    }
    with tempfile.TemporaryDirectory(prefix="nullfuscator-benchmark-suite-") as temp:
        root = Path(temp)
        for name, config in profiles.items():
            samples = []
            for run in range(args.warmup + args.runs):
                sample_file = root / f"{name}-{run}.json"
                command = ["python3", str(ROOT / "scripts/benchmark-gate.py"),
                           "--input", str(args.input), "--config", str(config),
                           "--obfuscator", str(args.obfuscator), "--seed", str(args.seed),
                           "--max-build-seconds", "1000000", "--max-peak-rss-mib", "1000000",
                           "--max-output-ratio", "1000000", "--report", str(sample_file)]
                subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
                if run >= args.warmup:
                    samples.append(json.loads(sample_file.read_text(encoding="utf-8")))
            data["profiles"][name] = {
                "config": str(config),
                "sampleCount": len(samples),
                "buildSecondsMedian": median([s["buildSeconds"] for s in samples]),
                "peakRssMiBMedian": median([s["peakRssMiB"] for s in samples]),
                "outputBytesMedian": median([s["outputBytes"] for s in samples]),
                "outputRatioMedian": median([s["outputRatio"] for s in samples]),
            }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(data, indent=2))


if __name__ == "__main__":
    main()
