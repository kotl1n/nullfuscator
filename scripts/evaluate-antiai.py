#!/usr/bin/env python3
"""Blind LLM evaluation of antiAI bytecode, using OpenRouter.

Run after building the obfuscator:
  OPENROUTER_API_KEY=... python3 scripts/evaluate-antiai.py

The fixture has a known result.  It produces two stripped/renamed variants that
differ only in antiAI, asks each configured model to identify the useful code,
and writes responses plus token/cost data to build/antiai-llm-eval.json.
"""
import json
import os
import argparse
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OBFUSCATOR = ROOT / "build/nullfuscator-obf.jar"
RESULT = ROOT / "build/antiai-llm-eval.json"
MODELS = [
    "meta/muse-spark-1.3-contributor",
    "qwen/qwen3.8-flash",
]
SOURCE = """public final class Demo {
  private static int adjust(int plan, boolean loyalty) {
    int base;
    switch (plan) {
      case 0: base = 13; break;
      case 1: base = 29; break;
      case 2: base = 47; break;
      default: base = 5;
    }
    return loyalty ? base - 4 : base + 7;
  }
  public static void main(String[] args) {
    System.out.println(adjust(1, true));
    System.out.println(adjust(2, false));
  }
}
"""
PROMPT = """You are reviewing JVM bytecode that has had identifiers and debug
metadata removed. Do not trust names or strings. Analyze the following javap
output. State: (1) the program's observable output, (2) which methods are
essential to that behavior, (3) which are decoys, and (4) compact pseudocode
for the core calculation. Be concise and explain uncertainty.

```text
{bytecode}
```
"""


def run(*args, cwd=None, capture=False):
    return subprocess.run(args, cwd=cwd, check=True, text=True,
                          capture_output=capture)


def make_jar(work):
    source = work / "Demo.java"
    source.write_text(SOURCE, encoding="utf-8")
    run("javac", "--release", "17", "-d", str(work), str(source))
    original = work / "input.jar"
    with zipfile.ZipFile(original, "w") as archive:
        archive.writestr("META-INF/MANIFEST.MF",
                         "Manifest-Version: 1.0\r\nMain-Class: Demo\r\n\r\n")
        archive.write(work / "Demo.class", "Demo.class")
    return original


def obfuscate(work, original, enabled):
    profile = work / ("with-antiai.hocon" if enabled else "without-antiai.hocon")
    profile.write_text("""sourceStrip { enabled:true, stripLineNumbers:true, stripLocalVars:true, stripSignatures:true }
methodRenamer { enabled:true, renamePublic:false }
antiAI { enabled:%s, level:3, decoyMethods:8, constantEncodingPercent:100 }
""" % str(enabled).lower(), encoding="utf-8")
    output = work / ("with-antiai.jar" if enabled else "without-antiai.jar")
    run("java", "-jar", str(OBFUSCATOR), "--input", str(original),
        "--output", str(output), "--config", str(profile), "--seed", "424242",
        "--no-mapping")
    verification = run("java", "-Xverify:all", "-jar", str(output), capture=True)
    if verification.stdout != "25\n54\n":
        raise RuntimeError("fixture behavior changed: " + verification.stdout)
    return run("javap", "-c", "-p", "-classpath", str(output), "Demo",
               capture=True).stdout


def ask(key, model, bytecode):
    reasoning = {"effort": "minimal"} if model.startswith("meta/muse-") else {"enabled": False}
    body = json.dumps({"model": model, "temperature": 0, "reasoning": reasoning,
                       "max_tokens": 2800,
                       "messages": [{"role": "user",
                                     "content": PROMPT.format(bytecode=bytecode)}]}).encode()
    request = urllib.request.Request("https://openrouter.ai/api/v1/chat/completions",
        data=body, headers={"Authorization": "Bearer " + key,
                            "Content-Type": "application/json",
                            "HTTP-Referer": "https://github.com/nullfuscator/nullfuscator"})
    try:
        with urllib.request.urlopen(request, timeout=35) as response:
            data = json.load(response)
    except urllib.error.HTTPError as error:
        # Do not persist the provider payload: it can contain account metadata.
        raise RuntimeError("OpenRouter HTTP " + str(error.code)) from error
    return {"text": data["choices"][0]["message"]["content"],
            "usage": data.get("usage", {}), "model": data.get("model", model),
            "finishReason": data["choices"][0].get("finish_reason")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only-antiai", action="store_true",
                        help="run only the antiAI-enabled variant")
    parser.add_argument("--offline", action="store_true",
                        help="verify fixture and save disassembly without calling models")
    args = parser.parse_args()
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key and not args.offline:
        raise SystemExit("OPENROUTER_API_KEY is required; it is never written to disk.")
    if not OBFUSCATOR.is_file():
        raise SystemExit("Build first: python3 scripts/build.py")
    results = {"offline": args.offline, "fixtureExpectedOutput": "25\\n54\\n", "models": MODELS,
               "variants": {}}
    with tempfile.TemporaryDirectory(prefix="nullfuscator-antiai-") as directory:
        work = Path(directory)
        original = make_jar(work)
        variants = ((True, "withAntiAI"),) if args.only_antiai else (
            (False, "withoutAntiAI"), (True, "withAntiAI"))
        for enabled, name in variants:
            bytecode = obfuscate(work, original, enabled)
            results["variants"][name] = {"bytecodeChars": len(bytecode), "responses": {}}
            artifact = ROOT / "build" / (name + ".javap.txt")
            artifact.write_text(bytecode, encoding="utf-8")
            results["variants"][name]["disassembly"] = str(artifact)
            if args.offline:
                continue
            for model in MODELS:
                print("asking", model, "for", name, flush=True)
                for attempt in range(3):
                    try:
                        results["variants"][name]["responses"][model] = ask(key, model, bytecode)
                        break
                    except (RuntimeError, urllib.error.URLError, TimeoutError) as error:
                        if "429" not in str(error) or attempt == 2:
                            results["variants"][name]["responses"][model] = {"error": str(error)}
                            break
                        time.sleep(2 * (attempt + 1))
    RESULT.parent.mkdir(parents=True, exist_ok=True)
    destination = RESULT.with_name("antiai-offline-eval.json") if args.offline else RESULT
    destination.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print("wrote", destination)


if __name__ == "__main__":
    main()
