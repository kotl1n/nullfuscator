<p align="center">
  <img src="assets/logo.jpg" alt="NULLFUSCATOR Logo" width="280" />
</p>

<h1 align="center">NULLFUSCATOR</h1>

<p align="center">
  <b>Hardened, Standalone Java Bytecode Obfuscator with Bounded Growth and AST-Disruption Technology</b>
</p>

<p align="center">
  <a href="https://github.com/kotl1n/nullfuscator"><img src="https://img.shields.io/badge/version-0.2.0--beta-blue.svg" alt="Version"></a>
  <a href="https://github.com/kotl1n/nullfuscator"><img src="https://img.shields.io/badge/java-17%2B-orange.svg" alt="Java 17+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License"></a>
  <a href="https://github.com/kotl1n/nullfuscator"><img src="https://img.shields.io/badge/build-offline%20%2F%20reproducible-brightgreen.svg" alt="Build Status"></a>
</p>

---

## Overview

**NULLFUSCATOR** is a standalone, deterministic Java bytecode obfuscator built on the OW2 ASM engine. Designed for modern JVM workloads (supporting Java 17 through Java 21+), NULLFUSCATOR significantly raises the cost of static reverse engineering, automated decompilation, runtime debugging, and code tampering.

Unlike conventional obfuscators that merely rename symbols or recklessly bloat bytecode to the point of runtime instability, NULLFUSCATOR provides:
- **Strict budget gates and bounded growth**: Enforces hard caps on instruction expansion, method size limits, and archive growth to eliminate `MethodTooLargeException` and avoid runaway memory leaks.
- **Preflight compatibility safeguards**: Detects missing classpath hierarchies, multi-release JAR conflicts, Gson reflection models, and Fabric/Minecraft entrypoints before executing transformations.
- **Advanced decompiler disruption**: Combines synthetic control-flow flattening, invokedynamic reference hiding, polymorphic constant synthesis, exception-routed returns, and AST-shattering metadata traps.
- **Deterministic, offline-first operation**: Builds completely offline using pinned, checksum-verified dependencies; guarantees bit-identical output archives when supplied with identical inputs and seeds.
- **Mapping format v2 & Stacktrace Retracer**: Full ProGuard-compatible mapping generation and built-in CLI stack trace demangling.

> [!WARNING]
> **Experimental Feature Notice (`antiAI`)**:
> The `antiAI` transformation pass (keyed permutation networks for constant reconstruction) is currently an **experimental/testing feature** and may not work as intended in all environments. Do not enable it on critical production paths without rigorous testing.

---

## Architecture & Transformation Pipeline

NULLFUSCATOR applies up to 27 modular transformation passes organized into focused defensive layers:

```
+-------------------------------------------------------------------------------+
|                             NULLFUSCATOR Pipeline                             |
+-------------------------------------------------------------------------------+
  [ Input JAR ]
        |
        v
  [ Preflight & Validation ]   (Hierarchy checks, Multi-Release check, Gson scan)
        |
        v
  +--------------------------+
  |  1. Metadata Stripping   |  -> sourceStrip, recordMetadata
  +--------------------------+
  |  2. Semantic Protection  |  -> semanticCore, semanticFabric, antiDebug,
  |                          |     runtimeIntegrity
  +--------------------------+
  |  3. Control Flow Warp    |  -> flatten, bogusJump, switchFlow,
  |                          |     returnFlow, exceptionReturn
  +--------------------------+
  |  4. Constant Protection  |  -> stringEncryption (rolling XOR),
  |                          |     numberEncryption (polymorphic math),
  |                          |     antiAI (experimental)
  +--------------------------+
  |  5. Reference Obfuscation|  -> referenceHiding (invokedynamic bootstrap),
  |                          |     fieldIndirection, fieldPacking,
  |                          |     crossClassDispersion, methodExtraction
  +--------------------------+
  |  6. Identifier Renaming  |  -> classRenamer, methodRenamer, fieldRenamer
  +--------------------------+
  |  7. Anti-Decompilation   |  -> antiDecompiler, antiDeobf, fileCrasher
  +--------------------------+
        |
        v
  [ Budget & Verification ]   (Size growth check, instruction budget, -Xverify:all)
        |
        v
  [ Output JAR + Mapping v2 ]
```

### Detailed Passes

| Layer | Pass ID | Description |
| :--- | :--- | :--- |
| **Stripping** | `sourceStrip` | Removes SourceFile, SourceDebugExtension, LineNumberTable, and LocalVariableTable attributes. |
| | `recordMetadata` | Erases Java 14+ Record component metadata into plain class structures without breaking access. |
| **Control Flow** | `flatten` | Flattens basic execution blocks into a unified switch state-machine dispatcher. |
| | `bogusJump` | Injects opaque branch predicates whose conditions evaluate identically at runtime. |
| | `switchFlow` | Converts linear code paths into mutated lookup/table switch topologies. |
| | `returnFlow` | Unifies multiple return vectors into synthesized common exits. |
| | `exceptionReturn` | Replaces standard typed returns with caught control-flow exception dispatch. |
| **Encryption** | `stringEncryption` | Encrypts string literals using per-site rolling XOR keys with polymorphic runtime decoders. |
| | `numberEncryption` | Converts numeric constants into dynamic algebraic identities and runtime helpers. |
| | `antiAI` *(Experimental)* | Links constants through keyed Feistel permutation networks to disrupt LLM heuristics. |
| **Structural** | `referenceHiding` | Replaces direct `INVOKEVIRTUAL` / `INVOKESTATIC` calls with encrypted `invokedynamic` instructions. |
| **Semantic** | `semanticCore` *(Experimental)* | Keeps eligible integer methods in a method-specific encoded domain from entry to return. |
| | `fieldIndirection` | Routes direct field reads/writes through generated bridge methods. |
| | `fieldPacking` | Compresses instance primitive fields into boxed arrays or bitmasks. |
| | `crossClassDispersion`| Relocates internal business logic into synthetic helper classes across the archive. |
| | `methodRelocation` | Atomically migrates method implementations across carrier classes. |
| **Renaming** | `classRenamer` | Renames classes to unreadable Unicode or short dictionary identifiers. |
| | `methodRenamer` | Renames private, package-private, static, and public/virtual methods. |
| | `fieldRenamer` | Renames member fields to minimal collisions. |
| **Decompiler Traps**| `antiDecompiler` | Emits bytecode-valid, source-illegal constructs designed to crash CFR, Fernflower, and Procyon. |
| | `antiDeobf` | Disrupts AST reconstructing decompilers (JADX, Bytecode-Viewer) with illegal generic signatures. |
| | `fileCrasher` | Appends valid zero-length class attributes that break naive ZIP extractors and older tools. |
| **Runtime** | `antiDebug` | Injects active JVM runtime monitoring against `jdb`, Java agents, and instrumentation. |
| | `runtimeIntegrity` | Injects runtime SHA-256 self-checksum validation guards. |

---

## Configuration Profiles

NULLFUSCATOR ships with four preconfigured HOCON profiles in `config/`:

| Profile | Target Use-Case | Size Impact | Runtime Overhead | Protection Level |
| :--- | :--- | :---: | :---: | :---: |
| **`light.hocon`** | High-performance services, tick loops, games, Fabric mods | Minimal (+5% – +15%) | Near Zero (<1%) | Basic (Renaming + Strings + Stripping) |
| **`balanced.hocon`** | Production commercial software, enterprise APIs | Moderate (+20% – +50%) | Low (1% – 5%) | High (Control flow + Number/String + Indirection) |
| **`strong.hocon`** | Sensitive licensing modules, proprietary algorithms | Substantial (+50% – +120%) | Medium (5% – 15%) | Very High (+ InvokeDynamic + Exceptions + Anti-Deobf) |
| **`full.hocon`** | Maximum paranoia, core cryptographic routines, crack-me challenges | Heavy (up to ~5.5x) | High (avoid on hot loops) | Maximum (All 27 passes enabled simultaneously) |

Shared exclusions and naming options can be declared once and inherited by every relevant section:

```hocon
defaults {
  exempt = [ "class{^dev/murk/mixin/}" ]
  naming {
    chars = [ "I", "l1", "lI", "1l" ]
    depth = 8
  }
}
```

`defaults.exempt` applies to every transformation. A section-level `exempt` list adds rules without replacing the shared list. `defaults.naming` applies to `classRenamer`, `methodRenamer`, `fieldRenamer`, and `recordMetadata`; values declared in a section override the shared values.

---

## Reproducible Profile Benchmark

Run `python3 scripts/benchmark.py` after building the tool. The script generates a two-class Java 17 fixture with eight integer arithmetic/bitwise kernels and a non-eligible long-arithmetic method, transforms it with a fixed seed, verifies every result with `-Xverify:all`, and reports the median of three runs.

The measurements below were recorded for 0.2.0 on Linux x86_64, AMD Ryzen 7 7735HS, OpenJDK 21.0.12. The input archive is 6.98 KiB. They compare profiles on the same fixture; they are not a comparison with other obfuscators or a prediction for an application workload.

| Profile | Obfuscation | Obfuscator RSS | Output | Semantic Core Methods | Process Launch | Kernel Loop | Process RSS |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **Input baseline** | — | — | 6.98 KiB | 0 | 242.0 ms | 14.34 ms | 41.67 MiB |
| **light** | 508.9 ms | 76.06 MiB | 7.26 KiB (+4.1%) | 0 | 253.4 ms | 17.29 ms | 41.88 MiB |
| **balanced** | 661.6 ms | 87.59 MiB | 16.65 KiB (+138.6%) | 0 | 332.1 ms | 51.21 ms | 43.59 MiB |
| **strong** | 1,001.8 ms | 131.47 MiB | 80.95 KiB (+1,059.9%) | 3 | 663.5 ms | 190.33 ms | 54.72 MiB |
| **full** | 987.3 ms | 133.77 MiB | 295.75 KiB (+4,138.0%) | 3 | 3,462.9 ms | 1,397.86 ms | 88.41 MiB |

`semanticCore` is enabled through the inherited full profile, so it is active in `strong` and `full`; light and balanced intentionally report zero protected methods. The fixture is designed to exercise this pass and therefore exaggerates the overhead of high-strength profiles. Keep hot code excluded with `hotPaths.exclude`; use full protection for small, sensitive routines rather than a latency-sensitive loop.

---

### 2. Decompiler Resilience & Static Analysis Stress Test

The resulting obfuscated archives were subjected to decompilation via **CFR 0.152** and **Vineflower 1.12.0**, followed by recompilation of the emitted Java source code with `javac` (JDK 21).

| Output Artifact | CFR Time | CFR Decompile Errors | CFR `javac` Recompile Errors | Vineflower Time | Vineflower `javac` Errors |
| :--- | ---: | ---: | ---: | ---: | ---: |
| **Input Baseline** | 8.83 s | 0 | 1 | 6.42 s | 85 |
| **ProGuard** *(rename)* | 9.42 s | 0 | 206 | 6.20 s | 440 |
| **yGuard** *(rename)* | 10.89 s | 0 | 403 | 7.41 s | 3 |
| **Skidfuscator CE** | 178.03 s | 12 | 6,337 | 49.15 s | 7,685 |
| **NULLFUSCATOR** *(rename)* | 9.25 s | 0 | 4,992 | 7.15 s | 3,863 |
| **NULLFUSCATOR** *(full)* | **82.30 s** | **34** | **188,897** *(complete AST collapse)* | **17.59 s** | **5,425** |

- NULLFUSCATOR `full.hocon` generated **188,897 javac recompile errors** on CFR's output, rendering decompiled code completely unusable for reverse engineering or recompilation.
- Decompiled source trees exploded from **0.92 MiB** (input) to **58.59 MiB** (CFR) and **86.92 MiB** (Vineflower).

---

## Quickstart

### Prerequisites
- **JDK 17** or newer.
- **Python 3.9** or newer (for build & packaging scripts).

### 1. Build the Obfuscator Offline
All dependencies (ASM 9.10.1, Typesafe Config 1.4.2) are checked into `libs/` with pinned SHA-256 sums. No internet connection is needed to build:

```bash
python3 scripts/build.py
```
This produces `build/nullfuscator-obf.jar`.

### 2. Run Obfuscation
You can use the convenient `bin/nullfuscator` launcher or `java -jar build/nullfuscator-obf.jar`:

```bash
# Minimal zero-ceremony run (auto-generates myapp-obf.jar)
./bin/nullfuscator myapp.jar

# Recommended: use built-in presets directly (-p light | balanced | strong | full)
./bin/nullfuscator myapp.jar -p balanced

# Full options with short flags, custom seed, and verbose logging
./bin/nullfuscator -i myapp.jar -o myapp-hardened.jar -p strong -s 1337 -v
```

---

## Command-Line Reference

```text
nullfuscator <input.jar> [output.jar] [options]
   or: nullfuscator [options] -i <input.jar> -o <output.jar>
   or: nullfuscator presets
   or: nullfuscator init-config [preset] [-o config.hocon]
   or: nullfuscator check <input.jar>
   or: nullfuscator retrace <mapping-file> [trace-file]
   or: nullfuscator mapping-info <mapping-file>
```

### Options

| Flag | Short | Argument | Description |
| :--- | :--- | :--- | :--- |
| `--input` | `-i` | `<path>` | Input JAR file (or 1st positional argument). |
| `--output` | `-o` | `<path>` | Output JAR destination (defaults to `<input>-obf.jar`). |
| `--preset` | `-p` | `<name>` | Built-in preset (`light`, `balanced`, `strong`, `full`). No external files required! |
| `--config` | `-c` | `<path>` | Custom HOCON profile or preset name. Can be combined with `-p` for overrides. |
| `--lib` | `-l` | `<path>` | External dependency JAR for classpath analysis (repeatable or comma-separated). |
| `--seed` | `-s` | `<long>` | Fixed seed for reproducible obfuscation. If omitted, uses `SecureRandom`. |
| `--mapping` | `-m` | `<path>` | ProGuard-compatible mapping destination (defaults to `<output>.map`). |
| `--no-mapping`| `-M` | — | Explicitly disables mapping file generation. |
| `--report` | `-r` | `<path>` | Generates a JSON execution report (schema v1) with timings and growth metrics. |
| `--dry-run` / `--report-only` | — | — | Executes preflight and transformations in-memory without writing output JAR. |
| `--verbose` | `-v` | — | Enables detailed stderr diagnostics for every transformation pass. |
| `--quiet` | `-q` | — | Suppresses non-essential informational output. |
| `--no-color` | — | — | Disables ANSI terminal coloring. |
| `--version` | `-V` | — | Prints NULLFUSCATOR version (`0.2.0`). |
| `--help` | `-h` | — | Displays command-line help summary. |

### Commands

| Command | Usage | Description |
| :--- | :--- | :--- |
| `presets` | `nullfuscator presets` | Displays a comparison table of built-in profiles and performance trade-offs. |
| `init-config` | `nullfuscator init-config [preset] [-o file]` | Scaffolds a commented `.hocon` template for custom configuration. |
| `check` | `nullfuscator check <input.jar>` | Fast standalone preflight verification without writing output. |
| `retrace` | `nullfuscator retrace <mapping> [trace]` | Demangles obfuscated stack traces (supports positional args, `-m`, `-t`, or stdin). |
| `mapping-info` | `nullfuscator mapping-info <mapping>` | Displays mapping metadata, seed, format, and input SHA-256 digest. |

### Stack Trace Retracing
Demangle obfuscated production crash traces back to original class, method, and line numbers:

```bash
# Retrace using positional arguments
./bin/nullfuscator retrace myapp.map crash.log

# Retrace using flags
./bin/nullfuscator retrace -m myapp.map -t crash.log

# Retrace directly from stdin pipe
cat crash.log | ./bin/nullfuscator retrace myapp.map
```

---

## Gradle Integration

Integrate NULLFUSCATOR directly into your Gradle build pipeline:

```groovy
task obfuscate(type: JavaExec) {
    dependsOn jar
    classpath = files('tools/nullfuscator-0.2.0.jar')
    mainClass = 'com.nullfuscator.obf.core.Main'

    args = [
        '--input', jar.archiveFile.get().asFile.absolutePath,
        '--output', "${buildDir}/libs/${project.name}-${project.version}-obf.jar",
        '--config', 'config/balanced.hocon',
        '--mapping', "${buildDir}/libs/${project.name}.map",
        '--seed', '42'
    ]
}
```
See [`docs/gradle/nullfuscator-obfuscate.gradle`](docs/gradle/nullfuscator-obfuscate.gradle) for a complete standalone task implementation.

---

## Verification & Testing

NULLFUSCATOR maintains an exhaustive test suite covering bytecode legality, verifier compliance, and arithmetic equivalence:

```bash
# Run transformation regressions, growth budgets, and -Xverify:all tests
python3 scripts/test-growth.py

# Run CLI arguments and packaging integration tests
python3 scripts/test-cli.py

# Build official release candidate and verify SHA-256 signatures
python3 scripts/package-release.py
(cd build/release && sha256sum -c SHA256SUMS)
```

---

## Security & Transparency

- **Not a DRM**: No bytecode obfuscation can completely prevent a skilled reverse-engineer with kernel or JVM-agent access from inspecting memory or extracting keys. NULLFUSCATOR's goal is to maximize the time and cost barrier to reverse engineering.
- **Mapping Privacy**: Mapping files contain the 1:1 translation between original and obfuscated symbols. Treat `.map` files as highly sensitive internal credentials. Never bundle them into public releases.

---

## License & Third-Party Notices

NULLFUSCATOR is open-source software licensed under the [MIT License](LICENSE).

This project bundles and relies upon:
- **OW2 ASM 9.10.1** ([BSD 3-Clause](licenses/ASM-BSD-3-Clause.txt))
- **Typesafe Config 1.4.2** ([Apache 2.0](licenses/Typesafe-Config-Apache-2.0.txt))

Detailed notices and full license texts are available in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
