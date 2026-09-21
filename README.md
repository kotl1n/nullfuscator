<p align="center">
  <img src="assets/logo.jpg" alt="NULLFUSCATOR Logo" width="280" />
</p>

<h1 align="center">NULLFUSCATOR</h1>

<p align="center">
  <b>Hardened, Standalone Java Bytecode Obfuscator with Bounded Growth and AST-Disruption Technology</b>
</p>

<p align="center">
  <a href="https://github.com/kotl1n/nullfuscator"><img src="https://img.shields.io/badge/version-0.2.4-blue.svg" alt="Version"></a>
  <a href="https://github.com/kotl1n/nullfuscator"><img src="https://img.shields.io/badge/java-17%2B-orange.svg" alt="Java 17+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License"></a>
  <a href="https://github.com/kotl1n/nullfuscator"><img src="https://img.shields.io/badge/build-offline%20%2F%20reproducible-brightgreen.svg" alt="Build Status"></a>
</p>

---

## Overview

**NULLFUSCATOR** is a standalone, deterministic Java bytecode obfuscator built on the OW2 ASM engine. Designed for modern JVM workloads (supporting Java 17 through Java 21+), NULLFUSCATOR significantly raises the cost of static reverse engineering, automated decompilation, runtime debugging, and code tampering.

### 0.2.4

This release fixes access and dispatch regressions during class renaming, method movement and field packing. Class renaming now preserves private-member behavior and package boundaries that remain externally visible. The default command uses the `light` profile, and `--dry-run` performs the same archive-size validation as a normal run without leaving output files behind. The release was rechecked with verifier and differential tests across shipped profiles, Java 17/21 class files, mappings, enum and record metadata, Fabric/Mixin, ServiceLoader and package-access fixtures.

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

NULLFUSCATOR has 31 configurable transformation passes organized into focused defensive layers:

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
| | `resourceRenamer` | Renames mod-owned asset paths and rewrites literal lookups in classes and text resources. |
| **Release cleanup** | `releaseHardening` | Removes Maven/ProGuard metadata and clears Fabric mod descriptions. |
| | `annotationSanitizer` | Removes explicitly selected runtime annotations; use only when their metadata is non-essential. |
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
| **`light.hocon`** | High-performance services, tick loops, games, Fabric mods | Input-dependent; budgeted | Measure on target workload | Basic (Renaming + Strings + Stripping) |
| **`balanced.hocon`** | Production commercial software, enterprise APIs | Input-dependent; budgeted | Measure on target workload | High (Control flow + Number/String + Indirection) |
| **`strong.hocon`** | Sensitive licensing modules, proprietary algorithms | Input-dependent; budgeted | Measure on target workload | Very High (+ InvokeDynamic + Exceptions + Anti-Deobf) |
| **`full.hocon`** | Small sensitive routines, crack-me challenges | Input-dependent; set application budgets | Measure on target workload; avoid hot loops | Broad protection; some passes require explicit configuration |

These profiles do not guarantee a percentage overhead or size multiplier. The historical measurements below describe one fixture; measure the current build on your application.

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

Class renaming preserves access flags and keeps distinct packages separate. Packages containing retained classes, including a retained main class, keep their original package path. Other packages receive distinct opaque paths under `classRenamer.prefix`. Method extraction and relocation skip bodies that cannot legally access their dependencies from a carrier class.

For a Fabric release that only needs resource and metadata cleanup, use `config/resource-hardening.hocon`. It is intentionally compatible with incomplete game classpaths; do not combine its `compatibility.allowIncompleteClasspath` override with bytecode transformations unless the dependencies have been reviewed.

---

## Reproducible Profile Benchmark

Run `python3 scripts/benchmark.py` after building the tool. The script generates a two-class Java 17 fixture with eight integer arithmetic/bitwise kernels and a non-eligible long-arithmetic method, transforms it with a fixed seed, verifies every result with `-Xverify:all`, and reports medians across the configured runs.

See [the measured overhead comparison](docs/PERFORMANCE.md) for the current optimization results and protection tradeoffs.

For comparisons between builds, use `python3 scripts/benchmark.py --jar /path/to/obfuscator.jar --runs 5 --profiles strong full`. Output includes the result checksum, uncompressed class bytes, and class count. Every transformed checksum must match the input. Run builds sequentially without concurrent tests to reduce timing noise.

Runtime guards and exception-return dispatch target input methods, including semantic bridges and input synthetic methods. Generated arithmetic helpers are not wrapped again for each operation. Exception returns use a shared stackless token and a method-local result, preserving raw floating-point bits and concurrent/reentrant calls without `ThreadLocal` traffic. Field indirection emits only accessors that are actually used; output archives use maximum DEFLATE compression. These changes retain configured input-method coverage but reduce redundant helper layering; equal resistance to reverse engineering is not established by runtime tests.

The measurements below were recorded for 0.2.2-beta on Linux x86_64 with OpenJDK 21.0.12.1. The input archive is 6.98 KiB. They are medians from five runs on the same fixture; they are not a comparison with other obfuscators or a prediction for an application workload.

| Profile | Obfuscation | Obfuscator RSS | Output | Semantic Core Methods | Process Launch | Kernel Loop | Process RSS |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **Input baseline** | — | — | 6.98 KiB | 0 | 131.56 ms | 9.47 ms | 50.52 MiB |
| **light** | 269.12 ms | 92.21 MiB | 7.26 KiB (+4.1%) | 0 | 141.56 ms | 9.77 ms | 50.77 MiB |
| **balanced** | 328.79 ms | 97.98 MiB | 16.65 KiB (+138.5%) | 0 | 190.65 ms | 33.24 ms | 52.34 MiB |
| **strong** | 461.36 ms | 124.39 MiB | 68.27 KiB (+879.0%) | 3 | 295.62 ms | 78.53 ms | 60.89 MiB |
| **full** | 561.55 ms | 143.52 MiB | 282.96 KiB (+3,959.0%) | 3 | 1,555.99 ms | 603.60 ms | 98.21 MiB |

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

With neither `--preset` nor `--config`, the CLI uses `light`. An explicit custom configuration enables only the passes it declares unless combined with a preset.

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
| `--preset` | `-p` | `<name>` | Built-in preset (`light`, `balanced`, `strong`, `full`); defaults to `light` when no config is supplied. |
| `--config` | `-c` | `<path>` | Custom HOCON profile or preset name. Can be combined with `-p` for overrides. |
| `--lib` | `-l` | `<path>` | External dependency JAR for classpath analysis (repeatable or comma-separated). |
| `--seed` | `-s` | `<long>` | Fixed seed for reproducible obfuscation. If omitted, uses `SecureRandom`. |
| `--mapping` | `-m` | `<path>` | ProGuard-compatible mapping destination (defaults to `<output>.map`). |
| `--no-mapping`| `-M` | — | Explicitly disables mapping file generation. |
| `--report` | `-r` | `<path>` | Generates a JSON execution report (schema v1) with timings and growth metrics. |
| `--dry-run` / `--report-only` | — | — | Runs preflight, transformations, frame computation and archive serialization without saving the JAR or mapping; enforces archive budgets and reports the measured `outputJarBytes`. |
| `--verbose` | `-v` | — | Enables detailed stderr diagnostics for every transformation pass. |
| `--quiet` | `-q` | — | Suppresses non-essential informational output. |
| `--no-color` | — | — | Disables ANSI terminal coloring. |
| `--version` | `-V` | — | Prints NULLFUSCATOR version (`0.2.4`). |
| `--help` | `-h` | — | Displays command-line help summary. |

### Commands

| Command | Usage | Description |
| :--- | :--- | :--- |
| `presets` | `nullfuscator presets` | Displays a comparison table of built-in profiles and performance trade-offs. |
| `init-config` | `nullfuscator init-config [preset] [-o file]` | Scaffolds a commented `.hocon` template for custom configuration. |
| `check` | `nullfuscator check <input.jar>` | Fast standalone preflight verification without writing output. |
| `retrace` | `nullfuscator retrace <mapping> [trace]` | Demangles obfuscated stack traces (supports positional args, `-m`, `-t`, or stdin). |
| `mapping-info` | `nullfuscator mapping-info <mapping>` | Displays mapping metadata, seed, format, and input SHA-256 digest. |

### Enum symbols

Enum helper methods and ordinary fields are renamed while `values()`, `valueOf(String)`
and runtime enum names are preserved. To also hide enum constant field symbols for
reviewed application classes, set `fieldRenamer.enumConstantsInclude = ["class{^my/app/}"]`.
This option defaults to empty: consumers using `Class.getField(enum.name())` require
the original field names. String encryption hides runtime names in the archive;
`Enum.name()`, saved enum values and Java enum serialization retain their identities.

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
    classpath = files('tools/nullfuscator-0.2.4.jar')
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
