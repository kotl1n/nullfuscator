# Changelog

## 0.2.4

- Preserved access semantics during class renaming: private members remain private, package-private classes remain together, and packages that reference retained or external classes stay in place.
- Made method extraction and relocation skip bodies that would lose legal access when moved to generated carriers.
- Fixed field packing for constructor initialization and inherited field accesses.
- Made `light` the default profile when neither `--preset` nor `--config` is supplied.
- Made `--dry-run` serialize the archive in memory and enforce output-size budgets without writing artifacts.
- Hardened configuration list validation, stack-trace retracing, negative seed parsing, and `--quiet` output handling.
- Added compatibility coverage for package visibility, private dispatch, nested classes, inherited fields, external dependencies, dry-run budgets, CLI behavior, and retracing.

## 0.2.3-beta

- Refactored the core and transformer implementations for a consistent code style and simpler maintenance.
- Simplified several internal local-variable and initialization paths without changing the public CLI, configuration format, mapping format, or bundled profiles.
- Revalidated the supported transformation matrix: verifier and differential tests, Java 17/21 class files, enum and record handling, Fabric/Mixin and ServiceLoader fixtures, mappings, CLI safety checks, and reproducible packaging.

## 0.2.2-beta

- Reduced archive growth and runtime overhead in strong and full profiles by avoiding repeated protection of generated helpers.
- Reworked exception-return transport to use a shared stackless token and invocation-local results.
- Removed unused field indirection accessors and unused anti-debug detector classes before later transformations expand them.
- Added checksum-checked profile benchmarking with archive and class-size measurements, plus return-transport concurrency regression coverage.
- Added release resource, annotation, Fabric and enum compatibility improvements.

## 0.2.1 — beta

- Added shared configuration defaults for exclusions and naming options.
- Global `defaults.exempt` rules now apply to every transformation, while per-section rules extend them.
- Added regression coverage for configuration defaults, overrides and legacy compatibility.
- Simplified the full protection profile by removing duplicated exclusion and naming settings.

## 0.2.0 — beta

- Added Semantic Core encoded integer-domain protection.
- Added preset-aware CLI improvements and release packaging updates.

## 0.1.0 — beta

First public release candidate. Supports Java 17+ and offline builds.

- Bounded light, balanced and strong profiles; global growth and coverage gates.
- Preflight compatibility warnings, JSON reports, mapping v2 and retrace.
- CLI protects input/configuration/dependency files from sidecar collisions,
  including symbolic and hard links. In-place mappings retain input identity.
- Machine-readable stdout, argument diagnostics, `--help` and `--version`.
- Java 17/21 regression matrix, bytecode verifier and differential cases.
- MIT project license, bundled dependency licenses and verified dependency hashes.
- Reproducible JAR/ZIP packaging with SHA-256 checksums.

### Known limits

This is a beta, not a guarantee of compatibility with arbitrary reflection,
frameworks or Minecraft/Fabric launches. The full profile can materially increase
size and execution cost. The large historical README benchmark has not been
rerun after bounded-growth changes. Full keep rules, shrinking and incremental
caching are not implemented. See `docs/COMPATIBILITY.md` for tested surfaces.
