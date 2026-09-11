# Changelog

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
