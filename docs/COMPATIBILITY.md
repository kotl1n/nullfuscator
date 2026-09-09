# Compatibility matrix

The checked cases are compact JVM fixtures. They establish bytecode and resource
contracts, not compatibility with a running Minecraft client or arbitrary
framework reflection graphs.

| Surface | Fixture | Current expected behavior |
| --- | --- | --- |
| Java 17 | records and sealed classes | Obfuscates and runs with `-Xverify:all`. |
| Java 21 | `List.getFirst()` classfile version 65 | Light profile obfuscates and runs on JDK 21. |
| Modules | `module-info` plus executable module | Module metadata remains; class renaming is skipped. |
| Multi-release JAR | `META-INF/versions/17` override | Override remains untouched; class renaming is rejected unless explicitly allowed. |
| Services | `META-INF/services` provider | Descriptor path and provider names remap with classes. |
| Fabric/Mixin/access widener references | resource contract fixture | Referenced class names remain stable. |
| Gson signal | annotated DTO fixture | Field renaming emits a preflight report warning. |
| Missing hierarchy | omitted direct superclass | Preflight fails with the missing type list. |

`scripts/test-growth.py` runs on JDK 17 and JDK 21. The Java 21-only fixture is
skipped on JDK 17; Java 17 artifacts execute on each runner's actual JVM.
`.github/workflows/ci.yml` runs both versions on Linux, including CLI regressions
and repeat-build comparison. Performance RSS gates require Linux `/proc`.

## Not covered

No Minecraft/Fabric game-launch fixture is bundled. A meaningful smoke test
needs a pinned loader, mappings, game assets, mod fixture, headless launch
policy, and a legal way to provision them. Do not equate a verifier-only test
with loading a real mod in the game.

Decompiler and deobfuscator integration is not run because CFR, Vineflower,
JADX, Recaf, and Bytecode Viewer are not vendored in this repository. Their
versions and licenses should be pinned before adding a CI contract.
