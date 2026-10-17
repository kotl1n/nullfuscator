# Runtime and archive overhead comparison

## 2026-10-17: dispersed arithmetic state access

Cross-class dispersion was spending a full volatile-store fence on each protected arithmetic operation. The new default uses opaque VarHandle element access for its private state, with handles resolved once through constant-pool entries. Each helper still samples and updates runtime state, uses the same masks and arithmetic, and keeps the sampled value local to the invocation. Application volatile fields retain their original semantics. No profile percentages, encryption layers, helper counts or operation budgets were reduced.

This path applies when the transformation targets already contain Java 11+ class files, including mixed archives with older shaded dependencies. Archives containing only older classes keep the previous implementation. Set `crossClassDispersion.opaqueState = false` to restore the previous access strategy; balanced, strong and full outputs with that setting were byte-identical to the pre-change build for the fixed-seed fixture.

Measured on OpenJDK 21.0.12.1 with seed `20260910`. The table uses medians from three interleaved before/after runs, reversing run order in the middle pair. Each fresh JVM warms up for 1,000,000 rounds and measures another 1,000,000 rounds. Every run uses `-Xverify:all` and returns checksum `1020676914`. Raw samples, the earlier short-loop and sequential long-loop measurements, coverage counters and measured build hashes are in [performance-state-access.json](performance-state-access.json).

| Profile | Metric | Before | After | Change |
| --- | --- | ---: | ---: | ---: |
| strong | Kernel loop | 845.21 ms | 637.23 ms | -24.6% |
| strong | Peak process RSS | 54.93 MiB | 68.36 MiB | +13.44 MiB |
| strong | JAR bytes | 67,619 | 69,781 | +3.2% |
| full | Kernel loop | 8002.23 ms | 3956.87 ms | -50.6% |
| full | Peak process RSS | 101.30 MiB | 137.38 MiB | +36.07 MiB |
| full | JAR bytes | 290,032 | 297,320 | +2.5% |

The speed improvement has a memory and archive-size cost, shown above. Opaque access reduces ordering costs for generated state; it does not remove dispersed helpers or their state updates. Full still has substantial overhead on this arithmetic-heavy fixture. These are desktop measurements with background load, not an isolated JMH result or an application FPS measurement. Matched coverage and differential checks do not establish identical reverse-engineering resistance.

Sequential long-loop measurements also recorded higher obfuscator peak RSS for full: 144.61 MiB before and 192.92 MiB after. Peak process RSS includes JVM compilation and native allocations, not only live application heap.

Coverage counters matched before/after: strong dispersed 240 operations through 37 helpers in 8 sinks and hid 73 calls; full dispersed 3,142 operations through 290 helpers in 24 sinks and hid 1,225 calls. Both retained three semanticCore methods. The dedicated regression checks all 15 integer/long operations, overflow and shift boundaries, concurrent calls, actual state updates, renamed classes/fields, unchanged application volatile fields, and Java 8/9/11/17 class-file fixtures.

Validation passed: `python3 scripts/test-growth.py` and `python3 scripts/test-cli.py`. The rebuilt artifact after comment removal reproduced both measured strong/full outputs byte-for-byte.

Reproduce the longer workload sequentially with a saved pre-change build and the current build:

```sh
python3 scripts/benchmark.py --jar /path/to/before.jar --runs 3 --profiles strong full --warmup-rounds 1000000 --rounds 1000000
python3 scripts/benchmark.py --jar build/nullfuscator-obf.jar --runs 3 --profiles strong full --warmup-rounds 1000000 --rounds 1000000
```

For interleaving, generate the fixture with the same iteration counts, transform it once with each build and fixed seed, then alternate the resulting JARs for three runs, reversing order in the middle pair. Run other verification jobs after timing finishes.

## 2026-09-13: helper layering and exception transport

Measured on 2026-09-13 with OpenJDK 21.0.12.1. The baseline is the working-tree build before these optimizations, including pre-existing local changes. Each value is a median of five runs with seed `20260910`; builds were measured sequentially without concurrent regression tests. Raw measurements and build hashes are in [performance-comparison.json](performance-comparison.json).

The published 0.2.2-beta benchmark is in [benchmark-0.2.2-beta.json](benchmark-0.2.2-beta.json). It verifies the same output checksum for every profile run.

| Profile | Metric | Before | After | Change |
| --- | --- | ---: | ---: | ---: |
| strong | JAR bytes | 82,889 | 69,908 | -15.7% |
| strong | Uncompressed class bytes | 141,617 | 118,802 | -16.1% |
| strong | Kernel time | 148.61 ms | 107.32 ms | -27.8% |
| strong | Whole process time | 473.73 ms | 399.82 ms | -15.6% |
| strong | Obfuscation time | 719.61 ms | 694.91 ms | -3.4% |
| full | JAR bytes | 302,849 | 289,749 | -4.3% |
| full | Uncompressed class bytes | 469,656 | 451,275 | -3.9% |
| full | Kernel time | 998.07 ms | 765.83 ms | -23.3% |
| full | Whole process time | 2,533.52 ms | 2,079.91 ms | -17.9% |
| full | Obfuscation time | 775.54 ms | 765.24 ms | -1.3% |

Input kernel time was 12.61 ms before and 12.85 ms after. Every input/output run returned checksum `79434320`; semanticCore protected three methods in both profiles and both builds. The fixture is small (7,146 bytes) and intentionally stresses arithmetic protection. It includes JVM warmup and compilation effects and is not a steady-state JMH benchmark or a prediction for a real application.

Changes:

- Input methods, including semantic bridges and input synthetic methods, remain eligible for anti-debug and exception-return protection. Generated arithmetic helpers no longer receive redundant guards and exception-return wrappers.
- Exception dispatch uses one stackless, suppression-disabled token. Results stay in invocation-local slots instead of mutable exception fields and ThreadLocal storage. Typed throw/catch routing remains in place.
- Unused field accessors and unused detector classes are removed before later passes expand them.
- Maximum DEFLATE compression reduces archive bytes without changing class contents.

No profile percentages or encryption settings were reduced. Helper layering is lower and return transport is simpler; equal reverse-engineering resistance has not been demonstrated. This comparison measures size, execution and semantics, not attack cost.

Validation: `python3 scripts/test-growth.py` (including RuntimeOverheadRegression, all shipped primary profiles, verifier, deterministic output, Java 17/21, module/Fabric/ServiceLoader fixtures) and `python3 scripts/test-cli.py`. Return tests cover primitives, raw NaN/signed-zero bits, object/array identity, void side effects, recursive and concurrent calls, and application exception propagation.

Reproduce after building:

```sh
python3 scripts/benchmark.py --jar /path/to/before.jar --runs 5 --profiles strong full
python3 scripts/benchmark.py --jar build/nullfuscator-obf.jar --runs 5 --profiles strong full
```
