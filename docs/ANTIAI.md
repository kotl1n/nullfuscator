# AntiAI: live constant dependencies

> [!WARNING]
> **Экспериментальная функция / Experimental Feature**
> `antiAI` является тестовой экспериментальной функцией и может работать не так, как задумано. Не используйте в критичных production-контурах без предварительного тестирования.
> `antiAI` is an experimental test feature and may not work as intended. Test thoroughly before use.

Integer constants are encoded as preimages of a per-class network of keyed,
two-round Feistel permutations. Each call returns the actual value needed by the
original instruction. Routes vary between call sites; the first site traverses
every helper, so helpers are not merely unreachable padding. Long constants use
independent routes for their upper and lower 32-bit halves, with unsigned
reconstruction of the lower half.

### L1 — round-function diversity (0.2.6)

Feistel is invertible for *any* round function, so each helper draws its round
function from a pool of distinct flavors (rotate/multiply, multiply-xor-shift,
mixed boolean-arithmetic, rotate-xor). No two helpers share one inverse template,
so an analyzer cannot recognize a single shape and invert every site with it; the
compile-time `mix` and the emitted `emitMix` bytecode mirror each other bit-for-bit.

### L4 — plausibly-wrong decoy branches (0.2.6)

A share of encoded integer sites (`decoyBranchPercent`) is wrapped in a
runtime-dead branch: the real value is stored, then a data-dependent opaque-false
guard `((s & m) + (s | m)) - (s + m)` — which is `0` for every int, since
`(a & b) + (a | b) == a + b` — guards a dead store of a *different, plausibly-wrong*
value produced through the same `ldc; invokestatic helper` shape. The real value
always wins at runtime; nothing is discarded (no `POP`), so the decoy is not
trivially-dead code a pruner removes. A cost-capped analyzer that skips proving the
guard false may report the decoy value, and the branch adds control structure
around a value that was previously a straight-line load.

### Honest limits

This raises the *cost* of static analysis; it does **not** establish resistance to
an LLM or deobfuscator. Helpers are deterministic and keys are in the class, so an
analyzer that writes an emulator from the listing still recovers the constants; a
blind Opus-class model recovered the uniform (pre-L1/L4) output that way. The next
steps are to hide control structure, derive keys from data not present in the
snippet, and stop decoding to small clean integers. No cryptographic secrecy or
AI-proof claim is made.

## Configuration and compatibility

- `constantEncodingPercent`: 0–100; zero leaves classes unchanged.
- `decoyBranchPercent`: 0–100; share of encoded integer sites wrapped with an
  L4 decoy branch. Defaults to 15 at level 1 and 30 at levels 2–3. Zero disables
  decoys. Higher values add branches and archive size; measure the target workload.
- `level`: 1–3; level 1 encodes integers, levels 2–3 also encode longs.
- `decoyMethods`: retained for profile compatibility, now a helper budget.
  Effective count is `min(32, max(2, clamp(decoyMethods, 0, 32) + 2*(level-1)))`.
  Helpers are emitted only when a constant is transformed. Zero therefore no
  longer disables helpers when constant encoding is enabled.
- Existing encoded numeric keys, generated methods, hot paths, and oversized
  methods retain their existing exclusions. Growth stops at the method guard.
- Java 8 classes are supported. Interfaces before Java 9 are skipped to avoid
  adding public helper methods. Modern interfaces use private static helpers.
- Calls add runtime work (up to 32 helper stages); measure the target workload.

## Validation

`python3 scripts/test-growth.py` includes JVM verification, pipeline checks,
and AntiAiRegression: 10,800 int/long values over 30 seeds and levels 1–3,
including overflow boundaries, Java 8 classes and modern interfaces, exercising
all L1 round-function flavors and L4 decoy branches. Mutation of the deepest
helper must change a real result, detecting discarded decoys; the suite also
asserts decoy branches are actually emitted.

`python3 scripts/evaluate-antiai.py --offline` checks the reported fixture's
output (`25`, `54`) and saves both disassemblies under `build/`. Its report is
separate from the online report, so it cannot overwrite prior model evidence.

With `OPENROUTER_API_KEY` available, omit `--offline` to repeat the blind model
comparison. Responses include provider finish reasons. Errors, timeouts, and
truncated responses are inconclusive, not evidence of protection. A successful
runtime regression is also not evidence that a model cannot recover the logic.
