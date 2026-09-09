# AntiAI: live constant dependencies

> [!WARNING]
> **Экспериментальная функция / Experimental Feature**
> `antiAI` является тестовой экспериментальной функцией и может работать не так, как задумано. Не используйте в критичных production-контурах без предварительного тестирования.
> `antiAI` is an experimental test feature and may not work as intended. Test thoroughly before use.

The old implementation emitted discarded decoy calls (`INVOKESTATIC; POP`) and
literal XOR pairs. These were independently removable or locally foldable.
The replacement encodes integer constants as preimages of a per-class network
of keyed, two-round Feistel permutations. Each call returns the actual value
needed by the original instruction. Routes vary between call sites; the first
site traverses every helper, so helpers are not merely unreachable padding.
Long constants use independent routes for their upper and lower 32-bit halves,
with unsigned reconstruction of the lower half.

This removes the two reported shortcuts. It does **not** establish resistance
to an LLM or deobfuscator: helpers are deterministic, keys are in the class,
and evaluating them recovers the constants. Original switch/branch structure
remains visible. No cryptographic secrecy or AI-proof claim is made.

## Configuration and compatibility

- `constantEncodingPercent`: 0–100; zero leaves classes unchanged.
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
including overflow boundaries, Java 8 classes and modern interfaces. Mutation
of the deepest helper must change a real result, detecting discarded decoys.

`python3 scripts/evaluate-antiai.py --offline` checks the reported fixture's
output (`25`, `54`) and saves both disassemblies under `build/`. Its report is
separate from the online report, so it cannot overwrite prior model evidence.

With `OPENROUTER_API_KEY` available, omit `--offline` to repeat the blind model
comparison. Responses include provider finish reasons. Errors, timeouts, and
truncated responses are inconclusive, not evidence of protection. A successful
runtime regression is also not evidence that a model cannot recover the logic.
