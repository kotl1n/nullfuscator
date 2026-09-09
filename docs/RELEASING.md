# Publishing a release

1. Run the JDK 17 and JDK 21 CI jobs successfully on the commit to publish.
2. Check `BuildInfo.VERSION`, README binary commands and CHANGELOG agree.
3. Run `python3 scripts/package-release.py` on the verified tree.
4. Verify `(cd build/release && sha256sum -c SHA256SUMS)`.
5. Create a GitHub release for the verified commit, tagged `v0.1.0`, and mark
   it as a pre-release while compatibility is beta. Use CHANGELOG as the notes.
6. Attach the versioned JAR, ZIP and SHA256SUMS from `build/release/` together.

The build is offline and checks `libs/SHA256SUMS` before compilation. Update that
inventory only after independently verifying a deliberate dependency update.
The binary JAR and ZIP both carry license notices. Never attach mappings or
private input JARs to the public release.

The repository history contains old development fixtures and IDE metadata
removed from the current tree. A normal Git push publishes reachable history;
source ZIP exports contain the current tree only. No history rewrite is needed
for the release fixes, and none is performed by packaging.
