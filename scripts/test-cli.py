#!/usr/bin/env python3
"""CLI regression tests against an already built executable JAR."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
JAR = ROOT / 'build/nullfuscator-obf.jar'


def run(*args, stdin=''):
    return subprocess.run(['java', '-jar', str(JAR), *map(str, args)], capture_output=True, text=True, input=stdin)


with tempfile.TemporaryDirectory(prefix='nullfuscator-cli-') as temp:
    work = Path(temp)
    source = work / 'App.java'
    source.write_text('public class App { static int f(int x) { return x+42; } public static void main(String[] a) { System.out.println(f(1)); } }')
    subprocess.run(['javac', '--release', '17', '-d', temp, str(source)], check=True)
    original = work / 'input.jar'
    with zipfile.ZipFile(original, 'w') as archive:
        archive.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\r\nMain-Class: App\r\n\r\n')
        archive.write(work / 'App.class', 'App.class')
    config = work / 'profile.hocon'
    config.write_text('methodRenamer { enabled:true, renamePublic:true }')
    base = ['--input', original, '--config', config, '--seed', '77']
    output = work / 'output.jar'
    for option in ('--report', '--mapping'):
        for target in (original, config, output):
            output.write_bytes(b'existing output')
            before = {p: p.read_bytes() for p in (original, config, output)}
            result = run(*base, '--output', output, option, target)
            assert result.returncode != 0, result.stdout + result.stderr
            assert all(p.read_bytes() == data for p, data in before.items())
    result = run(*base, '--output', config)
    assert result.returncode != 0 and config.read_text().startswith('methodRenamer')
    sidecar = work / 'both.txt'
    sidecar.write_text('keep')
    assert run(*base, '--output', output, '--mapping', sidecar, '--report', sidecar).returncode != 0
    assert sidecar.read_text() == 'keep'
    # Existing aliases and normalized paths must not bypass collision detection.
    for kind in ('symlink', 'hardlink'):
        alias = work / (kind + '.jar')
        if kind == 'symlink': alias.symlink_to(original)
        else: os.link(original, alias)
        before = original.read_bytes()
        assert run(*base, '--output', output, '--report', alias).returncode != 0
        assert original.read_bytes() == before
    assert run(*base, '--output', output, '--mapping', work / '.' / 'output.jar').returncode != 0
    # Includes and inherited config files are protected from output writes.
    child = work / 'child.hocon'
    child.write_text('baseConfig = "profile.hocon"\nmethodRenamer { enabled:false, renamePublic:false }\n')
    assert run('--input', original, '--output', config, '--config', child).returncode != 0
    included = work / 'included.hocon'
    included.write_text('include required(file(' + json.dumps(str(config)) + '))\n')
    assert run('--input', original, '--output', output, '--config', included, '--report', config).returncode != 0
    lib = work / 'library.jar'
    lib.write_bytes(original.read_bytes())
    assert run(*base, '--output', lib, '--lib', lib).returncode != 0
    assert run(*base, '--report-only', '--report', original).returncode != 0
    assert run(*base, '--output', output, '--mapping', sidecar, '--no-mapping').returncode == 2
    result = run(*base, '--report-only')
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['schemaVersion'] == 1
    assert '[*]' in result.stderr
    before_hash = hashlib.sha256(original.read_bytes()).hexdigest()
    before_size = original.stat().st_size
    result = run(*base, '--output', original)
    assert result.returncode == 0, result.stderr
    mapping = Path(str(original) + '.map').read_text()
    assert f'input-sha256: {before_hash}' in mapping
    assert f'input-bytes: {before_size}' in mapping
    assert subprocess.check_output(['java', '-Xverify:all', '-jar', str(original)]) == b'43\n'
    for args in (['--input'], ['--input', '--output', 'x'], ['retrace', '--mapping'],
                 ['mapping-info', '--mapping'], ['--input', original, '--output', output, '--seed', 'abc']):
        result = run(*args)
        assert result.returncode == 2 and 'Exception' not in result.stderr, result.stderr
    assert run('--help').returncode == 0 and '--lib' in run('--help').stdout
    assert run('--version').returncode == 0 and '0.2.0' in run('--version').stdout
    short_out = work / 'short_out.jar'
    result = run('-i', original, '-o', short_out, '-p', 'balanced', '-s', '42', '-v')
    assert result.returncode == 0 and short_out.is_file(), result.stderr
    assert subprocess.check_output(['java', '-Xverify:all', '-jar', str(short_out)]) == b'43\n'

    eq_out = work / 'eq_out.jar'
    result = run(f'--input={original}', f'--output={eq_out}', '-p=light', '-s=99')
    assert result.returncode == 0 and eq_out.is_file(), result.stderr

    pos_out = work / 'pos_out.jar'
    result = run(original, pos_out, '-p', 'balanced')
    assert result.returncode == 0 and pos_out.is_file(), result.stderr

    default_target = work / 'mytest.jar'
    default_target.write_bytes(original.read_bytes())
    expected_default_out = work / 'mytest-obf.jar'
    result = run(default_target, '-p', 'light')
    assert result.returncode == 0 and expected_default_out.is_file(), result.stderr

    assert run('presets').returncode == 0 and 'balanced' in run('presets').stdout
    init_file = work / 'exported-config.hocon'
    assert run('init-config', 'balanced', '-o', init_file).returncode == 0 and init_file.is_file()
    assert 'stringEncryption' in init_file.read_text()
    assert run('check', original).returncode == 0 and 'Preflight check PASSED' in run('check', original).stdout

    map_test = Path(str(short_out) + '.map')
    assert run('mapping-info', map_test).returncode == 0 and 'format=2' in run('mapping-info', map_test).stdout
    crash_file = work / 'crash.txt'
    crash_file.write_text('at a.b(Unknown Source)\n')
    assert run('retrace', map_test, crash_file).returncode == 0
    assert run('retrace', map_test, stdin='at a.b(Unknown Source)\n').returncode == 0

    typo_result = run('--confg')
    assert typo_result.returncode == 2 and 'did you mean --config' in typo_result.stderr

    launcher = ROOT / 'bin/nullfuscator'
    launcher_res = subprocess.run([str(launcher), '--version'], capture_output=True, text=True)
    assert launcher_res.returncode == 0 and 'NULLFUSCATOR' in launcher_res.stdout

    with zipfile.ZipFile(JAR) as archive:
        for name in ('LICENSE', 'THIRD_PARTY_NOTICES.md', 'licenses/ASM-BSD-3-Clause.txt',
                     'licenses/Typesafe-Config-Apache-2.0.txt'):
            assert archive.read('META-INF/' + name) == (ROOT / name).read_bytes()
        for preset in ('light.hocon', 'balanced.hocon', 'strong.hocon', 'full.hocon'):
            assert f'presets/{preset}' in archive.namelist()

print('PASS CLI: path collisions, aliases, in-place identity, JSON stdout, arguments, licenses, ergonomic CLI, presets, launcher')
