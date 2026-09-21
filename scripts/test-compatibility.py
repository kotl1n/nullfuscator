#!/usr/bin/env python3
from pathlib import Path
import json
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
JAR = ROOT / 'build/nullfuscator-obf.jar'


def obfuscate(*args):
    return subprocess.run(['java', '-jar', str(JAR), *map(str, args)],
                          capture_output=True, text=True)


with tempfile.TemporaryDirectory(prefix='nullfuscator-compatibility-') as temp:
    work = Path(temp)
    sources = {
        'p/Main.java': '''package p;
public class Main {
    static int value = 40;
    static int value() { return value + 2; }
    public static void main(String[] args) {
        System.out.println(Helper.call() + ":" + new Child().call()
                + ":" + new Nest().read() + ":" + new q.Child().call()
                + ":" + Movable.read() + ":" + Movable.safe(4)
                + ":" + new q.BoxChild().read());
    }
}
class Helper { static int call() { return Main.value(); } }
class Base { private int value() { return 1; } public int call() { return value(); } }
class Child extends Base { public int value() { return 2; } }
class Nest {
    private int value = 7;
    private int value() { return value; }
    private class Reader { int read() { return value(); } }
    int read() { return new Reader().read(); }
}
''',
        'p/Parent.java': '''package p;
public class Parent { int value() { return 1; } public int call() { return value(); } }
''',
        'q/Child.java': '''package q;
public class Child extends p.Parent { public int value() { return 2; } }
''',
        'p/Movable.java': '''package p;
public class Movable {
    private static int secret = 11;
    public static int read() { int n = 0; for (int i = 0; i < 5; i++) n += secret; return n; }
    public static int safe(int x) { return ((x * 3) ^ 7) + 4; }
}
''',
        'p/Box.java': 'package p; public class Box { public int value = 3; }',
        'q/BoxChild.java': 'package q; public class BoxChild extends p.Box { '
                           'public int read() { return value; } }',
    }
    source_paths = []
    for name, text in sources.items():
        path = work / 'src' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
        source_paths.append(str(path))
    classes = work / 'classes'
    subprocess.run(['javac', '--release', '17', '-d', str(classes), *source_paths], check=True)
    original = work / 'input.jar'
    with zipfile.ZipFile(original, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\r\nMain-Class: p.Main\r\n\r\n')
        for path in sorted(classes.rglob('*.class')):
            archive.write(path, path.relative_to(classes).as_posix())
    expected = subprocess.check_output(['java', '-Xverify:all', '-jar', str(original)])
    assert expected == b'42:1:7:1:55:15:3\n'
    profiles = []
    for index, config in enumerate((
            'classRenamer { enabled:true, renameMain:true }',
            'classRenamer { enabled:true, renameMain:false }',
            'classRenamer { enabled:true, exempt:["class{^p/Main$}"] }',
            'classRenamer { enabled:true, exempt:["class{^p/Nest$}"] }',
            'classRenamer { enabled:true }\n'
            'methodExtraction { enabled:true, percent:100, minInstructions:4 }',
            'classRenamer { enabled:true }\n'
            'methodRelocation { enabled:true, percent:100, minInstructions:8 }',
            'fieldPacking { enabled:true }')):
        path = work / f'rename-{index}.hocon'
        path.write_text(config)
        profiles.append((f'rename-{index}', ['-c', path]))
    profiles.append(('light', ['-p', 'light']))
    headroom = work / 'headroom.hocon'
    headroom.write_text('budgets { instructionGrowthAllowance:100000, methodGrowthAllowance:1000, '
                        'classGrowthAllowance:100, jarGrowthAllowanceBytes:1000000 }')
    profiles.extend((name, ['-p', name, '-c', headroom]) for name in ('balanced', 'strong', 'full'))
    for name, options in profiles:
        output = work / f'{name}.jar'
        result = obfuscate(original, output, *options, '-s', '42')
        assert result.returncode == 0, name + '\n' + result.stderr
        actual = subprocess.run(['java', '-Xverify:all', '-jar', str(output)], capture_output=True)
        assert actual.returncode == 0 and actual.stdout == expected, (name, actual.stdout, actual.stderr)
        print('PASS package access, private dispatch, nests and package boundaries:', name)

    budget_config = work / 'budget.hocon'
    budget_config.write_text('numberEncryption { enabled:true, layers:5 }\n'
                             'budgets { maxJarGrowthPercent:0, jarGrowthAllowanceBytes:0 }')
    absent = work / 'dry.jar'
    before = set(work.iterdir())
    dry = obfuscate(original, absent, '-c', budget_config, '-s', '42', '--dry-run')
    actual = obfuscate(original, absent, '-c', budget_config, '-s', '42')
    assert dry.returncode == actual.returncode == 1, dry.stderr + actual.stderr
    assert 'JAR bytes grew' in dry.stderr and 'JAR bytes grew' in actual.stderr
    assert not absent.exists() and set(work.iterdir()) == before
    assert json.loads(dry.stdout)['outputJarBytes'] > original.stat().st_size
    print('PASS dry-run enforces serialized archive budgets without artifacts')

    split_src = work / 'split-src' / 'shared'
    split_src.mkdir(parents=True)
    (split_src / 'Entry.java').write_text('package shared; public class Entry { '
                                        'public static void main(String[] a) { '
                                        'System.out.println(Dependency.value()); } }')
    (split_src / 'Dependency.java').write_text('package shared; class Dependency { '
                                             'static int value() { return 42; } }')
    split_classes = work / 'split-classes'
    subprocess.run(['javac', '--release', '17', '-d', str(split_classes),
                    *map(str, sorted(split_src.glob('*.java')))], check=True)
    dependency = work / 'dependency.jar'
    with zipfile.ZipFile(dependency, 'w') as archive:
        archive.write(split_classes / 'shared/Dependency.class', 'shared/Dependency.class')
    split_input = work / 'split.jar'
    with zipfile.ZipFile(split_input, 'w') as archive:
        archive.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\r\n'
                         'Main-Class: shared.Entry\r\nClass-Path: dependency.jar\r\n\r\n')
        archive.write(split_classes / 'shared/Entry.class', 'shared/Entry.class')
    split_output = work / 'split-output.jar'
    result = obfuscate(split_input, split_output, '-c', work / 'rename-0.hocon', '-l', dependency, '-s', '42')
    assert result.returncode == 0, result.stderr
    assert subprocess.check_output(['java', '-Xverify:all', '-jar', str(split_output)]) == b'42\n'
    print('PASS package access to external dependencies')
