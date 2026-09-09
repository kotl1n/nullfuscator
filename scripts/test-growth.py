#!/usr/bin/env python3
"""Build and run bounded-growth and arithmetic differential tests offline (JDK 17+)."""
from pathlib import Path
import subprocess
import tempfile
import os
import json
import re
import zipfile

ROOT = Path(__file__).resolve().parents[1]
subprocess.run(["python3", str(ROOT / "scripts/build.py")], check=True)
with tempfile.TemporaryDirectory(prefix="growth-regression-") as temp:
    jar = ROOT / "build/nullfuscator-obf.jar"
    subprocess.run(["javac", "--release", "17", "-cp", str(jar), "-d", temp,
                    str(ROOT / "src/test/java/com/nullfuscator/obf/GrowthRegression.java"),
                    str(ROOT / "src/test/java/com/nullfuscator/obf/CompactGrowthRegression.java"),
                    str(ROOT / "src/test/java/com/nullfuscator/obf/AntiAiRegression.java")], check=True)
    subprocess.run(["java", "-Xverify:all", "-Xmx256m", "-cp", os.pathsep.join([temp, str(jar)]),
                    "com.nullfuscator.obf.GrowthRegression"], check=True)

    subprocess.run(["java", "-Xverify:all", "-Xmx256m", "-cp", os.pathsep.join([temp, str(jar)]),
                    "com.nullfuscator.obf.CompactGrowthRegression"], check=True)

    subprocess.run(["java", "-Xverify:all", "-Xmx256m", "-cp", os.pathsep.join([temp, str(jar)]),
                    "com.nullfuscator.obf.AntiAiRegression"], check=True)

    work = Path(temp)
    source = work / "Smoke.java"
    source.write_text("""public class Smoke {
        static int value(int x) { return ((x * 31) ^ (x >>> 3)) + 17; }
        public static void main(String[] args) {
            long sum = 0;
            for (int i = -500; i < 500; i++) sum += value(i);
            System.out.println("result=" + sum);
        }
    }""", encoding="utf-8")
    subprocess.run(["javac", "--release", "17", "-d", temp, str(source)], check=True)
    original = work / "input.jar"
    subprocess.run(["jar", "--create", "--file", str(original), "--main-class", "Smoke",
                    "-C", temp, "Smoke.class"], check=True)
    expected = subprocess.check_output(["java", "-Xverify:all", "-jar", str(original)])
    artifacts = []
    for index in range(2):
        output = work / f"output{index}.jar"
        result = subprocess.run(["java", "-Xmx256m", "-jar", str(jar), "--input", str(original),
                        "--output", str(output), "--config", str(ROOT / "config/full.hocon"),
                        "--seed", "12345", "--no-mapping"], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        actual = subprocess.check_output(["java", "-Xverify:all", "-jar", str(output)])
        assert actual == expected, (expected, actual)
        artifacts.append(output.read_bytes())
    assert artifacts[0] == artifacts[1], "same-seed output differs"
    print("PASS full pipeline: verifier, differential output, same-seed reproducibility")

    # Mapping v2 carries reproducible release identity and remains retrace-compatible.
    mapped_output = work / "mapped.jar"
    mapped_file = work / "mapped.map"
    subprocess.run(["java", "-jar", str(jar), "--input", str(original), "--output", str(mapped_output),
                    "--config", str(ROOT / "config/light.hocon"), "--mapping", str(mapped_file),
                    "--seed", "77"], check=True, stdout=subprocess.DEVNULL)
    info = subprocess.check_output(["java", "-jar", str(jar), "mapping-info", "--mapping", str(mapped_file)],
                                   text=True)
    assert "format=2" in info and "seed=77" in info and "inputSha256=" in info
    class_line = next(line for line in mapped_file.read_text(encoding="utf-8").splitlines()
                      if " -> " in line and line.endswith(":"))
    original_name, obfuscated_name = re.match(r"([^ ]+) -> ([^:]+):", class_line).groups()
    trace = subprocess.check_output(["java", "-jar", str(jar), "retrace", "--mapping", str(mapped_file)],
                                    input=f"at {obfuscated_name}.x(Unknown Source)\n", text=True)
    assert original_name in trace
    legacy_mapping = work / "legacy.map"
    legacy_mapping.write_text("# legacy\nlegacy.Name -> a.Name:\n", encoding="utf-8")
    legacy_trace = subprocess.check_output(["java", "-jar", str(jar), "retrace", "--mapping", str(legacy_mapping)],
                                           input="at a.Name.run(Unknown Source)\n", text=True)
    assert "legacy.Name" in legacy_trace
    future_mapping = work / "future.map"
    future_mapping.write_text("# nullfuscator-mapping-format: 99\na.Name -> b.Name:\n", encoding="utf-8")
    rejected = subprocess.run(["java", "-jar", str(jar), "retrace", "--mapping", str(future_mapping)],
                              input="", capture_output=True, text=True)
    assert rejected.returncode != 0 and "incompatible" in (rejected.stdout + rejected.stderr)
    print("PASS mapping v2 identity, mapping-info, and retrace compatibility")

    # Every shipped profile must produce a verified, semantically equivalent artifact.
    for profile in ("light", "balanced", "strong"):
        output = work / f"{profile}.jar"
        report = work / f"{profile}.json"
        result = subprocess.run(["java", "-Xmx256m", "-jar", str(jar), "--input", str(original),
                        "--output", str(output), "--config", str(ROOT / f"config/{profile}.hocon"),
                        "--report", str(report), "--seed", "12345", "--no-mapping"],
                        capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(profile + ":\n" + result.stdout + result.stderr)
        assert subprocess.check_output(["java", "-Xverify:all", "-jar", str(output)]) == expected
        data = json.loads(report.read_text(encoding="utf-8"))
        assert data["schemaVersion"] == 1 and data["outputJarBytes"] == output.stat().st_size
        assert data["passes"] and any("changedMethods" in item for item in data["passes"])
        print(f"PASS {profile} profile: report, budgets, verifier, differential output")

    # Method selectors retain original identities after method and class renaming.
    hot_config = work / "hot.hocon"
    hot_config.write_text(r'''
methodRenamer { enabled:true, renameVirtual:true, renamePublic:true }
classRenamer { enabled:true, renameMain:true }
numberEncryption { enabled:true, layers:2 }
hotPaths.exclude = ["method{^Smoke#value\\(I\\)I$}"]
''', encoding="utf-8")
    hot_report = work / "hot.json"
    hot_output = work / "hot.jar"
    subprocess.run(["java", "-jar", str(jar), "--input", str(original), "--output", str(hot_output),
                    "--config", str(hot_config), "--report", str(hot_report), "--seed", "7",
                    "--no-mapping"], check=True, stdout=subprocess.DEVNULL)
    passes = {p["id"]: p for p in json.loads(hot_report.read_text())["passes"]}
    assert passes["numberEncryption"]["changedMethods"] > 0
    assert "Smoke#value(I)I" not in passes["numberEncryption"]["changedMethodOrigins"]
    assert subprocess.check_output(["java", "-Xverify:all", "-jar", str(hot_output)]) == expected
    print("PASS hot method policy survives method/class remapping")

    # report-only must leave no output artifact behind.
    absent = work / "must-not-exist.jar"
    report_only = work / "report-only.json"
    subprocess.run(["java", "-jar", str(jar), "--input", str(original), "--report-only",
                    "--config", str(ROOT / "config/light.hocon"), "--report", str(report_only),
                    "--seed", "1"], check=True, stdout=subprocess.DEVNULL)
    assert not absent.exists() and json.loads(report_only.read_text())["outputJarBytes"] == -1
    print("PASS report-only creates no transformed artifact")

    # Multi-release class overrides fail safely when class renaming is requested.
    mr = work / "mr.jar"
    versioned = work / "META-INF/versions/17"
    versioned.mkdir(parents=True)
    (versioned / "Smoke.class").write_bytes((work / "Smoke.class").read_bytes())
    subprocess.run(["jar", "--create", "--file", str(mr), "--main-class", "Smoke",
                    "-C", temp, "Smoke.class", "-C", temp, "META-INF/versions/17/Smoke.class"], check=True)
    rejected = subprocess.run(["java", "-jar", str(jar), "--input", str(mr), "--report-only",
                    "--config", str(ROOT / "config/light.hocon")], capture_output=True, text=True)
    assert rejected.returncode != 0 and "META-INF/versions" in (rejected.stdout + rejected.stderr)
    print("PASS unsafe multi-release rename rejected in preflight")

    # Java 17 records/sealed classes and Java 21 class files remain executable.
    modern17_src = work / "modern17-src"
    modern17_classes = work / "modern17-classes"
    modern17_src.mkdir()
    modern17_classes.mkdir()
    (modern17_src / "Modern17.java").write_text("""
public class Modern17 {
  public static void main(String[] args) { System.out.println(area(new Circle(3))); }
  static int area(Shape shape) { return shape instanceof Circle c ? c.radius() * c.radius() : 0; }
}
sealed interface Shape permits Circle {}
record Circle(int radius) implements Shape {}
""", encoding="utf-8")
    subprocess.run(["javac", "--release", "17", "-d", str(modern17_classes),
                    str(modern17_src / "Modern17.java")], check=True)
    modern17_jar = work / "modern17.jar"
    subprocess.run(["jar", "--create", "--file", str(modern17_jar), "--main-class", "Modern17",
                    "-C", str(modern17_classes), "."], check=True)
    modern17_output = work / "modern17-obf.jar"
    subprocess.run(["java", "-jar", str(jar), "--input", str(modern17_jar), "--output",
                    str(modern17_output), "--config", str(ROOT / "config/strong.hocon"),
                    "--seed", "17", "--no-mapping"], check=True, stdout=subprocess.DEVNULL)
    assert subprocess.check_output(["java", "-Xverify:all", "-jar", str(modern17_output)]) == b"9\n"

    print("PASS Java 17 record/sealed fixture")
    javac_version = subprocess.check_output(["javac", "-version"], stderr=subprocess.STDOUT, text=True)
    if int(re.search(r"javac (\d+)", javac_version).group(1)) >= 21:
        modern21_src = work / "modern21-src"
        modern21_classes = work / "modern21-classes"
        modern21_src.mkdir()
        modern21_classes.mkdir()
        (modern21_src / "Modern21.java").write_text("""
    import java.util.List;
    public class Modern21 { public static void main(String[] args) { System.out.println(List.of(7, 9).getFirst()); } }
    """, encoding="utf-8")
        subprocess.run(["javac", "--release", "21", "-d", str(modern21_classes),
                        str(modern21_src / "Modern21.java")], check=True)
        modern21_jar = work / "modern21.jar"
        subprocess.run(["jar", "--create", "--file", str(modern21_jar), "--main-class", "Modern21",
                        "-C", str(modern21_classes), "."], check=True)
        modern21_output = work / "modern21-obf.jar"
        subprocess.run(["java", "-jar", str(jar), "--input", str(modern21_jar), "--output",
                        str(modern21_output), "--config", str(ROOT / "config/light.hocon"),
                        "--seed", "21", "--no-mapping"], check=True, stdout=subprocess.DEVNULL)
        assert subprocess.check_output(["java", "-Xverify:all", "-jar", str(modern21_output)]) == b"7\n"
        print("PASS Java 21 classfile fixture")

    else:
        print("SKIP Java 21 fixture: current JDK is older than 21")

    # Modular output preserves module metadata; class renaming is intentionally skipped.
    module_src = work / "module-src"
    module_classes = work / "module-classes"
    (module_src / "p").mkdir(parents=True)
    module_classes.mkdir()
    (module_src / "module-info.java").write_text("module fixture.module {}", encoding="utf-8")
    (module_src / "p/Main.java").write_text(
            "package p; public class Main { public static void main(String[] args) { System.out.println(\"module\"); } }",
            encoding="utf-8")
    subprocess.run(["javac", "--release", "17", "-d", str(module_classes),
                    str(module_src / "module-info.java"), str(module_src / "p/Main.java")], check=True)
    module_jar = work / "module.jar"
    subprocess.run(["jar", "--create", "--file", str(module_jar), "-C", str(module_classes), "."], check=True)
    module_output = work / "module-obf.jar"
    subprocess.run(["java", "-jar", str(jar), "--input", str(module_jar), "--output", str(module_output),
                    "--config", str(ROOT / "config/light.hocon"), "--seed", "31", "--no-mapping"],
                    check=True, stdout=subprocess.DEVNULL)
    assert subprocess.check_output(["java", "--module-path", str(module_output),
                                    "--module", "fixture.module/p.Main"]) == b"module\n"
    print("PASS modular JAR fixture")

    # Fabric entrypoint metadata keeps its externally referenced class name stable.
    fabric_jar = work / "fabric.jar"
    with zipfile.ZipFile(original) as source_jar, zipfile.ZipFile(fabric_jar, "w") as target_jar:
        for item in source_jar.infolist():
            target_jar.writestr(item, source_jar.read(item))
        target_jar.writestr("fabric.mod.json", '{"schemaVersion":1,"id":"smoke",'
                '"version":"1","entrypoints":{"main":["Smoke"]}}')
    rename_config = work / "rename.hocon"
    rename_config.write_text("classRenamer { enabled:true, renameMain:true }", encoding="utf-8")
    fabric_output = work / "fabric-output.jar"
    subprocess.run(["java", "-jar", str(jar), "--input", str(fabric_jar),
                    "--output", str(fabric_output), "--config", str(rename_config),
                    "--no-mapping"], check=True, capture_output=True, text=True)
    with zipfile.ZipFile(fabric_output) as output_jar:
        assert "Smoke.class" in output_jar.namelist()
    print("PASS Fabric entrypoint class name preserved")

    # Service descriptor paths and provider names follow renamed classes.
    service_src = work / "service-src"
    service_classes = work / "service-classes"
    (service_src / "svc").mkdir(parents=True)
    service_classes.mkdir()
    (service_src / "svc/Service.java").write_text(
            "package svc; public interface Service { String value(); }", encoding="utf-8")
    (service_src / "svc/Provider.java").write_text(
            "package svc; public class Provider implements Service { public String value() { return \"service\"; } }",
            encoding="utf-8")
    (service_src / "svc/Main.java").write_text(
            "package svc; public class Main { public static void main(String[] args) { "
            "System.out.println(java.util.ServiceLoader.load(Service.class).findFirst().orElseThrow().value()); } }",
            encoding="utf-8")
    subprocess.run(["javac", "--release", "17", "-d", str(service_classes),
                    str(service_src / "svc/Service.java"), str(service_src / "svc/Provider.java"),
                    str(service_src / "svc/Main.java")], check=True)
    service_resource = service_classes / "META-INF/services"
    service_resource.mkdir(parents=True)
    (service_resource / "svc.Service").write_text("svc.Provider\n", encoding="utf-8")
    service_jar = work / "service.jar"
    subprocess.run(["jar", "--create", "--file", str(service_jar), "--main-class", "svc.Main",
                    "-C", str(service_classes), "."], check=True)
    service_output = work / "service-obf.jar"
    subprocess.run(["java", "-jar", str(jar), "--input", str(service_jar), "--output", str(service_output),
                    "--config", str(ROOT / "config/light.hocon"), "--seed", "41", "--no-mapping"],
                    check=True, stdout=subprocess.DEVNULL)
    assert subprocess.check_output(["java", "-Xverify:all", "-jar", str(service_output)]) == b"service\n"
    print("PASS ServiceLoader descriptor remap")

    # Missing direct hierarchy dependencies fail before any pass runs.
    hierarchy_src = work / "hierarchy-src"
    hierarchy_classes = work / "hierarchy-classes"
    hierarchy_src.mkdir()
    hierarchy_classes.mkdir()
    (hierarchy_src / "Parent.java").write_text("public class Parent {}", encoding="utf-8")
    (hierarchy_src / "Child.java").write_text("public class Child extends Parent {}", encoding="utf-8")
    subprocess.run(["javac", "--release", "17", "-d", str(hierarchy_classes),
                    str(hierarchy_src / "Parent.java"), str(hierarchy_src / "Child.java")], check=True)
    missing_jar = work / "missing-parent.jar"
    subprocess.run(["jar", "--create", "--file", str(missing_jar),
                    "-C", str(hierarchy_classes), "Child.class"], check=True)
    empty_config = work / "empty.hocon"
    empty_config.write_text("", encoding="utf-8")
    rejected = subprocess.run(["java", "-jar", str(jar), "--input", str(missing_jar),
                    "--report-only", "--config", str(empty_config)], capture_output=True, text=True)
    assert rejected.returncode != 0 and "incomplete classpath" in (rejected.stdout + rejected.stderr)
    print("PASS incomplete hierarchy classpath rejected in preflight")

    # Gson-like schemas are surfaced in the CI report before field renaming.
    gson_src = work / "gson-src"
    gson_classes = work / "gson-classes"
    annotation_dir = gson_src / "com/google/gson/annotations"
    annotation_dir.mkdir(parents=True)
    gson_classes.mkdir()
    (annotation_dir / "Expose.java").write_text(
            "package com.google.gson.annotations; public @interface Expose {}", encoding="utf-8")
    (gson_src / "GsonRisk.java").write_text(
            "public class GsonRisk { @com.google.gson.annotations.Expose public String value; }",
            encoding="utf-8")
    subprocess.run(["javac", "--release", "17", "-d", str(gson_classes),
                    str(annotation_dir / "Expose.java"), str(gson_src / "GsonRisk.java")], check=True)
    gson_jar = work / "gson-risk.jar"
    subprocess.run(["jar", "--create", "--file", str(gson_jar), "-C", str(gson_classes), "."], check=True)
    gson_config = work / "gson.hocon"
    gson_config.write_text("fieldRenamer { enabled:true }", encoding="utf-8")
    gson_report = work / "gson.json"
    subprocess.run(["java", "-jar", str(jar), "--input", str(gson_jar), "--report-only",
                    "--config", str(gson_config), "--report", str(gson_report)], check=True,
                    capture_output=True, text=True)
    assert any("Gson schema" in warning for warning in json.load(open(gson_report))["warnings"])
    print("PASS risky Gson schema reported")

    # Coverage and exact archive budgets fail without installing a partial output.
    coverage_config = work / "coverage.hocon"
    coverage_config.write_text(
            'coverage { required:["method{^Smoke#value\\\\(I\\\\)I$}"], minPercent:100 }',
            encoding="utf-8")
    forbidden_output = work / "coverage-output.jar"
    rejected = subprocess.run(["java", "-jar", str(jar), "--input", str(original),
                    "--output", str(forbidden_output), "--config", str(coverage_config)],
                    capture_output=True, text=True)
    assert rejected.returncode != 0 and "coverage" in (rejected.stdout + rejected.stderr)
    assert not forbidden_output.exists()

    jar_budget_config = work / "jar-budget.hocon"
    jar_budget_config.write_text(
            "stringEncryption { enabled:true }\nbudgets { maxJarGrowthPercent:0 }", encoding="utf-8")
    budget_output = work / "budget-output.jar"
    rejected = subprocess.run(["java", "-jar", str(jar), "--input", str(original),
                    "--output", str(budget_output), "--config", str(jar_budget_config)],
                    capture_output=True, text=True)
    assert rejected.returncode != 0 and "JAR bytes" in (rejected.stdout + rejected.stderr)
    assert not budget_output.exists()
    print("PASS coverage and exact JAR budgets reject before output install")

    benchmark_report = work / "benchmark.json"
    subprocess.run(["python3", str(ROOT / "scripts/benchmark-gate.py"),
                    "--input", str(original), "--config", str(ROOT / "config/balanced.hocon"),
                    "--max-build-seconds", "20", "--max-peak-rss-mib", "512",
                    "--max-output-ratio", "100", "--max-startup-ms", "5000",
                    "--startup-runs", "2", "--report", str(benchmark_report)],
                    check=True, stdout=subprocess.DEVNULL)
    benchmark = json.loads(benchmark_report.read_text(encoding="utf-8"))
    assert benchmark["passed"] and benchmark["startupMedianMs"] is not None
    print("PASS explicit build/RSS/size/cold-start benchmark gate")

    suite_report = work / "benchmark-suite.json"
    subprocess.run(["python3", str(ROOT / "scripts/benchmark-suite.py"), "--input", str(original),
                    "--profile", f"light={ROOT / 'config/light.hocon'}", "--runs", "1", "--warmup", "0",
                    "--report", str(suite_report)], check=True, stdout=subprocess.DEVNULL)
    suite = json.loads(suite_report.read_text(encoding="utf-8"))
    assert suite["profiles"]["light"]["sampleCount"] == 1 and suite["inputSha256"]
    print("PASS reproducible benchmark suite report")
