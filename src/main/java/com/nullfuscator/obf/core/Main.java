package com.nullfuscator.obf.core;

import com.nullfuscator.obf.transform.AntiAiTransformer;
import com.nullfuscator.obf.transform.AntiDebugTransformer;
import com.nullfuscator.obf.transform.AntiDecompilerTransformer;
import com.nullfuscator.obf.transform.AntiDeobfuscatorTransformer;
import com.nullfuscator.obf.transform.BogusJumpTransformer;
import com.nullfuscator.obf.transform.ClassRenamer;
import com.nullfuscator.obf.transform.ControlFlowTransformer;
import com.nullfuscator.obf.transform.CrossClassDispersionTransformer;
import com.nullfuscator.obf.transform.FieldIndirectionTransformer;
import com.nullfuscator.obf.transform.FieldRenamer;
import com.nullfuscator.obf.transform.ExceptionReturnTransformer;
import com.nullfuscator.obf.transform.FileCrasherTransformer;
import com.nullfuscator.obf.transform.FlatteningTransformer;
import com.nullfuscator.obf.transform.MethodRenamer;
import com.nullfuscator.obf.transform.NumberEncryptionTransformer;
import com.nullfuscator.obf.transform.ReferenceHidingTransformer;
import com.nullfuscator.obf.transform.RecordMetadataTransformer;
import com.nullfuscator.obf.transform.MethodRelocationTransformer;
import com.nullfuscator.obf.transform.MethodExtractionTransformer;
import com.nullfuscator.obf.transform.FieldPackingTransformer;
import com.nullfuscator.obf.transform.ReturnFlowTransformer;
import com.nullfuscator.obf.transform.SemanticFabricTransformer;
import com.nullfuscator.obf.transform.SourceStripper;
import com.nullfuscator.obf.transform.StringEncryptionTransformer;
import com.nullfuscator.obf.transform.SwitchFlowTransformer;
import com.nullfuscator.obf.util.Ansi;
import com.nullfuscator.obf.util.NameGenerator;
import com.nullfuscator.obf.util.ObfLog;

import java.io.File;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public final class Main {

    public static void main(String[] args) {
        try {
            run(args);
        } catch (Exception e) {
            System.err.println("error: " + e.getMessage());
            if (java.util.Arrays.asList(args).contains("--verbose") || java.util.Arrays.asList(args).contains("-v")) {
                e.printStackTrace(System.err);
            }
            System.exit(e instanceof IllegalArgumentException ? 2 : 1);
        }
    }

    private static void run(String[] args) throws Exception {
        for (String a : args) {
            if ("--no-color".equals(a)) Ansi.setEnabled(false);
        }

        if (args.length == 0) {
            help();
            System.exit(2);
            return;
        }

        for (String a : args) {
            if ("--help".equals(a) || "-h".equals(a)) { help(); return; }
            if ("--version".equals(a) || "-V".equals(a)) {
                System.out.println("NULLFUSCATOR " + BuildInfo.VERSION);
                return;
            }
        }

        if (args.length == 1 && ("-v".equals(args[0]) || "-version".equals(args[0]) || "version".equals(args[0]))) {
            System.out.println("NULLFUSCATOR " + BuildInfo.VERSION);
            return;
        }

        String first = args[0];
        if ("retrace".equals(first)) { retrace(args); return; }
        if ("mapping-info".equals(first)) { mappingInfo(args); return; }
        if ("presets".equals(first) || "preset-list".equals(first)) { presets(); return; }
        if ("init-config".equals(first) || "init".equals(first)) { initConfig(args); return; }
        if ("check".equals(first) || "verify".equals(first) || "preflight".equals(first)) { checkJar(args); return; }

        File input = null, output = null, mapping = null, reportFile = null;
        String configArg = null, presetArg = null;
        Long seed = null;
        boolean verbose = false;
        boolean quiet = false;
        boolean noMapping = false;
        boolean reportOnly = false;
        List<String> additionalLibs = new ArrayList<>();

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (i == 0 && "obfuscate".equals(arg)) continue;

            if (arg.startsWith("-")) {
                int eq = arg.indexOf('=');
                String flag = eq > 0 ? arg.substring(0, eq) : arg;
                String val = eq > 0 ? arg.substring(eq + 1) : null;

                switch (flag) {
                    case "--input", "-i" -> input = new File(val != null ? val : value(args, ++i));
                    case "--output", "-o" -> output = new File(val != null ? val : value(args, ++i));
                    case "--config", "-c" -> configArg = (val != null ? val : value(args, ++i));
                    case "--preset", "-p" -> presetArg = (val != null ? val : value(args, ++i));
                    case "--lib", "-l" -> {
                        String libVal = (val != null ? val : value(args, ++i));
                        if (libVal.contains(",")) {
                            for (String p : libVal.split(",")) if (!p.isBlank()) additionalLibs.add(p.trim());
                        } else {
                            additionalLibs.add(libVal);
                        }
                    }
                    case "--mapping", "-m" -> mapping = new File(val != null ? val : value(args, ++i));
                    case "--report", "-r" -> reportFile = new File(val != null ? val : value(args, ++i));
                    case "--report-only", "--dry-run" -> reportOnly = true;
                    case "--no-mapping", "-M" -> noMapping = true;
                    case "--seed", "-s" -> {
                        String s = (val != null ? val : value(args, ++i));
                        try {
                            seed = Long.parseLong(s);
                        } catch (NumberFormatException e) {
                            throw new IllegalArgumentException("invalid seed value: " + s);
                        }
                    }
                    case "--verbose", "-v" -> verbose = true;
                    case "--quiet", "-q" -> quiet = true;
                    case "--no-color" -> Ansi.setEnabled(false);
                    default -> {
                        String suggestion = suggestFlag(flag);
                        String msg = "unknown arg: " + arg + (suggestion != null ? " (did you mean " + suggestion + "?)" : "");
                        throw new IllegalArgumentException(msg);
                    }
                }
            } else {
                if (input == null) {
                    input = new File(arg);
                } else if (output == null && !reportOnly) {
                    output = new File(arg);
                } else {
                    throw new IllegalArgumentException("unexpected positional argument: " + arg);
                }
            }
        }

        if (input == null) {
            System.err.println("error: missing required input JAR file");
            System.err.println("usage: nullfuscator <input.jar> [output.jar] [options]");
            System.err.println("Run 'nullfuscator --help' for complete usage reference.");
            System.exit(2);
            return;
        }

        if (!reportOnly && output == null) {
            String inputPath = input.getPath();
            if (inputPath.toLowerCase().endsWith(".jar")) {
                output = new File(inputPath.substring(0, inputPath.length() - 4) + "-obf.jar");
            } else {
                output = new File(inputPath + "-obf.jar");
            }
        }

        if (noMapping && mapping != null) throw new IllegalArgumentException("--mapping conflicts with --no-mapping");
        if (!input.isFile()) throw new IllegalArgumentException("input JAR does not exist: " + input);

        ObfConfig cfg;
        File configForValidation = null;
        if (configArg != null && presetArg != null) {
            File custom = new File(configArg);
            if (!custom.isFile()) throw new IllegalArgumentException("config file does not exist: " + custom);
            cfg = ObfConfig.loadWithPresetFallback(custom, presetArg);
            configForValidation = custom;
        } else if (configArg != null) {
            File custom = new File(configArg);
            boolean hasDir = configArg.contains("/") || configArg.contains("\\");
            if (custom.isFile()) {
                cfg = ObfConfig.load(custom);
                configForValidation = custom;
            } else if (!hasDir && ObfConfig.isKnownPreset(configArg)) {
                cfg = ObfConfig.loadPreset(configArg);
            } else {
                cfg = ObfConfig.load(custom);
            }
        } else if (presetArg != null) {
            cfg = ObfConfig.loadPreset(presetArg);
        } else {
            cfg = ObfConfig.empty();
        }
        cfg = cfg.withAdditionalLibs(additionalLibs);

        ObfLog log = new ObfLog(verbose);
        File mapFile = noMapping || reportOnly ? null
                : mapping != null ? mapping : new File(output.getPath() + ".map");
        validatePaths(input, reportOnly ? null : output, mapFile, reportFile, configForValidation, cfg);
        long inputBytes = input.length();
        String inputHash = reportOnly || noMapping ? null : ArtifactDigest.sha256(input);
        long theSeed = (seed != null) ? seed : new SecureRandom().nextLong();

        NameGenerator names = new NameGenerator(new String[] { "I", "l", "1", "lI", "Il", "ll" });
        ObfContext ctx = new ObfContext(cfg, theSeed, log, names);
        boolean needsReport = reportFile != null || reportOnly
                || cfg.section("budgets").present() || cfg.section("coverage").present();
        RunReport report = needsReport ? new RunReport(theSeed, inputBytes) : null;
        ctx.report(report);

        log.info("reading " + input.getName());
        JarIO.read(input, ctx);

        ObfEngine engine = new ObfEngine(buildPipeline());
        try {
            Preflight.run(ctx);
            engine.run(ctx);
            BudgetPolicy.verifyStructure(ctx);
            if (!reportOnly) {
                log.info("writing " + output.getName());
                JarIO.write(output, ctx);
                if (!noMapping && !ctx.mapping().isEmpty()) {
                    ctx.mapping().write(mapFile, new ObfMapping.Metadata(BuildInfo.MAPPING_FORMAT,
                            BuildInfo.VERSION, theSeed, inputHash, inputBytes));
                    log.info("mapping -> " + mapFile.getPath());
                }
                log.info("done: " + ctx.classes().size() + " classes -> " + output.getPath());
                if (!quiet) {
                    long outBytes = output.length();
                    long diff = outBytes - inputBytes;
                    double pct = inputBytes > 0 ? (diff * 100.0) / inputBytes : 0;
                    String sign = diff >= 0 ? "+" : "";
                    System.err.printf("[✓] Obfuscation finished: %s -> %s (%s%.1f%%) | %d classes%n",
                            formatBytes(inputBytes), formatBytes(outBytes), sign, pct, ctx.classes().size());
                }
            } else {
                log.info("report-only: output and mapping were not written");
            }
        } catch (Exception e) {
            if (report != null) report.warn("fatal: " + e.getMessage());
            throw e;
        } finally {
            if (reportFile != null) {
                File parent = reportFile.getAbsoluteFile().getParentFile();
                if (parent != null) parent.mkdirs();
                report.write(reportFile);
                log.info("report -> " + reportFile.getPath());
            } else if (reportOnly) {
                System.out.print(report.json());
            }
        }
    }

    private static String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format(java.util.Locale.US, "%.1f KB", bytes / 1024.0);
        return String.format(java.util.Locale.US, "%.2f MB", bytes / (1024.0 * 1024.0));
    }

    private static String value(String[] args, int index) {
        if (index >= args.length || args[index].startsWith("-"))
            throw new IllegalArgumentException("missing value for " + args[index - 1]);
        return args[index];
    }

    private static final List<String> KNOWN_FLAGS = List.of(
            "--input", "-i",
            "--output", "-o",
            "--config", "-c",
            "--preset", "-p",
            "--lib", "-l",
            "--mapping", "-m",
            "--no-mapping", "-M",
            "--report", "-r",
            "--report-only", "--dry-run",
            "--seed", "-s",
            "--verbose", "-v",
            "--quiet", "-q",
            "--no-color",
            "--help", "-h",
            "--version", "-V"
    );

    private static String suggestFlag(String typo) {
        String best = null;
        int minDistance = Integer.MAX_VALUE;
        for (String flag : KNOWN_FLAGS) {
            if (typo.startsWith("--") != flag.startsWith("--")) continue;
            int d = levenshtein(typo, flag);
            if (d < minDistance && d <= 3) {
                minDistance = d;
                best = flag;
            }
        }
        return best;
    }

    private static int levenshtein(String a, String b) {
        int[] costs = new int[b.length() + 1];
        for (int j = 0; j <= b.length(); j++) costs[j] = j;
        for (int i = 1; i <= a.length(); i++) {
            costs[0] = i;
            int nw = i - 1;
            for (int j = 1; j <= b.length(); j++) {
                int cj = Math.min(1 + Math.min(costs[j], costs[j - 1]),
                        a.charAt(i - 1) == b.charAt(j - 1) ? nw : nw + 1);
                nw = costs[j];
                costs[j] = cj;
            }
        }
        return costs[b.length()];
    }

    private static void presets() {
        System.out.println("Available Built-in Presets:\n");
        System.out.printf("%-10s %-12s %-16s %-10s %s%n", "Preset", "Protection", "Size Growth", "Overhead", "Recommended For");
        System.out.println("-----------------------------------------------------------------------------------------------");
        for (var p : ObfConfig.PRESET_INFOS) {
            System.out.printf("%-10s %-12s %-16s %-10s %s%n",
                    p.name(), p.protectionLevel(), p.sizeImpact(), p.runtimeOverhead(), p.description());
        }
        System.out.println("-----------------------------------------------------------------------------------------------");
        System.out.println("\nUsage: nullfuscator -i <app.jar> -p <preset>");
        System.out.println("Export template: nullfuscator init-config <preset> -o <file.hocon>");
    }

    private static void initConfig(String[] args) throws Exception {
        String preset = "balanced";
        File out = null;
        for (int i = 1; i < args.length; i++) {
            String arg = args[i];
            if (arg.equals("-o") || arg.equals("--output")) {
                out = new File(value(args, ++i));
            } else if (arg.startsWith("-o=")) {
                out = new File(arg.substring(3));
            } else if (arg.startsWith("--output=")) {
                out = new File(arg.substring(9));
            } else if (!arg.startsWith("-")) {
                preset = arg;
            } else {
                throw new IllegalArgumentException("unknown arg for init-config: " + arg);
            }
        }
        String content = ObfConfig.readPresetContent(preset);
        if (out == null) {
            out = new File("nullfuscator-" + ObfConfig.normalizePresetName(preset) + ".hocon");
        }
        if (out.exists()) {
            throw new IllegalArgumentException("destination configuration file already exists: " + out);
        }
        File parent = out.getAbsoluteFile().getParentFile();
        if (parent != null) parent.mkdirs();
        java.nio.file.Files.writeString(out.toPath(), content, java.nio.charset.StandardCharsets.UTF_8);
        System.out.println("[+] Configuration template created: " + out.getPath() + " (preset '" + preset + "')");
    }

    private static void checkJar(String[] args) throws Exception {
        File input = null;
        String preset = null;
        File config = null;
        List<String> libs = new ArrayList<>();
        for (int i = 1; i < args.length; i++) {
            String arg = args[i];
            if (arg.equals("-p") || arg.equals("--preset")) preset = value(args, ++i);
            else if (arg.equals("-c") || arg.equals("--config")) config = new File(value(args, ++i));
            else if (arg.equals("-l") || arg.equals("--lib")) libs.add(value(args, ++i));
            else if (!arg.startsWith("-") && input == null) input = new File(arg);
            else throw new IllegalArgumentException("unknown arg for check: " + arg);
        }
        if (input == null || !input.isFile()) {
            throw new IllegalArgumentException("check: valid input JAR file is required");
        }
        ObfLog log = new ObfLog(false);
        ObfConfig cfg = (config != null) ? ObfConfig.load(config) :
                (preset != null ? ObfConfig.loadPreset(preset) : ObfConfig.empty());
        cfg = cfg.withAdditionalLibs(libs);
        ObfContext ctx = new ObfContext(cfg, 0L, log, new NameGenerator(new String[]{"I", "l"}));
        RunReport report = new RunReport(0L, input.length());
        ctx.report(report);
        JarIO.read(input, ctx);
        Preflight.run(ctx);
        System.out.println("[✓] Preflight check PASSED for " + input.getName());
        System.out.println("    Classes: " + ctx.classes().size());
        System.out.println("    Archive size: " + formatBytes(input.length()));
        if (!report.warnings().isEmpty()) {
            System.out.println("    Warnings (" + report.warnings().size() + "):");
            for (String w : report.warnings()) System.out.println("      ! " + w);
        } else {
            System.out.println("    No compatibility issues detected.");
        }
    }

    private static void help() {
        System.out.println("""
                NULLFUSCATOR %s - Standalone Hardened Java Bytecode Obfuscator

                USAGE:
                  java -jar nullfuscator-obf.jar [options] <input.jar> [output.jar]
                  nullfuscator <input.jar> [output.jar] [options]

                PRIMARY OPTIONS:
                  -i, --input <path>         Input JAR file (or 1st positional argument)
                  -o, --output <path>        Output JAR destination (default: <input>-obf.jar)
                  -p, --preset <name>        Built-in preset: light, balanced, strong, full
                  -c, --config <path>        Custom HOCON configuration profile or preset name
                  -l, --lib <path>           External library JAR for hierarchy analysis (repeatable)
                  -s, --seed <long>          Deterministic seed for reproducible builds (default: random)

                MAPPING & REPORTING:
                  -m, --mapping <path>       ProGuard-compatible mapping output (default: <output>.map)
                  -M, --no-mapping           Disable mapping output
                  -r, --report <path>        JSON execution report destination (schema v1)
                      --dry-run              Analyze & run transforms in memory without writing JAR
                      --report-only          Alias for --dry-run (JSON emitted to stdout unless -r set)

                OUTPUT & DIAGNOSTICS:
                  -v, --verbose              Enable detailed diagnostic logging on stderr
                  -q, --quiet                Suppress non-essential informational output
                      --no-color             Disable ANSI color formatting
                  -h, --help                 Show this help message and exit
                  -V, --version              Show tool version and exit

                COMMANDS:
                  presets                    List built-in presets and their trade-offs
                  init-config [preset] [-o]  Scaffold a starter HOCON configuration file
                  check <jar>                Run preflight compatibility check on an input JAR
                  retrace -m <map> [-t log]  De-obfuscate stack traces (default: stdin)
                  mapping-info -m <map>      Inspect mapping metadata, seed, and input digest

                EXAMPLES:
                  nullfuscator app.jar
                  nullfuscator app.jar -p balanced
                  nullfuscator app.jar app-hardened.jar -p strong -s 42
                  nullfuscator retrace -m app.map < crash.log
                """.formatted(BuildInfo.VERSION));
    }

    private static boolean sameFile(File a, File b) throws java.io.IOException {
        return a.getCanonicalFile().equals(b.getCanonicalFile())
                || (a.exists() && b.exists() && java.nio.file.Files.isSameFile(a.toPath(), b.toPath()));
    }

    private static void validatePaths(File input, File output, File mapping, File report,
                                      File config, ObfConfig cfg) throws java.io.IOException {
        List<File> protectedFiles = new ArrayList<>();
        protectedFiles.add(input);
        if (config != null) protectedFiles.add(config);
        for (String lib : cfg.libs()) protectedFiles.add(new File(lib));
        protectedFiles.addAll(cfg.sourceFiles());
        File[] destinations = {output, mapping, report};
        for (int i = 0; i < destinations.length; i++) {
            File destination = destinations[i];
            if (destination == null) continue;
            if (destination.isDirectory()) throw new IllegalArgumentException("destination is a directory: " + destination);
            for (int j = 0; j < i; j++) {
                if (destinations[j] != null && sameFile(destination, destinations[j]))
                    throw new IllegalArgumentException("output, mapping and report paths must be distinct: " + destination);
            }
            for (int j = 0; j < protectedFiles.size(); j++) {
                // In-place JAR replacement is supported; sidecars may never overwrite inputs.
                if (i == 0 && j == 0) continue;
                if (sameFile(destination, protectedFiles.get(j)))
                    throw new IllegalArgumentException("destination would overwrite an input or configuration: " + destination);
            }
        }
    }

    private static void retrace(String[] args) throws Exception {
        File mappingFile = null, trace = null;
        for (int i = 1; i < args.length; i++) {
            String arg = args[i];
            if (arg.equals("--mapping") || arg.equals("-m")) {
                mappingFile = new File(value(args, ++i));
            } else if (arg.startsWith("--mapping=")) {
                mappingFile = new File(arg.substring(10));
            } else if (arg.startsWith("-m=")) {
                mappingFile = new File(arg.substring(3));
            } else if (arg.equals("--trace") || arg.equals("-t")) {
                trace = new File(value(args, ++i));
            } else if (arg.startsWith("--trace=")) {
                trace = new File(arg.substring(8));
            } else if (arg.startsWith("-t=")) {
                trace = new File(arg.substring(3));
            } else if (!arg.startsWith("-")) {
                if (mappingFile == null) mappingFile = new File(arg);
                else if (trace == null) trace = new File(arg);
                else { System.err.println("unknown arg: " + arg); System.exit(2); }
            } else {
                System.err.println("unknown arg: " + arg);
                System.exit(2);
            }
        }
        if (mappingFile == null || !mappingFile.exists()) {
            System.err.println("retrace: --mapping <file> is required and must exist");
            System.exit(2);
            return;
        }
        String text = (trace != null)
                ? java.nio.file.Files.readString(trace.toPath())
                : new String(System.in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        System.out.print(ObfMapping.retrace(mappingFile, text));
    }

    private static void mappingInfo(String[] args) throws Exception {
        File mappingFile = null;
        for (int i = 1; i < args.length; i++) {
            String arg = args[i];
            if (arg.equals("--mapping") || arg.equals("-m")) {
                mappingFile = new File(value(args, ++i));
            } else if (arg.startsWith("--mapping=")) {
                mappingFile = new File(arg.substring(10));
            } else if (arg.startsWith("-m=")) {
                mappingFile = new File(arg.substring(3));
            } else if (!arg.startsWith("-")) {
                if (mappingFile == null) mappingFile = new File(arg);
                else { System.err.println("unknown arg: " + arg); System.exit(2); }
            } else {
                System.err.println("unknown arg: " + arg);
                System.exit(2);
            }
        }
        if (mappingFile == null || !mappingFile.isFile()) {
            System.err.println("mapping-info: --mapping <file> is required and must exist");
            System.exit(2);
            return;
        }
        ObfMapping.Metadata metadata = ObfMapping.readMetadata(mappingFile);
        if (metadata.format() > BuildInfo.MAPPING_FORMAT || metadata.format() < 1) {
            throw new IllegalArgumentException("mapping format " + metadata.format()
                    + " is incompatible with this tool (supports 1.." + BuildInfo.MAPPING_FORMAT + ")");
        }
        System.out.println("format=" + metadata.format());
        System.out.println("toolVersion=" + metadata.toolVersion());
        System.out.println("seed=" + metadata.seed());
        System.out.println("inputSha256=" + metadata.inputSha256());
        System.out.println("inputBytes=" + metadata.inputBytes());
    }

    public static List<Transformer> buildPipeline() {
        List<Transformer> p = new ArrayList<>();

        p.add(new com.nullfuscator.obf.transform.GsonSchemaTransformer());

        p.add(new SourceStripper());

        p.add(new com.nullfuscator.obf.transform.SemanticCoreTransformer());

        p.add(new SemanticFabricTransformer());

        p.add(new AntiDebugTransformer());

        p.add(new FlatteningTransformer());
        p.add(new ControlFlowTransformer());
        p.add(new BogusJumpTransformer());
        p.add(new SwitchFlowTransformer());
        p.add(new ReturnFlowTransformer());
        p.add(new ExceptionReturnTransformer());

        p.add(new NumberEncryptionTransformer());
        p.add(new StringEncryptionTransformer());

        p.add(new AntiAiTransformer());

        p.add(new CrossClassDispersionTransformer());

        p.add(new RecordMetadataTransformer());
        p.add(new FieldPackingTransformer());

        p.add(new MethodRenamer());
        p.add(new FieldRenamer());

        p.add(new MethodExtractionTransformer());
        p.add(new ClassRenamer());

        p.add(new MethodRelocationTransformer());

        p.add(new FieldIndirectionTransformer());

        p.add(new ReferenceHidingTransformer());

        p.add(new AntiDecompilerTransformer());

        p.add(new AntiDeobfuscatorTransformer());
        p.add(new FileCrasherTransformer());
        p.add(new com.nullfuscator.obf.transform.RuntimeIntegrityTransformer());
        return p;
    }
}
