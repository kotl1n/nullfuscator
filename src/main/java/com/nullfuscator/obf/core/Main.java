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
            if (java.util.Arrays.asList(args).contains("--verbose")) e.printStackTrace(System.err);
            System.exit(e instanceof IllegalArgumentException ? 2 : 1);
        }
    }

    private static void run(String[] args) throws Exception {
        if (args.length == 1 && "--help".equals(args[0])) { help(); return; }
        if (args.length == 1 && "--version".equals(args[0])) {
            System.out.println("NULLFUSCATOR " + BuildInfo.VERSION);
            return;
        }

        if (args.length > 0 && ("retrace".equals(args[0]) || "mapping-info".equals(args[0]))) {
            if ("retrace".equals(args[0])) retrace(args);
            else mappingInfo(args);
            return;
        }

        File input = null, config = null, output = null, mapping = null, reportFile = null;
        Long seed = null;
        boolean verbose = false;
        boolean noMapping = false;
        boolean reportOnly = false;
        List<String> additionalLibs = new ArrayList<>();

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--input"      -> input   = new File(value(args, ++i));
                case "--config"     -> config  = new File(value(args, ++i));
                case "--lib"        -> additionalLibs.add(value(args, ++i));
                case "--output"     -> output  = new File(value(args, ++i));
                case "--mapping"    -> mapping = new File(value(args, ++i));
                case "--report"     -> reportFile = new File(value(args, ++i));
                case "--report-only" -> reportOnly = true;
                case "--no-mapping" -> noMapping = true;
                case "--seed"       -> seed    = Long.parseLong(value(args, ++i));
                case "--verbose"    -> verbose = true;
                default -> { System.err.println("unknown arg: " + args[i]); System.exit(2); }
            }
        }
        if (input == null || (!reportOnly && output == null)) {
            System.err.println("required: --input <jar> (--output <jar>|--report-only) [--config <hocon>]"
                    + " [--mapping <file>|--no-mapping] [--report <json>] [--seed N] [--verbose]");
            System.err.println("       or: retrace --mapping <file> [--trace <file>]  (reads stdin if no --trace)");
            System.err.println("       or: mapping-info --mapping <file>");
            System.exit(2);
            return;
        }

        if (noMapping && mapping != null) throw new IllegalArgumentException("--mapping conflicts with --no-mapping");
        if (!input.isFile()) throw new IllegalArgumentException("input JAR does not exist: " + input);
        ObfLog log = new ObfLog(verbose);
        ObfConfig cfg = (config != null)
                ? ObfConfig.load(config) : ObfConfig.empty();
        cfg = cfg.withAdditionalLibs(additionalLibs);
        File mapFile = noMapping || reportOnly ? null
                : mapping != null ? mapping : new File(output.getPath() + ".map");
        validatePaths(input, reportOnly ? null : output, mapFile, reportFile, config, cfg);
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

    private static String value(String[] args, int index) {
        if (index >= args.length || args[index].startsWith("--"))
            throw new IllegalArgumentException("missing value for " + args[index - 1]);
        return args[index];
    }

    private static void help() {
        System.out.println("""
                NULLFUSCATOR %s
                Usage: java -jar nullfuscator-obf.jar --input <jar> (--output <jar>|--report-only)
                  --config <hocon>   Transformation profile (omitted: no transformations)
                  --lib <jar>        Dependency JAR; repeat as needed
                  --seed <long>      Reproducible seed
                  --mapping <file>   Mapping destination (default: <output>.map)
                  --no-mapping       Disable mapping output
                  --report <file>    JSON report destination
                  --report-only      Transform in memory; JSON to stdout unless --report is set
                  --verbose          Detailed diagnostics on stderr
                  --help            Show this help
                  --version         Show tool version
                Commands:
                  retrace --mapping <file> [--trace <file>] (default: stdin)
                  mapping-info --mapping <file>
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
            switch (args[i]) {
                case "--mapping" -> mappingFile = new File(value(args, ++i));
                case "--trace"   -> trace = new File(value(args, ++i));
                default -> { System.err.println("unknown arg: " + args[i]); System.exit(2); }
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
            if ("--mapping".equals(args[i])) mappingFile = new File(value(args, ++i));
            else { System.err.println("unknown arg: " + args[i]); System.exit(2); }
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
