package com.nullfuscator.obf.core;

import org.objectweb.asm.Type;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class ObfMapping {

    public record Metadata(int format, String toolVersion, long seed, String inputSha256,
                           long inputBytes) {
        public boolean legacy() { return format == 1; }
    }

    private record Member(String oldName, String desc, String newName) {}

    private final Map<String, String> classes = new LinkedHashMap<>();

    private final Map<String, List<Member>> methods = new LinkedHashMap<>();
    private final Map<String, List<Member>> fields = new LinkedHashMap<>();

    public void recordClass(String oldInternal, String newInternal) {
        if (oldInternal != null && newInternal != null && !oldInternal.equals(newInternal)) {
            classes.put(oldInternal, newInternal);
        }
    }

    public void recordMethod(String ownerOld, String oldName, String desc, String newName) {
        if (ownerOld == null || oldName == null || newName == null || oldName.equals(newName)) return;
        methods.computeIfAbsent(ownerOld, k -> new ArrayList<>())
                .add(new Member(oldName, desc, newName));
    }

    public void recordField(String ownerOld, String oldName, String desc, String newName) {
        if (ownerOld == null || oldName == null || newName == null || oldName.equals(newName)) return;
        fields.computeIfAbsent(ownerOld, k -> new ArrayList<>())
                .add(new Member(oldName, desc, newName));
    }

    public boolean isEmpty() {
        return classes.isEmpty() && methods.isEmpty() && fields.isEmpty();
    }

    public void write(File out) throws IOException {
        File parent = out.getAbsoluteFile().getParentFile();
        if (parent != null) Files.createDirectories(parent.toPath());
        try (Writer w = Files.newBufferedWriter(out.toPath(), StandardCharsets.UTF_8)) {
            write(w);
        }
    }

    public void write(File out, Metadata metadata) throws IOException {
        File parent = out.getAbsoluteFile().getParentFile();
        if (parent != null) Files.createDirectories(parent.toPath());
        try (Writer w = Files.newBufferedWriter(out.toPath(), StandardCharsets.UTF_8)) {
            write(w, metadata);
        }
    }

    public void write(Writer w) throws IOException {
        write(w, null);
    }

    public void write(Writer w, Metadata metadata) throws IOException {
        w.write("# nullfuscator-obf mapping - original -> obfuscated (ProGuard format)\n");
        if (metadata != null) {
            w.write("# nullfuscator-mapping-format: " + metadata.format() + "\n");
            w.write("# nullfuscator-tool-version: " + metadata.toolVersion() + "\n");
            w.write("# nullfuscator-seed: " + metadata.seed() + "\n");
            w.write("# nullfuscator-input-sha256: " + metadata.inputSha256() + "\n");
            w.write("# nullfuscator-input-bytes: " + metadata.inputBytes() + "\n");
        }

        Map<String, Boolean> owners = new TreeMap<>();
        for (String c : classes.keySet()) owners.put(c, Boolean.TRUE);
        for (String c : methods.keySet()) owners.putIfAbsent(c, Boolean.TRUE);
        for (String c : fields.keySet())  owners.putIfAbsent(c, Boolean.TRUE);

        for (String ownerOld : owners.keySet()) {
            String ownerNew = classes.getOrDefault(ownerOld, ownerOld);
            w.write(dot(ownerOld) + " -> " + dot(ownerNew) + ":\n");
            List<Member> fs = fields.get(ownerOld);
            if (fs != null) {
                for (Member m : fs) {
                    w.write("    " + typeName(m.desc()) + " " + m.oldName()
                            + " -> " + m.newName() + "\n");
                }
            }
            List<Member> ms = methods.get(ownerOld);
            if (ms != null) {
                for (Member m : ms) {
                    w.write("    " + methodSignature(m.desc()) + " " + m.oldName()
                            + " -> " + m.newName() + "\n");
                }
            }
        }
    }

    private static String dot(String internal) { return internal.replace('/', '.'); }

    private static String typeName(String desc) {
        if (desc == null) return "?";
        try { return Type.getType(desc).getClassName(); }
        catch (RuntimeException e) { return "?"; }
    }

    private static String methodSignature(String desc) {
        if (desc == null) return "?()";
        try {
            Type ret = Type.getReturnType(desc);
            Type[] args = Type.getArgumentTypes(desc);
            StringBuilder sb = new StringBuilder(ret.getClassName()).append('(');
            for (int i = 0; i < args.length; i++) {
                if (i > 0) sb.append(',');
                sb.append(args[i].getClassName());
            }
            return sb.append(')').toString();
        } catch (RuntimeException e) { return "?()"; }
    }

    public static String retrace(File mappingFile, String text) throws IOException {
        validateMetadata(readMetadata(mappingFile));
        Reversed rev = parse(mappingFile);
        return rev.apply(text);
    }

    public static Metadata readMetadata(File mappingFile) throws IOException {
        int format = 1;
        String tool = "unknown", hash = "unknown";
        long seed = 0, bytes = -1;
        try (BufferedReader reader = Files.newBufferedReader(mappingFile.toPath(), StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.startsWith("#")) break;
                int colon = line.indexOf(':');
                if (colon < 0) continue;
                String key = line.substring(1, colon).trim();
                String value = line.substring(colon + 1).trim();
                switch (key) {
                    case "nullfuscator-mapping-format" -> format = Integer.parseInt(value);
                    case "nullfuscator-tool-version" -> tool = value;
                    case "nullfuscator-seed" -> seed = Long.parseLong(value);
                    case "nullfuscator-input-sha256" -> hash = value;
                    case "nullfuscator-input-bytes" -> bytes = Long.parseLong(value);
                }
            }
        }
        return new Metadata(format, tool, seed, hash, bytes);
    }

    private static void validateMetadata(Metadata metadata) {
        if (metadata.format() > BuildInfo.MAPPING_FORMAT || metadata.format() < 1) {
            throw new IllegalArgumentException("mapping format " + metadata.format()
                    + " is incompatible with this tool (supports 1.." + BuildInfo.MAPPING_FORMAT + ")");
        }
    }

    private static final class Reversed {
        final Map<String, String> classBack = new LinkedHashMap<>();
        final Map<String, Map<String, String>> methodBack = new LinkedHashMap<>();

        String apply(String text) {

            Matcher fm = FRAME.matcher(text);
            StringBuilder sb = new StringBuilder();
            while (fm.find()) {
                String obfClass = fm.group(1);
                String obfMethod = fm.group(2);
                String origClass = classBack.getOrDefault(obfClass, obfClass);
                Map<String, String> mm = methodBack.get(obfClass);
                String origMethod = (mm != null) ? mm.getOrDefault(obfMethod, obfMethod) : obfMethod;
                fm.appendReplacement(sb, Matcher.quoteReplacement(
                        "at " + origClass + "." + origMethod));
            }
            fm.appendTail(sb);
            String out = sb.toString();

            List<String> keys = new ArrayList<>(classBack.keySet());
            keys.sort((x, y) -> Integer.compare(y.length(), x.length()));
            for (String obf : keys) {
                out = out.replace(obf, classBack.get(obf));
            }
            return out;
        }
    }

    private static final Pattern FRAME =
            Pattern.compile("at\\s+([\\w$.]+)\\.([\\w$<>]+)");
    private static final Pattern CLASS_LINE =
            Pattern.compile("^([\\w$.]+)\\s*->\\s*([\\w$.]+):$");
    private static final Pattern MEMBER_LINE =
            Pattern.compile("^\\s+\\S+\\s+([\\w$<>]+)(?:\\([^)]*\\))?\\s*->\\s*([\\w$<>]+)$");

    private static Reversed parse(File mappingFile) throws IOException {
        Reversed rev = new Reversed();
        String currentObfClass = null;
        try (BufferedReader r = Files.newBufferedReader(mappingFile.toPath(), StandardCharsets.UTF_8)) {
            String line;
            while ((line = r.readLine()) != null) {
                if (line.isBlank() || line.startsWith("#")) continue;
                Matcher cm = CLASS_LINE.matcher(line);
                if (cm.matches()) {
                    String orig = cm.group(1), obf = cm.group(2);
                    rev.classBack.put(obf, orig);
                    rev.methodBack.computeIfAbsent(obf, k -> new LinkedHashMap<>());
                    currentObfClass = obf;
                    continue;
                }
                Matcher mm = MEMBER_LINE.matcher(line);
                if (mm.matches() && currentObfClass != null) {

                    String origName = mm.group(1), obfName = mm.group(2);
                    rev.methodBack.get(currentObfClass).put(obfName, origName);
                }
            }
        }
        return rev;
    }
}
