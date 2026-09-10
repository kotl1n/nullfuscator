package com.nullfuscator.obf.core;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Machine-readable measurements of what each pass actually changed. */
public final class RunReport {
    public record Totals(int classes, int methods, int fields, long instructions, long classBytes) { }
    public record Pass(String id, long millis, Totals before, Totals after, List<String> changedMethodOrigins) { }
    public record Snapshot(Totals totals, Map<String, String> methods) { }

    private final long seed;
    private final long inputJarBytes;
    private long outputJarBytes = -1;
    private Snapshot baseline;
    private Snapshot result;
    private final List<Pass> passes = new ArrayList<>();
    private final List<String> warnings = new ArrayList<>();
    private final Set<String> changedMethods = new HashSet<>();

    public RunReport(long seed, long inputJarBytes) {
        this.seed = seed;
        this.inputJarBytes = inputJarBytes;
    }

    public Snapshot capture(ObfContext ctx) {
        return capture(ctx, true);
    }

    public Snapshot captureLight(ObfContext ctx) {
        return capture(ctx, false);
    }

    private Snapshot capture(ObfContext ctx, boolean includeClassBytes) {
        int classes = 0, methods = 0, fields = 0;
        long instructions = 0, bytes = 0;
        Map<String, String> fingerprints = new LinkedHashMap<>();
        for (ClassNode cn : ctx.classes()) {
            classes++;
            fields += cn.fields == null ? 0 : cn.fields.size();
            if (includeClassBytes) {
                try {
                    ClassWriter writer = new ClassWriter(0);
                    cn.accept(writer);
                    bytes += writer.toByteArray().length;
                } catch (RuntimeException ignored) {
                    // Intermediate poison passes can intentionally reject ordinary writers.
                }
            }
            if (cn.methods == null) continue;
            for (MethodNode mn : cn.methods) {
                methods++;
                instructions += mn.instructions == null ? 0 : mn.instructions.size();
                fingerprints.put(ctx.methodOrigin(cn, mn), fingerprint(mn));
            }
        }
        return new Snapshot(new Totals(classes, methods, fields, instructions, bytes), fingerprints);
    }

    public void baseline(Snapshot value) { baseline = value; }
    public void result(Snapshot value) { result = value; }
    public Snapshot baseline() { return baseline; }
    public Snapshot result() { return result; }
    public Set<String> changedMethods() { return Set.copyOf(changedMethods); }
    public void outputJarBytes(long value) { outputJarBytes = value; }
    public void warn(String warning) { warnings.add(warning); }
    public List<String> warnings() { return List.copyOf(warnings); }

    public void pass(String id, long millis, Snapshot before, Snapshot after) {
        Set<String> keys = new HashSet<>(before.methods.keySet());
        keys.addAll(after.methods.keySet());
        List<String> changed = new ArrayList<>();
        for (String key : keys) if (!java.util.Objects.equals(before.methods.get(key), after.methods.get(key))) {
            changed.add(key);
            changedMethods.add(key);
        }
        changed.sort(String::compareTo);
        passes.add(new Pass(id, millis, before.totals, after.totals, changed));
    }

    public void write(File file) throws IOException {
        Files.writeString(file.toPath(), json(), StandardCharsets.UTF_8);
    }

    public String json() {
        StringBuilder out = new StringBuilder("{\n");
        out.append("  \"schemaVersion\": 1,\n  \"seed\": ").append(seed)
                .append(",\n  \"inputJarBytes\": ").append(inputJarBytes)
                .append(",\n  \"outputJarBytes\": ").append(outputJarBytes).append(",\n");
        totals(out, "input", baseline == null ? null : baseline.totals, true);
        totals(out, "output", result == null ? null : result.totals, true);
        out.append("  \"passes\": [\n");
        for (int i = 0; i < passes.size(); i++) {
            Pass p = passes.get(i);
            out.append("    {\"id\":\"").append(escape(p.id)).append("\",\"millis\":")
                    .append(p.millis).append(",\"changedMethods\":").append(p.changedMethodOrigins.size())
                    .append(",\"beforeInstructions\":").append(p.before.instructions)
                    .append(",\"afterInstructions\":").append(p.after.instructions)
                    .append(",\"changedMethodOrigins\":[");
            for (int j = 0; j < p.changedMethodOrigins.size(); j++) {
                if (j > 0) out.append(',');
                out.append('\"').append(escape(p.changedMethodOrigins.get(j))).append('\"');
            }
            out.append("]}").append(i + 1 == passes.size() ? "\n" : ",\n");
        }
        out.append("  ],\n  \"warnings\": [");
        for (int i = 0; i < warnings.size(); i++) {
            if (i > 0) out.append(',');
            out.append('\"').append(escape(warnings.get(i))).append('\"');
        }
        return out.append("]\n}\n").toString();
    }

    private static void totals(StringBuilder out, String key, Totals t, boolean comma) {
        if (t == null) t = new Totals(0, 0, 0, 0, 0);
        out.append("  \"").append(key).append("\": {\"classes\":").append(t.classes)
                .append(",\"methods\":").append(t.methods).append(",\"fields\":").append(t.fields)
                .append(",\"instructions\":").append(t.instructions).append(",\"classBytes\":")
                .append(t.classBytes).append("}").append(comma ? ",\n" : "\n");
    }

    private static String fingerprint(MethodNode method) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            update(digest, method.access, method.name, method.desc, method.signature);
            method.accept(new MethodVisitor(Opcodes.ASM9) {
                private final Map<Label, Integer> labels = new IdentityHashMap<>();
                private int label(Label value) { return labels.computeIfAbsent(value, key -> labels.size()); }
                @Override public void visitInsn(int opcode) { update(digest, opcode); }
                @Override public void visitIntInsn(int opcode, int operand) { update(digest, opcode, operand); }
                @Override public void visitVarInsn(int opcode, int var) { update(digest, opcode, var); }
                @Override public void visitTypeInsn(int opcode, String type) { update(digest, opcode, type); }
                @Override public void visitFieldInsn(int opcode, String owner, String name, String descriptor) {
                    update(digest, opcode, owner, name, descriptor);
                }
                @Override public void visitMethodInsn(int opcode, String owner, String name,
                                                      String descriptor, boolean itf) {
                    update(digest, opcode, owner, name, descriptor, itf);
                }
                @Override public void visitInvokeDynamicInsn(String name, String descriptor,
                                                             Handle bootstrap, Object... args) {
                    update(digest, name, descriptor, bootstrap);
                    for (Object arg : args) update(digest, arg);
                }
                @Override public void visitJumpInsn(int opcode, Label target) { update(digest, opcode, label(target)); }
                @Override public void visitLabel(Label value) { update(digest, "label", label(value)); }
                @Override public void visitLdcInsn(Object value) { update(digest, "ldc", value); }
                @Override public void visitIincInsn(int var, int increment) { update(digest, "iinc", var, increment); }
                @Override public void visitTableSwitchInsn(int min, int max, Label dflt, Label... targets) {
                    update(digest, "table", min, max, label(dflt));
                    for (Label target : targets) update(digest, label(target));
                }
                @Override public void visitLookupSwitchInsn(Label dflt, int[] keys, Label[] targets) {
                    update(digest, "lookup", label(dflt));
                    for (int key : keys) update(digest, key);
                    for (Label target : targets) update(digest, label(target));
                }
                @Override public void visitMultiANewArrayInsn(String descriptor, int dimensions) {
                    update(digest, descriptor, dimensions);
                }
                @Override public void visitTryCatchBlock(Label start, Label end, Label handler, String type) {
                    update(digest, "try", label(start), label(end), handler == null ? -1 : label(handler), type);
                }
            });
            return java.util.HexFormat.of().formatHex(digest.digest());
        } catch (Exception e) {
            return method.name + method.desc + ":" + (method.instructions == null ? 0 : method.instructions.size());
        }
    }

    private static void update(MessageDigest digest, Object... values) {
        for (Object value : values) {
            String text = String.valueOf(value);
            digest.update(text.getBytes(StandardCharsets.UTF_8));
            digest.update((byte) 0);
        }
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r");
    }
}
