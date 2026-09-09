package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;
import com.nullfuscator.obf.util.NameGenerator;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.Remapper;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.RecordComponentNode;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class RecordMetadataTransformer implements Transformer {
    private static final String SEP = "\u0001";
    private static final String[] DEFAULT_ALPHABET = {"I", "l", "1"};

    @Override public String id() { return "recordMetadata"; }
    @Override public String description() { return "atomically hide Java record component schemas"; }

    @Override
    public void transform(ObfContext ctx) {
        var sec = ctx.config().section(id());
        boolean eraseIdentity = sec.getBoolean("eraseIdentity", false);
        int depth = Math.max(2, Math.min(32, sec.getInt("depth", 8)));
        List<String> chars = sec.getStringList("chars");
        NameGenerator names = new NameGenerator(chars.isEmpty()
                ? DEFAULT_ALPHABET : chars.toArray(new String[0]));
        Map<String, String> componentMap = new LinkedHashMap<>();
        int records = 0, components = 0;

        for (ClassNode cn : ctx.targets(id())) {
            if (cn.recordComponents == null || cn.recordComponents.isEmpty()) continue;
            if (cn.fields.stream().anyMatch(GsonSchemaTransformer::hasName)) continue;
            records++;
            Map<String, String> local = new LinkedHashMap<>();
            for (RecordComponentNode rc : cn.recordComponents) {
                String next = names.nextRandom(ctx.random(), depth);
                componentMap.put(key(cn.name, rc.name, rc.descriptor), next);
                local.put(rc.name, next);
                ctx.mapping().recordField(cn.name, rc.name, rc.descriptor, next);
                ctx.mapping().recordMethod(cn.name, rc.name, "()" + rc.descriptor, next);
                components++;
            }

            for (var mn : cn.methods) for (AbstractInsnNode in : mn.instructions.toArray()) {
                if (!(in instanceof InvokeDynamicInsnNode indy)
                        || !indy.bsm.getOwner().equals("java/lang/runtime/ObjectMethods")) continue;
                for (int i = 0; i < indy.bsmArgs.length; i++) {
                    if (!(indy.bsmArgs[i] instanceof String s)) continue;
                    String[] parts = s.split(";", -1);
                    boolean changed = false;
                    for (int p = 0; p < parts.length; p++) {
                        String mapped = local.get(parts[p]);
                        if (mapped != null) { parts[p] = mapped; changed = true; }
                    }
                    if (changed) indy.bsmArgs[i] = String.join(";", parts);
                }
            }
        }
        if (componentMap.isEmpty()) {
            ctx.log().debug("recordMetadata: no records");
            return;
        }

        Remapping.applyRemap(ctx, new Remapper(Opcodes.ASM9) {
            @Override public String mapRecordComponentName(String owner, String name, String descriptor) {
                return componentMap.getOrDefault(key(owner, name, descriptor), name);
            }
            @Override public String mapFieldName(String owner, String name, String descriptor) {
                return componentMap.getOrDefault(key(owner, name, descriptor), name);
            }
            @Override public String mapMethodName(String owner, String name, String descriptor) {
                if (descriptor.startsWith("()")) {
                    String mapped = componentMap.get(key(owner, name, descriptor.substring(2)));
                    if (mapped != null) return mapped;
                }
                return name;
            }
        });
        if (eraseIdentity) {
            for (ClassNode cn : ctx.targets(id())) {
                if (cn.recordComponents == null || cn.recordComponents.isEmpty()) continue;
                if (cn.fields.stream().anyMatch(GsonSchemaTransformer::hasName)) continue;
                cn.access &= ~Opcodes.ACC_RECORD;
                cn.recordComponents = null;
                if ("java/lang/Record".equals(cn.superName)) {
                    cn.superName = "java/lang/Object";
                    for (var mn : cn.methods) for (AbstractInsnNode in : mn.instructions.toArray()) {
                        if (in instanceof MethodInsnNode call
                                && call.getOpcode() == Opcodes.INVOKESPECIAL
                                && call.owner.equals("java/lang/Record")
                                && call.name.equals("<init>") && call.desc.equals("()V")) {
                            call.owner = "java/lang/Object";
                        }
                    }
                }
            }
        }
        ctx.log().debug("recordMetadata: renamed " + components + " components across " + records + " records");
    }

    private static String key(String owner, String name, String desc) {
        return owner + SEP + name + SEP + desc;
    }
}
