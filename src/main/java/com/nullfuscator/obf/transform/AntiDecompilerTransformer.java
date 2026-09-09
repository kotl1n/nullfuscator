package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

public final class AntiDecompilerTransformer implements Transformer {

    private static final String[] FIELD_DESCS = {
            "I", "J", "Z", "F", "D", "B", "C", "S",
            "Ljava/lang/String;", "Ljava/lang/Object;", "[I", "[Ljava/lang/Object;"
    };

    private static final String[] RETURN_DESCS = {
            "Ljava/lang/Object;", "Ljava/lang/String;", "I", "Z", "J", "D", "F", "[I", "V"
    };

    private static final String[] BAD_NAMES = {
            "do", "goto", "true", "false", "null", "for", "if", "new",
            "class", "int", "void", "return", "const", "1", "2do", "0x0"
    };

    @Override public String id() { return "antiDecompiler"; }

    @Override public String description() { return "class-file-legal, source-illegal member poison"; }

    @Override
    public void transform(ObfContext ctx) {
        int level = clamp(ctx.config().section(id()).getInt("level", 1), 1, 3);
        Random rnd = ctx.random();
        int classes = 0, fieldPoison = 0, methodPoison = 0, illegal = 0;

        for (ClassNode cn : ctx.targets(id())) {
            if (ctx.isHotClass(cn)) continue;

            if ((cn.access & Opcodes.ACC_INTERFACE) != 0) continue;

            if (reflectionSensitive(cn)) continue;

            fieldPoison += addFieldCollisions(cn, level, rnd, ctx);
            if (level >= 2) methodPoison += addReturnTypeCollisions(cn, level, rnd);
            if (level >= 3) illegal += addIllegalNamedMembers(cn, rnd);
            classes++;
        }

        ctx.log().debug("antiDecompiler: classes=" + classes
                + " fieldPoison=" + fieldPoison
                + " methodPoison=" + methodPoison
                + " illegal=" + illegal + " (level=" + level + ")");
    }

    private int addFieldCollisions(ClassNode cn, int level, Random rnd, ObfContext ctx) {
        if (cn.fields == null) cn.fields = new ArrayList<>();
        Set<String> present = new HashSet<>();
        List<String> baseNames = new ArrayList<>();
        for (FieldNode f : cn.fields) {
            present.add(f.name + " " + f.desc);
            if (!f.name.equals("serialVersionUID") && !f.name.equals("serialPersistentFields"))
                baseNames.add(f.name);
        }

        int want = level;
        int added = 0;
        for (int i = 0; i < want; i++) {

            String base = baseNames.isEmpty()
                    ? ctx.names().next()
                    : baseNames.get(rnd.nextInt(baseNames.size()));
            String desc = pickUnusedFieldDesc(base, present, rnd);
            if (desc == null) continue;

            cn.fields.add(new FieldNode(
                    Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                    base, desc, null, null));
            present.add(base + " " + desc);
            if (!baseNames.contains(base)) baseNames.add(base);
            added++;
        }
        return added;
    }

    private String pickUnusedFieldDesc(String name, Set<String> present, Random rnd) {
        int start = rnd.nextInt(FIELD_DESCS.length);
        for (int k = 0; k < FIELD_DESCS.length; k++) {
            String d = FIELD_DESCS[(start + k) % FIELD_DESCS.length];
            if (!present.contains(name + " " + d)) return d;
        }
        return null;
    }

    private int addReturnTypeCollisions(ClassNode cn, int level, Random rnd) {
        Set<String> present = new HashSet<>();
        List<MethodNode> candidates = new ArrayList<>();
        for (MethodNode m : cn.methods) {
            present.add(m.name + m.desc);
            if (m.name.equals("<init>") || m.name.equals("<clinit>")) continue;
            if (MethodRenamer.isSerializationHook(m)) continue;
            candidates.add(m);
        }
        if (candidates.isEmpty()) return 0;

        int want = level - 1;
        int added = 0;
        for (int i = 0; i < want; i++) {
            MethodNode src = candidates.get(rnd.nextInt(candidates.size()));
            String params = src.desc.substring(0, src.desc.indexOf(')') + 1);
            String ret = pickUnusedReturn(src.name, params, present, rnd);
            if (ret == null) continue;

            String desc = params + ret;
            MethodNode mn = new MethodNode(
                    Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                    src.name, desc, null, null);
            emitReturnStub(mn.instructions, ret);
            cn.methods.add(mn);
            present.add(src.name + desc);
            added++;
        }
        return added;
    }

    private String pickUnusedReturn(String name, String params, Set<String> present, Random rnd) {
        int start = rnd.nextInt(RETURN_DESCS.length);
        for (int k = 0; k < RETURN_DESCS.length; k++) {
            String ret = RETURN_DESCS[(start + k) % RETURN_DESCS.length];
            if (!present.contains(name + params + ret)) return ret;
        }
        return null;
    }

    private int addIllegalNamedMembers(ClassNode cn, Random rnd) {
        if (cn.fields == null) cn.fields = new ArrayList<>();
        Set<String> fieldKeys = new HashSet<>();
        for (FieldNode f : cn.fields) fieldKeys.add(f.name + " " + f.desc);
        Set<String> methodKeys = new HashSet<>();
        for (MethodNode m : cn.methods) methodKeys.add(m.name + m.desc);

        int added = 0;
        for (int i = 0; i < 2; i++) {
            String nm = BAD_NAMES[rnd.nextInt(BAD_NAMES.length)];
            String desc = FIELD_DESCS[rnd.nextInt(FIELD_DESCS.length)];
            if (fieldKeys.add(nm + " " + desc)) {
                cn.fields.add(new FieldNode(
                        Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC, nm, desc, null, null));
                added++;
            }
        }
        String mnm = BAD_NAMES[rnd.nextInt(BAD_NAMES.length)];
        if (methodKeys.add(mnm + "()V")) {
            MethodNode mn = new MethodNode(
                    Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                    mnm, "()V", null, null);
            mn.instructions.add(new InsnNode(Opcodes.RETURN));
            cn.methods.add(mn);
            added++;
        }
        return added;
    }

    private static void emitReturnStub(InsnList il, String ret) {
        char c = ret.charAt(0);
        switch (c) {
            case 'V':
                il.add(new InsnNode(Opcodes.RETURN));
                break;
            case 'J':
                il.add(new InsnNode(Opcodes.LCONST_0));
                il.add(new InsnNode(Opcodes.LRETURN));
                break;
            case 'F':
                il.add(new InsnNode(Opcodes.FCONST_0));
                il.add(new InsnNode(Opcodes.FRETURN));
                break;
            case 'D':
                il.add(new InsnNode(Opcodes.DCONST_0));
                il.add(new InsnNode(Opcodes.DRETURN));
                break;
            case 'L':
            case '[':
                il.add(new InsnNode(Opcodes.ACONST_NULL));
                il.add(new InsnNode(Opcodes.ARETURN));
                break;
            default:
                il.add(new InsnNode(Opcodes.ICONST_0));
                il.add(new InsnNode(Opcodes.IRETURN));
                break;
        }
    }

    private static int clamp(int v, int lo, int hi) {
        return v < lo ? lo : (v > hi ? hi : v);
    }

    private static boolean reflectionSensitive(ClassNode cn) {
        if (cn.visibleAnnotations != null && !cn.visibleAnnotations.isEmpty()) return true;
        for (FieldNode field : cn.fields)
            if (field.visibleAnnotations != null && !field.visibleAnnotations.isEmpty()) return true;
        for (MethodNode method : cn.methods)
            if (method.visibleAnnotations != null && !method.visibleAnnotations.isEmpty()) return true;
        return false;
    }
}
