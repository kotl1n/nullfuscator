package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.MethodInsnNode;

import static org.objectweb.asm.Opcodes.*;

public final class NumberEncryptionTransformer implements Transformer {

    @Override public String id() { return "numberEncryption"; }
    @Override public String description() { return "hide numeric constants behind polymorphic runtime math"; }

    @Override
    public void transform(ObfContext ctx) {
        int touchedClasses = 0;
        int rewritten = 0;
        boolean trackEncodedNumbers = ctx.config().section("antiAI").enabled();
        int layers = Math.max(2, Math.min(5,
                ctx.config().section(id()).getInt("layers", 3)));

        for (ClassNode cn : ctx.targets(id())) {
            boolean touched = false;
            if (com.nullfuscator.obf.core.Limits.hugeClass(cn)) continue;
            for (MethodNode mn : cn.methods) {
                if (ctx.isHotPath(cn, mn)) continue;
                if ((mn.access & (ACC_ABSTRACT | ACC_NATIVE)) != 0) continue;
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                if (com.nullfuscator.obf.core.Limits.oversizeMethod(mn)) continue;

                for (AbstractInsnNode insn : mn.instructions.toArray()) {
                    InsnList repl = null;

                    if (insn instanceof IntInsnNode ii) {
                        int op = ii.getOpcode();
                        if (op == BIPUSH || op == SIPUSH) {
                            repl = encodeInt(ctx, ii.operand, layers);
                        }

                    } else if (insn instanceof LdcInsnNode ldc) {
                        Object cst = ldc.cst;
                        if (cst instanceof Integer i) {
                            repl = encodeInt(ctx, i, layers);
                        } else if (cst instanceof Long l) {
                            repl = encodeLong(ctx, l, layers);
                        } else if (cst instanceof Float f) {
                            repl = encodeFloat(ctx, f, layers);
                        } else if (cst instanceof Double d) {
                            repl = encodeDouble(ctx, d, layers);
                        }
                    } else {
                        int op = insn.getOpcode();
                        if (op >= ICONST_M1 && op <= ICONST_5) {
                            repl = encodeInt(ctx, op - ICONST_0, layers);
                        } else if (op == LCONST_0) {
                            repl = encodeLong(ctx, 0L, layers);
                        } else if (op == LCONST_1) {
                            repl = encodeLong(ctx, 1L, layers);
                        } else if (op >= FCONST_0 && op <= FCONST_2) {
                            repl = encodeFloat(ctx, op - FCONST_0, layers);
                        } else if (op >= DCONST_0 && op <= DCONST_1) {
                            repl = encodeDouble(ctx, op - DCONST_0, layers);
                        }
                    }

                    if (repl != null) {
                        // Check the projected size, not only the input method: one pass
                        // can otherwise expand a near-limit method several times over.
                        if (mn.instructions.size() - 1 + repl.size()
                                > com.nullfuscator.obf.core.Limits.MAX_GROW_INSNS) break;
                        if (trackEncodedNumbers) for (AbstractInsnNode encoded : repl) {
                            if (encoded instanceof LdcInsnNode || encoded instanceof IntInsnNode
                                    || (encoded.getOpcode() >= ICONST_M1 && encoded.getOpcode() <= DCONST_1))
                                ctx.markEncodedNumber(encoded);
                        }
                        mn.instructions.insertBefore(insn, repl);
                        mn.instructions.remove(insn);
                        rewritten++;
                        touched = true;
                    }
                }
            }
            if (touched) touchedClasses++;
        }
        ctx.log().debug(id() + ": rewrote " + rewritten + " numeric constants across "
                + touchedClasses + " classes using " + layers + " layers");
    }

    private static InsnList encodeFloat(ObfContext ctx, float value, int layers) {
        // Encode raw bits: floating-point arithmetic would lose signed zero and NaN payloads.
        InsnList il = encodeInt(ctx, Float.floatToRawIntBits(value), layers);
        il.add(new MethodInsnNode(INVOKESTATIC, "java/lang/Float", "intBitsToFloat", "(I)F", false));
        return il;
    }

    private static InsnList encodeDouble(ObfContext ctx, double value, int layers) {
        InsnList il = encodeLong(ctx, Double.doubleToRawLongBits(value), layers);
        il.add(new MethodInsnNode(INVOKESTATIC, "java/lang/Double", "longBitsToDouble", "(J)D", false));
        return il;
    }

    private static InsnList encodeInt(ObfContext ctx, int v, int layers) {
        int[] op = new int[layers];
        int[] key = new int[layers];
        int encoded = v;
        for (int i = 0; i < layers; i++) {
            op[i] = ctx.random().nextInt(4);
            key[i] = ctx.random().nextInt();
            encoded = switch (op[i]) {
                case 0 -> encoded ^ key[i];
                case 1 -> encoded - key[i];
                case 2 -> encoded + key[i];
                default -> -encoded;
            };
        }
        InsnList il = new InsnList();
        il.add(pushInt(encoded));
        for (int i = layers - 1; i >= 0; i--) {
            switch (op[i]) {
                case 0 -> { il.add(pushInt(key[i])); il.add(new InsnNode(IXOR)); }
                case 1 -> { il.add(pushInt(key[i])); il.add(new InsnNode(IADD)); }
                case 2 -> { il.add(pushInt(key[i])); il.add(new InsnNode(ISUB)); }
                default -> il.add(new InsnNode(INEG));
            }
        }
        return il;
    }

    private static InsnList encodeLong(ObfContext ctx, long v, int layers) {
        int[] op = new int[layers];
        long[] key = new long[layers];
        long encoded = v;
        for (int i = 0; i < layers; i++) {
            op[i] = ctx.random().nextInt(4);
            key[i] = ctx.random().nextLong();
            encoded = switch (op[i]) {
                case 0 -> encoded ^ key[i];
                case 1 -> encoded - key[i];
                case 2 -> encoded + key[i];
                default -> -encoded;
            };
        }
        InsnList il = new InsnList();
        il.add(pushLong(encoded));
        for (int i = layers - 1; i >= 0; i--) {
            switch (op[i]) {
                case 0 -> { il.add(pushLong(key[i])); il.add(new InsnNode(LXOR)); }
                case 1 -> { il.add(pushLong(key[i])); il.add(new InsnNode(LADD)); }
                case 2 -> { il.add(pushLong(key[i])); il.add(new InsnNode(LSUB)); }
                default -> il.add(new InsnNode(LNEG));
            }
        }
        return il;
    }

    private static AbstractInsnNode pushInt(int v) {
        if (v >= -1 && v <= 5) return new InsnNode(ICONST_0 + v);
        if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) return new IntInsnNode(BIPUSH, v);
        if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) return new IntInsnNode(SIPUSH, v);
        return new LdcInsnNode(Integer.valueOf(v));
    }

    private static AbstractInsnNode pushLong(long v) {
        if (v == 0L) return new InsnNode(LCONST_0);
        if (v == 1L) return new InsnNode(LCONST_1);
        return new LdcInsnNode(Long.valueOf(v));
    }
}
