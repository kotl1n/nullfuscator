package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

/**
 * Anti-AI bytecode transformation pass.
 *
 * NOTE / ВНИМАНИЕ:
 * antiAI является экспериментальной (тестовой) функцией и может работать не так, как задумано.
 * antiAI is an experimental / test feature and may not work as intended.
 */
public final class AntiAiTransformer implements Transformer {

    @Override public String id() { return "antiAI"; }

    @Override public String description() { return "live constant dependencies through keyed permutation networks"; }

    @Override
    public void transform(ObfContext ctx) {
        ctx.initializePolicies();
        var sec = ctx.config().section(id());
        int level = clamp(sec.getInt("level", 1), 1, 3);
        // Keep the legacy option, but spend its budget on useful dependencies.
        int helpers = clamp(sec.getInt("decoyMethods", 4), 0, 32);
        helpers = Math.min(32, Math.max(2, helpers + (level - 1) * 2));
        int pct = clamp(sec.getInt("constantEncodingPercent", 50), 0, 100);
        int encoded = 0, added = 0;
        for (ClassNode cn : ctx.targets(id())) {
            if (pct == 0 || ctx.isHotClass(cn)
                    || com.nullfuscator.obf.core.Limits.hugeClass(cn)) continue;
            // Private static interface methods require Java 9. Older interfaces
            // are left alone rather than growing their public API.
            if ((cn.access & Opcodes.ACC_INTERFACE) != 0 && cn.version < Opcodes.V9) continue;
            Network network = new Network(cn, helpers, ctx);
            for (MethodNode mn : new ArrayList<>(cn.methods)) {
                if (!ctx.isInputMethod(mn) || ctx.isHotPath(cn, mn)) continue;
                if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) continue;
                if (mn.instructions == null) continue;
                for (AbstractInsnNode insn : mn.instructions.toArray()) {
                    if (com.nullfuscator.obf.core.Limits.oversizeMethod(mn)) break;
                    if (ctx.isEncodedNumber(insn)) continue;
                    int op = insn.getOpcode();
                    boolean integer = (op >= Opcodes.ICONST_M1 && op <= Opcodes.ICONST_5)
                            || op == Opcodes.BIPUSH || op == Opcodes.SIPUSH
                            || insn instanceof LdcInsnNode ldc && ldc.cst instanceof Integer;
                    boolean wide = level >= 2 && (op == Opcodes.LCONST_0 || op == Opcodes.LCONST_1
                            || insn instanceof LdcInsnNode ldc && ldc.cst instanceof Long);
                    if ((!integer && !wide) || ctx.random().nextInt(100) >= pct) continue;
                    InsnList repl = new InsnList();
                    if (integer) network.decode(repl, intValueOf(insn));
                    else {
                        long value = longValueOf(insn);
                        network.decode(repl, (int) (value >>> 32));
                        repl.add(new InsnNode(Opcodes.I2L));
                        pushInt(repl, 32);
                        repl.add(new InsnNode(Opcodes.LSHL));
                        network.decode(repl, (int) value);
                        repl.add(new InsnNode(Opcodes.I2L));
                        pushLong(repl, 0xffffffffL);
                        repl.add(new InsnNode(Opcodes.LAND));
                        repl.add(new InsnNode(Opcodes.LOR));
                    }
                    mn.instructions.insertBefore(insn, repl);
                    mn.instructions.remove(insn);
                    encoded++;
                }
            }
            added += network.emit();
        }
        ctx.clearEncodedNumbers();
        ctx.log().debug("antiAI: liveHelpers=" + added + " encodedConsts=" + encoded);
    }

    /** Each stage is a two-round 16+16 Feistel permutation, followed by
     * its predecessor. All arithmetic deliberately uses Java int overflow.
     * This raises static analysis cost; it is not a cryptographic boundary:
     * an analyst who executes the helpers can still recover constants.
     */
    private static final class Network {
        final ClassNode owner;
        final ObfContext ctx;
        final String[] names;
        final int[][] keys;
        boolean used;

        Network(ClassNode owner, int count, ObfContext ctx) {
            this.owner = owner;
            this.ctx = ctx;
            names = new String[count];
            keys = new int[count][6];
            Set<String> existing = new HashSet<>();
            for (MethodNode m : owner.methods) existing.add(m.name + m.desc);
            for (int i = 0; i < count; i++) {
                do { names[i] = ctx.names().next(); }
                while (!existing.add(names[i] + "(I)I"));
                for (int j = 0; j < 6; j++) keys[i][j] = ctx.random().nextInt();
            }
        }

        void decode(InsnList il, int value) {
            // The first use reaches every stage; subsequent uses vary routes.
            int stage = used ? ctx.random().nextInt(names.length) : names.length - 1;
            used = true;
            int encoded = value;
            for (int i = 0; i <= stage; i++) {
                for (int round = 1; round >= 0; round--) {
                    int left = encoded >>> 16;
                    int right = encoded & 65535;
                    int oldLeft = right ^ mix(left, keys[i], round);
                    encoded = (oldLeft << 16) | left;
                }
            }
            pushInt(il, encoded);
            il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, owner.name,
                    names[stage], "(I)I", (owner.access & Opcodes.ACC_INTERFACE) != 0));
        }

        static int mix(int value, int[] key, int round) {
            int k = round * 3;
            return Integer.rotateLeft((value ^ key[k]) * (key[k + 1] | 1),
                    1 + (key[k + 2] & 15)) & 65535;
        }

        int emit() {
            if (!used) return 0;
            for (int i = 0; i < names.length; i++) {
                MethodNode mn = new MethodNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
                        names[i], "(I)I", null, null);
                InsnList il = mn.instructions;
                for (int round = 0; round < 2; round++) {
                    int k = round * 3;
                    il.add(new VarInsnNode(Opcodes.ILOAD, 0));
                    pushInt(il, 65535);
                    il.add(new InsnNode(Opcodes.IAND));
                    il.add(new VarInsnNode(Opcodes.ISTORE, 1));
                    il.add(new VarInsnNode(Opcodes.ILOAD, 1));
                    pushInt(il, 16);
                    il.add(new InsnNode(Opcodes.ISHL));
                    il.add(new VarInsnNode(Opcodes.ILOAD, 0));
                    pushInt(il, 16);
                    il.add(new InsnNode(Opcodes.IUSHR));
                    il.add(new VarInsnNode(Opcodes.ILOAD, 1));
                    pushInt(il, keys[i][k]);
                    il.add(new InsnNode(Opcodes.IXOR));
                    pushInt(il, keys[i][k + 1] | 1);
                    il.add(new InsnNode(Opcodes.IMUL));
                    pushInt(il, 1 + (keys[i][k + 2] & 15));
                    il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer",
                            "rotateLeft", "(II)I", false));
                    pushInt(il, 65535);
                    il.add(new InsnNode(Opcodes.IAND));
                    il.add(new InsnNode(Opcodes.IXOR));
                    il.add(new InsnNode(Opcodes.IOR));
                    il.add(new VarInsnNode(Opcodes.ISTORE, 0));
                }
                il.add(new VarInsnNode(Opcodes.ILOAD, 0));
                if (i > 0) il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, owner.name,
                        names[i - 1], "(I)I", (owner.access & Opcodes.ACC_INTERFACE) != 0));
                il.add(new InsnNode(Opcodes.IRETURN));
                mn.maxLocals = 2;
                mn.maxStack = 5;
                owner.methods.add(mn);
            }
            return names.length;
        }
    }

    private static int intValueOf(AbstractInsnNode insn) {
        if (insn instanceof IntInsnNode) return ((IntInsnNode) insn).operand;
        if (insn instanceof LdcInsnNode) return (Integer) ((LdcInsnNode) insn).cst;

        return insn.getOpcode() - Opcodes.ICONST_0;
    }

    private static long longValueOf(AbstractInsnNode insn) {
        if (insn instanceof LdcInsnNode) return (Long) ((LdcInsnNode) insn).cst;
        return insn.getOpcode() - Opcodes.LCONST_0;
    }

    private static void pushInt(InsnList il, int v) {
        if (v >= -1 && v <= 5) {
            il.add(new InsnNode(Opcodes.ICONST_0 + v));
        } else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) {
            il.add(new IntInsnNode(Opcodes.BIPUSH, v));
        } else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) {
            il.add(new IntInsnNode(Opcodes.SIPUSH, v));
        } else {
            il.add(new LdcInsnNode(Integer.valueOf(v)));
        }
    }

    private static void pushLong(InsnList il, long v) {
        if (v == 0L) il.add(new InsnNode(Opcodes.LCONST_0));
        else if (v == 1L) il.add(new InsnNode(Opcodes.LCONST_1));
        else il.add(new LdcInsnNode(Long.valueOf(v)));
    }

    private static int clamp(int v, int lo, int hi) {
        return v < lo ? lo : (v > hi ? hi : v);
    }
}
