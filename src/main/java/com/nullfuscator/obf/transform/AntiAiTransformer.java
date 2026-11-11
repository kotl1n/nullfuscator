package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

public final class AntiAiTransformer implements Transformer {

    @Override
    public String id() {
        return "antiAI";
    }

    @Override
    public String description() {
        return "live constant dependencies through keyed permutation networks";
    }

    @Override
    public void transform(ObfContext ctx) {
        ctx.initializePolicies();
        var sec = ctx.config().section(id());
        int level = clamp(sec.getInt("level", 1), 1, 3);

        int helpers = clamp(sec.getInt("decoyMethods", 4), 0, 32);
        helpers = Math.min(32, Math.max(2, helpers + (level - 1) * 2));
        int pct = clamp(sec.getInt("constantEncodingPercent", 50), 0, 100);

        int decoyPct = clamp(sec.getInt("decoyBranchPercent", level >= 2 ? 30 : 15), 0, 100);

        int encoded = 0;
        int added = 0;
        int decoys = 0;
        for (ClassNode cn : ctx.targets(id())) {
            if (pct == 0 || ctx.isHotClass(cn) || com.nullfuscator.obf.core.Limits.hugeClass(cn)) {
                continue;
            }

            if ((cn.access & Opcodes.ACC_INTERFACE) != 0 && cn.version < Opcodes.V9) {
                continue;
            }

            Network network = new Network(cn, helpers, ctx);
            for (MethodNode mn : new ArrayList<>(cn.methods)) {
                if (!ctx.isInputMethod(mn) || ctx.isHotPath(cn, mn)) {
                    continue;
                }
                if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
                    continue;
                }
                if (mn.instructions == null) {
                    continue;
                }

                int scratch = freeSlot(mn);
                for (AbstractInsnNode insn : mn.instructions.toArray()) {
                    if (com.nullfuscator.obf.core.Limits.oversizeMethod(mn)) {
                        break;
                    }
                    if (ctx.isEncodedNumber(insn)) {
                        continue;
                    }

                    int op = insn.getOpcode();
                    boolean integer = (op >= Opcodes.ICONST_M1 && op <= Opcodes.ICONST_5)
                            || op == Opcodes.BIPUSH || op == Opcodes.SIPUSH
                            || insn instanceof LdcInsnNode ldc && ldc.cst instanceof Integer;
                    boolean wide = level >= 2 && (op == Opcodes.LCONST_0 || op == Opcodes.LCONST_1
                            || insn instanceof LdcInsnNode ldc && ldc.cst instanceof Long);
                    if ((!integer && !wide) || ctx.random().nextInt(100) >= pct) {
                        continue;
                    }

                    InsnList repl = new InsnList();
                    if (integer) {
                        int cst = intValueOf(insn);
                        if (decoyPct > 0 && ctx.random().nextInt(100) < decoyPct) {
                            emitDecoyInteger(repl, network, cst, scratch, ctx);
                            decoys++;
                        } else {
                            network.decode(repl, cst);
                        }
                    } else {
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
        ctx.log().debug("antiAI: liveHelpers=" + added + " encodedConsts=" + encoded
                + " decoyBranches=" + decoys);
    }

    private static int freeSlot(MethodNode mn) {
        int slots = org.objectweb.asm.Type.getArgumentsAndReturnSizes(mn.desc) >> 2;
        if ((mn.access & Opcodes.ACC_STATIC) != 0) {
            slots -= 1;
        }
        for (AbstractInsnNode insn : mn.instructions) {
            if (insn instanceof VarInsnNode v) {
                int op = v.getOpcode();
                int width = (op == Opcodes.LLOAD || op == Opcodes.LSTORE
                        || op == Opcodes.DLOAD || op == Opcodes.DSTORE) ? 2 : 1;
                slots = Math.max(slots, v.var + width);
            }
        }
        return Math.max(slots, mn.maxLocals);
    }

    private static void emitDecoyInteger(InsnList repl, Network net, int value,
                                         int slot, ObfContext ctx) {
        LabelNode cont = new LabelNode();
        int m = ctx.random().nextInt();

        net.decode(repl, value);
        repl.add(new VarInsnNode(Opcodes.ISTORE, slot));

        repl.add(new VarInsnNode(Opcodes.ILOAD, slot));
        pushInt(repl, m);
        repl.add(new InsnNode(Opcodes.IAND));
        repl.add(new VarInsnNode(Opcodes.ILOAD, slot));
        pushInt(repl, m);
        repl.add(new InsnNode(Opcodes.IOR));
        repl.add(new InsnNode(Opcodes.IADD));
        repl.add(new VarInsnNode(Opcodes.ILOAD, slot));
        pushInt(repl, m);
        repl.add(new InsnNode(Opcodes.IADD));
        repl.add(new InsnNode(Opcodes.ISUB));
        repl.add(new JumpInsnNode(Opcodes.IFEQ, cont));

        int decoy = value ^ (1 + ctx.random().nextInt(0x3fffffff));
        net.decode(repl, decoy);
        repl.add(new VarInsnNode(Opcodes.ISTORE, slot));

        repl.add(cont);
        repl.add(new VarInsnNode(Opcodes.ILOAD, slot));
    }

    private static final class Network {

        static final int FLAVORS = 4;

        final ClassNode owner;
        final ObfContext ctx;
        final String[] names;
        final int[][] keys;
        final int[] flavor;
        boolean used;

        Network(ClassNode owner, int count, ObfContext ctx) {
            this.owner = owner;
            this.ctx = ctx;
            names = new String[count];
            keys = new int[count][6];
            flavor = new int[count];

            Set<String> existing = new HashSet<>();
            for (MethodNode m : owner.methods) {
                existing.add(m.name + m.desc);
            }
            for (int i = 0; i < count; i++) {
                do {
                    names[i] = ctx.names().next();
                } while (!existing.add(names[i] + "(I)I"));
                for (int j = 0; j < 6; j++) {
                    keys[i][j] = ctx.random().nextInt();
                }
                flavor[i] = ctx.random().nextInt(FLAVORS);
            }
        }

        void decode(InsnList il, int value) {
            int stage = used ? ctx.random().nextInt(names.length) : names.length - 1;
            used = true;

            int encoded = value;
            for (int i = 0; i <= stage; i++) {
                for (int round = 1; round >= 0; round--) {
                    int left = encoded >>> 16;
                    int right = encoded & 65535;
                    int k = round * 3;
                    int oldLeft = right ^ mix(flavor[i], left,
                            keys[i][k], keys[i][k + 1], keys[i][k + 2]);
                    encoded = (oldLeft << 16) | left;
                }
            }

            pushInt(il, encoded);
            il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, owner.name,
                    names[stage], "(I)I", (owner.access & Opcodes.ACC_INTERFACE) != 0));
        }

        static int mix(int flavor, int v, int k0, int k1, int k2) {
            int r;
            switch (flavor) {
                case 1:  r = ((v * (k0 | 1)) ^ (v >>> 5)) + k1; break;
                case 2:  r = ((v ^ k0) * 3) + ((v & k1) * 5) + k2; break;
                case 3:  r = Integer.rotateLeft(v, 3) ^ (v * (k0 | 1)) ^ k1; break;
                default: r = Integer.rotateLeft((v ^ k0) * (k1 | 1), 1 + (k2 & 15)); break;
            }
            return r & 65535;
        }

        static void emitMix(int flavor, InsnList il, int k0, int k1, int k2) {
            switch (flavor) {
                case 1:
                    il.add(new VarInsnNode(Opcodes.ILOAD, 1));
                    pushInt(il, k0 | 1);
                    il.add(new InsnNode(Opcodes.IMUL));
                    il.add(new VarInsnNode(Opcodes.ILOAD, 1));
                    pushInt(il, 5);
                    il.add(new InsnNode(Opcodes.IUSHR));
                    il.add(new InsnNode(Opcodes.IXOR));
                    pushInt(il, k1);
                    il.add(new InsnNode(Opcodes.IADD));
                    break;
                case 2:
                    il.add(new VarInsnNode(Opcodes.ILOAD, 1));
                    pushInt(il, k0);
                    il.add(new InsnNode(Opcodes.IXOR));
                    pushInt(il, 3);
                    il.add(new InsnNode(Opcodes.IMUL));
                    il.add(new VarInsnNode(Opcodes.ILOAD, 1));
                    pushInt(il, k1);
                    il.add(new InsnNode(Opcodes.IAND));
                    pushInt(il, 5);
                    il.add(new InsnNode(Opcodes.IMUL));
                    il.add(new InsnNode(Opcodes.IADD));
                    pushInt(il, k2);
                    il.add(new InsnNode(Opcodes.IADD));
                    break;
                case 3:
                    il.add(new VarInsnNode(Opcodes.ILOAD, 1));
                    pushInt(il, 3);
                    il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer",
                            "rotateLeft", "(II)I", false));
                    il.add(new VarInsnNode(Opcodes.ILOAD, 1));
                    pushInt(il, k0 | 1);
                    il.add(new InsnNode(Opcodes.IMUL));
                    il.add(new InsnNode(Opcodes.IXOR));
                    pushInt(il, k1);
                    il.add(new InsnNode(Opcodes.IXOR));
                    break;
                default:
                    il.add(new VarInsnNode(Opcodes.ILOAD, 1));
                    pushInt(il, k0);
                    il.add(new InsnNode(Opcodes.IXOR));
                    pushInt(il, k1 | 1);
                    il.add(new InsnNode(Opcodes.IMUL));
                    pushInt(il, 1 + (k2 & 15));
                    il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer",
                            "rotateLeft", "(II)I", false));
                    break;
            }
        }

        int emit() {
            if (!used) {
                return 0;
            }

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

                    emitMix(flavor[i], il, keys[i][k], keys[i][k + 1], keys[i][k + 2]);

                    pushInt(il, 65535);
                    il.add(new InsnNode(Opcodes.IAND));
                    il.add(new InsnNode(Opcodes.IXOR));
                    il.add(new InsnNode(Opcodes.IOR));
                    il.add(new VarInsnNode(Opcodes.ISTORE, 0));
                }

                il.add(new VarInsnNode(Opcodes.ILOAD, 0));
                if (i > 0) {
                    il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, owner.name,
                            names[i - 1], "(I)I", (owner.access & Opcodes.ACC_INTERFACE) != 0));
                }
                il.add(new InsnNode(Opcodes.IRETURN));

                mn.maxLocals = 2;
                mn.maxStack = 6;
                owner.methods.add(mn);
            }
            return names.length;
        }
    }

    private static int intValueOf(AbstractInsnNode insn) {
        if (insn instanceof IntInsnNode) {
            return ((IntInsnNode) insn).operand;
        }
        if (insn instanceof LdcInsnNode) {
            return (Integer) ((LdcInsnNode) insn).cst;
        }
        return insn.getOpcode() - Opcodes.ICONST_0;
    }

    private static long longValueOf(AbstractInsnNode insn) {
        if (insn instanceof LdcInsnNode) {
            return (Long) ((LdcInsnNode) insn).cst;
        }
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
        if (v == 0L) {
            il.add(new InsnNode(Opcodes.LCONST_0));
        } else if (v == 1L) {
            il.add(new InsnNode(Opcodes.LCONST_1));
        } else {
            il.add(new LdcInsnNode(Long.valueOf(v)));
        }
    }

    private static int clamp(int v, int lo, int hi) {
        return v < lo ? lo : (v > hi ? hi : v);
    }
}
