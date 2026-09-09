package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;
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
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.AnalyzerException;
import org.objectweb.asm.tree.analysis.BasicInterpreter;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import static org.objectweb.asm.Opcodes.ACC_ABSTRACT;
import static org.objectweb.asm.Opcodes.ACC_NATIVE;
import static org.objectweb.asm.Opcodes.ATHROW;
import static org.objectweb.asm.Opcodes.BIPUSH;
import static org.objectweb.asm.Opcodes.DUP;
import static org.objectweb.asm.Opcodes.IAND;
import static org.objectweb.asm.Opcodes.IOR;
import static org.objectweb.asm.Opcodes.ICONST_0;
import static org.objectweb.asm.Opcodes.IFGT;
import static org.objectweb.asm.Opcodes.IFNE;
import static org.objectweb.asm.Opcodes.IF_ICMPEQ;
import static org.objectweb.asm.Opcodes.IMUL;
import static org.objectweb.asm.Opcodes.INVOKESPECIAL;
import static org.objectweb.asm.Opcodes.INVOKESTATIC;
import static org.objectweb.asm.Opcodes.L2I;
import static org.objectweb.asm.Opcodes.NEW;
import static org.objectweb.asm.Opcodes.SIPUSH;

public final class ControlFlowTransformer implements Transformer {

    @Override public String id() { return "safeControlFlow"; }
    @Override public String description() { return "opaque-predicate control-flow guards"; }

    @Override
    public void transform(ObfContext ctx) {
        int level = clamp(ctx.config().section(id()).getInt("level", 1), 1, 3);
        Random rnd = ctx.random();
        int sitesPerMethod = level * 2;

        int methods = 0, inserted = 0;
        for (ClassNode cn : ctx.targets(id())) {
            for (MethodNode mn : cn.methods) {
                if (ctx.isHotPath(cn, mn)) continue;
                if (skip(mn)) continue;

                List<AbstractInsnNode> points = emptyStackPoints(cn.name, mn);
                if (points.isEmpty()) continue;
                Collections.shuffle(points, rnd);
                int take = Math.min(sitesPerMethod, points.size());
                for (int i = 0; i < take; i++) {
                    AbstractInsnNode at = points.get(i);
                    LabelNode cont = new LabelNode();
                    InsnList frag = new InsnList();
                    frag.add(alwaysTrueJump(rnd, cont, level >= 2));
                    frag.add(junkThrow());
                    frag.add(cont);
                    mn.instructions.insertBefore(at, frag);
                    inserted++;
                }
                methods++;
            }
        }
        ctx.log().debug("safeControlFlow: " + inserted + " guards across " + methods + " methods (level " + level + ")");
    }

    private static boolean skip(MethodNode mn) {
        if ((mn.access & (ACC_ABSTRACT | ACC_NATIVE)) != 0) return true;
        if (mn.name.equals("<clinit>") || mn.name.equals("<init>")) return true;
        if (mn.instructions == null || mn.instructions.size() == 0) return true;
        if (com.nullfuscator.obf.core.Limits.oversizeMethod(mn)) return true;
        if (mn.tryCatchBlocks != null && !mn.tryCatchBlocks.isEmpty()) return true;
        return false;
    }

    private static List<AbstractInsnNode> emptyStackPoints(String owner, MethodNode mn) {
        List<AbstractInsnNode> pts = new ArrayList<>();
        try {
            Analyzer<BasicValue> a = new Analyzer<>(new BasicInterpreter());
            Frame<BasicValue>[] frames = a.analyze(owner, mn);
            AbstractInsnNode[] arr = mn.instructions.toArray();
            for (int i = 0; i < arr.length; i++) {
                Frame<BasicValue> f = frames[i];
                if (f == null) continue;
                if (f.getStackSize() != 0) continue;
                if (arr[i].getOpcode() < 0) continue;
                pts.add(arr[i]);
            }
        } catch (AnalyzerException | RuntimeException e) {
            AbstractInsnNode first = firstReal(mn);
            if (first != null) pts.add(first);
        }
        return pts;
    }

    private static AbstractInsnNode firstReal(MethodNode mn) {
        for (AbstractInsnNode n = mn.instructions.getFirst(); n != null; n = n.getNext())
            if (n.getOpcode() >= 0) return n;
        return null;
    }

    static InsnList alwaysTrueJump(Random rnd, LabelNode target, boolean runtimeAllowed) {
        InsnList il = new InsnList();
        int r = 1 + rnd.nextInt(10000);
        int variant = rnd.nextInt(runtimeAllowed ? 4 : 3);
        switch (variant) {
            case 0 -> {
                pushInt(il, r);
                il.add(new InsnNode(DUP));
                il.add(new InsnNode(IMUL));
                il.add(new JumpInsnNode(IFGT, target));
            }
            case 1 -> {
                pushInt(il, r);
                pushInt(il, r);
                il.add(new JumpInsnNode(IF_ICMPEQ, target));
            }
            case 2 -> {
                pushInt(il, r | 1);
                pushInt(il, 1);
                il.add(new InsnNode(IAND));
                il.add(new JumpInsnNode(IFNE, target));
            }
            default -> {
                int rotation = 1 + rnd.nextInt(31);
                int selectedBit = 1 << rnd.nextInt(32);
                il.add(new MethodInsnNode(INVOKESTATIC, "java/lang/System",
                        "currentTimeMillis", "()J", false));
                il.add(new InsnNode(L2I));
                il.add(new MethodInsnNode(INVOKESTATIC, "java/lang/Thread",
                        "currentThread", "()Ljava/lang/Thread;", false));
                il.add(new MethodInsnNode(INVOKESTATIC, "java/lang/System",
                        "identityHashCode", "(Ljava/lang/Object;)I", false));
                il.add(new InsnNode(org.objectweb.asm.Opcodes.IXOR));
                pushInt(il, rotation);
                il.add(new MethodInsnNode(INVOKESTATIC, "java/lang/Integer",
                        "rotateLeft", "(II)I", false));
                pushInt(il, selectedBit);
                il.add(new InsnNode(IOR));
                pushInt(il, selectedBit);
                il.add(new InsnNode(IAND));
                il.add(new JumpInsnNode(IFNE, target));
            }
        }
        return il;
    }

    static InsnList junkThrow() {
        InsnList il = new InsnList();
        il.add(new TypeInsnNode(NEW, "java/lang/RuntimeException"));
        il.add(new InsnNode(DUP));
        il.add(new MethodInsnNode(INVOKESPECIAL, "java/lang/RuntimeException", "<init>", "()V", false));
        il.add(new InsnNode(ATHROW));
        return il;
    }

    static void pushInt(InsnList il, int v) {
        if (v >= -1 && v <= 5) il.add(new InsnNode(ICONST_0 + v));
        else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) il.add(new IntInsnNode(BIPUSH, v));
        else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) il.add(new IntInsnNode(SIPUSH, v));
        else il.add(new LdcInsnNode(Integer.valueOf(v)));
    }

    private static int clamp(int v, int lo, int hi) {
        return v < lo ? lo : (v > hi ? hi : v);
    }
}
