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
import static org.objectweb.asm.Opcodes.GOTO;
import static org.objectweb.asm.Opcodes.ICONST_0;
import static org.objectweb.asm.Opcodes.IFLE;
import static org.objectweb.asm.Opcodes.IMUL;
import static org.objectweb.asm.Opcodes.INVOKESPECIAL;
import static org.objectweb.asm.Opcodes.NEW;
import static org.objectweb.asm.Opcodes.SIPUSH;

public final class BogusJumpTransformer implements Transformer {

    @Override public String id() { return "mangledJump"; }
    @Override public String description() { return "bogus GOTO indirection + junk islands"; }

    @Override
    public void transform(ObfContext ctx) {
        Random rnd = ctx.random();
        int methods = 0, islands = 0;
        for (ClassNode cn : ctx.targets(id())) {
            for (MethodNode mn : cn.methods) {
                if (ctx.isHotPath(cn, mn)) continue;
                if (skip(mn)) continue;

                List<AbstractInsnNode> points = emptyStackPoints(cn.name, mn);
                if (points.isEmpty()) continue;
                Collections.shuffle(points, rnd);
                int take = Math.min(3, points.size());
                for (int i = 0; i < take; i++) {
                    AbstractInsnNode at = points.get(i);
                    LabelNode island = new LabelNode();
                    LabelNode real = new LabelNode();
                    InsnList frag = new InsnList();

                    if (rnd.nextBoolean()) {
                        int r = 1 + rnd.nextInt(10000);
                        pushInt(frag, r);
                        frag.add(new InsnNode(DUP));
                        frag.add(new InsnNode(IMUL));
                        frag.add(new JumpInsnNode(IFLE, island));
                    } else {

                        int rotation = 1 + rnd.nextInt(31);
                        int selectedBit = 1 << rnd.nextInt(32);
                        frag.add(new MethodInsnNode(org.objectweb.asm.Opcodes.INVOKESTATIC,
                                "java/lang/System", "currentTimeMillis", "()J", false));
                        frag.add(new InsnNode(org.objectweb.asm.Opcodes.L2I));
                        frag.add(new MethodInsnNode(org.objectweb.asm.Opcodes.INVOKESTATIC,
                                "java/lang/Thread", "currentThread", "()Ljava/lang/Thread;", false));
                        frag.add(new MethodInsnNode(org.objectweb.asm.Opcodes.INVOKESTATIC,
                                "java/lang/System", "identityHashCode", "(Ljava/lang/Object;)I", false));
                        frag.add(new InsnNode(org.objectweb.asm.Opcodes.IXOR));
                        pushInt(frag, rotation);
                        frag.add(new MethodInsnNode(org.objectweb.asm.Opcodes.INVOKESTATIC,
                                "java/lang/Integer", "rotateLeft", "(II)I", false));
                        pushInt(frag, selectedBit);
                        frag.add(new InsnNode(org.objectweb.asm.Opcodes.IOR));
                        pushInt(frag, selectedBit);
                        frag.add(new InsnNode(org.objectweb.asm.Opcodes.IAND));
                        frag.add(new JumpInsnNode(org.objectweb.asm.Opcodes.IFEQ, island));
                    }

                    frag.add(new JumpInsnNode(GOTO, real));
                    frag.add(island);
                    frag.add(junkThrow());
                    frag.add(real);
                    mn.instructions.insertBefore(at, frag);
                    islands++;
                }
                methods++;
            }
        }
        ctx.log().debug("mangledJump: " + islands + " junk islands across " + methods + " methods");
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

    private static InsnList junkThrow() {
        InsnList il = new InsnList();
        il.add(new TypeInsnNode(NEW, "java/lang/RuntimeException"));
        il.add(new InsnNode(DUP));
        il.add(new MethodInsnNode(INVOKESPECIAL, "java/lang/RuntimeException", "<init>", "()V", false));
        il.add(new InsnNode(ATHROW));
        return il;
    }

    private static void pushInt(InsnList il, int v) {
        if (v >= -1 && v <= 5) il.add(new InsnNode(ICONST_0 + v));
        else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) il.add(new IntInsnNode(BIPUSH, v));
        else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) il.add(new IntInsnNode(SIPUSH, v));
        else il.add(new LdcInsnNode(Integer.valueOf(v)));
    }
}
