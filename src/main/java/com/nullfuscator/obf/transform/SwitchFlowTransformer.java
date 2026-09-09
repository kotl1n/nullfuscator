package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
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
import static org.objectweb.asm.Opcodes.ICONST_0;
import static org.objectweb.asm.Opcodes.INVOKESPECIAL;
import static org.objectweb.asm.Opcodes.NEW;
import static org.objectweb.asm.Opcodes.SIPUSH;

public final class SwitchFlowTransformer implements Transformer {

    @Override public String id() { return "flowSwitch"; }
    @Override public String description() { return "known-key switch dispatch"; }

    @Override
    public void transform(ObfContext ctx) {
        Random rnd = ctx.random();
        int methods = 0, switches = 0;
        for (ClassNode cn : ctx.targets(id())) {
            for (MethodNode mn : cn.methods) {
                if (ctx.isHotPath(cn, mn)) continue;
                if (skip(mn)) continue;

                List<AbstractInsnNode> points = emptyStackPoints(cn.name, mn);
                if (points.isEmpty()) continue;
                Collections.shuffle(points, rnd);
                int take = Math.min(2, points.size());
                for (int i = 0; i < take; i++) {
                    insertSwitch(rnd, mn.instructions, points.get(i));
                    switches++;
                }
                methods++;
            }
        }
        ctx.log().debug("flowSwitch: " + switches + " switch wrappers across " + methods + " methods");
    }

    private static void insertSwitch(Random rnd, InsnList insns, AbstractInsnNode at) {
        int n = 3 + rnd.nextInt(3);
        int realIndex = rnd.nextInt(n);
        LabelNode real = new LabelNode();
        LabelNode junk = new LabelNode();
        LabelNode[] labels = new LabelNode[n];
        for (int k = 0; k < n; k++) labels[k] = (k == realIndex) ? real : junk;

        InsnList frag = new InsnList();
        if (rnd.nextBoolean()) {

            pushInt(frag, realIndex);
            frag.add(new TableSwitchInsnNode(0, n - 1, junk, labels));
        } else {

            int[] keys = new int[n];
            int cur = rnd.nextInt(20);
            for (int k = 0; k < n; k++) { keys[k] = cur; cur += 1 + rnd.nextInt(7); }
            pushInt(frag, keys[realIndex]);
            frag.add(new LookupSwitchInsnNode(junk, keys, labels));
        }
        frag.add(junk);
        frag.add(junkThrow());
        frag.add(real);
        insns.insertBefore(at, frag);
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
