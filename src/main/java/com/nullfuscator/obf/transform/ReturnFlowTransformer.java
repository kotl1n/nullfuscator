package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static org.objectweb.asm.Opcodes.ACC_ABSTRACT;
import static org.objectweb.asm.Opcodes.ACC_NATIVE;
import static org.objectweb.asm.Opcodes.BIPUSH;
import static org.objectweb.asm.Opcodes.ICONST_0;
import static org.objectweb.asm.Opcodes.IRETURN;
import static org.objectweb.asm.Opcodes.IXOR;
import static org.objectweb.asm.Opcodes.LRETURN;
import static org.objectweb.asm.Opcodes.LXOR;
import static org.objectweb.asm.Opcodes.LCONST_0;
import static org.objectweb.asm.Opcodes.LCONST_1;
import static org.objectweb.asm.Opcodes.SIPUSH;

public final class ReturnFlowTransformer implements Transformer {

    @Override public String id() { return "integerReturn"; }
    @Override public String description() { return "opaque-identity integer returns"; }

    @Override
    public void transform(ObfContext ctx) {
        Random rnd = ctx.random();
        int methods = 0, sites = 0;
        for (ClassNode cn : ctx.targets(id())) {
            for (MethodNode mn : cn.methods) {
                if (ctx.isHotPath(cn, mn)) continue;
                if ((mn.access & (ACC_ABSTRACT | ACC_NATIVE)) != 0) continue;
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                int returnSort = Type.getReturnType(mn.desc).getSort();
                boolean longKind = returnSort == Type.LONG;
                if (!longKind && !isIntKind(returnSort)) continue;

                List<AbstractInsnNode> rets = new ArrayList<>();
                for (AbstractInsnNode n = mn.instructions.getFirst(); n != null; n = n.getNext())
                    if (n.getOpcode() == (longKind ? LRETURN : IRETURN)) rets.add(n);
                if (rets.isEmpty()) continue;

                for (AbstractInsnNode ret : rets) {
                    int pairs = 1 + rnd.nextInt(2);
                    InsnList frag = new InsnList();
                    for (int p = 0; p < pairs; p++) {
                        if (longKind) {
                            long key = rnd.nextLong();
                            pushLong(frag, key);
                            frag.add(new InsnNode(LXOR));
                            pushLong(frag, key);
                            frag.add(new InsnNode(LXOR));
                        } else {
                            int key = rnd.nextInt();
                            pushInt(frag, key);
                            frag.add(new InsnNode(IXOR));
                            pushInt(frag, key);
                            frag.add(new InsnNode(IXOR));
                        }
                    }
                    mn.instructions.insertBefore(ret, frag);
                    sites++;
                }
                methods++;
            }
        }
        ctx.log().debug("integerReturn: " + sites + " return sites across " + methods + " methods");
    }

    private static boolean isIntKind(int sort) {
        return sort == Type.INT || sort == Type.BOOLEAN || sort == Type.SHORT
                || sort == Type.BYTE || sort == Type.CHAR;
    }

    private static void pushInt(InsnList il, int v) {
        if (v >= -1 && v <= 5) il.add(new InsnNode(ICONST_0 + v));
        else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) il.add(new IntInsnNode(BIPUSH, v));
        else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) il.add(new IntInsnNode(SIPUSH, v));
        else il.add(new LdcInsnNode(Integer.valueOf(v)));
    }

    private static void pushLong(InsnList il, long v) {
        if (v == 0L) il.add(new InsnNode(LCONST_0));
        else if (v == 1L) il.add(new InsnNode(LCONST_1));
        else il.add(new LdcInsnNode(Long.valueOf(v)));
    }
}
