package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.IincInsnNode;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

public final class SemanticFabricTransformer implements Transformer {

    private static final int[] BINARY_OPS = {
            Opcodes.IADD, Opcodes.ISUB, Opcodes.IMUL, Opcodes.IXOR,
            Opcodes.IOR, Opcodes.IAND, Opcodes.ISHL, Opcodes.ISHR, Opcodes.IUSHR
    };

    @Override public String id() { return "semanticFabric"; }
    @Override public String description() {
        return "distribute pure method semantics across per-build carrier fragments";
    }

    @Override
    public void transform(ObfContext ctx) {
        if (ctx.isModularJar()) {
            ctx.log().warn("semanticFabric: modular jar skipped (generated package is not in module metadata)");
            return;
        }
        int percent = clamp(ctx.config().section(id()).getInt("percent", 35), 0, 100);
        int minOps = Math.max(1, ctx.config().section(id()).getInt("minArithmeticOps", 3));
        int maxMethods = Math.max(1, ctx.config().section(id()).getInt("maxMethods", 64));
        int carrierCount = clamp(ctx.config().section(id()).getInt("carriers", 8), 3, 32);
        if (percent == 0) return;

        Random rnd = ctx.random();
        List<ClassNode> original = ctx.targets(id());
        List<ClassNode> carriers = makeCarriers(ctx, original, carrierCount);
        int protectedMethods = 0, fragments = 0;

        outer:
        for (ClassNode owner : original) {
            for (MethodNode method : owner.methods) {
                if (ctx.isHotPath(owner, method)) continue;
                int arithmetic = eligibleArithmeticCount(method);
                if (arithmetic < minOps || rnd.nextInt(100) >= percent) continue;

                ClassNode implementationOwner = carriers.get(rnd.nextInt(carriers.size()));
                String implementationName = "f" + ctx.names().nextRandom(rnd, 5 + rnd.nextInt(5));
                MethodNode implementation = cloneBody(method, implementationName);

                for (AbstractInsnNode insn : implementation.instructions.toArray()) {
                    int opcode = insn.getOpcode();
                    if (!isFragmentable(opcode)) continue;
                    ClassNode fragmentOwner = pickOther(carriers, implementationOwner, rnd);
                    String fragmentName = "g" + ctx.names().nextRandom(rnd, 4 + rnd.nextInt(6));
                    MethodNode fragment = fragment(fragmentName, opcode, rnd);
                    fragmentOwner.methods.add(fragment);
                    implementation.instructions.set(insn, new MethodInsnNode(
                            Opcodes.INVOKESTATIC, fragmentOwner.name, fragmentName,
                            opcode == Opcodes.INEG ? "(I)I" : "(II)I", false));
                    fragments++;
                }

                implementationOwner.methods.add(implementation);
                replaceWithBridge(method, implementationOwner.name, implementationName);
                protectedMethods++;
                if (protectedMethods >= maxMethods) break outer;
            }
        }

        int activeCarriers = 0;
        for (ClassNode carrier : carriers) {
            if (protectedMethods == 0 || carrier.methods.isEmpty()) ctx.removeClass(carrier.name);
            else activeCarriers++;
        }
        ctx.log().debug("semanticFabric: protected=" + protectedMethods
                + " methods, fragments=" + fragments + ", carriers="
                + activeCarriers);
    }

    private static List<ClassNode> makeCarriers(ObfContext ctx, List<ClassNode> inputs, int count) {
        int version = Opcodes.V1_8;
        for (ClassNode cn : inputs) version = Math.max(version, cn.version & 0xFFFF);
        List<ClassNode> out = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            ClassNode cn = new ClassNode();
            cn.version = version;
            cn.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC;
            cn.name = ctx.names().nextRandomClass("ez/sf/", ctx.random(), 7 + i % 5);
            cn.superName = "java/lang/Object";
            cn.methods = new ArrayList<>();
            ctx.putClass(cn);
            out.add(cn);
        }
        return out;
    }

    private static int eligibleArithmeticCount(MethodNode mn) {
        int forbidden = Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE | Opcodes.ACC_SYNTHETIC
                | Opcodes.ACC_BRIDGE | Opcodes.ACC_SYNCHRONIZED;
        if ((mn.access & forbidden) != 0 || (mn.access & Opcodes.ACC_STATIC) == 0) return -1;
        if (mn.name.charAt(0) == '<' || mn.instructions == null || mn.instructions.size() == 0) return -1;
        if (mn.tryCatchBlocks != null && !mn.tryCatchBlocks.isEmpty()) return -1;
        if (!integerSignature(mn.desc)) return -1;

        int arithmetic = 0, returns = 0;
        for (AbstractInsnNode in : mn.instructions.toArray()) {
            int op = in.getOpcode();
            if (op < 0) continue;
            if (isFragmentable(op)) { arithmetic++; continue; }
            if (op == Opcodes.IRETURN) { returns++; continue; }
            if (in instanceof VarInsnNode v && (op == Opcodes.ILOAD || op == Opcodes.ISTORE)) continue;
            if (in instanceof IincInsnNode) continue;
            if (in instanceof JumpInsnNode && isIntegerJump(op)) continue;
            if (in instanceof LdcInsnNode ldc && ldc.cst instanceof Integer) continue;
            if (in instanceof IntInsnNode && (op == Opcodes.BIPUSH || op == Opcodes.SIPUSH)) continue;
            if (op >= Opcodes.ICONST_M1 && op <= Opcodes.ICONST_5) continue;
            if (op == Opcodes.NOP) continue;
            return -1;
        }
        return returns >= 1 ? arithmetic : -1;
    }

    private static boolean integerSignature(String desc) {
        Type ret = Type.getReturnType(desc);
        if (!intLike(ret)) return false;
        for (Type arg : Type.getArgumentTypes(desc)) if (!intLike(arg)) return false;
        return true;
    }

    private static boolean intLike(Type type) {
        int s = type.getSort();
        return s == Type.BOOLEAN || s == Type.BYTE || s == Type.CHAR
                || s == Type.SHORT || s == Type.INT;
    }

    private static MethodNode cloneBody(MethodNode source, String name) {
        MethodNode copy = new MethodNode(Opcodes.ASM9,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                name, source.desc, null, source.exceptions == null ? null : source.exceptions.toArray(String[]::new));
        Map<LabelNode, LabelNode> labels = new HashMap<>();
        for (AbstractInsnNode in : source.instructions.toArray())
            if (in instanceof LabelNode label) labels.put(label, new LabelNode());
        for (AbstractInsnNode in : source.instructions.toArray()) copy.instructions.add(in.clone(labels));
        copy.maxLocals = source.maxLocals;
        copy.maxStack = source.maxStack;
        return copy;
    }

    private static void replaceWithBridge(MethodNode method, String owner, String name) {
        InsnList bridge = new InsnList();
        int slot = 0;
        for (Type ignored : Type.getArgumentTypes(method.desc)) {
            bridge.add(new VarInsnNode(Opcodes.ILOAD, slot++));
        }
        bridge.add(new MethodInsnNode(Opcodes.INVOKESTATIC, owner, name, method.desc, false));
        bridge.add(new InsnNode(Opcodes.IRETURN));
        method.instructions = bridge;
        method.tryCatchBlocks = new ArrayList<>();
        method.localVariables = null;
        method.maxLocals = slot;
        method.maxStack = Math.max(1, slot);
    }

    private static MethodNode fragment(String name, int opcode, Random rnd) {
        String desc = opcode == Opcodes.INEG ? "(I)I" : "(II)I";
        MethodNode mn = new MethodNode(Opcodes.ASM9,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                name, desc, null, null);
        InsnList il = mn.instructions;

        int mask = rnd.nextInt();
        il.add(new VarInsnNode(Opcodes.ILOAD, 0));
        il.add(pushInt(mask));
        il.add(new InsnNode(Opcodes.IXOR));
        il.add(pushInt(mask));
        il.add(new InsnNode(Opcodes.IXOR));
        if (opcode != Opcodes.INEG) il.add(new VarInsnNode(Opcodes.ILOAD, 1));
        il.add(new InsnNode(opcode));
        il.add(new InsnNode(Opcodes.IRETURN));
        mn.maxLocals = opcode == Opcodes.INEG ? 1 : 2;
        mn.maxStack = 3;
        return mn;
    }

    private static AbstractInsnNode pushInt(int value) {
        if (value >= -1 && value <= 5) return new InsnNode(Opcodes.ICONST_0 + value);
        if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) return new IntInsnNode(Opcodes.BIPUSH, value);
        if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) return new IntInsnNode(Opcodes.SIPUSH, value);
        return new LdcInsnNode(value);
    }

    private static boolean isFragmentable(int opcode) {
        if (opcode == Opcodes.INEG) return true;
        for (int op : BINARY_OPS) if (op == opcode) return true;
        return false;
    }

    private static boolean isIntegerJump(int opcode) {
        return opcode == Opcodes.GOTO
                || (opcode >= Opcodes.IFEQ && opcode <= Opcodes.IFLE)
                || (opcode >= Opcodes.IF_ICMPEQ && opcode <= Opcodes.IF_ICMPLE);
    }

    private static ClassNode pickOther(List<ClassNode> all, ClassNode avoid, Random rnd) {
        ClassNode picked;
        do picked = all.get(rnd.nextInt(all.size())); while (picked == avoid && all.size() > 1);
        return picked;
    }

    private static int clamp(int value, int low, int high) {
        return Math.max(low, Math.min(high, value));
    }
}
