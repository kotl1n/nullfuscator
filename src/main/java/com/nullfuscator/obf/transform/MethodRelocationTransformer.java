package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.Limits;
import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

public final class MethodRelocationTransformer implements Transformer {
    @Override public String id() { return "methodRelocation"; }
    @Override public String description() { return "relocate complete object method bodies across opaque carriers"; }

    @Override
    public void transform(ObfContext ctx) {
        var sec = ctx.config().section(id());
        int percent = clamp(sec.getInt("percent", 70), 0, 100);
        int maxMethods = Math.max(1, sec.getInt("maxMethods", 96));
        int carrierCount = clamp(sec.getInt("carriers", 12), 3, 48);
        int minInstructions = Math.max(8, sec.getInt("minInstructions", 20));
        if (percent == 0 || ctx.isModularJar()) return;

        List<Candidate> candidates = new ArrayList<>();
        for (ClassNode cn : ctx.targets(id())) {
            if ((cn.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION | Opcodes.ACC_MODULE)) != 0) continue;
            if (hasPrivateMembers(cn)) continue;
            for (MethodNode mn : cn.methods) {
                if (ctx.isHotPath(cn, mn)) continue;
                int score = eligibleScore(mn, minInstructions);
                if (score >= 0) candidates.add(new Candidate(cn, mn, score));
            }
        }

        candidates.sort(Comparator.comparingInt(Candidate::score).reversed());
        List<ClassNode> carriers = carriers(ctx, candidates, carrierCount);
        Random rnd = ctx.random();
        int moved = 0, instructions = 0;
        for (Candidate c : candidates) {
            if (moved >= maxMethods) break;
            if (rnd.nextInt(100) >= percent) continue;
            ClassNode carrier = carriers.get(rnd.nextInt(carriers.size()));
            String name = "m" + ctx.names().nextRandom(rnd, 8 + rnd.nextInt(8));
            String implDesc = implementationDescriptor(c.owner, c.method);
            MethodNode impl = cloneBody(c.method, name, implDesc);
            ctx.transferInputMethod(c.method, impl);
            carrier.methods.add(impl);
            replaceWithBridge(c.owner, c.method, carrier.name, name, implDesc);
            moved++;
            instructions += c.score;
        }
        if (moved == 0) for (ClassNode carrier : carriers) ctx.removeClass(carrier.name);
        ctx.log().debug("methodRelocation: moved " + moved + " complete bodies ("
                + instructions + " instructions) across " + (moved == 0 ? 0 : carriers.size()) + " carriers");
    }

    private static int eligibleScore(MethodNode mn, int minimum) {
        int forbidden = Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE | Opcodes.ACC_BRIDGE;
        if ((mn.access & forbidden) != 0 || mn.name.charAt(0) == '<') return -1;
        if (mn.instructions == null || mn.instructions.size() < minimum || Limits.oversizeMethod(mn)) return -1;
        for (AbstractInsnNode in : mn.instructions.toArray()) {
            if (in instanceof InvokeDynamicInsnNode) return -1;
            if (in instanceof MethodInsnNode call && call.getOpcode() == Opcodes.INVOKESPECIAL
                    && !call.name.equals("<init>")) return -1;
        }
        return mn.instructions.size();
    }

    private static List<ClassNode> carriers(ObfContext ctx, List<Candidate> candidates, int count) {
        int version = Opcodes.V1_8;
        for (Candidate c : candidates) version = Math.max(version, c.owner.version & 0xFFFF);
        List<ClassNode> out = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            ClassNode cn = new ClassNode();
            cn.version = version;
            cn.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER;
            cn.name = ctx.names().nextRandomClass("a/m/", ctx.random(), 8 + i % 7);
            cn.superName = "java/lang/Object";
            cn.methods = new ArrayList<>();
            ctx.putClass(cn);
            out.add(cn);
        }
        return out;
    }

    private static String implementationDescriptor(ClassNode owner, MethodNode mn) {
        if ((mn.access & Opcodes.ACC_STATIC) != 0) return mn.desc;
        Type[] args = Type.getArgumentTypes(mn.desc);
        StringBuilder b = new StringBuilder("(L").append(owner.name).append(';');
        for (Type arg : args) b.append(arg.getDescriptor());
        return b.append(')').append(Type.getReturnType(mn.desc).getDescriptor()).toString();
    }

    private static MethodNode cloneBody(MethodNode source, String name, String desc) {
        MethodNode copy = new MethodNode(Opcodes.ASM9, Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                name, desc, null,
                source.exceptions == null ? null : source.exceptions.toArray(String[]::new));
        Map<LabelNode, LabelNode> labels = new HashMap<>();
        for (AbstractInsnNode in : source.instructions.toArray())
            if (in instanceof LabelNode label) labels.put(label, new LabelNode());
        for (AbstractInsnNode in : source.instructions.toArray()) copy.instructions.add(in.clone(labels));
        if (source.tryCatchBlocks != null) for (TryCatchBlockNode t : source.tryCatchBlocks)
            copy.tryCatchBlocks.add(new TryCatchBlockNode(labels.get(t.start), labels.get(t.end), labels.get(t.handler), t.type));
        copy.maxLocals = source.maxLocals;
        copy.maxStack = source.maxStack;
        return copy;
    }

    private static void replaceWithBridge(ClassNode owner, MethodNode mn, String carrier,
                                          String name, String implDesc) {
        InsnList bridge = new InsnList();
        int slot = 0;
        if ((mn.access & Opcodes.ACC_STATIC) == 0) {
            bridge.add(new VarInsnNode(Opcodes.ALOAD, 0));
            slot = 1;
        }
        for (Type arg : Type.getArgumentTypes(mn.desc)) {
            bridge.add(new VarInsnNode(arg.getOpcode(Opcodes.ILOAD), slot));
            slot += arg.getSize();
        }
        Type ret = Type.getReturnType(mn.desc);
        bridge.add(new MethodInsnNode(Opcodes.INVOKESTATIC, carrier, name, implDesc, false));
        bridge.add(new InsnNode(ret.getOpcode(Opcodes.IRETURN)));
        mn.instructions = bridge;
        mn.tryCatchBlocks = new ArrayList<>();
        mn.localVariables = null;
        mn.maxLocals = slot;
        mn.maxStack = Math.max(slot, ret.getSize());
    }

    private record Candidate(ClassNode owner, MethodNode method, int score) { }
    private static boolean hasPrivateMembers(ClassNode cn) {
        for (var fn : cn.fields) if ((fn.access & Opcodes.ACC_PRIVATE) != 0) return true;
        for (var mn : cn.methods) if ((mn.access & Opcodes.ACC_PRIVATE) != 0) return true;
        return false;
    }
    private static int clamp(int v, int lo, int hi) { return Math.max(lo, Math.min(hi, v)); }
}
