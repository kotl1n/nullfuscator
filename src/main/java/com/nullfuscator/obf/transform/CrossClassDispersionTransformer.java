package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.Limits;
import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

public final class CrossClassDispersionTransformer implements Transformer {

    private static final String INT_STATE = "$i";
    private static final String LONG_STATE = "$j";

    @Override public String id() { return "crossClassDispersion"; }
    @Override public String description() { return "relocate ops into cross-class static helpers"; }

    private static final Map<Integer, String[]> OPS = new HashMap<>();
    static {
        int[] intOps  = { Opcodes.IADD, Opcodes.ISUB, Opcodes.IMUL, Opcodes.ISHL,
                          Opcodes.ISHR, Opcodes.IUSHR, Opcodes.IAND, Opcodes.IOR, Opcodes.IXOR };
        int[] longOps = { Opcodes.LADD, Opcodes.LSUB, Opcodes.LMUL,
                          Opcodes.LAND, Opcodes.LOR, Opcodes.LXOR };
        for (int op : intOps)  OPS.put(op, new String[] { "d" + op, "(II)I" });
        for (int op : longOps) OPS.put(op, new String[] { "d" + op, "(JJ)J" });
    }

    @Override
    public void transform(ObfContext ctx) {
        var section = ctx.config().section(id());
        int percent = Math.max(0, Math.min(100, section.getInt("dispersalPercent", 60)));

        int sinkCount = Math.max(1, Math.min(2048, section.getInt("sinks", 16)));
        int maxPerClass = Math.max(0, Math.min(12000, section.getInt("maxPerClass", 6000)));
        int variants = bounded(section.getInt("variantsPerOpcode", 2), 1, 16, "variantsPerOpcode");
        int maxHelpers = bounded(section.getInt("maxHelpers", 2048), 0, 8192, "maxHelpers");
        int maxOperations = bounded(section.getInt("maxOperations", 8192), 0,
                Integer.MAX_VALUE, "maxOperations");
        if (percent == 0 || maxPerClass == 0 || maxHelpers == 0 || maxOperations == 0) return;

        List<ClassNode> targets = ctx.targets(id());
        Random rnd = ctx.random();
        // Lazily allocate sinks and reuse a bounded family for each opcode. In particular,
        // number encryption must not turn every generated XOR/ADD into a new method.
        List<ClassNode> sinks = new ArrayList<>();
        Map<Integer, List<Helper>> helpers = new HashMap<>();
        int helperCount = 0;
        int replaced = 0;
        outer:
        for (ClassNode cn : targets) {
            if (ctx.isDispersionCarrier(cn)) continue;
            int classReplaced = 0;
            classLoop:
            for (MethodNode mn : cn.methods) {
                if (ctx.isHotPath(cn, mn)) continue;
                if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) continue;
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                if (Limits.oversizeMethod(mn)) continue;
                for (AbstractInsnNode insn : mn.instructions.toArray()) {
                    if (replaced >= maxOperations) break outer;
                    if (classReplaced >= maxPerClass) break classLoop;
                    if (insn.getType() != AbstractInsnNode.INSN) continue;
                    String[] shape = OPS.get(insn.getOpcode());
                    if (shape == null || rnd.nextInt(100) >= percent) continue;
                    List<Helper> family = helpers.computeIfAbsent(insn.getOpcode(), k -> new ArrayList<>());
                    int slot = rnd.nextInt(sinkCount * variants);
                    Helper helper;
                    if (slot >= family.size() && helperCount < maxHelpers) {
                        int sinkIndex = helperCount % sinkCount;
                        if (sinkIndex == sinks.size()) {
                            String name;
                            do { name = "a/d/" + ctx.names().next(); }
                            while (ctx.getClass(name) != null);
                            ClassNode sink = buildSink(name, rnd);
                            ctx.markDispersionCarrier(sink);
                            ctx.putClass(sink);
                            sinks.add(sink);
                        }
                        ClassNode sink = sinks.get(sinkIndex);
                        String name = "d" + ctx.names().next();
                        sink.methods.add(compositeHelper(sink.name, name, shape[1], insn.getOpcode(), rnd));
                        helper = new Helper(sink.name, name);
                        family.add(helper);
                        helperCount++;
                    } else {
                        // A saturated budget must never substitute a different opcode.
                        if (family.isEmpty()) continue;
                        helper = family.get(slot % family.size());
                    }
                    mn.instructions.set(insn, new MethodInsnNode(Opcodes.INVOKESTATIC,
                            helper.owner(), helper.name(), shape[1], false));
                    replaced++;
                    classReplaced++;
                }
            }
        }
        ctx.log().debug("crossClassDispersion: " + replaced + " ops, " + helperCount
                + " shared helpers, " + sinks.size() + " sinks; limits=" + maxOperations
                + " ops, " + maxHelpers + " helpers, " + maxPerClass + "/source class");
    }

    private record Helper(String owner, String name) { }

    private static int bounded(int value, int min, int max, String key) {
        if (value < min || value > max)
            throw new IllegalArgumentException("crossClassDispersion." + key
                    + " must be between " + min + " and " + max);
        return value;
    }

    private static ClassNode buildSink(String name, Random rnd) {
        ClassNode cn = new ClassNode();
        cn.version = 52;
        cn.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER;
        cn.name = name;
        cn.superName = "java/lang/Object";
        cn.fields = new ArrayList<>();
        cn.methods = new ArrayList<>();

        int fieldAccess = Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC
                | Opcodes.ACC_SYNTHETIC | Opcodes.ACC_VOLATILE;
        cn.fields.add(new FieldNode(Opcodes.ASM9, fieldAccess, INT_STATE, "I", null, null));
        cn.fields.add(new FieldNode(Opcodes.ASM9, fieldAccess, LONG_STATE, "J", null, null));

        MethodNode clinit = new MethodNode(Opcodes.ASM9, Opcodes.ACC_STATIC,
                "<clinit>", "()V", null, null);
        clinit.instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                "java/lang/System", "nanoTime", "()J", false));
        clinit.instructions.add(new InsnNode(Opcodes.DUP2));
        clinit.instructions.add(new InsnNode(Opcodes.L2I));
        clinit.instructions.add(new LdcInsnNode(rnd.nextInt()));
        clinit.instructions.add(new InsnNode(Opcodes.IXOR));
        clinit.instructions.add(new FieldInsnNode(Opcodes.PUTSTATIC, name, INT_STATE, "I"));
        clinit.instructions.add(new LdcInsnNode(rnd.nextLong()));
        clinit.instructions.add(new InsnNode(Opcodes.LXOR));
        clinit.instructions.add(new FieldInsnNode(Opcodes.PUTSTATIC, name, LONG_STATE, "J"));
        clinit.instructions.add(new InsnNode(Opcodes.RETURN));
        clinit.maxLocals = 0;
        clinit.maxStack = 4;
        cn.methods.add(clinit);
        return cn;
    }

    private static MethodNode compositeHelper(String owner, String name, String desc,
                                              int opcode, Random rnd) {
        boolean wide = desc.equals("(JJ)J");
        MethodNode mn = new MethodNode(Opcodes.ASM9, Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                name, desc, null, null);
        InsnList il = mn.instructions;
        if (wide) {
            long mask = rnd.nextLong(), delta = rnd.nextLong();
            int rotation = 1 + rnd.nextInt(63);
            il.add(new VarInsnNode(Opcodes.LLOAD, 0));
            il.add(new VarInsnNode(Opcodes.LLOAD, 2));
            il.add(new InsnNode(opcode));
            il.add(new VarInsnNode(Opcodes.LSTORE, 4));

            il.add(new FieldInsnNode(Opcodes.GETSTATIC, owner, LONG_STATE, "J"));
            il.add(new VarInsnNode(Opcodes.LSTORE, 6));
            il.add(new VarInsnNode(Opcodes.LLOAD, 6));
            il.add(new VarInsnNode(Opcodes.LLOAD, 4));
            il.add(new InsnNode(Opcodes.LXOR));
            il.add(new LdcInsnNode(rotation));
            il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Long",
                    "rotateLeft", "(JI)J", false));
            il.add(new FieldInsnNode(Opcodes.PUTSTATIC, owner, LONG_STATE, "J"));

            il.add(new VarInsnNode(Opcodes.LLOAD, 4));
            il.add(new VarInsnNode(Opcodes.LLOAD, 6));
            il.add(new InsnNode(Opcodes.LXOR));
            il.add(new LdcInsnNode(rotation));
            il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Long",
                    "rotateLeft", "(JI)J", false));
            il.add(new LdcInsnNode(rotation));
            il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Long",
                    "rotateRight", "(JI)J", false));
            il.add(new VarInsnNode(Opcodes.LLOAD, 6));
            il.add(new InsnNode(Opcodes.LXOR));
            il.add(new LdcInsnNode(mask)); il.add(new InsnNode(Opcodes.LXOR));
            il.add(new LdcInsnNode(delta)); il.add(new InsnNode(Opcodes.LADD));
            il.add(new LdcInsnNode(delta)); il.add(new InsnNode(Opcodes.LSUB));
            il.add(new LdcInsnNode(mask)); il.add(new InsnNode(Opcodes.LXOR));
            il.add(new InsnNode(Opcodes.LRETURN));
            mn.maxLocals = 8; mn.maxStack = 4;
        } else {
            int mask = rnd.nextInt(), delta = rnd.nextInt();
            int rotation = 1 + rnd.nextInt(31);
            il.add(new VarInsnNode(Opcodes.ILOAD, 0));
            il.add(new VarInsnNode(Opcodes.ILOAD, 1));
            il.add(new InsnNode(opcode));
            il.add(new VarInsnNode(Opcodes.ISTORE, 2));

            il.add(new FieldInsnNode(Opcodes.GETSTATIC, owner, INT_STATE, "I"));
            il.add(new VarInsnNode(Opcodes.ISTORE, 3));
            il.add(new VarInsnNode(Opcodes.ILOAD, 3));
            il.add(new VarInsnNode(Opcodes.ILOAD, 2));
            il.add(new InsnNode(Opcodes.IXOR));
            il.add(new LdcInsnNode(rotation));
            il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer",
                    "rotateLeft", "(II)I", false));
            il.add(new FieldInsnNode(Opcodes.PUTSTATIC, owner, INT_STATE, "I"));

            il.add(new VarInsnNode(Opcodes.ILOAD, 2));
            il.add(new VarInsnNode(Opcodes.ILOAD, 3));
            il.add(new InsnNode(Opcodes.IXOR));
            il.add(new LdcInsnNode(rotation));
            il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer",
                    "rotateLeft", "(II)I", false));
            il.add(new LdcInsnNode(rotation));
            il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer",
                    "rotateRight", "(II)I", false));
            il.add(new VarInsnNode(Opcodes.ILOAD, 3));
            il.add(new InsnNode(Opcodes.IXOR));
            il.add(new LdcInsnNode(mask)); il.add(new InsnNode(Opcodes.IXOR));
            il.add(new LdcInsnNode(delta)); il.add(new InsnNode(Opcodes.IADD));
            il.add(new LdcInsnNode(delta)); il.add(new InsnNode(Opcodes.ISUB));
            il.add(new LdcInsnNode(mask)); il.add(new InsnNode(Opcodes.IXOR));
            il.add(new InsnNode(Opcodes.IRETURN));
            mn.maxLocals = 4; mn.maxStack = 3;
        }
        return mn;
    }

}
