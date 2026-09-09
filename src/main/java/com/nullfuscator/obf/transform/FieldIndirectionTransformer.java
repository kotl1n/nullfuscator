package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.Limits;
import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

public final class FieldIndirectionTransformer implements Transformer {

    @Override public String id() { return "fieldIndirection"; }
    @Override public String description() { return "route field access through hidden accessors"; }

    private record Acc(String get, String set) {}

    @Override
    public void transform(ObfContext ctx) {
        int percent = Math.max(0, Math.min(100, ctx.config().section(id()).getInt("percent", 100)));
        if (percent == 0) return;
        Random rnd = ctx.random();

        List<ClassNode> targets = ctx.targets(id());
        Map<String, Acc> map = new HashMap<>();

        java.util.Set<MethodNode> generated =
                java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>());

        for (ClassNode cn : targets) {
            if (ctx.isHotClass(cn)) continue;
            if (ctx.isDispersionCarrier(cn)) continue;
            if ((cn.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION
                    | Opcodes.ACC_MODULE)) != 0) continue;
            if (Limits.hugeClass(cn)) continue;
            if (cn.fields == null) continue;
            for (FieldNode fn : new ArrayList<>(cn.fields)) {
                if (rnd.nextInt(100) >= percent) continue;
                boolean isStatic = (fn.access & Opcodes.ACC_STATIC) != 0;
                boolean isFinal = (fn.access & Opcodes.ACC_FINAL) != 0;
                Type ft = Type.getType(fn.desc);

                String getName = ctx.names().next();
                MethodNode getter = buildGetter(getName, cn.name, fn.name, fn.desc, ft, isStatic);
                cn.methods.add(getter);
                generated.add(getter);

                String setName = null;
                if (!isFinal) {
                    setName = ctx.names().next();
                    MethodNode setter = buildSetter(setName, cn.name, fn.name, fn.desc, ft, isStatic);
                    cn.methods.add(setter);
                    generated.add(setter);
                }
                map.put(key(cn.name, fn.name, fn.desc), new Acc(getName, setName));
            }
        }
        if (map.isEmpty()) return;

        int rewritten = 0;
        for (ClassNode cn : targets) {
            if (ctx.isDispersionCarrier(cn)) continue;
            if ((cn.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION
                    | Opcodes.ACC_MODULE)) != 0) continue;
            for (MethodNode mn : new ArrayList<>(cn.methods)) {
                if (ctx.isHotPath(cn, mn)) continue;
                if (generated.contains(mn)) continue;
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                if (Limits.oversizeMethod(mn)) continue;
                boolean initializedThis = !mn.name.equals("<init>");
                for (AbstractInsnNode insn : mn.instructions.toArray()) {
                    if (!initializedThis) {
                        if (insn instanceof MethodInsnNode call
                                && call.getOpcode() == Opcodes.INVOKESPECIAL
                                && call.name.equals("<init>")
                                && (call.owner.equals(cn.name) || call.owner.equals(cn.superName))) {
                            initializedThis = true;
                        }
                        continue;
                    }
                    if (!(insn instanceof FieldInsnNode fin)) continue;
                    Acc acc = map.get(key(fin.owner, fin.name, fin.desc));
                    if (acc == null) continue;
                    int op = fin.getOpcode();
                    if (op == Opcodes.GETFIELD) {
                        mn.instructions.set(fin, new MethodInsnNode(Opcodes.INVOKESTATIC,
                                fin.owner, acc.get(), "(L" + fin.owner + ";)" + fin.desc, false));
                        rewritten++;
                    } else if (op == Opcodes.GETSTATIC) {
                        mn.instructions.set(fin, new MethodInsnNode(Opcodes.INVOKESTATIC,
                                fin.owner, acc.get(), "()" + fin.desc, false));
                        rewritten++;
                    } else if (op == Opcodes.PUTFIELD && acc.set() != null) {
                        mn.instructions.set(fin, new MethodInsnNode(Opcodes.INVOKESTATIC,
                                fin.owner, acc.set(), "(L" + fin.owner + ";" + fin.desc + ")V", false));
                        rewritten++;
                    } else if (op == Opcodes.PUTSTATIC && acc.set() != null) {
                        mn.instructions.set(fin, new MethodInsnNode(Opcodes.INVOKESTATIC,
                                fin.owner, acc.set(), "(" + fin.desc + ")V", false));
                        rewritten++;
                    }
                }
            }
        }
        ctx.log().debug("fieldIndirection: " + map.size() + " accessors, " + rewritten + " accesses routed");
    }

    private static MethodNode buildGetter(String name, String owner, String fname, String fdesc,
                                          Type ft, boolean isStatic) {
        String desc = isStatic ? "()" + fdesc : "(L" + owner + ";)" + fdesc;
        MethodNode m = new MethodNode(Opcodes.ASM9,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC, name, desc, null, null);
        InsnList il = new InsnList();
        if (isStatic) {
            il.add(new FieldInsnNode(Opcodes.GETSTATIC, owner, fname, fdesc));
        } else {
            il.add(new VarInsnNode(Opcodes.ALOAD, 0));
            il.add(new FieldInsnNode(Opcodes.GETFIELD, owner, fname, fdesc));
        }
        il.add(new InsnNode(ft.getOpcode(Opcodes.IRETURN)));
        m.instructions = il;
        m.maxStack = ft.getSize() + (isStatic ? 0 : 0) + 1;
        m.maxLocals = isStatic ? 0 : 1;
        return m;
    }

    private static MethodNode buildSetter(String name, String owner, String fname, String fdesc,
                                          Type ft, boolean isStatic) {
        String desc = isStatic ? "(" + fdesc + ")V" : "(L" + owner + ";" + fdesc + ")V";
        MethodNode m = new MethodNode(Opcodes.ASM9,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC, name, desc, null, null);
        InsnList il = new InsnList();
        if (isStatic) {
            il.add(new VarInsnNode(ft.getOpcode(Opcodes.ILOAD), 0));
            il.add(new FieldInsnNode(Opcodes.PUTSTATIC, owner, fname, fdesc));
            m.maxLocals = ft.getSize();
        } else {
            il.add(new VarInsnNode(Opcodes.ALOAD, 0));
            il.add(new VarInsnNode(ft.getOpcode(Opcodes.ILOAD), 1));
            il.add(new FieldInsnNode(Opcodes.PUTFIELD, owner, fname, fdesc));
            m.maxLocals = 1 + ft.getSize();
        }
        il.add(new InsnNode(Opcodes.RETURN));
        m.instructions = il;
        m.maxStack = 1 + ft.getSize();
        return m;
    }

    private static String key(String owner, String name, String desc) {
        return owner + '\0' + name + '\0' + desc;
    }
}
