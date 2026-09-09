package com.nullfuscator.obf.transform;

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
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class FieldPackingTransformer implements Transformer {
    @Override public String id() { return "fieldPacking"; }
    @Override public String description() { return "erase instance schemas into boxed state vectors"; }

    @Override
    public void transform(ObfContext ctx) {
        int minFields = Math.max(1, ctx.config().section(id()).getInt("minFields", 1));
        Map<String, Slot> slots = new HashMap<>();
        List<Packed> packed = new ArrayList<>();

        for (ClassNode cn : ctx.targets(id())) {
            if (ctx.isHotClass(cn)) continue;
            if (!eligibleClass(cn)) continue;
            List<FieldNode> fields = new ArrayList<>();
            for (FieldNode fn : cn.fields) {
                if ((fn.access & Opcodes.ACC_STATIC) == 0) fields.add(fn);
            }
            if (fields.size() < minFields || !hasSuperConstructor(cn)) continue;
            String state = "$" + ctx.names().nextRandom(ctx.random(), 9 + ctx.random().nextInt(8));
            int index = 0;
            for (FieldNode fn : fields) {
                slots.put(key(cn.name, fn.name, fn.desc), new Slot(cn.name, state, index++, Type.getType(fn.desc)));
            }
            cn.fields.removeAll(fields);
            cn.fields.add(new FieldNode(Opcodes.ACC_PRIVATE, state, "[Ljava/lang/Object;", null, null));
            packed.add(new Packed(cn, state, fields));
        }
        if (slots.isEmpty()) { ctx.log().debug("fieldPacking: no eligible fields"); return; }

        int accesses = 0;
        for (ClassNode cn : ctx.classMap().values()) for (MethodNode mn : cn.methods) {
            for (AbstractInsnNode in : mn.instructions.toArray()) {
                if (!(in instanceof FieldInsnNode field)) continue;
                Slot slot = resolveSlot(field.owner, field.name, field.desc, slots, ctx.classMap());
                if (slot == null || (field.getOpcode() != Opcodes.GETFIELD && field.getOpcode() != Opcodes.PUTFIELD)) continue;
                InsnList repl = field.getOpcode() == Opcodes.GETFIELD
                        ? read(slot) : write(slot, mn);
                mn.instructions.insertBefore(field, repl);
                mn.instructions.remove(field);
                accesses++;
            }
        }
        for (Packed p : packed) initialize(p);
        ctx.log().debug("fieldPacking: packed " + slots.size() + " fields across "
                + packed.size() + " classes, rewrote " + accesses + " accesses");
    }

    private static boolean eligibleClass(ClassNode cn) {
        // Packing erases the fields and their serialization/reflection contracts.
        if (cn.visibleAnnotations != null && !cn.visibleAnnotations.isEmpty()) return false;
        for (FieldNode field : cn.fields)
            if (field.visibleAnnotations != null && !field.visibleAnnotations.isEmpty()) return false;
        if ((cn.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION | Opcodes.ACC_ENUM
                | Opcodes.ACC_RECORD | Opcodes.ACC_MODULE)) != 0) return false;
        if (!"java/lang/Object".equals(cn.superName)) return false;
        if (cn.interfaces != null && !cn.interfaces.isEmpty()) return false;
        if (cn.recordComponents != null && !cn.recordComponents.isEmpty()) return false;
        for (FieldNode fn : cn.fields) if ((fn.access & Opcodes.ACC_VOLATILE) != 0) return false;
        for (MethodNode mn : cn.methods) for (AbstractInsnNode in : mn.instructions.toArray())
            if (in instanceof InvokeDynamicInsnNode indy
                    && indy.bsm.getOwner().equals("java/lang/runtime/ObjectMethods")) return false;
        return true;
    }

    private static boolean hasSuperConstructor(ClassNode cn) {
        for (MethodNode mn : cn.methods) if (mn.name.equals("<init>"))
            for (AbstractInsnNode in : mn.instructions.toArray())
                if (in instanceof MethodInsnNode call && call.getOpcode() == Opcodes.INVOKESPECIAL
                        && call.name.equals("<init>") && call.owner.equals(cn.superName)) return true;
        return false;
    }

    private static InsnList read(Slot s) {
        InsnList il = new InsnList();
        il.add(new FieldInsnNode(Opcodes.GETFIELD, s.owner, s.state, "[Ljava/lang/Object;"));
        pushInt(il, s.index);
        il.add(new InsnNode(Opcodes.AALOAD));
        emitUnbox(il, s.type);
        return il;
    }

    private static InsnList write(Slot s, MethodNode mn) {
        InsnList il = new InsnList();
        int local = mn.maxLocals;
        mn.maxLocals += s.type.getSize();
        il.add(new VarInsnNode(s.type.getOpcode(Opcodes.ISTORE), local));
        il.add(new FieldInsnNode(Opcodes.GETFIELD, s.owner, s.state, "[Ljava/lang/Object;"));
        pushInt(il, s.index);
        il.add(new VarInsnNode(s.type.getOpcode(Opcodes.ILOAD), local));
        emitBox(il, s.type);
        il.add(new InsnNode(Opcodes.AASTORE));
        return il;
    }

    private static void initialize(Packed p) {
        for (MethodNode mn : p.owner.methods) {
            if (!mn.name.equals("<init>")) continue;

            boolean delegates = false;
            for (AbstractInsnNode in : mn.instructions.toArray()) {
                if (in instanceof MethodInsnNode call
                        && call.getOpcode() == Opcodes.INVOKESPECIAL
                        && call.name.equals("<init>")
                        && call.owner.equals(p.owner.name)) {
                    delegates = true;
                    break;
                }
            }
            if (delegates) continue;
            for (AbstractInsnNode in : mn.instructions.toArray()) {
                if (!(in instanceof MethodInsnNode call) || call.getOpcode() != Opcodes.INVOKESPECIAL
                        || !call.name.equals("<init>") || !call.owner.equals(p.owner.superName)
                        || !call.desc.equals("()V") || !receiverIsThis(call)) continue;
                InsnList il = new InsnList();
                il.add(new VarInsnNode(Opcodes.ALOAD, 0));
                pushInt(il, p.fields.size());
                il.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
                il.add(new FieldInsnNode(Opcodes.PUTFIELD, p.owner.name, p.state, "[Ljava/lang/Object;"));
                for (int i = 0; i < p.fields.size(); i++) {
                    Type t = Type.getType(p.fields.get(i).desc);
                    if (t.getSort() == Type.OBJECT || t.getSort() == Type.ARRAY) continue;
                    il.add(new VarInsnNode(Opcodes.ALOAD, 0));
                    il.add(new FieldInsnNode(Opcodes.GETFIELD, p.owner.name, p.state, "[Ljava/lang/Object;"));
                    pushInt(il, i); emitDefault(il, t); emitBox(il, t);
                    il.add(new InsnNode(Opcodes.AASTORE));
                }
                mn.instructions.insert(call, il);
                break;
            }
        }
    }

    private static boolean receiverIsThis(MethodInsnNode call) {
        AbstractInsnNode previous = call.getPrevious();
        while (previous != null && previous.getOpcode() < 0) previous = previous.getPrevious();
        return previous instanceof VarInsnNode var
                && var.getOpcode() == Opcodes.ALOAD && var.var == 0;
    }

    private static void emitDefault(InsnList il, Type t) {
        switch (t.getSort()) {
            case Type.LONG -> il.add(new InsnNode(Opcodes.LCONST_0));
            case Type.FLOAT -> il.add(new InsnNode(Opcodes.FCONST_0));
            case Type.DOUBLE -> il.add(new InsnNode(Opcodes.DCONST_0));
            default -> il.add(new InsnNode(Opcodes.ICONST_0));
        }
    }

    private static void emitBox(InsnList il, Type t) {
        String owner, desc;
        switch (t.getSort()) {
            case Type.BOOLEAN -> { owner = "java/lang/Boolean"; desc = "(Z)Ljava/lang/Boolean;"; }
            case Type.BYTE -> { owner = "java/lang/Byte"; desc = "(B)Ljava/lang/Byte;"; }
            case Type.CHAR -> { owner = "java/lang/Character"; desc = "(C)Ljava/lang/Character;"; }
            case Type.SHORT -> { owner = "java/lang/Short"; desc = "(S)Ljava/lang/Short;"; }
            case Type.INT -> { owner = "java/lang/Integer"; desc = "(I)Ljava/lang/Integer;"; }
            case Type.FLOAT -> { owner = "java/lang/Float"; desc = "(F)Ljava/lang/Float;"; }
            case Type.LONG -> { owner = "java/lang/Long"; desc = "(J)Ljava/lang/Long;"; }
            case Type.DOUBLE -> { owner = "java/lang/Double"; desc = "(D)Ljava/lang/Double;"; }
            default -> { return; }
        }
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, owner, "valueOf", desc, false));
    }

    private static void emitUnbox(InsnList il, Type t) {
        if (t.getSort() == Type.OBJECT || t.getSort() == Type.ARRAY) {
            il.add(new TypeInsnNode(Opcodes.CHECKCAST, t.getInternalName())); return;
        }
        String owner, name, desc;
        switch (t.getSort()) {
            case Type.BOOLEAN -> { owner="java/lang/Boolean"; name="booleanValue"; desc="()Z"; }
            case Type.BYTE -> { owner="java/lang/Byte"; name="byteValue"; desc="()B"; }
            case Type.CHAR -> { owner="java/lang/Character"; name="charValue"; desc="()C"; }
            case Type.SHORT -> { owner="java/lang/Short"; name="shortValue"; desc="()S"; }
            case Type.INT -> { owner="java/lang/Integer"; name="intValue"; desc="()I"; }
            case Type.FLOAT -> { owner="java/lang/Float"; name="floatValue"; desc="()F"; }
            case Type.LONG -> { owner="java/lang/Long"; name="longValue"; desc="()J"; }
            default -> { owner="java/lang/Double"; name="doubleValue"; desc="()D"; }
        }
        il.add(new TypeInsnNode(Opcodes.CHECKCAST, owner));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, owner, name, desc, false));
    }

    private static void pushInt(InsnList il, int v) {
        if (v >= -1 && v <= 5) il.add(new InsnNode(Opcodes.ICONST_0 + v));
        else if (v <= Byte.MAX_VALUE) il.add(new IntInsnNode(Opcodes.BIPUSH, v));
        else if (v <= Short.MAX_VALUE) il.add(new IntInsnNode(Opcodes.SIPUSH, v));
        else il.add(new LdcInsnNode(v));
    }
    private static Slot resolveSlot(String owner, String name, String desc,
                                    Map<String, Slot> slots, Map<String, ClassNode> classes) {
        String current = owner;
        while (current != null) {
            Slot slot = slots.get(key(current, name, desc));
            if (slot != null) return slot;
            ClassNode cn = classes.get(current);
            current = cn == null ? null : cn.superName;
        }
        return null;
    }
    private static String key(String owner, String name, String desc) { return owner+'\u0001'+name+'\u0001'+desc; }
    private record Slot(String owner, String state, int index, Type type) { }
    private record Packed(ClassNode owner, String state, List<FieldNode> fields) { }
}
