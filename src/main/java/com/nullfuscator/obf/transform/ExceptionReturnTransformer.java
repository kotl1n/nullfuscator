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
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public final class ExceptionReturnTransformer implements Transformer {

    @Override public String id() { return "exceptionReturn"; }
    @Override public String description() { return "route typed returns through a caught control exception"; }

    @Override
    public void transform(ObfContext ctx) {
        int percent = clamp(ctx.config().section(id()).getInt("percent", 100), 0, 100);
        if (percent == 0) return;
        List<ClassNode> targets = ctx.targets(id());
        int version = Opcodes.V1_7;
        for (ClassNode cn : targets) version = Math.max(version, cn.version & 0xFFFF);

        Random rnd = ctx.random();
        String tokenName = "ez/rt/" + ctx.names().nextRandomClass("", rnd, 10);
        ClassNode token = buildToken(tokenName, version);
        int methods = 0, sites = 0;

        for (ClassNode cn : targets) {
            if ((cn.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION | Opcodes.ACC_MODULE)) != 0) continue;
            for (MethodNode mn : cn.methods) {
                if (ctx.isHotPath(cn, mn)) continue;
                int count = eligibleReturnCount(mn);
                if (count == 0 || rnd.nextInt(100) >= percent) continue;
                transformMethod(mn, tokenName);
                methods++;
                sites += count;
            }
        }

        if (methods > 0) ctx.putClass(token);
        ctx.log().debug("exceptionReturn: routed " + sites + " sites across " + methods + " methods");
    }

    private static int eligibleReturnCount(MethodNode mn) {
        if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) return 0;
        if (mn.name.equals("<init>") || mn.name.equals("<clinit>")) return 0;
        if (mn.instructions == null || mn.instructions.size() == 0) return 0;
        if (mn.tryCatchBlocks != null && !mn.tryCatchBlocks.isEmpty()) return 0;
        if (Limits.oversizeMethod(mn)) return 0;
        int expected = Type.getReturnType(mn.desc).getOpcode(Opcodes.IRETURN);
        int count = 0;
        for (AbstractInsnNode in : mn.instructions.toArray()) if (in.getOpcode() == expected) count++;
        return count;
    }

    private static void transformMethod(MethodNode mn, String tokenName) {
        Type ret = Type.getReturnType(mn.desc);
        int returnOpcode = ret.getOpcode(Opcodes.IRETURN);
        int valueLocal = mn.maxLocals;
        if (ret.getSort() != Type.VOID) mn.maxLocals += ret.getSize();

        LabelNode start = new LabelNode();
        LabelNode end = new LabelNode();
        LabelNode handler = new LabelNode();
        mn.instructions.insertBefore(mn.instructions.getFirst(), start);

        for (AbstractInsnNode in : mn.instructions.toArray()) {
            if (in.getOpcode() != returnOpcode) continue;
            InsnList replacement = new InsnList();
            if (ret.getSort() != Type.VOID)
                replacement.add(new VarInsnNode(ret.getOpcode(Opcodes.ISTORE), valueLocal));
            replacement.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                    tokenName, "take", "()L" + tokenName + ";", false));
            if (ret.getSort() != Type.VOID) {
                replacement.add(new InsnNode(Opcodes.DUP));
                emitConstructorValue(replacement, ret, valueLocal);
                replacement.add(new FieldInsnNode(Opcodes.PUTFIELD, tokenName,
                        valueField(ret), valueFieldDescriptor(ret)));
            }
            replacement.add(new InsnNode(Opcodes.ATHROW));
            mn.instructions.insertBefore(in, replacement);
            mn.instructions.remove(in);
        }

        mn.instructions.add(end);
        mn.instructions.add(handler);
        emitHandlerReturn(mn.instructions, ret, tokenName, valueLocal);
        if (mn.tryCatchBlocks == null) mn.tryCatchBlocks = new ArrayList<>();
        mn.tryCatchBlocks.add(0, new TryCatchBlockNode(start, end, handler, tokenName));
    }

    private static String constructorDescriptor(Type ret) {
        return switch (ret.getSort()) {
            case Type.VOID -> "()V";
            case Type.LONG, Type.DOUBLE -> "(J)V";
            case Type.OBJECT, Type.ARRAY -> "(Ljava/lang/Object;)V";
            default -> "(I)V";
        };
    }

    private static String valueField(Type ret) {
        return switch (ret.getSort()) {
            case Type.LONG, Type.DOUBLE -> "v";
            case Type.OBJECT, Type.ARRAY -> "o";
            default -> "i";
        };
    }

    private static String valueFieldDescriptor(Type ret) {
        return switch (ret.getSort()) {
            case Type.LONG, Type.DOUBLE -> "J";
            case Type.OBJECT, Type.ARRAY -> "Ljava/lang/Object;";
            default -> "I";
        };
    }

    private static void emitConstructorValue(InsnList il, Type ret, int local) {
        switch (ret.getSort()) {
            case Type.VOID -> { }
            case Type.FLOAT -> {
                il.add(new VarInsnNode(Opcodes.FLOAD, local));
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Float",
                        "floatToRawIntBits", "(F)I", false));
            }
            case Type.DOUBLE -> {
                il.add(new VarInsnNode(Opcodes.DLOAD, local));
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Double",
                        "doubleToRawLongBits", "(D)J", false));
            }
            default -> il.add(new VarInsnNode(ret.getOpcode(Opcodes.ILOAD), local));
        }
    }

    private static void emitHandlerReturn(InsnList il, Type ret, String tokenName,
                                          int valueLocal) {
        switch (ret.getSort()) {
            case Type.VOID -> {
                il.add(new InsnNode(Opcodes.POP));
                il.add(new InsnNode(Opcodes.RETURN));
            }
            case Type.OBJECT, Type.ARRAY -> {
                il.add(new InsnNode(Opcodes.DUP));
                il.add(new FieldInsnNode(Opcodes.GETFIELD, tokenName, "o", "Ljava/lang/Object;"));
                il.add(new TypeInsnNode(Opcodes.CHECKCAST, ret.getInternalName()));
                il.add(new VarInsnNode(Opcodes.ASTORE, valueLocal));
                il.add(new InsnNode(Opcodes.ACONST_NULL));
                il.add(new FieldInsnNode(Opcodes.PUTFIELD, tokenName, "o", "Ljava/lang/Object;"));
                il.add(new VarInsnNode(Opcodes.ALOAD, valueLocal));
                il.add(new InsnNode(Opcodes.ARETURN));
            }
            case Type.LONG -> {
                il.add(new FieldInsnNode(Opcodes.GETFIELD, tokenName, "v", "J"));
                il.add(new InsnNode(Opcodes.LRETURN));
            }
            case Type.DOUBLE -> {
                il.add(new FieldInsnNode(Opcodes.GETFIELD, tokenName, "v", "J"));
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Double",
                        "longBitsToDouble", "(J)D", false));
                il.add(new InsnNode(Opcodes.DRETURN));
            }
            case Type.FLOAT -> {
                il.add(new FieldInsnNode(Opcodes.GETFIELD, tokenName, "i", "I"));
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Float",
                        "intBitsToFloat", "(I)F", false));
                il.add(new InsnNode(Opcodes.FRETURN));
            }
            default -> {
                il.add(new FieldInsnNode(Opcodes.GETFIELD, tokenName, "i", "I"));
                il.add(new InsnNode(Opcodes.IRETURN));
            }
        }
    }

    private static ClassNode buildToken(String name, int version) {
        ClassNode cn = new ClassNode();
        cn.version = version;
        cn.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC;
        cn.name = name;
        cn.superName = "java/lang/RuntimeException";
        cn.fields = new ArrayList<>();
        cn.methods = new ArrayList<>();
        cn.fields.add(new FieldNode(Opcodes.ACC_PUBLIC, "i", "I", null, null));
        cn.fields.add(new FieldNode(Opcodes.ACC_PUBLIC, "v", "J", null, null));
        cn.fields.add(new FieldNode(Opcodes.ACC_PUBLIC, "o", "Ljava/lang/Object;", null, null));
        cn.fields.add(new FieldNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                "t", "Ljava/lang/ThreadLocal;", null, null));
        cn.methods.add(tokenConstructor(name, "()V", null, null));
        cn.methods.add(tokenConstructor(name, "(I)V", "i", "I"));
        cn.methods.add(tokenConstructor(name, "(J)V", "v", "J"));
        cn.methods.add(tokenConstructor(name, "(Ljava/lang/Object;)V", "o", "Ljava/lang/Object;"));
        cn.methods.add(tokenClassInitializer(name));
        cn.methods.add(tokenTake(name));

        MethodNode fill = new MethodNode(Opcodes.ASM9, Opcodes.ACC_PUBLIC,
                "fillInStackTrace", "()Ljava/lang/Throwable;", null, null);
        fill.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        fill.instructions.add(new InsnNode(Opcodes.ARETURN));
        cn.methods.add(fill);
        return cn;
    }

    private static MethodNode tokenClassInitializer(String owner) {
        MethodNode mn = new MethodNode(Opcodes.ASM9, Opcodes.ACC_STATIC,
                "<clinit>", "()V", null, null);
        mn.instructions.add(new TypeInsnNode(Opcodes.NEW, "java/lang/ThreadLocal"));
        mn.instructions.add(new InsnNode(Opcodes.DUP));
        mn.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/ThreadLocal", "<init>", "()V", false));
        mn.instructions.add(new FieldInsnNode(Opcodes.PUTSTATIC, owner,
                "t", "Ljava/lang/ThreadLocal;"));
        mn.instructions.add(new InsnNode(Opcodes.RETURN));
        return mn;
    }

    private static MethodNode tokenTake(String owner) {
        MethodNode mn = new MethodNode(Opcodes.ASM9,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "take", "()L" + owner + ";", null, null);
        LabelNode create = new LabelNode();
        mn.instructions.add(new FieldInsnNode(Opcodes.GETSTATIC, owner,
                "t", "Ljava/lang/ThreadLocal;"));
        mn.instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/ThreadLocal", "get", "()Ljava/lang/Object;", false));
        mn.instructions.add(new TypeInsnNode(Opcodes.CHECKCAST, owner));
        mn.instructions.add(new InsnNode(Opcodes.DUP));
        mn.instructions.add(new JumpInsnNode(Opcodes.IFNULL, create));
        mn.instructions.add(new InsnNode(Opcodes.ARETURN));
        mn.instructions.add(create);
        mn.instructions.add(new InsnNode(Opcodes.POP));
        mn.instructions.add(new TypeInsnNode(Opcodes.NEW, owner));
        mn.instructions.add(new InsnNode(Opcodes.DUP));
        mn.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                owner, "<init>", "()V", false));
        mn.instructions.add(new InsnNode(Opcodes.DUP));
        mn.instructions.add(new FieldInsnNode(Opcodes.GETSTATIC, owner,
                "t", "Ljava/lang/ThreadLocal;"));
        mn.instructions.add(new InsnNode(Opcodes.SWAP));
        mn.instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/ThreadLocal", "set", "(Ljava/lang/Object;)V", false));
        mn.instructions.add(new InsnNode(Opcodes.ARETURN));
        return mn;
    }

    private static MethodNode tokenConstructor(String owner, String desc, String field, String fieldDesc) {
        MethodNode mn = new MethodNode(Opcodes.ASM9, Opcodes.ACC_PUBLIC,
                "<init>", desc, null, null);
        mn.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        mn.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/RuntimeException", "<init>", "()V", false));
        if (field != null) {
            mn.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
            Type type = Type.getType(fieldDesc);
            mn.instructions.add(new VarInsnNode(type.getOpcode(Opcodes.ILOAD), 1));
            mn.instructions.add(new FieldInsnNode(Opcodes.PUTFIELD, owner, field, fieldDesc));
        }
        mn.instructions.add(new InsnNode(Opcodes.RETURN));
        return mn;
    }

    private static int clamp(int value, int low, int high) {
        return Math.max(low, Math.min(high, value));
    }
}
