package com.nullfuscator.obf.util;

import com.nullfuscator.obf.core.ObfContext;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.util.*;

public final class BytecodeNoise {

    private BytecodeNoise() {
    }

    public static String randomPackage(ObfContext ctx, String defaultCategory) {
        List<String> pkgs = new ArrayList<>();
        Set<String> mixinPkgs = ctx.mixinPackages();
        for (ClassNode cn : ctx.classes()) {
            if (cn.name == null || cn.name.startsWith("META-INF/") || ObfContext.isMixin(cn) || ctx.isMixinPackage(cn.name)) {
                continue;
            }
            int lastSlash = cn.name.lastIndexOf('/');
            if (lastSlash > 0) {
                String p = cn.name.substring(0, lastSlash + 1);
                boolean isMixin = false;
                for (String mp : mixinPkgs) {
                    if (p.startsWith(mp) || mp.startsWith(p)) {
                        isMixin = true;
                        break;
                    }
                }
                if (!isMixin && !pkgs.contains(p)) {
                    pkgs.add(p);
                }
            }
        }
        if (pkgs.isEmpty()) {
            return "a/" + defaultCategory + "/";
        }
        Random rnd = ctx.random();
        String base = pkgs.get(rnd.nextInt(pkgs.size()));
        for (String mp : mixinPkgs) {
            if (base.startsWith(mp) || mp.startsWith(base)) {
                return "a/" + defaultCategory + "/";
            }
        }
        if (rnd.nextBoolean()) {
            return base;
        }
        return base + defaultCategory + "/";
    }

    public static void decorateCarrier(ClassNode cn, ObfContext ctx) {
        Random rnd = ctx.random();
        if (rnd.nextInt(100) < 35) {
            if (cn.interfaces == null) {
                cn.interfaces = new ArrayList<>();
            }
            String[] ifaces = { "java/io/Serializable", "java/lang/Cloneable" };
            String chosen = ifaces[rnd.nextInt(ifaces.length)];
            if (!cn.interfaces.contains(chosen)) {
                cn.interfaces.add(chosen);
            }
        }

        if (rnd.nextInt(100) < 60) {
            addConstructor(cn, rnd);
        }

        int extraFields = 1 + rnd.nextInt(3);
        for (int i = 0; i < extraFields; i++) {
            String name = ctx.names().next();
            FieldNode fn = generateDecoyField(name, rnd);
            cn.fields.add(fn);
        }

        int extraMethods = 1 + rnd.nextInt(3);
        for (int i = 0; i < extraMethods; i++) {
            String name = ctx.names().next();
            MethodNode mn = generateDecoyMethod(cn.name, name, rnd);
            cn.methods.add(mn);
        }
    }

    public static void addConstructor(ClassNode cn, Random rnd) {
        if (cn.methods != null) {
            for (MethodNode mn : cn.methods) {
                if ("<init>".equals(mn.name) && "()V".equals(mn.desc)) {
                    return;
                }
            }
        }
        String superName = cn.superName != null ? cn.superName : "java/lang/Object";
        MethodNode init = new MethodNode(Opcodes.ASM9,
                Opcodes.ACC_PRIVATE,
                "<init>", "()V", null, null);
        InsnList il = init.instructions;
        il.add(new VarInsnNode(Opcodes.ALOAD, 0));
        il.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, superName, "<init>", "()V", false));
        il.add(new InsnNode(Opcodes.RETURN));
        init.maxStack = 1;
        init.maxLocals = 1;
        cn.methods.add(init);
    }

    public static FieldNode generateDecoyField(String name, Random rnd) {
        int flavor = rnd.nextInt(6);
        String desc = switch (flavor) {
            case 0 -> "I";
            case 1 -> "J";
            case 2 -> "Z";
            case 3 -> "Ljava/lang/String;";
            case 4 -> "[B";
            default -> "Ljava/lang/Object;";
        };
        int access = switch (rnd.nextInt(4)) {
            case 0 -> Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
            case 1 -> Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC | Opcodes.ACC_VOLATILE;
            case 2 -> Opcodes.ACC_PROTECTED | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
            default -> Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC | Opcodes.ACC_TRANSIENT;
        };
        Object value = switch (flavor) {
            case 0 -> rnd.nextInt();
            case 1 -> rnd.nextLong();
            case 2 -> rnd.nextBoolean() ? 1 : 0;
            case 3 -> "v" + rnd.nextInt(0xffff);
            default -> null;
        };
        return new FieldNode(Opcodes.ASM9, access, name, desc, null, value);
    }

    public static MethodNode generateDecoyMethod(String owner, String name, Random rnd) {
        int flavor = rnd.nextInt(7);
        return switch (flavor) {
            case 0 -> buildIntMathMethod(name, rnd);
            case 1 -> buildPredicateMethod(name, rnd);
            case 2 -> buildStringHashMethod(name, rnd);
            case 3 -> buildLongMathMethod(name, rnd);
            case 4 -> buildClampMethod(name, rnd);
            case 5 -> buildChecksumMethod(name, rnd);
            default -> buildObjectSelectorMethod(name, rnd);
        };
    }

    private static MethodNode buildIntMathMethod(String name, Random rnd) {
        MethodNode mn = new MethodNode(Opcodes.ASM9,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                name, "(II)I", null, null);
        InsnList il = mn.instructions;
        int k1 = rnd.nextInt(0xffff);
        int k2 = rnd.nextInt(0xffff);
        il.add(new VarInsnNode(Opcodes.ILOAD, 0));
        il.add(new LdcInsnNode(k1));
        il.add(new InsnNode(Opcodes.IXOR));
        il.add(new VarInsnNode(Opcodes.ILOAD, 1));
        il.add(new LdcInsnNode(k2));
        il.add(new InsnNode(Opcodes.IADD));
        il.add(new InsnNode(Opcodes.IXOR));
        il.add(new InsnNode(Opcodes.IRETURN));
        mn.maxStack = 3;
        mn.maxLocals = 2;
        return mn;
    }

    private static MethodNode buildPredicateMethod(String name, Random rnd) {
        MethodNode mn = new MethodNode(Opcodes.ASM9,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                name, "(I)Z", null, null);
        InsnList il = mn.instructions;
        int mask = (1 << (1 + rnd.nextInt(15))) - 1;
        LabelNode lTrue = new LabelNode();
        il.add(new VarInsnNode(Opcodes.ILOAD, 0));
        il.add(new LdcInsnNode(mask));
        il.add(new InsnNode(Opcodes.IAND));
        il.add(new JumpInsnNode(Opcodes.IFNE, lTrue));
        il.add(new InsnNode(Opcodes.ICONST_0));
        il.add(new InsnNode(Opcodes.IRETURN));
        il.add(lTrue);
        il.add(new InsnNode(Opcodes.ICONST_1));
        il.add(new InsnNode(Opcodes.IRETURN));
        mn.maxStack = 2;
        mn.maxLocals = 1;
        return mn;
    }

    private static MethodNode buildStringHashMethod(String name, Random rnd) {
        MethodNode mn = new MethodNode(Opcodes.ASM9,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                name, "(Ljava/lang/String;)I", null, null);
        InsnList il = mn.instructions;
        int seed = rnd.nextInt();
        LabelNode lNull = new LabelNode();
        il.add(new VarInsnNode(Opcodes.ALOAD, 0));
        il.add(new JumpInsnNode(Opcodes.IFNULL, lNull));
        il.add(new VarInsnNode(Opcodes.ALOAD, 0));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "hashCode", "()I", false));
        il.add(new LdcInsnNode(seed));
        il.add(new InsnNode(Opcodes.IXOR));
        il.add(new InsnNode(Opcodes.IRETURN));
        il.add(lNull);
        il.add(new LdcInsnNode(seed));
        il.add(new InsnNode(Opcodes.IRETURN));
        mn.maxStack = 2;
        mn.maxLocals = 1;
        return mn;
    }

    private static MethodNode buildLongMathMethod(String name, Random rnd) {
        MethodNode mn = new MethodNode(Opcodes.ASM9,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                name, "(J)J", null, null);
        InsnList il = mn.instructions;
        long k = rnd.nextLong() | 1L;
        il.add(new VarInsnNode(Opcodes.LLOAD, 0));
        il.add(new VarInsnNode(Opcodes.LLOAD, 0));
        il.add(new IntInsnNode(Opcodes.BIPUSH, 16));
        il.add(new InsnNode(Opcodes.LUSHR));
        il.add(new InsnNode(Opcodes.LXOR));
        il.add(new LdcInsnNode(k));
        il.add(new InsnNode(Opcodes.LMUL));
        il.add(new InsnNode(Opcodes.LRETURN));
        mn.maxStack = 6;
        mn.maxLocals = 2;
        return mn;
    }

    private static MethodNode buildClampMethod(String name, Random rnd) {
        MethodNode mn = new MethodNode(Opcodes.ASM9,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                name, "(III)I", null, null);
        InsnList il = mn.instructions;
        LabelNode lMax = new LabelNode();
        il.add(new VarInsnNode(Opcodes.ILOAD, 0));
        il.add(new VarInsnNode(Opcodes.ILOAD, 1));
        il.add(new JumpInsnNode(Opcodes.IF_ICMPGE, lMax));
        il.add(new VarInsnNode(Opcodes.ILOAD, 1));
        il.add(new InsnNode(Opcodes.IRETURN));
        il.add(lMax);
        LabelNode lMin = new LabelNode();
        il.add(new VarInsnNode(Opcodes.ILOAD, 0));
        il.add(new VarInsnNode(Opcodes.ILOAD, 2));
        il.add(new JumpInsnNode(Opcodes.IF_ICMPLE, lMin));
        il.add(new VarInsnNode(Opcodes.ILOAD, 2));
        il.add(new InsnNode(Opcodes.IRETURN));
        il.add(lMin);
        il.add(new VarInsnNode(Opcodes.ILOAD, 0));
        il.add(new InsnNode(Opcodes.IRETURN));
        mn.maxStack = 2;
        mn.maxLocals = 3;
        return mn;
    }

    private static MethodNode buildChecksumMethod(String name, Random rnd) {
        MethodNode mn = new MethodNode(Opcodes.ASM9,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                name, "([B)I", null, null);
        InsnList il = mn.instructions;
        LabelNode lNull = new LabelNode();
        il.add(new VarInsnNode(Opcodes.ALOAD, 0));
        il.add(new JumpInsnNode(Opcodes.IFNULL, lNull));
        il.add(new VarInsnNode(Opcodes.ALOAD, 0));
        il.add(new InsnNode(Opcodes.ARRAYLENGTH));
        il.add(new LdcInsnNode(rnd.nextInt(0xffff) + 1));
        il.add(new InsnNode(Opcodes.IMUL));
        il.add(new InsnNode(Opcodes.IRETURN));
        il.add(lNull);
        il.add(new InsnNode(Opcodes.ICONST_0));
        il.add(new InsnNode(Opcodes.IRETURN));
        mn.maxStack = 2;
        mn.maxLocals = 1;
        return mn;
    }

    private static MethodNode buildObjectSelectorMethod(String name, Random rnd) {
        MethodNode mn = new MethodNode(Opcodes.ASM9,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                name, "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", null, null);
        InsnList il = mn.instructions;
        LabelNode lFirstNull = new LabelNode();
        il.add(new VarInsnNode(Opcodes.ALOAD, 0));
        il.add(new JumpInsnNode(Opcodes.IFNULL, lFirstNull));
        il.add(new VarInsnNode(Opcodes.ALOAD, 0));
        il.add(new InsnNode(Opcodes.ARETURN));
        il.add(lFirstNull);
        il.add(new VarInsnNode(Opcodes.ALOAD, 1));
        il.add(new InsnNode(Opcodes.ARETURN));
        mn.maxStack = 1;
        mn.maxLocals = 2;
        return mn;
    }
}
