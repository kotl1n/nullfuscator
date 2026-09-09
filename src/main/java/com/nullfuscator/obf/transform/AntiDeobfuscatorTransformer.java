package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InnerClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

public final class AntiDeobfuscatorTransformer implements Transformer {

    public static final int MAX_LEVEL = 3;

    private static final String[] BAD_CLASS_SIGS = {
            "<T:L;:Ljava/lang/Object;>Ljava/lang/Object;",
            "<T:Ljava/lang/Object<*>;>Ljava/lang/Object;",
            "<T::::Ljava/lang/Object;>Ljava/lang/Object;",
            "L<>;",
            "<T::Ljava/lang/Comparable<TT;>;:Ljava/lang/Cloneable;>Ljava/lang/Object;",
            "<X:TT;T:TX;>Ljava/lang/Object;",
    };

    private static final String[] BAD_FIELD_SIGS = {
            "Ljava/util/List<;",
            "Ljava/util/Map<TK;TV;",
            "L<>;",
            "TV;;;",
            "[LK",
            "Ljava/util/List<**>;",
            "L;",
            "Ljava/lang/Object<*>;",
            "Ljava/lang/Object<+*>;",
    };

    private static final String[] BAD_METHOD_SIGS = {
            "<T::::>()V",
            "()L;",
            "<>()V",
            "(TX;)TY",
            "()Ljava/util/List<;",
            "(L;)V",
            "(L<>;)V",
            "<A:Ljava/lang/Object;>(!)V",
            "(Ljava/util/Map<**>;)V",
            "<T:Ljava/lang/Object<*>;>Ljava/lang/Object;",
            "<T::Ljava/lang/Comparable<TT;>;:Ljava/lang/Cloneable;>(TT;)TT;",
            "<X:TT;T:TX;>()V",
            "(Ljava/util/List<Ljava/util/List<Ljava/util/List<Ljava/util/List<*>;>;>;>;)V"
    };

    private static final String[] GHOST_ANNOTATIONS = {
            "Lez/poison/$Ghost;",
            "Ljava/lang/$NoSuchAnno;",
            "Lsun/misc/$Removed;",
            "Lez/poison/Ǝ;",
            "Ljava/lang/annotation/$Invalid;",
    };

    private static final String[] STEMS = {
            "compute", "resolve", "handle", "state", "ctx", "cache",
            "buffer", "lookup", "codec", "mapper", "index", "session",
            "validate", "sync", "dispatch", "transform", "process", "encode"
    };

    @Override public String id() { return "antiDeobf"; }

    @Override public String description() { return "multi-layered anti-deobfuscator & AST shatter poison"; }

    @Override
    public void transform(ObfContext ctx) {
        ctx.initializePolicies();
        int level = clamp(ctx.config().section(id()).getInt("level", 2), 1, MAX_LEVEL);
        boolean poisonSignatures = ctx.config().section(id()).getBoolean("badSignatures", true);

        boolean poisonRealClassSignatures = ctx.config().section(id())
                .getBoolean("badRealClassSignatures", false);
        boolean poisonAnnos = ctx.config().section(id()).getBoolean("poisonAnnotations", true);
        boolean poisonInner = ctx.config().section(id()).getBoolean("poisonInnerClasses", level >= 2);
        boolean trapReal = ctx.config().section(id()).getBoolean("trapRealMethods", level >= 2);
        boolean honeypots = ctx.config().section(id()).getBoolean("honeypotEvaluators", level >= 2);

        Random rnd = ctx.random();
        int classes = 0, sigMethods = 0, sigFields = 0, annos = 0, innerPoison = 0, realTrapped = 0, honeypotCount = 0;

        for (ClassNode cn : ctx.targets(id())) {
            if (ctx.isHotClass(cn)) continue;

            if ((cn.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION | Opcodes.ACC_MODULE)) != 0) {
                continue;
            }
            if (ctx.isDispersionCarrier(cn)) continue;

            if (com.nullfuscator.obf.core.Limits.hugeClass(cn)) continue;
            if (reflectionSensitive(cn)) continue;
            if (cn.methods == null) cn.methods = new ArrayList<>();
            if (cn.fields == null) cn.fields = new ArrayList<>();

            if (poisonSignatures && poisonRealClassSignatures && cn.signature == null) {
                cn.signature = pick(BAD_CLASS_SIGS, rnd);
            }
            if (poisonAnnos && level >= 2) {
                if (cn.invisibleAnnotations == null) cn.invisibleAnnotations = new ArrayList<>();
                cn.invisibleAnnotations.add(ghostAnnotation(rnd, level));
                annos++;
            }

            Set<String> methodKeys = new HashSet<>();
            for (MethodNode m : cn.methods) methodKeys.add(m.name + m.desc);
            Set<String> fieldKeys = new HashSet<>();
            for (FieldNode f : cn.fields) fieldKeys.add(f.name + " " + f.desc);

            List<FieldNode> addedDecoyFields = new ArrayList<>();
            List<MethodNode> addedDecoyMethods = new ArrayList<>();

            int methodCount = 1 + level;
            for (int i = 0; i < methodCount; i++) {
                MethodNode mn = decoyMethod(ctx, rnd, methodKeys);
                if (mn == null) continue;
                if (poisonSignatures) {
                    mn.signature = pick(BAD_METHOD_SIGS, rnd);
                }
                if (poisonAnnos && level >= 2) {
                    annos += poisonAnnotations(mn, rnd, level);
                }
                cn.methods.add(mn);
                addedDecoyMethods.add(mn);
                sigMethods++;
            }

            int fieldCount = level;
            for (int i = 0; i < fieldCount; i++) {
                FieldNode fn = decoyField(ctx, rnd, fieldKeys);
                if (fn == null) continue;
                if (poisonSignatures) {
                    fn.signature = pick(BAD_FIELD_SIGS, rnd);
                }
                if (poisonAnnos && level >= 2) {
                    annos += poisonFieldAnnotations(fn, rnd, level);
                }
                cn.fields.add(fn);
                addedDecoyFields.add(fn);
                sigFields++;
            }

            if (honeypots && level >= 2) {
                MethodNode hp = honeypotMethod(ctx, rnd, methodKeys);
                if (hp != null) {
                    if (poisonSignatures) hp.signature = pick(BAD_METHOD_SIGS, rnd);
                    if (poisonAnnos) annos += poisonAnnotations(hp, rnd, level);
                    cn.methods.add(hp);
                    addedDecoyMethods.add(hp);
                    honeypotCount++;
                }
            }

            if (poisonInner) {
                innerPoison += poisonInnerClasses(cn, ctx, rnd);
            }

            if (trapReal && !addedDecoyFields.isEmpty()) {
                FieldNode primaryField = addedDecoyFields.get(0);
                MethodNode primaryMethod = addedDecoyMethods.isEmpty() ? null : addedDecoyMethods.get(0);
                FieldNode trapException = null;

                for (MethodNode mn : new ArrayList<>(cn.methods)) {

                    if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) continue;
                    if (mn.name.equals("<clinit>")) continue;

                    if (mn.name.equals("<init>")) continue;
                    if (!ctx.isInputMethod(mn) || ctx.isHotPath(cn, mn)) continue;
                    if (mn.instructions == null || mn.instructions.size() == 0) continue;

                    if (trapException == null) trapException = cachedTrapException(cn, ctx, rnd, fieldKeys);
                    injectDeadCfgTrap(cn, mn, primaryField, primaryMethod, trapException, level, rnd);
                    realTrapped++;
                }
            }

            classes++;
        }

        ctx.log().debug("antiDeobf: classes=" + classes
                + " sigMethods=" + sigMethods
                + " sigFields=" + sigFields
                + " poisonAnnos=" + annos
                + " innerPoison=" + innerPoison
                + " honeypots=" + honeypotCount
                + " realTrapped=" + realTrapped
                + " (level=" + level + ")");
    }

    private MethodNode decoyMethod(ObfContext ctx, Random rnd, Set<String> keys) {
        String name = uniqueName(ctx, rnd, keys, "()V");
        if (name == null) return null;
        MethodNode mn = new MethodNode(Opcodes.ASM9,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                name, "()V", null, null);
        InsnList il = new InsnList();
        il.add(new InsnNode(Opcodes.RETURN));
        mn.instructions = il;
        mn.maxStack = 0;
        mn.maxLocals = 0;
        keys.add(name + "()V");
        return mn;
    }

    private FieldNode decoyField(ObfContext ctx, Random rnd, Set<String> keys) {
        String desc = rnd.nextBoolean() ? "Ljava/lang/Object;" : "I";
        String name = uniqueName(ctx, rnd, keys, " " + desc);
        if (name == null) return null;
        FieldNode fn = new FieldNode(Opcodes.ASM9,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC | Opcodes.ACC_TRANSIENT,
                name, desc, null, null);
        keys.add(name + " " + desc);
        return fn;
    }

    private MethodNode honeypotMethod(ObfContext ctx, Random rnd, Set<String> keys) {
        String name = uniqueName(ctx, rnd, keys, "(Ljava/lang/String;I)Ljava/lang/String;");
        if (name == null) return null;
        MethodNode mn = new MethodNode(Opcodes.ASM9,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                name, "(Ljava/lang/String;I)Ljava/lang/String;", null, null);

        InsnList il = new InsnList();
        LabelNode l0 = new LabelNode();
        LabelNode l1 = new LabelNode();
        il.add(l0);
        il.add(new InsnNode(Opcodes.ICONST_1));
        il.add(new JumpInsnNode(Opcodes.IFEQ, l1));
        il.add(new InsnNode(Opcodes.ACONST_NULL));
        il.add(new InsnNode(Opcodes.ARETURN));
        il.add(l1);
        il.add(new InsnNode(Opcodes.ACONST_NULL));
        il.add(new InsnNode(Opcodes.ARETURN));

        mn.instructions = il;
        mn.maxStack = 1;
        mn.maxLocals = 2;
        keys.add(name + "(Ljava/lang/String;I)Ljava/lang/String;");
        return mn;
    }

    private int poisonInnerClasses(ClassNode cn, ObfContext ctx, Random rnd) {
        if (cn.innerClasses == null) cn.innerClasses = new ArrayList<>();

        String ghostInner1 = cn.name + "$" + ctx.names().next();
        String ghostInner2 = cn.name + "$" + ctx.names().next();
        cn.innerClasses.add(new InnerClassNode(ghostInner1, cn.name, "Decoy",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC));
        cn.innerClasses.add(new InnerClassNode(ghostInner2, cn.name, "Resolver",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC));

        cn.innerClasses.add(new InnerClassNode("ez/poison/$GhostInner", "ez/poison/$GhostOuter", "$Ghost",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC));

        return 3;
    }

    private FieldNode cachedTrapException(ClassNode cn, ObfContext ctx, Random rnd, Set<String> keys) {
        // This control token never escapes its local handler and carries no per-call data.
        // Reusing it avoids allocation and native stack capture on the live trap path.
        String type = switch (rnd.nextInt(4)) {
            case 0 -> "java/lang/IllegalStateException";
            case 1 -> "java/lang/IllegalArgumentException";
            case 2 -> "java/lang/ArithmeticException";
            default -> "java/lang/RuntimeException";
        };
        String desc = "L" + type + ";";
        String name;
        do { name = ctx.names().next(); } while (!keys.add(name + " " + desc));
        FieldNode field = new FieldNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC
                | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC, name, desc, null, null);
        cn.fields.add(field);
        MethodNode clinit = cn.methods.stream().filter(m -> m.name.equals("<clinit>"))
                .findFirst().orElse(null);
        if (clinit == null) {
            clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
            clinit.instructions.add(new InsnNode(Opcodes.RETURN));
            cn.methods.add(clinit);
        }
        InsnList init = new InsnList();
        init.add(new org.objectweb.asm.tree.TypeInsnNode(Opcodes.NEW, type));
        init.add(new InsnNode(Opcodes.DUP));
        init.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, type, "<init>", "()V", false));
        init.add(new FieldInsnNode(Opcodes.PUTSTATIC, cn.name, name, desc));
        clinit.instructions.insert(init);
        clinit.maxStack = Math.max(clinit.maxStack, 2);
        return field;
    }

    private void injectDeadCfgTrap(ClassNode cn, MethodNode mn, FieldNode decoyField,
                                   MethodNode decoyMethod, FieldNode trapException, int level, Random rnd) {
        if (mn.tryCatchBlocks == null) mn.tryCatchBlocks = new ArrayList<>();

        LabelNode lRealStart = new LabelNode();
        LabelNode lDeadStart = new LabelNode();
        LabelNode lDeadMid1 = new LabelNode();
        LabelNode lDeadMid2 = new LabelNode();
        LabelNode lDeadEnd = new LabelNode();
        LabelNode lHandler1 = new LabelNode();
        LabelNode lHandler2 = new LabelNode();

        InsnList trap = new InsnList();

        int rotation = 1 + rnd.nextInt(31);
        int selectedBit = 1 << rnd.nextInt(31);
        trap.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System",
                "currentTimeMillis", "()J", false));
        trap.add(new InsnNode(Opcodes.L2I));
        trap.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Thread",
                "currentThread", "()Ljava/lang/Thread;", false));
        trap.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System",
                "identityHashCode", "(Ljava/lang/Object;)I", false));
        trap.add(new InsnNode(Opcodes.IXOR));
        trap.add(new org.objectweb.asm.tree.LdcInsnNode(rotation));
        trap.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer",
                "rotateLeft", "(II)I", false));
        trap.add(new org.objectweb.asm.tree.LdcInsnNode(selectedBit));
        trap.add(new InsnNode(Opcodes.IAND));
        trap.add(new JumpInsnNode(Opcodes.IFNE, lDeadStart));
        trap.add(new JumpInsnNode(Opcodes.GOTO, lRealStart));

        trap.add(lDeadStart);

        if (decoyField != null) {
            trap.add(new FieldInsnNode(Opcodes.GETSTATIC, cn.name, decoyField.name, decoyField.desc));
            trap.add(new InsnNode(Opcodes.POP));
        }
        if (decoyMethod != null) {
            trap.add(new MethodInsnNode(Opcodes.INVOKESTATIC, cn.name, decoyMethod.name, decoyMethod.desc, false));
        }

        trap.add(new InsnNode(Opcodes.NOP));
        trap.add(lDeadMid1);

        if (level >= 3) {
            LabelNode lCase0 = new LabelNode();
            LabelNode lCase1 = new LabelNode();
            LabelNode lCaseDef = new LabelNode();
            trap.add(new InsnNode(Opcodes.ICONST_0));
            trap.add(new TableSwitchInsnNode(0, 1, lCaseDef, lCase0, lCase1));
            trap.add(lCase0);
            trap.add(new JumpInsnNode(Opcodes.GOTO, lDeadMid2));
            trap.add(lCase1);
            trap.add(new JumpInsnNode(Opcodes.GOTO, lDeadMid2));
            trap.add(lCaseDef);
        }

        trap.add(new InsnNode(Opcodes.NOP));
        trap.add(lDeadMid2);

        trap.add(new FieldInsnNode(Opcodes.GETSTATIC, cn.name, trapException.name, trapException.desc));
        trap.add(new InsnNode(Opcodes.ATHROW));
        trap.add(lDeadEnd);

        trap.add(lHandler1);
        trap.add(new InsnNode(Opcodes.POP));
        trap.add(new JumpInsnNode(Opcodes.GOTO, lRealStart));

        trap.add(lHandler2);
        trap.add(new InsnNode(Opcodes.POP));
        trap.add(new JumpInsnNode(Opcodes.GOTO, lRealStart));

        trap.add(lRealStart);

        mn.instructions.insertBefore(mn.instructions.getFirst(), trap);

        mn.tryCatchBlocks.add(new TryCatchBlockNode(lDeadStart, lDeadMid2, lHandler1, "java/lang/Throwable"));
        mn.tryCatchBlocks.add(new TryCatchBlockNode(lDeadMid1, lDeadEnd, lHandler2, "java/lang/Exception"));
    }

    private int poisonAnnotations(MethodNode mn, Random rnd, int level) {
        if (mn.invisibleAnnotations == null) mn.invisibleAnnotations = new ArrayList<>();
        AnnotationNode a = ghostAnnotation(rnd, level);
        mn.invisibleAnnotations.add(a);
        int n = 1;
        if (level >= 3) {
            if (mn.visibleAnnotations == null) mn.visibleAnnotations = new ArrayList<>();
            mn.visibleAnnotations.add(ghostAnnotation(rnd, level));
            n++;
        }
        return n;
    }

    private int poisonFieldAnnotations(FieldNode fn, Random rnd, int level) {
        if (fn.invisibleAnnotations == null) fn.invisibleAnnotations = new ArrayList<>();
        fn.invisibleAnnotations.add(ghostAnnotation(rnd, level));
        return 1;
    }

    private AnnotationNode ghostAnnotation(Random rnd, int level) {
        AnnotationNode a = new AnnotationNode(Opcodes.ASM9, pick(GHOST_ANNOTATIONS, rnd));
        a.values = new ArrayList<>();
        a.values.add("value");
        a.values.add(nestedArray(1 + level));
        return a;
    }

    private static Object nestedArray(int depth) {
        List<Object> cur = new ArrayList<>(Arrays.asList(0, 1, 2));
        for (int i = 0; i < depth; i++) {
            List<Object> outer = new ArrayList<>();
            outer.add(cur);
            cur = outer;
        }
        return cur;
    }

    private String uniqueName(ObfContext ctx, Random rnd, Set<String> keys, String tail) {
        for (int attempt = 0; attempt < 32; attempt++) {
            String base = pick(STEMS, rnd) + ctx.names().next();
            if (!keys.contains(base + tail)) return base;
        }
        return null;
    }

    private static String pick(String[] pool, Random rnd) {
        return pool[rnd.nextInt(pool.length)];
    }

    private static int clamp(int v, int lo, int hi) {
        return v < lo ? lo : (v > hi ? hi : v);
    }

    private static boolean reflectionSensitive(ClassNode cn) {
        if (cn.visibleAnnotations != null && !cn.visibleAnnotations.isEmpty()) return true;
        for (FieldNode field : cn.fields)
            if (field.visibleAnnotations != null && !field.visibleAnnotations.isEmpty()) return true;
        for (MethodNode method : cn.methods)
            if (method.visibleAnnotations != null && !method.visibleAnnotations.isEmpty()) return true;
        return false;
    }
}
