package com.nullfuscator.obf;

import com.nullfuscator.obf.core.*;
import com.nullfuscator.obf.transform.*;
import com.nullfuscator.obf.util.*;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;
import java.util.*;

/** Offline regression: actual loaded bytecode, arithmetic edge cases and growth caps. */
public final class GrowthRegression implements Opcodes {
    static final int[] OPS = {IADD, ISUB, IMUL, ISHL, ISHR, IUSHR, IAND, IOR, IXOR,
            LADD, LSUB, LMUL, LAND, LOR, LXOR};

    static ObfContext context(String options) {
        return new ObfContext(ObfConfig.parse("crossClassDispersion { enabled:true, dispersalPercent:100, "
                + options + " }"), 12345, new ObfLog(false), new NameGenerator(new String[]{"a", "b"}));
    }
    static ClassNode corpus() {
        ClassNode c = new ClassNode();
        c.version = V17; c.access = ACC_PUBLIC; c.name = "Fixture"; c.superName = "java/lang/Object";
        for (int op : OPS) {
            boolean wide = op == LADD || op == LSUB || op == LMUL || op == LAND || op == LOR || op == LXOR;
            MethodNode m = new MethodNode(ACC_PUBLIC | ACC_STATIC, "op" + op,
                    wide ? "(JJ)J" : "(II)I", null, null);
            m.instructions.add(new VarInsnNode(wide ? LLOAD : ILOAD, 0));
            for (int i = 0; i < 600; i++) {
                m.instructions.add(new VarInsnNode(wide ? LLOAD : ILOAD, wide ? 2 : 1));
                m.instructions.add(new InsnNode(op));
            }
            m.instructions.add(new InsnNode(wide ? LRETURN : IRETURN));
            c.methods.add(m);
        }
        return c;
    }
    static ClassLoader loader(ObfContext ctx) {
        Map<String, byte[]> bytes = new HashMap<>();
        for (ClassNode c : ctx.classes()) {
            ClassWriter w = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
            c.accept(w); bytes.put(c.name.replace('/', '.'), w.toByteArray());
        }
        return new ClassLoader(GrowthRegression.class.getClassLoader()) {
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                byte[] b = bytes.get(name);
                if (b == null) throw new ClassNotFoundException(name);
                return defineClass(name, b, 0, b.length);
            }
        };
    }
    static void check(boolean ok, String message) { if (!ok) throw new AssertionError(message); }
    static void run(String options, int operationCap, int helperCap) throws Exception {
        ObfContext original = context(options); original.putClass(corpus());
        ObfContext transformed = context(options); transformed.putClass(corpus());
        new CrossClassDispersionTransformer().transform(transformed);
        long calls = transformed.getClass("Fixture").methods.stream().flatMap(m ->
                Arrays.stream(m.instructions.toArray())).filter(i -> i instanceof MethodInsnNode).count();
        int helpers = transformed.classes().stream().filter(transformed::isDispersionCarrier)
                .mapToInt(c -> c.methods.size() - 1).sum();
        check(calls <= operationCap, "operation cap exceeded: " + calls);
        check(helpers <= helperCap, "helper cap exceeded: " + helpers);
        if (operationCap > 0 && helperCap > 0) check(calls > 0 && helpers > 0, "no transformation");
        else check(transformed.classes().size() == 1, "empty sinks generated");
        Class<?> a = loader(original).loadClass("Fixture"), b = loader(transformed).loadClass("Fixture");
        long[] values = {0, 1, -1, Integer.MIN_VALUE, Integer.MAX_VALUE, Long.MIN_VALUE, Long.MAX_VALUE, 63};
        for (var method : a.getDeclaredMethods()) {
            var other = b.getMethod(method.getName(), method.getParameterTypes());
            for (long x : values) for (long y : values) {
                Object[] args;
                if (method.getParameterTypes()[0] == long.class) args = new Object[]{x, y};
                else args = new Object[]{(int)x, (int)y};
                check(Objects.equals(method.invoke(null, args), other.invoke(null, args)), method.getName());
            }
        }
        System.out.println("PASS " + options + ": calls=" + calls + ", helpers=" + helpers);
    }
    static void asmFuzz() throws Exception {
        Random random = new Random(9981);
        for (int sample = 0; sample < 80; sample++) {
            ClassNode node = new ClassNode();
            node.version = V17; node.access = ACC_PUBLIC; node.name = "Fuzz" + sample; node.superName = "java/lang/Object";
            MethodNode method = new MethodNode(ACC_PUBLIC | ACC_STATIC, "run", "(I)I", null, null);
            method.instructions.add(new VarInsnNode(ILOAD, 0));
            for (int i = 0; i < 4 + random.nextInt(10); i++) {
                method.instructions.add(new LdcInsnNode(random.nextInt()));
                method.instructions.add(new InsnNode(new int[]{IADD, ISUB, IMUL, IXOR}[random.nextInt(4)]));
                if (random.nextBoolean()) {
                    LabelNode skip = new LabelNode();
                    method.instructions.add(new VarInsnNode(ILOAD, 0));
                    method.instructions.add(new JumpInsnNode(IFNE, skip));
                    method.instructions.add(new InsnNode(ICONST_1));
                    method.instructions.add(new InsnNode(IADD));
                    method.instructions.add(skip);
                }
            }
            method.instructions.add(new InsnNode(IRETURN));
            node.methods.add(method);
            ObfContext before = context("maxHelpers:32, maxOperations:1000"); before.putClass(node);
            ObfContext after = context("maxHelpers:32, maxOperations:1000");
            ClassNode copy = new ClassNode(); node.accept(copy); after.putClass(copy);
            new NumberEncryptionTransformer().transform(after);
            new CrossClassDispersionTransformer().transform(after);
            Class<?> a = loader(before).loadClass(node.name.replace('/', '.'));
            Class<?> b = loader(after).loadClass(node.name.replace('/', '.'));
            for (int input : new int[]{0, 1, -1, Integer.MIN_VALUE, Integer.MAX_VALUE})
                check(Objects.equals(a.getMethod("run", int.class).invoke(null, input),
                        b.getMethod("run", int.class).invoke(null, input)), "ASM fuzz " + sample);
        }
        System.out.println("PASS ASM generated class-file fuzz: 80 cases");
    }
    public static void main(String[] args) throws Exception {
        run("maxPerClass:12000, sinks:2, variantsPerOpcode:2, maxHelpers:128, maxOperations:20000", 20000, 60);
        run("sinks:2, maxHelpers:3, maxOperations:123", 123, 3);
        run("sinks:2, maxHelpers:3, maxOperations:20000", 20000, 3);
        run("maxPerClass:12000", 8192, 2048);
        run("maxHelpers:0", 0, 0);
        run("maxOperations:0", 0, 0);
        run("maxPerClass:0", 0, 0);
        run("exempt:[\"class{^Fixture$}\"]", 0, 0);
        try {
            new CrossClassDispersionTransformer().transform(context("maxHelpers:-1"));
            throw new AssertionError("negative budget accepted");
        } catch (IllegalArgumentException expected) { }
        ObfContext ctx = context("");
        ClassNode c = corpus(); c.methods.clear();
        MethodNode m = new MethodNode(ACC_PUBLIC | ACC_STATIC, "constants", "()I", null, null);
        for (int i = 0; i < 1900; i++) {
            m.instructions.add(new InsnNode(ICONST_1)); m.instructions.add(new InsnNode(POP));
        }
        m.instructions.add(new InsnNode(ICONST_5)); m.instructions.add(new InsnNode(IRETURN));
        c.methods.add(m); ctx.putClass(c);
        new NumberEncryptionTransformer().transform(ctx);
        check(m.instructions.size() <= Limits.MAX_GROW_INSNS, "numeric expansion escaped limit");
        check(loader(ctx).loadClass("Fixture").getMethod("constants").invoke(null).equals(5), "constants changed");
        System.out.println("PASS numeric growth cap: " + m.instructions.size());
        asmFuzz();
    }
}
