package com.nullfuscator.obf;

import com.nullfuscator.obf.core.*;
import com.nullfuscator.obf.transform.*;
import com.nullfuscator.obf.util.*;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;
import java.util.*;
import java.util.concurrent.*;

public final class RuntimeOverheadRegression implements Opcodes {
    public static class Fixture {
        public static int counter;
        public static int unread;
        public static final int CONSTANT = 17;
        public static int integer(int x) { return x < 0 ? x : x ^ 123; }
        public static long wide(long x) { return x; }
        public static float floating(float x) { return x; }
        public static double decimal(double x) { return x; }
        public static Object reference(Object x) { return x; }
        public static int[] array(int[] x) { return x; }
        public static void nothing() { counter++; }
        public static int recursion(int n) { return n == 0 ? 1 : n * recursion(n - 1); }
        public static int failure(int x) { return 100 / x; }
        public static int caught(int x) { try { return 100 / x; } catch (ArithmeticException e) { return -1; } }
    }

    private static ObfContext context(String config) {
        return new ObfContext(ObfConfig.parse(config), 42, new ObfLog(false),
                new NameGenerator(new String[]{"a", "b"}));
    }

    private static ClassNode fixture() throws Exception {
        ClassNode cn = new ClassNode();
        try (var in = RuntimeOverheadRegression.class.getResourceAsStream("RuntimeOverheadRegression$Fixture.class")) {
            new ClassReader(in).accept(cn, 0);
        }
        return cn;
    }

    private static Class<?> load(ObfContext ctx, String name) throws Exception {
        Map<String, byte[]> bytes = new HashMap<>();
        for (ClassNode cn : ctx.classes()) {
            ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
            cn.accept(writer);
            bytes.put(cn.name.replace('/', '.'), writer.toByteArray());
        }
        return new ClassLoader(null) {
            @Override protected Class<?> findClass(String name) throws ClassNotFoundException {
                byte[] data = bytes.get(name);
                if (data == null) throw new ClassNotFoundException(name);
                return defineClass(name, data, 0, data.length);
            }
        }.loadClass(name.replace('/', '.'));
    }

    private static void returns() throws Exception {
        ObfContext ctx = context("exceptionReturn { enabled:true, percent:100 }");
        ClassNode cn = fixture();
        ctx.putClass(cn);
        ctx.initializePolicies();
        MethodNode helper = new MethodNode(ACC_PUBLIC | ACC_STATIC, "helper", "()I", null, null);
        helper.instructions.add(new InsnNode(ICONST_1));
        helper.instructions.add(new InsnNode(IRETURN));
        cn.methods.add(helper);
        new ExceptionReturnTransformer().transform(ctx);
        check(helper.tryCatchBlocks.isEmpty());
        Class<?> cls = load(ctx, cn.name);
        for (int x : new int[]{Integer.MIN_VALUE, -1, 0, 1, Integer.MAX_VALUE})
            check(cls.getMethod("integer", int.class).invoke(null, x).equals(Fixture.integer(x)));
        for (long x : new long[]{Long.MIN_VALUE, -1, 0, Long.MAX_VALUE})
            check(cls.getMethod("wide", long.class).invoke(null, x).equals(x));
        for (int bits : new int[]{0, 0x80000000, 0x7fc01234, 0xff800000}) {
            float value = (float) cls.getMethod("floating", float.class).invoke(null, Float.intBitsToFloat(bits));
            check(Float.floatToRawIntBits(value) == bits);
        }
        for (long bits : new long[]{0, Long.MIN_VALUE, 0x7ff8000000001234L, 0xfff0000000000000L}) {
            double value = (double) cls.getMethod("decimal", double.class).invoke(null, Double.longBitsToDouble(bits));
            check(Double.doubleToRawLongBits(value) == bits);
        }
        Object marker = new Object();
        check(cls.getMethod("reference", Object.class).invoke(null, marker) == marker);
        check(cls.getMethod("reference", Object.class).invoke(null, new Object[]{null}) == null);
        int[] array = {1, 2};
        check(cls.getMethod("array", int[].class).invoke(null, array) == array);
        cls.getMethod("nothing").invoke(null);
        check(cls.getField("counter").getInt(null) == 1);
        check(cls.getMethod("caught", int.class).invoke(null, 0).equals(-1));
        try {
            cls.getMethod("failure", int.class).invoke(null, 0);
            throw new AssertionError("application exception was swallowed");
        } catch (java.lang.reflect.InvocationTargetException e) {
            check(e.getCause() instanceof ArithmeticException);
        }
        var recursion = cls.getMethod("recursion", int.class);
        var reference = cls.getMethod("reference", Object.class);
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            List<Callable<Void>> jobs = new ArrayList<>();
            for (int thread = 0; thread < 4; thread++) jobs.add(() -> {
                Object local = new Object();
                for (int i = 0; i < 2000; i++) {
                    check(recursion.invoke(null, 8).equals(40320));
                    check(reference.invoke(null, local) == local);
                }
                return null;
            });
            for (Future<Void> result : pool.invokeAll(jobs)) result.get();
        } finally { pool.shutdownNow(); }
        System.out.println("PASS compact exception returns: all types, raw bits, recursion, concurrency, exceptions");
    }

    private static void accessors() throws Exception {
        ObfContext ctx = context("fieldIndirection { enabled:true, percent:100 }");
        ClassNode cn = fixture();
        ctx.putClass(cn);
        Set<MethodNode> original = new HashSet<>(cn.methods);
        new FieldIndirectionTransformer().transform(ctx);
        long generated = cn.methods.stream().filter(m -> !original.contains(m)).count();
        check(generated == 2);
        Class<?> cls = load(ctx, cn.name);
        cls.getMethod("nothing").invoke(null);
        check(cls.getField("counter").getInt(null) == 1);
        System.out.println("PASS field indirection: only used accessors retained and executable");
    }

    private static void guards() throws Exception {
        ObfContext ctx = context("antiDebug { enabled:true, checkPercent:100, detectors:2 }");
        ClassNode cn = fixture();
        MethodNode input = cn.methods.stream().filter(m -> m.name.equals("integer")).findFirst().orElseThrow();
        input.access |= ACC_SYNTHETIC;
        ctx.putClass(cn);
        ctx.initializePolicies();
        MethodNode helper = new MethodNode(ACC_STATIC | ACC_PUBLIC, "helper", "()V", null, null);
        helper.instructions.add(new InsnNode(RETURN));
        cn.methods.add(helper);
        new AntiDebugTransformer().transform(ctx);
        check(helper.instructions.size() == 1);
        check(input.instructions.getFirst() instanceof MethodInsnNode call && call.name.equals("detected"));
        Class<?> cls = load(ctx, cn.name);
        check(cls.getMethod("integer", int.class).invoke(null, 1).equals(122));
        System.out.println("PASS debugger guards: input synthetic method protected, generated helper not guarded again");
    }

    private static void dispersion(int version, boolean opaque, boolean mixed) throws Exception {
        ObfContext ctx = context("crossClassDispersion { enabled:true, dispersalPercent:100, "
                + "sinks:2, variantsPerOpcode:1, opaqueState:" + opaque + " }\n"
                + "fieldRenamer { enabled:true }\nclassRenamer { enabled:true }");
        ClassNode cn = GrowthRegression.corpus();
        cn.version = version;
        for (MethodNode method : cn.methods) {
            boolean wide = method.desc.equals("(JJ)J");
            int opcode = Integer.parseInt(method.name.substring(2));
            method.instructions.clear();
            method.instructions.add(new VarInsnNode(wide ? LLOAD : ILOAD, 0));
            method.instructions.add(new VarInsnNode(wide ? LLOAD : ILOAD, wide ? 2 : 1));
            method.instructions.add(new InsnNode(opcode));
            method.instructions.add(new InsnNode(wide ? LRETURN : IRETURN));
            method.maxLocals = wide ? 4 : 2;
            method.maxStack = wide ? 4 : 2;
        }
        cn.fields.add(new FieldNode(ACC_PUBLIC | ACC_STATIC | ACC_VOLATILE, "application", "J", null, null));
        ctx.putClass(cn);
        if (mixed) {
            ClassNode legacy = new ClassNode();
            legacy.version = V1_8;
            legacy.access = ACC_PUBLIC;
            legacy.name = "LegacyMarker";
            legacy.superName = "java/lang/Object";
            ctx.putClass(legacy);
        }
        ctx.initializePolicies();
        ObfContext original = context("");
        ClassNode copy = new ClassNode();
        cn.accept(copy);
        original.putClass(copy);
        Class<?> baseline = load(original, cn.name);
        new CrossClassDispersionTransformer().transform(ctx);
        boolean expectOpaque = opaque && version >= V11;
        int routed = 0;
        for (MethodNode method : cn.methods) {
            for (AbstractInsnNode insn : method.instructions) {
                if (insn instanceof MethodInsnNode call && ctx.isDispersionCarrier(ctx.getClass(call.owner))) routed++;
            }
        }
        check(routed == GrowthRegression.OPS.length);
        for (ClassNode carrier : ctx.classes()) {
            if (!ctx.isDispersionCarrier(carrier)) continue;
            check(carrier.version == (expectOpaque ? V11 : V1_8));
            for (MethodNode method : carrier.methods) {
                new org.objectweb.asm.tree.analysis.Analyzer<>(
                        new org.objectweb.asm.tree.analysis.BasicVerifier()).analyze(carrier.name, method);
                if (method.name.equals("<clinit>")) continue;
                long reads = Arrays.stream(method.instructions.toArray()).filter(i ->
                        i instanceof MethodInsnNode call && call.owner.equals("java/lang/invoke/VarHandle")
                                && call.name.equals("getOpaque")).count();
                long writes = Arrays.stream(method.instructions.toArray()).filter(i ->
                        i instanceof MethodInsnNode call && call.owner.equals("java/lang/invoke/VarHandle")
                                && call.name.equals("setOpaque")).count();
                check(reads == (expectOpaque ? 1 : 0) && writes == reads);
            }
        }
        new FieldRenamer().transform(ctx);
        new ClassRenamer().transform(ctx);
        String renamed = ctx.classes().stream().filter(c -> ctx.originalName(c.name).equals("Fixture"))
                .findFirst().orElseThrow().name;
        check(ctx.getClass(renamed).fields.stream().anyMatch(f -> f.desc.equals("J")
                && (f.access & ACC_VOLATILE) != 0));
        Class<?> actual = load(ctx, renamed);
        List<java.lang.reflect.Method> methods = Arrays.stream(baseline.getDeclaredMethods()).toList();
        long[] edges = {0, 1, -1, Integer.MIN_VALUE, Integer.MAX_VALUE, Long.MIN_VALUE, Long.MAX_VALUE,
                -65, -33, 31, 32, 63, 64};
        for (var method : methods) {
            var transformed = actual.getMethod(method.getName(), method.getParameterTypes());
            for (long x : edges) for (long y : edges) {
                Object[] args = method.getParameterTypes()[0] == long.class
                        ? new Object[]{x, y} : new Object[]{(int) x, (int) y};
                check(method.invoke(null, args).equals(transformed.invoke(null, args)));
            }
        }
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            List<Callable<Void>> jobs = new ArrayList<>();
            for (int thread = 0; thread < 4; thread++) {
                final int seed = thread;
                jobs.add(() -> {
                    Random random = new Random(seed);
                    for (int i = 0; i < 400; i++) {
                        for (var method : methods) {
                            var transformed = actual.getMethod(method.getName(), method.getParameterTypes());
                            long x = random.nextLong(), y = random.nextLong();
                            Object[] args = method.getParameterTypes()[0] == long.class
                                    ? new Object[]{x, y} : new Object[]{(int) x, (int) y};
                            check(method.invoke(null, args).equals(transformed.invoke(null, args)));
                        }
                    }
                    return null;
                });
            }
            for (Future<Void> result : pool.invokeAll(jobs)) result.get();
        } finally { pool.shutdownNow(); }
        for (int opcode : new int[]{IADD, LADD}) {
            boolean wide = opcode == LADD;
            MethodNode caller = ctx.getClass(renamed).methods.stream()
                    .filter(m -> m.name.equals("op" + opcode)).findFirst().orElseThrow();
            MethodInsnNode call = (MethodInsnNode) Arrays.stream(caller.instructions.toArray())
                    .filter(i -> i instanceof MethodInsnNode).findFirst().orElseThrow();
            ClassNode carrier = ctx.getClass(call.owner);
            String descriptor = expectOpaque ? (wide ? "[J" : "[I") : (wide ? "J" : "I");
            FieldNode state = carrier.fields.stream().filter(f -> f.desc.equals(descriptor)).findFirst().orElseThrow();
            var field = actual.getClassLoader().loadClass(call.owner.replace('/', '.')).getDeclaredField(state.name);
            field.setAccessible(true);
            Object array = expectOpaque ? field.get(null) : null;
            if (expectOpaque) {
                if (wide) ((long[]) array)[0] = 0; else ((int[]) array)[0] = 0;
            } else {
                if (wide) field.setLong(null, 0); else field.setInt(null, 0);
            }
            if (wide) check(actual.getMethod("op" + opcode, long.class, long.class).invoke(null, 7L, 11L).equals(18L));
            else check(actual.getMethod("op" + opcode, int.class, int.class).invoke(null, 7, 11).equals(18));
            long value = expectOpaque ? (wide ? ((long[]) array)[0] : ((int[]) array)[0])
                    : (wide ? field.getLong(null) : field.getInt(null));
            check(value != 0);
        }
        System.out.println("PASS dispersion state: version=" + version + ", opaque=" + expectOpaque
                + ", mixed=" + mixed + "; all 15 operations, overflow, shifts, concurrency, renaming, live updates");
    }

    private static void check(boolean ok) { if (!ok) throw new AssertionError(); }
    public static void main(String[] args) throws Exception {
        returns(); accessors(); guards();
        dispersion(V1_8, true, false);
        dispersion(V9, true, false);
        dispersion(V11, true, false);
        dispersion(V17, true, false);
        dispersion(V17, false, false);
        dispersion(V17, true, true);
    }
}
