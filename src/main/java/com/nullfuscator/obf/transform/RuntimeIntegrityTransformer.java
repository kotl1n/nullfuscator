package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.*;
import org.objectweb.asm.*;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.SimpleRemapper;
import org.objectweb.asm.tree.*;
import java.io.InputStream;
import java.util.*;

/** Must be last: verifier bodies and their expected hashes cannot be transformed afterwards. */
public final class RuntimeIntegrityTransformer implements Transformer, Opcodes {
    private static final String TEMPLATE = "com/nullfuscator/obf/runtime/IntegrityGuard";
    @Override public String id() { return "runtimeIntegrity"; }
    @Override public String description() { return "bind protected methods to mutually verified archive guards"; }
    @Override public void transform(ObfContext ctx) {
        var section = ctx.config().section(id());
        var include = new ExemptMatcher(section.getStringList("include"));
        if (include.isEmpty()) throw new IllegalArgumentException("runtimeIntegrity requires explicit include selectors");
        List<ClassNode> targets = ctx.targets(id()).stream()
                .filter(c -> include.matches(ctx.originalName(c.name)))
                .filter(c -> (c.access & (ACC_ANNOTATION | ACC_INTERFACE)) == 0).toList();
        if (targets.isEmpty()) throw new IllegalArgumentException("runtimeIntegrity matched no classes");
        if (ctx.isModularJar()) throw new IllegalArgumentException("runtimeIntegrity does not support modular JARs");
        Set<String> targetPaths = new HashSet<>();
        for (var target : targets) targetPaths.add(ctx.originalName(target.name) + ".class");
        for (String path : ctx.resources().keySet()) {
            if (!path.startsWith("META-INF/versions/") || !path.endsWith(".class")) continue;
            int slash = path.indexOf('/', "META-INF/versions/".length());
            if (slash >= 0 && targetPaths.contains(path.substring(slash + 1)))
                throw new IllegalArgumentException("runtimeIntegrity cannot protect versioned override: " + path);
        }
        int count = Math.max(2, Math.min(8, section.getInt("guards", 3)));
        int percent = Math.max(0, Math.min(100, section.getInt("checkPercent", 10)));
        String resource = "META-INF/" + ctx.names().next() + ".integrity";
        if (ctx.resources().containsKey(resource)) throw new IllegalStateException("Integrity resource collision");
        List<String> guards = new ArrayList<>();
        try (InputStream in = getClass().getResourceAsStream("/" + TEMPLATE + ".class")) {
            if (in == null) throw new IllegalStateException("Integrity template missing");
            byte[] template = in.readAllBytes();
            for (int i = 0; i < count; i++) {
                String name;
                do { name = "a/integrity/" + ctx.names().next(); } while (ctx.getClass(name) != null);
                ClassNode copy = new ClassNode();
                new ClassReader(template).accept(new ClassRemapper(copy, new SimpleRemapper(TEMPLATE, name)), 0);
                copy.version = V1_8;
                copy.sourceFile = null;
                for (var method : copy.methods) for (var insn : method.instructions)
                    if (insn instanceof LdcInsnNode ldc && "@NULLFUSCATOR_INDEX@".equals(ldc.cst)) ldc.cst = resource;
                ctx.putClass(copy);
                guards.add(name);
            }
        } catch (java.io.IOException e) { throw new IllegalStateException("Cannot read integrity template", e); }
        Set<String> monitored = new HashSet<>(guards);
        int sites = 0;
        for (var cn : targets) {
            monitored.add(cn.name);
            MethodNode init = cn.methods.stream().filter(m -> m.name.equals("<clinit>")).findFirst().orElse(null);
            if (init == null) {
                init = new MethodNode(ACC_STATIC, "<clinit>", "()V", null, null);
                init.instructions.add(new InsnNode(RETURN));
                cn.methods.add(init);
            }
            for (var method : cn.methods) {
                if ((method.access & (ACC_NATIVE | ACC_ABSTRACT)) != 0 || method.name.equals("<init>")) continue;
                boolean decoder = method.desc.equals("(Ljava/lang/String;I)Ljava/lang/String;")
                        || method.desc.startsWith("(Ljava/lang/invoke/MethodHandles$Lookup;");
                if (!method.name.equals("<clinit>") && !decoder && ctx.random().nextInt(100) >= percent) continue;
                if (Limits.oversizeMethod(method)) throw new IllegalStateException("No integrity guard space: " + cn.name);
                int first = ctx.random().nextInt(count);
                InsnList checks = new InsnList();
                for (int offset = 0; offset < 2; offset++)
                    checks.add(new MethodInsnNode(INVOKESTATIC, guards.get((first + offset) % count), "check", "()V", false));
                method.instructions.insert(checks);
                sites++;
            }
        }
        ctx.integrityPlan(new IntegrityPlan(resource, Set.copyOf(monitored), Set.copyOf(guards)));
        ctx.log().info("runtimeIntegrity: " + monitored.size() + " classes, " + sites + " sites, " + count + " guards");
    }
}
