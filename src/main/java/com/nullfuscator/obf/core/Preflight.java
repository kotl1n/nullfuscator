package com.nullfuscator.obf.core;

import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodInsnNode;

import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Fails unsafe configurations before any class is transformed. */
public final class Preflight {
    private Preflight() { }

    public static void run(ObfContext ctx) throws Exception {
        boolean multiReleaseClasses = ctx.resources().keySet().stream()
                .anyMatch(p -> p.startsWith("META-INF/versions/") && p.endsWith(".class"));
        if (multiReleaseClasses && ctx.config().section("classRenamer").enabled()
                && !ctx.config().section("compatibility").getBoolean("allowMultiReleaseRename", false)) {
            throw new IllegalArgumentException("classRenamer with META-INF/versions class overrides is unsafe; "
                    + "disable renaming or explicitly set compatibility.allowMultiReleaseRename=true after review");
        }
        if (multiReleaseClasses) warn(ctx, "multi-release class overrides are preserved as resources and are not transformed");

        checkHierarchy(ctx);
        checkGson(ctx);
        checkDynamicContracts(ctx);
    }

    private static void checkHierarchy(ObfContext ctx) throws Exception {
        List<URL> urls = new ArrayList<>();
        for (String lib : ctx.config().libs()) urls.add(Path.of(lib).toUri().toURL());
        Set<String> missing = new LinkedHashSet<>();
        try (URLClassLoader loader = new URLClassLoader(urls.toArray(URL[]::new), Preflight.class.getClassLoader())) {
            for (ClassNode cn : ctx.classes()) {
                if (cn.superName != null && !available(ctx, loader, cn.superName)) missing.add(cn.superName);
                for (String itf : cn.interfaces) if (!available(ctx, loader, itf)) missing.add(itf);
            }
        }
        if (!missing.isEmpty()) {
            String sample = missing.stream().limit(8).reduce((a, b) -> a + ", " + b).orElse("");
            throw new IllegalArgumentException("incomplete classpath: missing direct hierarchy types: " + sample
                    + (missing.size() > 8 ? " (and " + (missing.size() - 8) + " more)" : "")
                    + "; add dependency JARs to libs");
        }
    }

    private static boolean available(ObfContext ctx, ClassLoader loader, String name) {
        if (ctx.getClass(name) != null) return true;
        try (InputStream in = loader.getResourceAsStream(name + ".class")) { return in != null; }
        catch (Exception ignored) { return false; }
    }

    private static void checkGson(ObfContext ctx) {
        if (!ctx.config().section("fieldRenamer").enabled()) return;
        Set<String> risky = new LinkedHashSet<>();
        for (ClassNode cn : ctx.classes()) {
            boolean gsonConsumer = annotationsUseGson(cn.visibleAnnotations)
                    || annotationsUseGson(cn.invisibleAnnotations);
            for (FieldNode field : cn.fields) {
                gsonConsumer |= annotationsUseGson(field.visibleAnnotations)
                        || annotationsUseGson(field.invisibleAnnotations);
            }
            for (var method : cn.methods) for (AbstractInsnNode insn : method.instructions.toArray()) {
                if (insn instanceof MethodInsnNode call && call.owner.startsWith("com/google/gson/")) gsonConsumer = true;
            }
            if (gsonConsumer) {
                boolean unpinned = cn.fields.stream().anyMatch(field ->
                        (field.access & (org.objectweb.asm.Opcodes.ACC_STATIC
                                | org.objectweb.asm.Opcodes.ACC_TRANSIENT
                                | org.objectweb.asm.Opcodes.ACC_SYNTHETIC)) == 0
                                && !com.nullfuscator.obf.transform.GsonSchemaTransformer.hasName(field));
                if (unpinned) risky.add(cn.name);
            }
        }
        if (!risky.isEmpty()) warn(ctx, "field renaming may change Gson schema in " + risky.size()
                + " class(es), for example " + risky.iterator().next()
                + "; use gsonSchema.include or exempt those fields/classes");
    }

    private static void checkDynamicContracts(ObfContext ctx) {
        if (!ctx.config().section("classRenamer").enabled()
                && !ctx.config().section("methodRenamer").enabled()
                && !ctx.config().section("fieldRenamer").enabled()) return;
        Set<String> risky = new LinkedHashSet<>();
        for (ClassNode cn : ctx.classes()) {
            boolean dynamic = cn.methods.stream().anyMatch(method -> {
                if ((method.access & org.objectweb.asm.Opcodes.ACC_NATIVE) != 0) return true;
                for (AbstractInsnNode insn : method.instructions.toArray()) {
                    if (!(insn instanceof MethodInsnNode call)) continue;
                    if (call.owner.equals("java/lang/Class") && (call.name.equals("forName")
                            || call.name.startsWith("getDeclared"))) return true;
                    if (call.owner.equals("java/util/ServiceLoader") && call.name.equals("load")) return true;
                    if (call.owner.startsWith("java/lang/reflect/")
                            || call.owner.startsWith("java/lang/invoke/MethodHandles$Lookup")) return true;
                }
                return false;
            });
            if (dynamic) risky.add(cn.name);
        }
        if (!risky.isEmpty()) warn(ctx, "renaming requires reviewed keep/exempt rules for " + risky.size()
                + " reflection, ServiceLoader, MethodHandles or JNI class(es), for example "
                + risky.iterator().next());
    }

    private static boolean annotationsUseGson(List<AnnotationNode> annotations) {
        if (annotations == null) return false;
        return annotations.stream().anyMatch(a -> a.desc.startsWith("Lcom/google/gson/"));
    }

    private static void warn(ObfContext ctx, String message) {
        ctx.log().warn(message);
        if (ctx.report() != null) ctx.report().warn(message);
    }
}
