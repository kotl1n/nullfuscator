package com.nullfuscator.obf.core;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.ClassNode;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.Comparator;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Locale;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipEntry;

public final class JarIO {

    private JarIO() {}

    public static void read(File input, ObfContext ctx) throws IOException {
        ctx.inputJarBytes(input.length());
        try (JarFile jar = new JarFile(input)) {
            // ZIP insertion order must not affect random draws in the pipeline.
            var entries = jar.stream().sorted(Comparator.comparing(JarEntry::getName)).toList();
            for (JarEntry e : entries) {
                if (e.isDirectory()) continue;
                byte[] data = readAll(jar.getInputStream(e));
                String name = e.getName();

                if (name.endsWith(".class") && !name.startsWith("META-INF/")) {
                    try {
                        ClassReader cr = new ClassReader(data);
                        ClassNode cn = new ClassNode();
                        cr.accept(cn, ClassReader.EXPAND_FRAMES);
                        ctx.putClass(cn);
                    } catch (RuntimeException ex) {

                        ctx.resources().put(name, data);
                        ctx.log().warn("kept unparseable class as resource: " + name);
                    }
                } else {
                    ctx.resources().put(name, data);
                }
            }
        }
    }

    public static void write(File output, ObfContext ctx) throws IOException {
        Path target = output.toPath().toAbsolutePath();
        Path parent = target.getParent();
        if (parent == null) parent = Path.of(".").toAbsolutePath();
        Files.createDirectories(parent);
        Path staged = Files.createTempFile(parent, ".nullfuscator-obf-", ".jar.tmp");
        boolean installed = false;
        try {
            writeArchive(staged, ctx);
            BudgetPolicy.verifyJar(ctx, Files.size(staged));
            try {
                Files.move(staged, target, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(staged, target, StandardCopyOption.REPLACE_EXISTING);
            }
            installed = true;
        } finally {
            if (!installed) Files.deleteIfExists(staged);
        }
    }

    private static void writeArchive(Path output, ObfContext ctx) throws IOException {
        var urls = new ArrayList<URL>();
        for (String lib : ctx.config().libs()) {
            urls.add(Path.of(lib).toUri().toURL());
        }
        try (URLClassLoader loader = new URLClassLoader(urls.toArray(new URL[0]),
                     HierarchyClassWriter.class.getClassLoader());
             JarOutputStream out = new JarOutputStream(Files.newOutputStream(output))) {
            var hierarchy = new HierarchyClassWriter.Hierarchy(ctx.classMap(), loader);
            // JarInputStream only recognizes a manifest at the start of the archive.
            byte[] manifest = ctx.resources().get("META-INF/MANIFEST.MF");
            if (manifest != null) {
                out.putNextEntry(stableEntry("META-INF/MANIFEST.MF"));
                out.write(manifest);
                out.closeEntry();
            }
            var classes = ctx.snapshot();
            classes.sort(Comparator.comparing(cn -> cn.name));
            var protectedBytes = new java.util.TreeMap<String, byte[]>();
            for (ClassNode cn : classes) {
                byte[] bytes;
                try {
                    ClassWriter cw = new HierarchyClassWriter(
                            ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS, hierarchy);
                    cn.accept(cw);
                    bytes = cw.toByteArray();
                } catch (RuntimeException | LinkageError ex) {

                    throw new IOException("failed to compute stack-map frames for "
                            + cn.name, ex);
                }
                if (ctx.integrityPlan() != null && ctx.integrityPlan().classes().contains(cn.name)) {
                    protectedBytes.put(cn.name, bytes);
                } else {
                    out.putNextEntry(stableEntry(cn.name + ".class"));
                    out.write(bytes);
                    out.closeEntry();
                }
            }
            if (ctx.integrityPlan() != null) {
                var plan = ctx.integrityPlan();
                if (ctx.resources().containsKey(plan.resource())) throw new IOException("Integrity resource collision");
                byte[] index = plan.seal(protectedBytes);
                for (var entry : protectedBytes.entrySet()) {
                    out.putNextEntry(stableEntry(entry.getKey() + ".class"));
                    out.write(entry.getValue());
                    out.closeEntry();
                }
                out.putNextEntry(stableEntry(plan.resource()));
                out.write(index);
                out.closeEntry();
            }
            int removedSignatures = 0;
            for (var entry : new java.util.TreeMap<>(ctx.resources()).entrySet()) {
                if (entry.getKey().equals("META-INF/MANIFEST.MF")) continue;
                if (isSignatureArtifact(entry.getKey())) {
                    removedSignatures++;
                    continue;
                }
                out.putNextEntry(stableEntry(entry.getKey()));
                out.write(entry.getValue());
                out.closeEntry();
            }
            if (removedSignatures > 0) {
                ctx.log().warn("removed " + removedSignatures
                        + " invalidated JAR signature artifacts; sign the output JAR again");
            }
        }
    }

    private static boolean isSignatureArtifact(String name) {
        if (name == null) return false;
        String upper = name.replace('\\', '/').toUpperCase(Locale.ROOT);
        if (!upper.startsWith("META-INF/")) return false;
        String leaf = upper.substring("META-INF/".length());
        if (leaf.indexOf('/') >= 0) return false;
        return leaf.endsWith(".SF") || leaf.endsWith(".RSA")
                || leaf.endsWith(".DSA") || leaf.endsWith(".EC")
                || leaf.startsWith("SIG-");
    }

    private static ZipEntry stableEntry(String name) {
        ZipEntry entry = new ZipEntry(name);
        entry.setTime(0L);
        return entry;
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(Math.max(64, in.available()));
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) bos.write(buf, 0, n);
        in.close();
        return bos.toByteArray();
    }
}
