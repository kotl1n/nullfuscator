package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;
import com.nullfuscator.obf.util.NameGenerator;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.Remapper;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;

import java.nio.charset.StandardCharsets;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

public final class ClassRenamer implements Transformer {

    private static final String[] DEFAULT_ALPHABET = { "I", "l1", "lI", "1l", "ll", "Il" };

    @Override public String id() { return "classRenamer"; }
    @Override public String description() { return "rename classes to opaque names"; }

    @Override
    public void transform(ObfContext ctx) {
        if (ctx.isModularJar()) {

            ctx.log().warn("classRenamer: skipped for modular JAR (module-info present)");
            return;
        }
        var section = ctx.config().section(id());
        String prefix = section.getString("prefix", "a/");
        boolean renameMain = section.getBoolean("renameMain", true);
        int depth = Math.max(1, Math.min(32, section.getInt("depth", 8)));
        List<String> chars = section.getStringList("chars");
        String[] alphabet = chars.isEmpty() ? DEFAULT_ALPHABET : chars.toArray(new String[0]);

        NameGenerator gen = new NameGenerator(alphabet);

        for (String existing : ctx.classMap().keySet()) gen.reserve(existing);

        Set<String> protectedNames = new HashSet<>();
        protectedNames.addAll(Remapping.resourceClassReferences(ctx));
        String mainClass = Remapping.mainClassInternalName(ctx);
        if (!renameMain && mainClass != null) protectedNames.add(mainClass);
        protectedNames.addAll(Remapping.resourceClassReferences(ctx));
        String mixinBlob = Remapping.mixinJsonBlob(ctx);

        final Map<String, String> classMap = new HashMap<>();
        for (ClassNode cn : ctx.targets(id())) {
            String name = cn.name;
            if (protectedNames.contains(name)) continue;
            if (!mixinBlob.isEmpty()) {
                String dotted = name.replace('/', '.');
                if (mixinBlob.contains(dotted)) continue;
            }
            String newName = gen.nextRandomClass(prefix, ctx.random(), depth);
            classMap.put(name, newName);
            ctx.mapping().recordClass(name, newName);

            makePublicDeep(cn);
        }

        if (classMap.isEmpty()) {
            ctx.log().debug("classRenamer: nothing to rename (depth=" + depth + ")");
            return;
        }

        ctx.remapDispersionCarriers(classMap);
        ctx.remapOriginalNames(classMap);
        Remapping.applyRemap(ctx, new Remapper(Opcodes.ASM9) {
            @Override public String map(String internalName) {
                String mapped = classMap.get(internalName);
                return mapped != null ? mapped : internalName;
            }
        });
        rewriteManifestEntrypoints(ctx, classMap);
        rewriteServiceDescriptors(ctx, classMap);

        ctx.log().debug("classRenamer renamed " + classMap.size() + " classes");
    }

    private static void rewriteManifestEntrypoints(ObfContext ctx, Map<String, String> classMap) {
        for (String path : new String[] { "META-INF/MANIFEST.MF", "MANIFEST.MF" }) {
            byte[] data = ctx.resources().get(path);
            if (data == null) continue;
            try {
                Manifest manifest = new Manifest(new ByteArrayInputStream(data));
                Attributes attributes = manifest.getMainAttributes();
                boolean changed = false;
                for (String attribute : new String[] {
                        "Main-Class", "Premain-Class", "Agent-Class", "Launcher-Agent-Class" }) {
                    String original = attributes.getValue(attribute);
                    if (original == null) continue;
                    String mapped = classMap.get(original.trim().replace('.', '/'));
                    if (mapped == null) continue;
                    attributes.putValue(attribute, mapped.replace('/', '.'));
                    changed = true;
                }
                if (changed) {
                    ByteArrayOutputStream out = new ByteArrayOutputStream(data.length + 64);
                    manifest.write(out);
                    ctx.resources().put(path, out.toByteArray());
                }
            } catch (Exception e) {
                throw new IllegalStateException("cannot rewrite entrypoints in " + path, e);
            }
        }
    }

    private static void rewriteServiceDescriptors(ObfContext ctx, Map<String, String> classMap) {
        final String root = "META-INF/services/";
        Map<String, byte[]> rewritten = new LinkedHashMap<>();
        int files = 0, providers = 0;
        for (Map.Entry<String, byte[]> entry : ctx.resources().entrySet()) {
            String oldPath = entry.getKey();
            String newPath = oldPath;
            byte[] data = entry.getValue();
            if (oldPath.startsWith(root) && oldPath.length() > root.length()) {
                String service = oldPath.substring(root.length()).replace('.', '/');
                String mappedService = classMap.get(service);
                if (mappedService != null) newPath = root + mappedService.replace('/', '.');

                String text = new String(data, StandardCharsets.UTF_8);
                String[] lines = text.split("\\n", -1);
                StringBuilder out = new StringBuilder(text.length());
                for (int i = 0; i < lines.length; i++) {
                    String line = lines[i];
                    int comment = line.indexOf('#');
                    String body = comment >= 0 ? line.substring(0, comment) : line;
                    String provider = body.trim();
                    if (!provider.isEmpty()) {
                        String mapped = classMap.get(provider.replace('.', '/'));
                        if (mapped != null) {
                            int start = body.indexOf(provider);
                            line = body.substring(0, start) + mapped.replace('/', '.')
                                    + body.substring(start + provider.length())
                                    + (comment >= 0 ? line.substring(comment) : "");
                            providers++;
                        }
                    }
                    out.append(line);
                    if (i + 1 < lines.length) out.append('\n');
                }
                data = out.toString().getBytes(StandardCharsets.UTF_8);
                files++;
            }
            if (rewritten.put(newPath, data) != null) {
                throw new IllegalStateException("resource collision after service remap: " + newPath);
            }
        }
        ctx.resources().clear();
        ctx.resources().putAll(rewritten);
        if (files > 0) ctx.log().debug("classRenamer remapped " + files
                + " service descriptors and " + providers + " providers");
    }

    private static void makePublicDeep(ClassNode cn) {
        cn.access = pub(cn.access);
        if (cn.methods != null) for (MethodNode m : cn.methods) {
            // Object streams require private readObject/writeObject hooks.
            if (!MethodRenamer.isSerializationHook(m)) m.access = pub(m.access);
        }
        if (cn.fields != null) for (FieldNode f : cn.fields) {
            if (!f.name.equals("serialPersistentFields")) f.access = pub(f.access);
        }
    }

    private static int pub(int access) {
        return (access & ~(Opcodes.ACC_PRIVATE | Opcodes.ACC_PROTECTED)) | Opcodes.ACC_PUBLIC;
    }
}
