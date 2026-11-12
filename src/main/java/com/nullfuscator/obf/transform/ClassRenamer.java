package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;
import com.nullfuscator.obf.util.NameGenerator;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.Remapper;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.tree.*;

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

    @Override
    public String id() {
        return "classRenamer";
    }

    @Override
    public String description() {
        return "rename classes to opaque names";
    }

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

        for (String existing : ctx.classMap().keySet()) {
            gen.reserve(existing);
        }

        Set<String> protectedNames = new HashSet<>();
        protectedNames.addAll(Remapping.resourceClassReferences(ctx));

        String mainClass = Remapping.mainClassInternalName(ctx);
        if (!renameMain && mainClass != null) {
            protectedNames.add(mainClass);
        }

        String mixinBlob = Remapping.mixinJsonBlob(ctx);

        Set<String> candidates = new HashSet<>();
        for (ClassNode cn : ctx.targets(id())) {
            String name = cn.name;
            if (protectedNames.contains(name)) {
                continue;
            }
            if (!mixinBlob.isEmpty()) {
                String dotted = name.replace('/', '.');
                if (mixinBlob.contains(dotted)) {
                    continue;
                }
            }

            candidates.add(name);
        }

        Set<String> pinnedPackages = new HashSet<>();
        Set<String> occupiedPackages = new HashSet<>();
        for (ClassNode cn : ctx.classes()) {
            String pkg = packagePrefix(cn.name);
            occupiedPackages.add(pkg);
            if (!candidates.contains(cn.name)) {
                pinnedPackages.add(pkg);
            }
            cn.accept(new ClassRemapper(new ClassNode(), new Remapper(Opcodes.ASM9) {
                @Override
                public String map(String name) {
                    if (ctx.getClass(name) == null && packagePrefix(name).equals(pkg)) {
                        pinnedPackages.add(pkg);
                    }
                    return name;
                }
            }));
        }

        Map<String, String> packages = new HashMap<>();
        final Map<String, String> classMap = new HashMap<>();
        for (ClassNode cn : ctx.classes()) {
            if (!candidates.contains(cn.name)) {
                continue;
            }
            String pkg = packagePrefix(cn.name);
            String destination = packages.get(pkg);
            if (destination == null) {
                destination = pkg;
                if (!pinnedPackages.contains(pkg)) {
                    do {
                        destination = gen.nextRandomClass(prefix, ctx.random(), depth) + "/";
                    } while (!occupiedPackages.add(destination));
                }
                packages.put(pkg, destination);
            }
            String newName = gen.nextRandomClass(destination, ctx.random(), depth);
            String name = cn.name;
            classMap.put(name, newName);
            ctx.mapping().recordClass(name, newName);
        }

        if (classMap.isEmpty()) {
            ctx.log().debug("classRenamer: nothing to rename (depth=" + depth + ")");
            return;
        }

        ctx.remapDispersionCarriers(classMap);
        ctx.remapOriginalNames(classMap);

        Remapping.applyRemap(ctx, new Remapper(Opcodes.ASM9) {
            @Override
            public String map(String internalName) {
                String mapped = classMap.get(internalName);
                return mapped != null ? mapped : internalName;
            }
        });

        sanitizeInnerClassLabels(ctx, classMap, gen, depth);
        rewriteManifestEntrypoints(ctx, classMap);
        rewriteServiceDescriptors(ctx, classMap);
        rewritePluginDescriptors(ctx, classMap);

        ctx.log().debug("classRenamer renamed " + classMap.size() + " classes");
    }

    private static void sanitizeInnerClassLabels(ObfContext ctx, Map<String, String> classMap,
                                                  NameGenerator gen, int depth) {
        Set<String> renamed = new HashSet<>(classMap.values());

        for (ClassNode cn : ctx.classes()) {
            if (cn.innerClasses == null) {
                continue;
            }
            for (InnerClassNode inner : cn.innerClasses) {
                if (inner.innerName != null) {
                    gen.reserve(inner.innerName);
                }
            }
        }

        int changed = 0;
        for (ClassNode cn : ctx.classes()) {
            if (cn.innerClasses == null) {
                continue;
            }
            for (InnerClassNode inner : cn.innerClasses) {
                if (inner.name == null || !renamed.contains(inner.name) || inner.innerName == null) {
                    continue;
                }
                inner.innerName = gen.nextRandom(ctx.random(), depth);
                changed++;
            }
        }
        if (changed > 0) {
            ctx.log().debug("classRenamer hid " + changed + " inner-class labels");
        }
    }

    private static void rewriteManifestEntrypoints(ObfContext ctx, Map<String, String> classMap) {
        for (String path : new String[] { "META-INF/MANIFEST.MF", "MANIFEST.MF" }) {
            byte[] data = ctx.resources().get(path);
            if (data == null) {
                continue;
            }
            try {
                Manifest manifest = new Manifest(new ByteArrayInputStream(data));
                Attributes attributes = manifest.getMainAttributes();
                boolean changed = false;

                for (String attribute : new String[] {
                        "Main-Class", "Premain-Class", "Agent-Class", "Launcher-Agent-Class" }) {
                    String original = attributes.getValue(attribute);
                    if (original == null) {
                        continue;
                    }
                    String mapped = classMap.get(original.trim().replace('.', '/'));
                    if (mapped == null) {
                        continue;
                    }
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
        int files = 0;
        int providers = 0;

        for (Map.Entry<String, byte[]> entry : ctx.resources().entrySet()) {
            String oldPath = entry.getKey();
            String newPath = oldPath;
            byte[] data = entry.getValue();

            if (oldPath.startsWith(root) && oldPath.length() > root.length()) {
                String service = oldPath.substring(root.length()).replace('.', '/');
                String mappedService = classMap.get(service);
                if (mappedService != null) {
                    newPath = root + mappedService.replace('/', '.');
                }

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
                    if (i + 1 < lines.length) {
                        out.append('\n');
                    }
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

        if (files > 0) {
            ctx.log().debug("classRenamer remapped " + files
                    + " service descriptors and " + providers + " providers");
        }
    }

    private static String packagePrefix(String name) {
        return name.substring(0, name.lastIndexOf('/') + 1);
    }

    private static void rewritePluginDescriptors(ObfContext ctx, Map<String, String> classMap) {
        if (classMap.isEmpty()) {
            return;
        }

        for (Map.Entry<String, byte[]> entry : ctx.resources().entrySet()) {
            String path = entry.getKey();
            if (path == null) {
                continue;
            }

            if (isYamlPluginDescriptor(path)) {
                byte[] data = entry.getValue();
                byte[] updated = rewriteYamlDescriptor(data, classMap);
                if (updated != null) {
                    entry.setValue(updated);
                    ctx.log().debug("classRenamer updated plugin descriptor: " + path);
                }
            } else if (isJsonPluginDescriptor(path)) {
                byte[] data = entry.getValue();
                byte[] updated = rewriteJsonDescriptor(data, classMap);
                if (updated != null) {
                    entry.setValue(updated);
                    ctx.log().debug("classRenamer updated plugin descriptor: " + path);
                }
            }
        }
    }

    private static boolean isYamlPluginDescriptor(String path) {
        return path.equals("plugin.yml") || path.endsWith("/plugin.yml")
                || path.equals("paper-plugin.yml") || path.endsWith("/paper-plugin.yml")
                || path.equals("bungee.yml") || path.endsWith("/bungee.yml");
    }

    private static boolean isJsonPluginDescriptor(String path) {
        return path.equals("velocity-plugin.json") || path.endsWith("/velocity-plugin.json");
    }

    private static byte[] rewriteYamlDescriptor(byte[] data, Map<String, String> classMap) {
        String text = new String(data, StandardCharsets.UTF_8);
        String[] lines = text.split("\n", -1);
        boolean modified = false;
        StringBuilder sb = new StringBuilder(text.length());

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            String rewrittenLine = remapYamlLine(line, classMap);
            if (!rewrittenLine.equals(line)) {
                modified = true;
                line = rewrittenLine;
            }
            sb.append(line);
            if (i + 1 < lines.length) {
                sb.append('\n');
            }
        }

        return modified ? sb.toString().getBytes(StandardCharsets.UTF_8) : null;
    }

    private static String remapYamlLine(String line, Map<String, String> classMap) {
        int hash = line.indexOf('#');
        String content = hash >= 0 ? line.substring(0, hash) : line;
        String comment = hash >= 0 ? line.substring(hash) : "";

        int colon = content.indexOf(':');
        if (colon >= 0) {
            String key = content.substring(0, colon + 1);
            String val = content.substring(colon + 1);
            String trimmedVal = val.trim();
            if (!trimmedVal.isEmpty()) {
                char quote = 0;
                String rawVal = trimmedVal;
                if ((rawVal.startsWith("\"") && rawVal.endsWith("\"") && rawVal.length() >= 2)
                        || (rawVal.startsWith("'") && rawVal.endsWith("'") && rawVal.length() >= 2)) {
                    quote = rawVal.charAt(0);
                    rawVal = rawVal.substring(1, rawVal.length() - 1);
                }
                String internal = rawVal.replace('.', '/');
                String mapped = classMap.get(internal);
                if (mapped != null) {
                    String newDotted = mapped.replace('/', '.');
                    String newQuotedVal = quote != 0 ? ("" + quote + newDotted + quote) : newDotted;
                    int valStart = val.indexOf(trimmedVal);
                    String prefix = val.substring(0, valStart);
                    String suffix = val.substring(valStart + trimmedVal.length());
                    return key + prefix + newQuotedVal + suffix + comment;
                }
            }
            return line;
        }

        int dash = content.indexOf('-');
        if (dash >= 0) {
            String prefix = content.substring(0, dash + 1);
            String val = content.substring(dash + 1);
            String trimmedVal = val.trim();
            if (!trimmedVal.isEmpty()) {
                char quote = 0;
                String rawVal = trimmedVal;
                if ((rawVal.startsWith("\"") && rawVal.endsWith("\"") && rawVal.length() >= 2)
                        || (rawVal.startsWith("'") && rawVal.endsWith("'") && rawVal.length() >= 2)) {
                    quote = rawVal.charAt(0);
                    rawVal = rawVal.substring(1, rawVal.length() - 1);
                }
                String internal = rawVal.replace('.', '/');
                String mapped = classMap.get(internal);
                if (mapped != null) {
                    String newDotted = mapped.replace('/', '.');
                    String newQuotedVal = quote != 0 ? ("" + quote + newDotted + quote) : newDotted;
                    int valStart = val.indexOf(trimmedVal);
                    String vPrefix = val.substring(0, valStart);
                    String suffix = val.substring(valStart + trimmedVal.length());
                    return prefix + vPrefix + newQuotedVal + suffix + comment;
                }
            }
        }

        return line;
    }

    private static byte[] rewriteJsonDescriptor(byte[] data, Map<String, String> classMap) {
        String text = new String(data, StandardCharsets.UTF_8);
        boolean modified = false;

        for (Map.Entry<String, String> e : classMap.entrySet()) {
            String origDotted = e.getKey().replace('/', '.');
            String newDotted = e.getValue().replace('/', '.');
            String target = "\"" + origDotted + "\"";
            if (text.contains(target)) {
                text = text.replace(target, "\"" + newDotted + "\"");
                modified = true;
            }
        }

        return modified ? text.getBytes(StandardCharsets.UTF_8) : null;
    }
}
