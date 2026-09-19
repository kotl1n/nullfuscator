package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;
import com.nullfuscator.obf.util.NameGenerator;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class ResourceRenamer implements Transformer {

    private static final String[] DEFAULT_RESOURCE_ALPHABET = { "i", "l", "1" };
    private static final Set<String> TEXT_EXTENSIONS = Set.of(
            "accesswidener", "cfg", "fsh", "glsl", "json", "lang", "mcmeta",
            "properties", "txt", "vsh");

    @Override
    public String id() {
        return "resourceRenamer";
    }

    @Override
    public String description() {
        return "rename mod asset paths and rewrite literal lookups";
    }

    @Override
    public void transform(ObfContext ctx) {
        var section = ctx.config().section(id());
        int depth = Math.max(1, Math.min(32, section.getInt("depth", 6)));
        Set<String> excludedNamespaces = new HashSet<>(section.getStringList("excludeNamespaces"));
        if (excludedNamespaces.isEmpty()) {
            excludedNamespaces.add("minecraft");
        }
        Set<String> excludedDirectories = new HashSet<>(section.getStringList("excludeDirectories"));

        List<String> oldPaths = ctx.resources().keySet().stream()
                .filter(path -> isRenamableAsset(path, excludedNamespaces))
                .filter(path -> !excludedDirectories.contains(AssetPath.parse(path).firstSegment()))
                .sorted()
                .toList();
        if (oldPaths.isEmpty()) {
            return;
        }

        List<String> chars = section.getStringList("chars");
        String[] alphabet;
        if (!chars.isEmpty()) {
            alphabet = chars.stream()
                    .map(s -> s.toLowerCase(Locale.ROOT))
                    .filter(s -> s.matches("[a-z0-9_.-]+"))
                    .toArray(String[]::new);
            if (alphabet.length == 0) {
                alphabet = DEFAULT_RESOURCE_ALPHABET;
            }
        } else {
            alphabet = DEFAULT_RESOURCE_ALPHABET;
        }
        NameGenerator gen = new NameGenerator(alphabet);

        Map<String, String> topLevelDirectories = new HashMap<>();
        Map<String, String> renamedPaths = new LinkedHashMap<>();
        Set<String> occupied = new HashSet<>(ctx.resources().keySet());
        Set<String> occupiedDirs = new HashSet<>();

        for (String oldPath : oldPaths) {
            AssetPath asset = AssetPath.parse(oldPath);
            String directoryKey = asset.namespace + "/" + asset.firstSegment();

            String obfuscatedDirectory = topLevelDirectories.computeIfAbsent(directoryKey, ignored -> {
                String d;
                do {
                    d = gen.nextRandom(ctx.random(), depth);
                } while (!occupiedDirs.add(asset.namespace + "/" + d));
                return d;
            });

            String extension = asset.extension();
            String newPath;
            do {
                newPath = "assets/" + asset.namespace + "/" + obfuscatedDirectory + "/"
                        + gen.nextRandom(ctx.random(), depth) + extension;
            } while (!occupied.add(newPath));

            renamedPaths.put(oldPath, newPath);
        }

        List<Map.Entry<String, String>> replacements = buildReplacements(renamedPaths, topLevelDirectories);
        rewriteClassLiterals(ctx, replacements);
        rewriteTextResources(ctx, replacements);

        Map<String, byte[]> rewritten = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> entry : ctx.resources().entrySet()) {
            String path = renamedPaths.getOrDefault(entry.getKey(), entry.getKey());
            if (rewritten.put(path, entry.getValue()) != null) {
                throw new IllegalStateException("resource collision after asset rename: " + path);
            }
        }
        ctx.resources().clear();
        ctx.resources().putAll(rewritten);

        ctx.log().debug("resourceRenamer renamed " + renamedPaths.size() + " assets in "
                + topLevelDirectories.size() + " directories");
    }

    private static boolean isRenamableAsset(String path, Set<String> excludedNamespaces) {
        if (path == null || !path.startsWith("assets/")) {
            return false;
        }
        String[] parts = path.split("/", 4);
        return parts.length == 4 && !parts[1].isEmpty() && !parts[2].isEmpty()
                && !excludedNamespaces.contains(parts[1]);
    }

    private static List<Map.Entry<String, String>> buildReplacements(Map<String, String> renamedPaths,
                                                                    Map<String, String> directories) {
        Map<String, String> replacements = new LinkedHashMap<>();

        for (Map.Entry<String, String> entry : renamedPaths.entrySet()) {
            AssetPath oldAsset = AssetPath.parse(entry.getKey());
            AssetPath newAsset = AssetPath.parse(entry.getValue());
            String oldRelative = oldAsset.relative();
            String newRelative = newAsset.relative();
            replacements.put(entry.getKey(), entry.getValue());
            replacements.put(oldRelative, newRelative);
        }

        for (Map.Entry<String, String> entry : directories.entrySet()) {
            String[] key = entry.getKey().split("/", 2);
            String oldPrefix = key[1] + "/";
            String newPrefix = entry.getValue() + "/";
            replacements.put("assets/" + key[0] + "/" + oldPrefix,
                    "assets/" + key[0] + "/" + newPrefix);
            replacements.put(oldPrefix, newPrefix);
        }

        List<Map.Entry<String, String>> ordered = new ArrayList<>(replacements.entrySet());
        ordered.sort(Comparator.comparingInt((Map.Entry<String, String> e) -> e.getKey().length()).reversed());
        return ordered;
    }

    private static void rewriteClassLiterals(ObfContext ctx, List<Map.Entry<String, String>> replacements) {
        for (ClassNode cn : ctx.classes()) {
            for (MethodNode method : cn.methods) {
                for (AbstractInsnNode instruction : method.instructions.toArray()) {
                    if (instruction instanceof LdcInsnNode ldc && ldc.cst instanceof String value) {
                        ldc.cst = replace(value, replacements);
                    } else if (instruction instanceof InvokeDynamicInsnNode indy) {
                        for (int i = 0; i < indy.bsmArgs.length; i++) {
                            if (indy.bsmArgs[i] instanceof String value) {
                                indy.bsmArgs[i] = replace(value, replacements);
                            }
                        }
                    }
                }
            }
        }
    }

    private static void rewriteTextResources(ObfContext ctx, List<Map.Entry<String, String>> replacements) {
        for (Map.Entry<String, byte[]> entry : ctx.resources().entrySet()) {
            if (!isText(entry.getKey())) {
                continue;
            }
            String original = new String(entry.getValue(), StandardCharsets.UTF_8);
            String updated = replace(original, replacements);
            if (!original.equals(updated)) {
                entry.setValue(updated.getBytes(StandardCharsets.UTF_8));
            }
        }
    }

    private static boolean isText(String path) {
        int dot = path.lastIndexOf('.');
        return dot >= 0 && TEXT_EXTENSIONS.contains(path.substring(dot + 1).toLowerCase(Locale.ROOT));
    }

    private static String replace(String value, List<Map.Entry<String, String>> replacements) {
        String result = value;
        for (Map.Entry<String, String> replacement : replacements) {
            result = result.replace(replacement.getKey(), replacement.getValue());
        }
        return result;
    }

    private record AssetPath(String namespace, String relative) {

        static AssetPath parse(String path) {
            String[] parts = path.split("/", 3);
            if (parts.length != 3 || !"assets".equals(parts[0])) {
                throw new IllegalArgumentException("not an asset path: " + path);
            }
            return new AssetPath(parts[1], parts[2]);
        }

        String firstSegment() {
            int slash = relative.indexOf('/');
            return slash < 0 ? relative : relative.substring(0, slash);
        }

        String extension() {
            int slash = relative.lastIndexOf('/');
            int dot = relative.lastIndexOf('.');
            return dot > slash ? relative.substring(dot) : "";
        }
    }
}