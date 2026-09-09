package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.ObfContext;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.Remapper;
import org.objectweb.asm.tree.ClassNode;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashSet;
import java.util.Set;
import com.typesafe.config.ConfigFactory;
import com.typesafe.config.ConfigList;
import com.typesafe.config.ConfigObject;
import com.typesafe.config.ConfigValue;
import com.typesafe.config.ConfigValueType;

public final class Remapping {

    private Remapping() {}

    public static void applyRemap(ObfContext ctx, Remapper remapper) {
        List<ClassNode> oldNodes = ctx.snapshot();
        List<ClassNode> newNodes = new ArrayList<>(oldNodes.size());
        for (ClassNode old : oldNodes) {
            ClassNode nn = new ClassNode();
            old.accept(new ClassRemapper(nn, remapper));
            ctx.transferMethodOrigins(old, nn);
            newNodes.add(nn);
        }
        Map<String, ClassNode> map = ctx.classMap();
        map.clear();
        for (ClassNode nn : newNodes) map.put(nn.name, nn);
        ctx.reindex();
    }

    public static String mainClassInternalName(ObfContext ctx) {
        byte[] data = ctx.resources().get("META-INF/MANIFEST.MF");
        if (data == null) return null;
        try {
            java.util.jar.Manifest mf = new java.util.jar.Manifest(new ByteArrayInputStream(data));
            String mc = mf.getMainAttributes().getValue("Main-Class");
            if (mc == null) return null;
            mc = mc.trim();
            return mc.isEmpty() ? null : mc.replace('.', '/');
        } catch (Exception e) {
            return null;
        }
    }

    public static String mixinJsonBlob(ObfContext ctx) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, byte[]> e : ctx.resources().entrySet()) {
            String key = e.getKey();
            if (key == null) continue;
            if (key.endsWith(".mixins.json") || key.equals("fabric.mod.json")
                    || key.endsWith("/fabric.mod.json")) {
                sb.append(new String(e.getValue(), StandardCharsets.UTF_8)).append('\n');
            }
        }
        return sb.toString();
    }

    /** Classes named by known runtime resources must retain their external names. */
    public static Set<String> resourceClassReferences(ObfContext ctx) {
        Set<String> references = new HashSet<>();
        for (Map.Entry<String, byte[]> entry : ctx.resources().entrySet()) {
            String path = entry.getKey();
            String text = new String(entry.getValue(), StandardCharsets.UTF_8);
            if (path.equals("fabric.mod.json") || path.endsWith("/fabric.mod.json")) {
                try { collectStrings(ConfigFactory.parseString(text).root(), references); }
                catch (RuntimeException e) { ctx.log().warn("cannot inspect class references in " + path); }
            } else if (path.endsWith(".mixins.json")) {
                try {
                    var config = ConfigFactory.parseString(text);
                    String pkg = config.hasPath("package") ? config.getString("package") : "";
                    for (String key : new String[] { "mixins", "client", "server" }) {
                        if (!config.hasPath(key)) continue;
                        for (String value : config.getStringList(key))
                            references.add((value.indexOf('.') >= 0 || pkg.isEmpty() ? value : pkg + "." + value)
                                    .replace('.', '/'));
                    }
                } catch (RuntimeException e) { ctx.log().warn("cannot inspect mixin references in " + path); }
            } else if (path.endsWith(".accesswidener")) {
                for (String token : text.split("\\s+")) if (ctx.getClass(token) != null) references.add(token);
            }
        }
        Set<String> existing = new HashSet<>();
        for (String value : references) {
            String candidate = value.replace('.', '/');
            int method = candidate.indexOf("::");
            if (method >= 0) candidate = candidate.substring(0, method);
            if (ctx.getClass(candidate) != null) existing.add(candidate);
        }
        return existing;
    }

    private static void collectStrings(ConfigValue value, Set<String> out) {
        if (value.valueType() == ConfigValueType.STRING) out.add((String) value.unwrapped());
        else if (value instanceof ConfigObject object)
            for (ConfigValue child : object.values()) collectStrings(child, out);
        else if (value instanceof ConfigList list)
            for (ConfigValue child : list) collectStrings(child, out);
    }
}
