package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;
import com.nullfuscator.obf.util.NameGenerator;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.Remapper;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class FieldRenamer implements Transformer {

    private static final String[] DEFAULT_ALPHABET = { "I", "l1", "lI", "1l", "ll", "Il" };
    private static final String SEP = ".";

    @Override public String id() { return "fieldRenamer"; }
    @Override public String description() { return "rename fields (alphabetical/opaque)"; }

    @Override
    public void transform(ObfContext ctx) {
        var section = ctx.config().section(id());
        List<String> chars = section.getStringList("chars");
        String[] alphabet = chars.isEmpty() ? DEFAULT_ALPHABET : chars.toArray(new String[0]);
        int depth = Math.max(1, Math.min(32, section.getInt("depth", 8)));
        NameGenerator gen = new NameGenerator(alphabet);

        Map<String, ClassNode> all = ctx.classMap();

        final Map<String, String> superOf = new HashMap<>();
        final Map<String, List<String>> ifacesOf = new HashMap<>();
        final Set<String> declaredFields = new HashSet<>();
        for (ClassNode cn : all.values()) {
            if (cn.superName != null) superOf.put(cn.name, cn.superName);
            if (cn.interfaces != null && !cn.interfaces.isEmpty())
                ifacesOf.put(cn.name, cn.interfaces);
            for (FieldNode fn : cn.fields) {
                declaredFields.add(key(cn.name, fn.name, fn.desc));
                gen.reserve(fn.name);
            }
        }

        String mixinBlob = Remapping.mixinJsonBlob(ctx);

        final Map<String, String> renameFields = new HashMap<>();
        for (ClassNode cn : ctx.targets(id())) {
            if ((cn.access & Opcodes.ACC_ENUM) != 0) continue;
            if ((cn.access & Opcodes.ACC_RECORD) != 0
                    || (cn.recordComponents != null && !cn.recordComponents.isEmpty())) continue;
            if (reflectionSensitive(cn)) continue;
            for (FieldNode fn : cn.fields) {
                if (section.getBoolean("annotatedOnly", false) && !GsonSchemaTransformer.hasName(fn)) continue;
                if (fn.visibleAnnotations != null && fn.visibleAnnotations.stream()
                        .anyMatch(a -> !GsonSchemaTransformer.isGsonAnnotation(a.desc))) continue;
                if ("serialVersionUID".equals(fn.name) || "serialPersistentFields".equals(fn.name)) continue;
                if ((fn.access & Opcodes.ACC_ENUM) != 0) continue;
                if (!mixinBlob.isEmpty() && mixinBlob.contains(fn.name)) continue;
                String nf = gen.nextRandom(ctx.random(), depth);
                renameFields.put(key(cn.name, fn.name, fn.desc), nf);
                ctx.mapping().recordField(cn.name, fn.name, fn.desc, nf);
            }
        }

        if (renameFields.isEmpty()) {
            ctx.log().debug("fieldRenamer: no eligible fields");
            return;
        }

        Remapping.applyRemap(ctx, new Remapper(Opcodes.ASM9) {
            @Override
            public String mapFieldName(String owner, String name, String descriptor) {
                for (String owned : resolutionOrder(owner)) {
                    String k = key(owned, name, descriptor);
                    if (declaredFields.contains(k)) {
                        String mapped = renameFields.get(k);
                        return mapped != null ? mapped : name;
                    }
                }
                return name;
            }

            private List<String> resolutionOrder(String owner) {
                LinkedHashSet<String> order = new LinkedHashSet<>();
                order.add(owner);

                String cur = superOf.get(owner);
                while (cur != null && all.containsKey(cur)) {
                    order.add(cur);
                    cur = superOf.get(cur);
                }

                List<String> queue = new ArrayList<>(order);
                for (int i = 0; i < queue.size(); i++) {
                    List<String> ifs = ifacesOf.get(queue.get(i));
                    if (ifs == null) continue;
                    for (String itf : ifs) {
                        if (all.containsKey(itf) && order.add(itf)) queue.add(itf);
                    }
                }
                return new ArrayList<>(order);
            }
        });

        ctx.log().debug("fieldRenamer renamed " + renameFields.size() + " fields");
    }

    private static boolean reflectionSensitive(ClassNode cn) {
        if (cn.visibleAnnotations != null && !cn.visibleAnnotations.isEmpty()) return true;
        return false;
    }

    private static String key(String owner, String name, String desc) {
        return owner + SEP + name + SEP + desc;
    }
}
