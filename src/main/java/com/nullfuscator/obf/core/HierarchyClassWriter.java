package com.nullfuscator.obf.core;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class HierarchyClassWriter extends ClassWriter {
    private final Hierarchy hierarchy;

    public HierarchyClassWriter(int flags, Map<String, ClassNode> classes) {
        this(flags, new Hierarchy(classes, HierarchyClassWriter.class.getClassLoader()));
    }

    HierarchyClassWriter(int flags, Hierarchy hierarchy) {
        super(flags);
        this.hierarchy = hierarchy;
    }

    @Override
    protected String getCommonSuperClass(String type1, String type2) {
        return hierarchy.common(type1, type2);
    }

    // Scoped to one immutable class-map snapshot / archive write, never shared across jobs.
    static final class Hierarchy {
        private static final String OBJECT = "java/lang/Object";
        private final Map<String, ClassNode> classes;
        private final ClassLoader loader;
        private final Map<String, Info> metadata = new HashMap<>();
        private final Map<String, Set<String>> ancestors = new HashMap<>();
        private final Map<Pair, String> commonTypes = new HashMap<>();

        Hierarchy(Map<String, ClassNode> classes, ClassLoader loader) {
            this.classes = classes;
            this.loader = loader;
        }

        String common(String a, String b) {
            if (a.equals(b)) return a;
            Pair key = a.compareTo(b) < 0 ? new Pair(a, b) : new Pair(b, a);
            String cached = commonTypes.get(key);
            if (cached != null) return cached;
            String result = merge(a, b);
            commonTypes.put(key, result);
            return result;
        }

        private String merge(String a, String b) {
            if (assignable(a, b)) return a;
            if (assignable(b, a)) return b;
            if (a.startsWith("[") && b.startsWith("[")) {
                String ac = component(a), bc = component(b);
                if (ac != null && bc != null) {
                    String merged = common(ac, bc);
                    return merged.startsWith("[") ? "[" + merged : "[L" + merged + ";";
                }
                return OBJECT;
            }
            if (a.startsWith("[") || b.startsWith("[")) return OBJECT;
            if (info(a).itf || info(b).itf) return OBJECT;
            Set<String> seen = new HashSet<>();
            String parent = info(a).parent;
            while (parent != null && seen.add(parent)) {
                if (assignable(parent, b)) return parent;
                parent = info(parent).parent;
            }
            return OBJECT;
        }

        private boolean assignable(String target, String source) {
            if (target.equals(source) || OBJECT.equals(target)) return true;
            if (source.startsWith("[")) {
                if (target.equals("java/lang/Cloneable") || target.equals("java/io/Serializable"))
                    return true;
                if (!target.startsWith("[")) return false;
                String tc = component(target), sc = component(source);
                return tc != null && sc != null && assignable(tc, sc);
            }
            if (target.startsWith("[")) return false;
            return ancestors(source).contains(target);
        }

        // Null denotes a primitive component; primitive arrays are only covariant by identity.
        private static String component(String array) {
            String c = array.substring(1);
            if (c.startsWith("[")) return c;
            return c.startsWith("L") ? c.substring(1, c.length() - 1) : null;
        }

        private Set<String> ancestors(String name) {
            Set<String> cached = ancestors.get(name);
            if (cached != null) return cached;
            Set<String> result = new HashSet<>();
            ArrayDeque<String> queue = new ArrayDeque<>();
            queue.add(name);
            while (!queue.isEmpty()) {
                String next = queue.removeFirst();
                if (!result.add(next)) continue;
                Info info = info(next);
                if (info.parent != null) queue.add(info.parent);
                queue.addAll(info.interfaces);
            }
            ancestors.put(name, result);
            return result;
        }

        private Info info(String name) {
            Info cached = metadata.get(name);
            if (cached != null) return cached;
            ClassNode node = classes.get(name);
            Info result;
            if (node != null) {
                result = new Info(node.superName, List.copyOf(node.interfaces),
                        (node.access & Opcodes.ACC_INTERFACE) != 0);
            } else {
                // Read headers without defining or initializing dependency classes.
                try (InputStream in = loader.getResourceAsStream(name + ".class")) {
                    if (in == null) throw new IllegalStateException(
                            "Missing hierarchy type " + name + "; add its dependency to libs");
                    ClassReader reader = new ClassReader(in);
                    result = new Info(reader.getSuperName(), List.of(reader.getInterfaces()),
                            (reader.getAccess() & Opcodes.ACC_INTERFACE) != 0);
                } catch (IOException e) {
                    throw new IllegalStateException("Cannot read hierarchy type " + name, e);
                }
            }
            metadata.put(name, result);
            return result;
        }

        private record Info(String parent, List<String> interfaces, boolean itf) { }
        private record Pair(String a, String b) { }
    }
}
