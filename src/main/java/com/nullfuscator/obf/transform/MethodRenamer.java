package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;
import com.nullfuscator.obf.util.NameGenerator;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.Remapper;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class MethodRenamer implements Transformer {

    private static final String[] DEFAULT_ALPHABET = { "I", "l1", "lI", "1l", "ll", "Il" };
    private static final String SEP = ".";
    private static final String MIXIN_PREFIX = "Lorg/spongepowered/asm/mixin/";

    @Override public String id() { return "methodRenamer"; }
    @Override public String description() { return "rename private/static methods"; }

    @Override
    public void transform(ObfContext ctx) {
        try (URLClassLoader loader = buildLibLoader(ctx)) {
            transform(ctx, loader);
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot close method-renaming dependencies", e);
        }
    }

    private void transform(ObfContext ctx, ClassLoader libLoader) {
        var section = ctx.config().section(id());
        int depth = Math.max(1, Math.min(32, section.getInt("depth", 8)));
        boolean renameVirtual = section.getBoolean("renameVirtual", false);
        boolean renamePublic = section.getBoolean("renamePublic", false);
        List<String> chars = section.getStringList("chars");
        String[] alphabet = chars.isEmpty() ? DEFAULT_ALPHABET : chars.toArray(new String[0]);
        NameGenerator gen = new NameGenerator(alphabet);

        Map<String, ClassNode> all = ctx.classMap();

        final Map<String, String> superOf = new HashMap<>();
        final Map<String, List<String>> ifacesOf = new HashMap<>();
        final Set<String> declaredMethods = new HashSet<>();
        for (ClassNode cn : all.values()) {
            if (cn.superName != null) superOf.put(cn.name, cn.superName);
            if (cn.interfaces != null && !cn.interfaces.isEmpty())
                ifacesOf.put(cn.name, cn.interfaces);
            for (MethodNode mn : cn.methods) {
                declaredMethods.add(key(cn.name, mn.name, mn.desc));
                gen.reserve(mn.name);
            }
        }

        final Map<String, String> renameMethods = new HashMap<>();
        List<ClassNode> targets = ctx.targets(id());
        Set<String> targetOwners = new HashSet<>();
        for (ClassNode cn : targets) targetOwners.add(cn.name);
        int skippedLib = 0;
        for (ClassNode cn : targets) {
            if ((cn.access & (Opcodes.ACC_ENUM | Opcodes.ACC_ANNOTATION)) != 0) continue;
            for (MethodNode mn : cn.methods) {
                if (!eligible(mn)) continue;
                if (isRecordAccessor(cn, mn)) continue;
                if (hasMixinAnnotation(mn)) continue;
                if (matchesNonOwnedSuper(cn.name, mn.name, mn.desc, all, superOf, ifacesOf, libLoader)) {
                    skippedLib++;
                    continue;
                }
                String nm = gen.nextRandom(ctx.random(), depth);
                renameMethods.put(key(cn.name, mn.name, mn.desc), nm);
                ctx.mapping().recordMethod(cn.name, mn.name, mn.desc, nm);
            }
        }

        int virtualRenamed = 0;
        if (renameVirtual) {
            Map<String, List<Decl>> groups = new HashMap<>();
            for (ClassNode cn : all.values()) {
                for (MethodNode mn : cn.methods) {
                    if (!virtualCandidate(mn)) continue;
                    groups.computeIfAbsent(mn.name + SEP + mn.desc, k -> new ArrayList<>())
                            .add(new Decl(cn, mn));
                }
            }
            for (List<Decl> group : groups.values()) {
                boolean safe = true;
                for (Decl d : group) {
                    ClassNode cn = d.owner();
                    MethodNode mn = d.method();
                    if (!targetOwners.contains(cn.name)
                            || (cn.access & (Opcodes.ACC_ENUM | Opcodes.ACC_ANNOTATION)) != 0
                            || isRecordAccessor(cn, mn)
                            || hasMixinAnnotation(mn)
                            || (!renamePublic && (mn.access & Opcodes.ACC_PUBLIC) != 0)
                            || matchesNonOwnedSuper(cn.name, mn.name, mn.desc,
                                    all, superOf, ifacesOf, libLoader)) {
                        safe = false;
                        break;
                    }
                }
                if (!safe) continue;
                String mapped = gen.nextRandom(ctx.random(), depth);
                for (Decl d : group) {
                    renameMethods.put(key(d.owner().name, d.method().name, d.method().desc), mapped);
                    ctx.mapping().recordMethod(d.owner().name, d.method().name, d.method().desc, mapped);
                    virtualRenamed++;
                }
            }
        }

        if (renameMethods.isEmpty()) {
            ctx.log().debug("methodRenamer: no eligible methods (depth=" + depth
                    + ", skippedForLibrary=" + skippedLib + ")");
            return;
        }

        Remapping.applyRemap(ctx, new Remapper(Opcodes.ASM9) {
            private final Map<String, List<String>> resolutionCache = new HashMap<>();

            @Override
            public String mapMethodName(String owner, String name, String descriptor) {
                for (String owned : resolutionOrder(owner)) {
                    String k = key(owned, name, descriptor);
                    if (declaredMethods.contains(k)) {
                        String mapped = renameMethods.get(k);
                        return mapped != null ? mapped : name;
                    }
                }
                return name;
            }

            private List<String> resolutionOrder(String owner) {
                return resolutionCache.computeIfAbsent(owner, this::computeResolutionOrder);
            }

            private List<String> computeResolutionOrder(String owner) {
                LinkedHashSet<String> order = new LinkedHashSet<>();
                order.add(owner);
                String cur = superOf.get(owner);
                while (cur != null && all.containsKey(cur) && order.add(cur)) {
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

        ctx.log().debug("methodRenamer renamed " + renameMethods.size()
                + " methods (virtual=" + virtualRenamed
                + ", skippedForLibrary=" + skippedLib + ")");
    }

    private static boolean eligible(MethodNode mn) {
        if (isSerializationHook(mn) || isAgentEntrypoint(mn)) return false;
        if ("<init>".equals(mn.name) || "<clinit>".equals(mn.name)) return false;
        if ("main".equals(mn.name) && "([Ljava/lang/String;)V".equals(mn.desc)) return false;
        if ((mn.access & Opcodes.ACC_NATIVE) != 0) return false;
        boolean privateOrStatic =
                (mn.access & Opcodes.ACC_PRIVATE) != 0 || (mn.access & Opcodes.ACC_STATIC) != 0;
        return privateOrStatic;
    }

    private static boolean virtualCandidate(MethodNode mn) {
        if (isSerializationHook(mn) || isAgentEntrypoint(mn)) return false;
        if ("<init>".equals(mn.name) || "<clinit>".equals(mn.name)) return false;
        if ("main".equals(mn.name) && "([Ljava/lang/String;)V".equals(mn.desc)) return false;
        if ((mn.access & (Opcodes.ACC_NATIVE | Opcodes.ACC_STATIC | Opcodes.ACC_PRIVATE)) != 0)
            return false;
        return true;
    }

    // The JVM discovers agent callbacks by name, without a bytecode call site.
    static boolean isAgentEntrypoint(MethodNode mn) {
        return (mn.access & (Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC))
                == (Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC)
                && (mn.name.equals("premain") || mn.name.equals("agentmain"))
                && (mn.desc.equals("(Ljava/lang/String;)V")
                    || mn.desc.equals("(Ljava/lang/String;Ljava/lang/instrument/Instrumentation;)V"));
    }

    // Object streams discover these methods by name, without a bytecode call site to remap.
    static boolean isSerializationHook(MethodNode mn) {
        return switch (mn.name) {
            case "readObject" -> mn.desc.equals("(Ljava/io/ObjectInputStream;)V");
            case "writeObject" -> mn.desc.equals("(Ljava/io/ObjectOutputStream;)V");
            case "readObjectNoData" -> mn.desc.equals("()V");
            case "readResolve", "writeReplace" -> mn.desc.equals("()Ljava/lang/Object;");
            default -> false;
        };
    }

    private static boolean hasMixinAnnotation(MethodNode mn) {
        return hasMixin(mn.visibleAnnotations) || hasMixin(mn.invisibleAnnotations);
    }

    private static boolean hasMixin(List<AnnotationNode> anns) {
        if (anns == null) return false;
        for (AnnotationNode an : anns) {
            if (an.desc != null && an.desc.startsWith(MIXIN_PREFIX)) return true;
        }
        return false;
    }

    private static boolean matchesNonOwnedSuper(String owner, String name, String desc,
                                                Map<String, ClassNode> all,
                                                Map<String, String> superOf,
                                                Map<String, List<String>> ifacesOf,
                                                ClassLoader libLoader) {
        Deque<String> work = new ArrayDeque<>();
        Set<String> seen = new HashSet<>();
        enqueueOwnedSupers(owner, all, superOf, ifacesOf, work, seen);
        while (!work.isEmpty()) {
            String s = work.poll();
            if (s == null || !seen.add(s)) continue;
            ClassNode ocn = all.get(s);
            if (ocn != null) {

                enqueueOwnedSupers(s, all, superOf, ifacesOf, work, seen);
                continue;
            }
            Class<?> c = tryLoad(s, libLoader);
            if (c == null) return true;
            if (declaresMethod(c, name, desc)) return true;
            enqueueReflectiveSupers(c, work);
        }
        return false;
    }

    private static void enqueueOwnedSupers(String type, Map<String, ClassNode> all,
                                           Map<String, String> superOf,
                                           Map<String, List<String>> ifacesOf,
                                           Deque<String> work, Set<String> seen) {
        String sup = superOf.get(type);
        if (sup == null) {
            ClassNode cn = all.get(type);
            if (cn != null && cn.superName != null) sup = cn.superName;
        }
        if (sup != null && !seen.contains(sup)) work.add(sup);
        List<String> ifs = ifacesOf.get(type);
        if (ifs == null) {
            ClassNode cn = all.get(type);
            if (cn != null) ifs = cn.interfaces;
        }
        if (ifs != null) for (String i : ifs) if (!seen.contains(i)) work.add(i);
    }

    private static void enqueueReflectiveSupers(Class<?> c, Deque<String> work) {
        Class<?> sup = c.getSuperclass();
        if (sup != null) work.add(sup.getName().replace('.', '/'));
        for (Class<?> i : c.getInterfaces()) work.add(i.getName().replace('.', '/'));
    }

    private static boolean declaresMethod(Class<?> c, String name, String desc) {
        try {
            for (java.lang.reflect.Method m : c.getDeclaredMethods()) {
                if (m.getName().equals(name) && Type.getMethodDescriptor(m).equals(desc)) return true;
            }
        } catch (Throwable ignored) {
            return true;
        }
        return false;
    }

    private static Class<?> tryLoad(String internalName, ClassLoader loader) {
        try {
            return Class.forName(internalName.replace('/', '.'), false, loader);
        } catch (Throwable t) {
            return null;
        }
    }

    private static URLClassLoader buildLibLoader(ObfContext ctx) {
        List<URL> urls = new ArrayList<>();
        for (String p : ctx.config().libs()) {
            if (p == null || p.isEmpty()) continue;
            try {
                File f = new File(p);
                if (f.exists()) urls.add(f.toURI().toURL());
            } catch (Exception ignored) {  }
        }
        ClassLoader parent = MethodRenamer.class.getClassLoader();
        return new URLClassLoader(urls.toArray(new URL[0]), parent);
    }

    private static String key(String owner, String name, String desc) {
        return owner + SEP + name + SEP + desc;
    }

    private record Decl(ClassNode owner, MethodNode method) { }

    private static boolean isRecordAccessor(ClassNode cn, MethodNode mn) {
        if (cn.recordComponents == null || cn.recordComponents.isEmpty()) return false;
        for (var rc : cn.recordComponents) {
            if (mn.name.equals(rc.name) && mn.desc.equals("()" + rc.descriptor)) return true;
        }
        return false;
    }
}
