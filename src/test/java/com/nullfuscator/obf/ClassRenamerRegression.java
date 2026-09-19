package com.nullfuscator.obf;

import com.nullfuscator.obf.core.ObfConfig;
import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.transform.ClassRenamer;
import com.nullfuscator.obf.util.NameGenerator;
import com.nullfuscator.obf.util.ObfLog;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InnerClassNode;

import java.util.ArrayList;
import java.nio.charset.StandardCharsets;

public final class ClassRenamerRegression {

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    public static void main(String[] args) {
        ObfContext context = new ObfContext(ObfConfig.parse("""
                classRenamer { enabled: true, prefix: "a/", chars: [ "I", "l" ], depth: 3 }
                """), 23L, new ObfLog(false), new NameGenerator(new String[] { "I", "l" }));

        ClassNode outer = type("fixture/Outer");
        ClassNode inner = type("fixture/Outer$FeatureName");

        InnerClassNode entry = new InnerClassNode(
                "fixture/Outer$FeatureName", "fixture/Outer", "FeatureName",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC);
        outer.innerClasses = new ArrayList<>(java.util.List.of(entry));
        inner.innerClasses = new ArrayList<>(java.util.List.of(new InnerClassNode(
                "fixture/Outer$FeatureName", "fixture/Outer", "FeatureName",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC)));

        context.putClass(outer);
        context.putClass(inner);

        new ClassRenamer().transform(context);

        for (ClassNode node : context.classes()) {
            for (InnerClassNode metadata : node.innerClasses) {
                if (metadata.innerName != null) {
                    check(!"FeatureName".equals(metadata.innerName),
                            "inner class simple name leaked after class renaming");
                }
            }
        }
        System.out.println("PASS class renamer inner-class metadata");

        mixinReferences("ru.ezdlc.mixin");
        mixinReferences("");
        mixinReferences(null);
    }

    private static void mixinReferences(String pkg) {
        ObfContext context = new ObfContext(ObfConfig.parse("classRenamer { enabled: true }"),
                23L, new ObfLog(false), new NameGenerator(new String[] { "I", "l" }));

        String prefix = pkg == null || pkg.isEmpty() ? "" : pkg.replace('.', '/') + "/";
        String[] mixins = {
                "CommonMixin",
                "accessors/FramebufferAccessor",
                "server/nested/ServerMixin$Inner"
        };
        for (String mixin : mixins) {
            context.putClass(type(prefix + mixin));
        }
        context.putClass(type("fixture/Unreferenced"));

        String metadata = "{" + (pkg == null ? "" : "\"package\":\"" + pkg + "\",") + """
                "mixins":["CommonMixin"],
                "client":["accessors.FramebufferAccessor"],
                "server":["server.nested.ServerMixin$Inner"]}
                """;

        byte[] bytes = metadata.getBytes(StandardCharsets.UTF_8);
        context.resources().put("ezdlc.mixins.json", bytes);

        new ClassRenamer().transform(context);

        for (String mixin : mixins) {
            check(context.getClass(prefix + mixin) != null,
                    "Mixin config no longer resolves class: " + prefix + mixin);
        }
        check(context.getClass("fixture/Unreferenced") == null, "ordinary class was not renamed");
        check(java.util.Arrays.equals(bytes, context.resources().get("ezdlc.mixins.json")),
                "Mixin config changed while preserving class names");
        System.out.println("PASS mixin class references, package=" + pkg);
    }

    private static ClassNode type(String name) {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V17;
        node.access = Opcodes.ACC_PUBLIC;
        node.name = name;
        node.superName = "java/lang/Object";
        return node;
    }
}