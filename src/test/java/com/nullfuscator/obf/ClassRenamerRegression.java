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
        pluginDescriptorRemapping();
        partialMixinRemapping();
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

    private static void pluginDescriptorRemapping() {
        ObfContext context = new ObfContext(ObfConfig.parse("""
                classRenamer { enabled: true, prefix: "a/", chars: [ "I", "l" ], depth: 3 }
                """), 23L, new ObfLog(false), new NameGenerator(new String[] { "I", "l" }));

        ClassNode mainNode = type("fixture/plugin/SamplePlugin");
        mainNode.superName = "org/bukkit/plugin/java/JavaPlugin";
        context.putClass(mainNode);

        ClassNode helperNode = type("fixture/plugin/util/Helper");
        context.putClass(helperNode);

        String yaml = """
                name: SamplePlugin
                version: 1.0.0
                main: fixture.plugin.SamplePlugin
                author: Developer
                """;
        context.resources().put("plugin.yml", yaml.getBytes(StandardCharsets.UTF_8));

        new ClassRenamer().transform(context);

        check(context.getClass("fixture/plugin/SamplePlugin") == null,
                "Plugin main class was not renamed");

        byte[] updatedYamlBytes = context.resources().get("plugin.yml");
        check(updatedYamlBytes != null, "plugin.yml missing from resources");
        String updatedYaml = new String(updatedYamlBytes, StandardCharsets.UTF_8);

        check(!updatedYaml.contains("fixture.plugin.SamplePlugin"),
                "plugin.yml still contains original main class name");
        check(updatedYaml.contains("main: a."),
                "plugin.yml does not contain remapped dotted main class name: " + updatedYaml);
        System.out.println("PASS plugin descriptor remapping: " + updatedYaml.trim().replace("\n", " | "));
    }

    private static void partialMixinRemapping() {
        ObfContext context = new ObfContext(ObfConfig.parse("""
                defaults { partialMixins: true }
                classRenamer { enabled: true, chars: [ "I", "l" ], depth: 3 }
                """), 23L, new ObfLog(false), new NameGenerator(new String[] { "I", "l" }));

        String pkg = "com.sample.mod.mixin";
        String prefix = pkg.replace('.', '/') + "/";
        String[] mixins = { "SampleEntityMixin", "SampleScreenMixin" };
        for (String m : mixins) {
            ClassNode node = type(prefix + m);
            node.visibleAnnotations = new ArrayList<>(java.util.List.of(
                    new org.objectweb.asm.tree.AnnotationNode("Lorg/spongepowered/asm/mixin/Mixin;")));
            context.putClass(node);
        }

        String json = """
                {
                  "package": "com.sample.mod.mixin",
                  "client": [
                    "SampleEntityMixin",
                    "SampleScreenMixin"
                  ]
                }
                """;
        context.resources().put("mixins.json", json.getBytes(StandardCharsets.UTF_8));

        String refmap = """
                {
                  "mappings": {
                    "com/sample/mod/mixin/SampleEntityMixin": {
                      "render": "m_1234"
                    }
                  }
                }
                """;
        context.resources().put("sample.refmap.json", refmap.getBytes(StandardCharsets.UTF_8));

        new ClassRenamer().transform(context);

        check(context.getClass(prefix + "SampleEntityMixin") == null, "SampleEntityMixin was not renamed under partialMixins");
        check(context.getClass(prefix + "SampleScreenMixin") == null, "SampleScreenMixin was not renamed under partialMixins");

        byte[] updatedJsonBytes = context.resources().get("mixins.json");
        String updatedJson = new String(updatedJsonBytes, StandardCharsets.UTF_8);
        check(!updatedJson.contains("SampleEntityMixin"), "mixins.json still contains SampleEntityMixin");
        check(!updatedJson.contains("SampleScreenMixin"), "mixins.json still contains SampleScreenMixin");
        check(updatedJson.contains("\"package\": \"com.sample.mod.mixin\""), "package changed in mixins.json");

        byte[] updatedRefmapBytes = context.resources().get("sample.refmap.json");
        String updatedRefmap = new String(updatedRefmapBytes, StandardCharsets.UTF_8);
        check(!updatedRefmap.contains("com/sample/mod/mixin/SampleEntityMixin"), "refmap still contains old mixin name");
        check(updatedRefmap.contains("com/sample/mod/mixin/"), "refmap does not contain new mixin name");

        System.out.println("PASS partial mixin remapping: mixins.json and refmap updated successfully");
    }
}