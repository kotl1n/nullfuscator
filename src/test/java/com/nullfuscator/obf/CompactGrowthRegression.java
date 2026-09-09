package com.nullfuscator.obf;

import com.nullfuscator.obf.core.*;
import com.nullfuscator.obf.transform.*;
import com.nullfuscator.obf.util.*;
import org.objectweb.asm.*;
import org.objectweb.asm.commons.SimpleRemapper;
import org.objectweb.asm.tree.*;
import java.util.*;

/** Checks compact helpers against real JVM linkage, not only instruction counts. */
public final class CompactGrowthRegression implements Opcodes {
    private static ObfContext context(String config) {
        return new ObfContext(ObfConfig.parse(config), 1337, new ObfLog(false),
                new NameGenerator(new String[]{"a", "b"}));
    }

    private static ClassNode node(String name, int version) {
        ClassNode node = new ClassNode();
        node.version = version;
        node.access = ACC_PUBLIC;
        node.name = name;
        node.superName = "java/lang/Object";
        return node;
    }

    private static void references(int poolSize) throws Exception {
        ObfContext ctx = context("referenceHiding { enabled:true, hidePercent:100, bootstrapPoolSize:"
                + poolSize + ", variantsPerTarget:2 }\nantiDeobf { enabled:true, level:3, badSignatures:false }");
        String secretName = "секрет\uD801\uDC00\uD800";
        for (int i = 0; i < 24; i++) {
            ClassNode cn = node("compact/Класс" + i, V17);
            MethodNode secret = new MethodNode(ACC_PRIVATE | ACC_STATIC | ACC_SYNTHETIC,
                    secretName, "()I", null, null);
            secret.instructions.add(new LdcInsnNode(123));
            secret.instructions.add(new InsnNode(IRETURN));
            cn.methods.add(secret);
            // An input synthetic method must still receive protection.
            MethodNode run = new MethodNode(ACC_PUBLIC | ACC_STATIC | ACC_SYNTHETIC,
                    "run", "()I", null, null);
            run.instructions.add(new InsnNode(ICONST_0));
            for (int call = 0; call < 50; call++) {
                run.instructions.add(new MethodInsnNode(INVOKESTATIC, cn.name, secretName, "()I", false));
                run.instructions.add(new InsnNode(IADD));
            }
            run.instructions.add(new InsnNode(IRETURN));
            cn.methods.add(run);
            cn.interfaces.add("java/util/function/IntSupplier");
            MethodNode init = new MethodNode(ACC_PUBLIC, "<init>", "()V", null, null);
            init.instructions.add(new VarInsnNode(ALOAD, 0));
            init.instructions.add(new MethodInsnNode(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false));
            init.instructions.add(new InsnNode(RETURN));
            cn.methods.add(init);
            MethodNode virtual = new MethodNode(ACC_PRIVATE, "virtual", "()I", null, null);
            virtual.instructions.add(new InsnNode(ICONST_5));
            virtual.instructions.add(new InsnNode(IRETURN));
            cn.methods.add(virtual);
            MethodNode supplier = new MethodNode(ACC_PUBLIC, "getAsInt", "()I", null, null);
            supplier.instructions.add(new VarInsnNode(ALOAD, 0));
            supplier.instructions.add(new MethodInsnNode(INVOKESPECIAL, cn.name, "virtual", "()I", false));
            supplier.instructions.add(new InsnNode(IRETURN));
            cn.methods.add(supplier);
            MethodNode indirect = new MethodNode(ACC_PUBLIC | ACC_STATIC, "indirect", "()I", null, null);
            indirect.instructions.add(new TypeInsnNode(NEW, cn.name));
            indirect.instructions.add(new InsnNode(DUP));
            indirect.instructions.add(new MethodInsnNode(INVOKESPECIAL, cn.name, "<init>", "()V", false));
            indirect.instructions.add(new MethodInsnNode(INVOKEINTERFACE, "java/util/function/IntSupplier",
                    "getAsInt", "()I", true));
            indirect.instructions.add(new InsnNode(IRETURN));
            cn.methods.add(indirect);
            ctx.putClass(cn);
        }
        ctx.initializePolicies();
        for (ClassNode cn : ctx.classes()) {
            MethodNode generated = new MethodNode(ACC_PUBLIC | ACC_STATIC, "generated", "()I", null, null);
            generated.instructions.add(new InsnNode(ICONST_M1));
            generated.instructions.add(new MethodInsnNode(INVOKESTATIC, "java/lang/Math", "abs", "(I)I", false));
            generated.instructions.add(new InsnNode(IRETURN));
            cn.methods.add(generated);
        }
        // Provenance must survive ASM rebuilding every class and method.
        Map<String, String> renames = new HashMap<>();
        for (ClassNode cn : ctx.classes()) renames.put(cn.name, cn.name + "Renamed");
        Remapping.applyRemap(ctx, new SimpleRemapper(renames));
        new ReferenceHidingTransformer().transform(ctx);
        Set<String> hosts = new HashSet<>();
        for (int i = 0; i < 24; i++) {
            ClassNode cn = ctx.getClass("compact/Класс" + i + "Renamed");
            Set<String> variants = new HashSet<>();
            int calls = 0;
            for (MethodNode mn : cn.methods) {
                if (mn.name.equals("generated"))
                    GrowthRegression.check(mn.instructions.get(1) instanceof MethodInsnNode,
                            "generated helper recursively hidden after remapping");
                if (!mn.name.equals("run")) continue;
                for (AbstractInsnNode insn : mn.instructions) {
                    if (!(insn instanceof InvokeDynamicInsnNode indy)) continue;
                    calls++;
                    hosts.add(indy.bsm.getOwner());
                    variants.add(indy.name);
                    String cipher = (String) indy.bsmArgs[0];
                    GrowthRegression.check(cipher.chars().allMatch(c -> c <= 255), "wide cipher payload");
                }
            }
            GrowthRegression.check(calls == 50 && variants.size() == 2,
                    "reference coverage or target reuse changed: " + calls + "/" + variants.size());
        }
        GrowthRegression.check(hosts.size() == (poolSize == 0 ? 24 : poolSize), "bootstrap pool escaped");
        GrowthRegression.check(ctx.classes().size() == 24 + poolSize, "unexpected helper classes");
        new AntiDeobfuscatorTransformer().transform(ctx);
        ClassLoader loader = GrowthRegression.loader(ctx);
        for (int i = 0; i < 24; i++) {
            String owner = "compact/Класс" + i + "Renamed";
            for (MethodNode mn : ctx.getClass(owner).methods)
                if (mn.name.equals("generated"))
                    GrowthRegression.check(mn.instructions.size() == 3, "generated helper received trap");
            Class<?> type = loader.loadClass(owner.replace('/', '.'));
            GrowthRegression.check(type.getMethod("run").invoke(null).equals(6150), "private lookup failed");
            GrowthRegression.check(type.getMethod("indirect").invoke(null).equals(5), "special/interface lookup failed");
            GrowthRegression.check(type.getMethod("generated").invoke(null).equals(1), "helper changed");
        }
        System.out.println("PASS compact references: pool=" + poolSize + ", Unicode, private lookup, reuse, provenance");
    }

    private static void strings(int version, boolean fieldOnly) throws Exception {
        ObfContext ctx = context("stringEncryption { enabled:true, type:POLYMORPHIC }");
        ClassNode cn = node("CompactStrings", version);
        String value = "hello \u0000 Привет \uD801\uDC00 \uD800";
        MethodNode run = new MethodNode(ACC_PUBLIC | ACC_STATIC, "run", "()Ljava/lang/String;", null, null);
        if (fieldOnly) {
            cn.fields.add(new FieldNode(ACC_PUBLIC | ACC_STATIC | ACC_FINAL, "value", "Ljava/lang/String;", null, value));
            run.instructions.add(new FieldInsnNode(GETSTATIC, cn.name, "value", "Ljava/lang/String;"));
        } else run.instructions.add(new LdcInsnNode(value));
        run.instructions.add(new InsnNode(ARETURN));
        cn.methods.add(run);
        ctx.putClass(cn);
        new StringEncryptionTransformer().transform(ctx);
        int expectedMethods = fieldOnly ? 3 : version >= V11 ? 3 : 2;
        GrowthRegression.check(cn.methods.size() == expectedMethods, "unused decoder family emitted");
        GrowthRegression.check(GrowthRegression.loader(ctx).loadClass(cn.name).getMethod("run")
                .invoke(null).equals(value), "string changed");
        System.out.println("PASS compact strings: version=" + version + ", fieldOnly=" + fieldOnly);
    }

    private static void oversizedReference() throws Exception {
        ObfContext ctx = context("referenceHiding { enabled:true, hidePercent:100 }");
        ClassNode cn = node("LongReference", V17);
        String name = "\u0800".repeat(21000);
        MethodNode target = new MethodNode(ACC_PUBLIC | ACC_STATIC, name, "()I", null, null);
        target.instructions.add(new InsnNode(ICONST_5));
        target.instructions.add(new InsnNode(IRETURN));
        cn.methods.add(target);
        MethodNode run = new MethodNode(ACC_PUBLIC | ACC_STATIC, "run", "()I", null, null);
        run.instructions.add(new MethodInsnNode(INVOKESTATIC, cn.name, name, "()I", false));
        run.instructions.add(new InsnNode(IRETURN));
        cn.methods.add(run);
        ctx.putClass(cn);
        new ReferenceHidingTransformer().transform(ctx);
        GrowthRegression.check(run.instructions.getFirst() instanceof MethodInsnNode, "oversized payload emitted");
        GrowthRegression.check(GrowthRegression.loader(ctx).loadClass(cn.name).getMethod("run")
                .invoke(null).equals(5), "long reference changed");
        System.out.println("PASS oversized encrypted reference: valid input remains loadable");
    }

    private static void numericComposition() throws Exception {
        ObfContext ctx = context("numberEncryption { enabled:true, layers:5 }\n"
                + "antiAI { enabled:true, level:1, decoyMethods:0, constantEncodingPercent:100 }");
        ClassNode cn = node("CompactNumbers", V17);
        MethodNode run = new MethodNode(ACC_PUBLIC | ACC_STATIC, "run", "()I", null, null);
        run.instructions.add(new LdcInsnNode(1234567));
        run.instructions.add(new InsnNode(IRETURN));
        cn.methods.add(run);
        ctx.putClass(cn);
        ctx.initializePolicies();
        new NumberEncryptionTransformer().transform(ctx);
        int size = run.instructions.size();
        new AntiAiTransformer().transform(ctx);
        GrowthRegression.check(size == run.instructions.size(), "encrypted keys re-encoded by antiAI");
        GrowthRegression.check(GrowthRegression.loader(ctx).loadClass(cn.name).getMethod("run")
                .invoke(null).equals(1234567), "numeric composition changed value");
        System.out.println("PASS numeric composition: no recursive key expansion");
    }

    public static void main(String[] args) throws Exception {
        numericComposition();
        oversizedReference();
        references(0);
        references(1);
        references(8);
        strings(V1_8, false);
        strings(V17, false);
        strings(V17, true);
    }
}
