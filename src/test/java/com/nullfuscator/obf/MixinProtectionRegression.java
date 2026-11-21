package com.nullfuscator.obf;

import com.nullfuscator.obf.core.*;
import com.nullfuscator.obf.util.*;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.util.TraceClassVisitor;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;

public final class MixinProtectionRegression {
    public static void main(String[] args) throws Exception {
        var factory = Main.class.getDeclaredMethod("buildPipeline");
        factory.setAccessible(true);
        @SuppressWarnings("unchecked")
        List<Transformer> pipeline = (List<Transformer>) factory.invoke(null);
        for (boolean visible : new boolean[] { false, true }) {
            ObfContext ctx = new ObfContext(ObfConfig.loadPreset("full"), 42,
                    new ObfLog(false), new NameGenerator(new String[] { "I", "l" }));
            ClassNode mixin = new ClassNode();
            mixin.version = Opcodes.V17;
            mixin.access = Opcodes.ACC_PUBLIC;
            mixin.name = "fixture/InjectedCode";
            mixin.superName = "java/lang/Object";
            var annotations = new ArrayList<>(List.of(new AnnotationNode(
                    "Lorg/spongepowered/asm/mixin/Mixin;")));
            if (visible) mixin.visibleAnnotations = annotations;
            else mixin.invisibleAnnotations = annotations;
            FieldNode field = new FieldNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_FINAL,
                    "targetField", "I", null, null);
            field.invisibleAnnotations = new ArrayList<>(List.of(
                    new AnnotationNode("Lorg/spongepowered/asm/mixin/Shadow;"),
                    new AnnotationNode("Lorg/spongepowered/asm/mixin/Final;")));
            mixin.fields.add(field);
            MethodNode hook = new MethodNode(Opcodes.ACC_PRIVATE, "hook", "()Ljava/lang/String;", null, null);
            hook.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
            hook.instructions.add(new FieldInsnNode(Opcodes.GETFIELD, mixin.name, field.name, "I"));
            hook.instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                    "java/lang/Integer", "toString", "(I)Ljava/lang/String;", false));
            hook.instructions.add(new InsnNode(Opcodes.ARETURN));
            hook.maxStack = 1;
            hook.maxLocals = 1;
            mixin.methods.add(hook);
            ctx.putClass(mixin);
            String before = trace(mixin);
            new ObfEngine(pipeline).run(ctx);
            ClassNode result = ctx.getClass(mixin.name);
            if (result == null || !before.equals(trace(result)))
                throw new AssertionError("full pipeline changed injectable Mixin code");
            System.out.println("PASS full pipeline preserves Mixin hooks and @Final shadows; visible=" + visible);
        }
        testMixinConstructorLinePreservation(pipeline);
    }

    private static void testMixinConstructorLinePreservation(List<Transformer> pipeline) {
        ObfContext ctx = new ObfContext(ObfConfig.loadPreset("full"), 42,
                new ObfLog(false), new NameGenerator(new String[] { "I", "l" }));
        ClassNode mixin = new ClassNode();
        mixin.version = Opcodes.V17;
        mixin.access = Opcodes.ACC_PUBLIC;
        mixin.name = "fixture/InitMixin";
        mixin.superName = "java/lang/Object";
        mixin.visibleAnnotations = new ArrayList<>(List.of(new AnnotationNode(
                "Lorg/spongepowered/asm/mixin/Mixin;")));
        FieldNode fn = new FieldNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_FINAL,
                "matrices", "Ljava/lang/Object;", null, null);
        fn.visibleAnnotations = new ArrayList<>(List.of(new AnnotationNode(
                "Lorg/spongepowered/asm/mixin/Unique;")));
        mixin.fields.add(fn);

        MethodNode ctor = new MethodNode(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        LabelNode l0 = new LabelNode();
        LabelNode l1 = new LabelNode();
        ctor.instructions.add(l0);
        ctor.instructions.add(new LineNumberNode(47, l0));
        ctor.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        ctor.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/Object", "<init>", "()V", false));
        ctor.instructions.add(l1);
        ctor.instructions.add(new LineNumberNode(72, l1));
        ctor.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        ctor.instructions.add(new TypeInsnNode(Opcodes.NEW, "java/lang/Object"));
        ctor.instructions.add(new InsnNode(Opcodes.DUP));
        ctor.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/Object", "<init>", "()V", false));
        ctor.instructions.add(new FieldInsnNode(Opcodes.PUTFIELD, mixin.name, fn.name, "Ljava/lang/Object;"));
        ctor.instructions.add(new InsnNode(Opcodes.RETURN));
        mixin.methods.add(ctor);

        ctx.putClass(mixin);
        new ObfEngine(pipeline).run(ctx);

        ClassNode result = ctx.getClass(mixin.name);
        if (result == null) {
            throw new AssertionError("mixin class was removed");
        }
        MethodNode resultCtor = result.methods.stream()
                .filter(m -> "<init>".equals(m.name))
                .findFirst()
                .orElseThrow(() -> new AssertionError("constructor was removed"));

        List<Integer> lines = new ArrayList<>();
        for (AbstractInsnNode insn = resultCtor.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof LineNumberNode lnn) {
                lines.add(lnn.line);
            }
        }
        if (lines.isEmpty() || !lines.contains(47) || !lines.contains(72)) {
            throw new AssertionError("lines were stripped from mixin constructor: " + lines);
        }
        System.out.println("PASS mixin constructor preserves line numbers for Sponge Mixin initialiser range");
    }

    private static String trace(ClassNode node) {
        StringWriter out = new StringWriter();
        node.accept(new TraceClassVisitor(new PrintWriter(out)));
        return out.toString();
    }
}
