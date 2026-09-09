package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.Limits;
import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.SimpleRemapper;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public final class AntiDebugTransformer implements Transformer {

    private static final String SRC = "com/nullfuscator/obf/runtime/DebugCheck";

    @Override public String id() { return "antiDebug"; }
    @Override public String description() { return "inject debugger/agent detection guards"; }

    @Override
    public void transform(ObfContext ctx) {
        if (ctx.isModularJar()) {

            ctx.log().warn("antiDebug: skipped for modular JAR (would require java.management)");
            return;
        }
        var section = ctx.config().section(id());
        int percent = Math.max(0, Math.min(100, section.getInt("checkPercent", 30)));
        int pool = Math.max(1, Math.min(64, section.getInt("detectors", 4)));
        if (percent == 0) return;

        List<ClassNode> targets = ctx.targets(id());
        int targetVersion = highestClassVersion(targets, Opcodes.V1_5);

        List<String> detectors = new ArrayList<>();
        byte[] src = load();
        if (src == null) { ctx.log().warn("antiDebug: DebugCheck resource missing, skipped"); return; }
        for (int i = 0; i < pool; i++) {
            String name = "a/g/" + ctx.names().next();
            ClassNode raw = new ClassNode();
            new ClassReader(src).accept(raw, 0);
            ClassNode renamed = new ClassNode();
            raw.accept(new ClassRemapper(renamed, new SimpleRemapper(SRC, name)));

            renamed.version = targetVersion;
            if (section.getBoolean("rejectAgents", false)) {
                for (MethodNode method : renamed.methods) if (method.name.equals("rejectAgents")) {
                    method.instructions.clear();
                    method.instructions.add(new InsnNode(Opcodes.ICONST_1));
                    method.instructions.add(new InsnNode(Opcodes.IRETURN));
                }
            }
            ctx.putClass(renamed);
            detectors.add(name);
        }

        Random rnd = ctx.random();
        int guarded = 0;
        for (ClassNode cn : targets) {
            for (MethodNode mn : cn.methods) {
                if (ctx.isHotPath(cn, mn)) continue;
                if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) continue;
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                if (mn.name.equals("<init>") || mn.name.equals("<clinit>")) continue;
                if (Limits.oversizeMethod(mn)) continue;
                if (rnd.nextInt(100) >= percent) continue;

                String det = detectors.get(rnd.nextInt(detectors.size()));
                InsnList g = new InsnList();
                LabelNode ok = new LabelNode();
                g.add(new MethodInsnNode(Opcodes.INVOKESTATIC, det, "detected", "()Z", false));
                g.add(new JumpInsnNode(Opcodes.IFEQ, ok));
                g.add(new TypeInsnNode(Opcodes.NEW, "java/lang/RuntimeException"));
                g.add(new InsnNode(Opcodes.DUP));
                g.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/RuntimeException", "<init>", "()V", false));
                g.add(new InsnNode(Opcodes.ATHROW));
                g.add(ok);
                mn.instructions.insert(g);
                guarded++;
            }
        }
        if (guarded == 0) {
            for (String detector : detectors) ctx.removeClass(detector);
            detectors.clear();
        }
        ctx.log().debug("antiDebug: guarded " + guarded + " methods with " + detectors.size() + " detectors");
    }

    private static byte[] load() {
        try (InputStream in = AntiDebugTransformer.class
                .getResourceAsStream("/com/nullfuscator/obf/runtime/DebugCheck.class")) {
            return in == null ? null : in.readAllBytes();
        } catch (IOException e) { return null; }
    }

    private static int highestClassVersion(List<ClassNode> classes, int minimum) {
        int version = minimum;
        for (ClassNode cn : classes) version = Math.max(version, cn.version & 0xFFFF);
        return version;
    }
}
