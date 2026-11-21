package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

public final class SourceStripper implements Transformer {

    @Override
    public String id() {
        return "sourceStrip";
    }

    @Override
    public String description() {
        return "strip debug/source metadata";
    }

    @Override
    public void transform(ObfContext ctx) {
        boolean stripLines = ctx.config().section(id()).getBoolean("stripLineNumbers", true);
        boolean stripVars = ctx.config().section(id()).getBoolean("stripLocalVars", true);
        boolean stripSignatures = ctx.config().section(id()).getBoolean("stripSignatures", false);

        int classes = 0;
        for (ClassNode cn : ctx.targets(id())) {
            if (ctx.isExempt(id(), cn)) {
                continue;
            }

            cn.sourceFile = null;
            cn.sourceDebug = null;

            boolean isMixin = ObfContext.isMixin(cn) || ctx.isMixinPackage(cn.name);
            boolean preserveSchema = cn.fields.stream().anyMatch(GsonSchemaTransformer::hasName)
                    || isTypeToken(cn) || isMixin;

            if (stripSignatures && !preserveSchema) {
                cn.signature = null;
                for (var fn : cn.fields) {
                    fn.signature = null;
                }
                if (cn.recordComponents != null) {
                    for (var rc : cn.recordComponents) {
                        rc.signature = null;
                    }
                }
            }

            for (MethodNode mn : cn.methods) {
                if (stripSignatures && !preserveSchema) {
                    mn.signature = null;
                }

                if (stripVars && !isMixin) {
                    mn.localVariables = null;
                    if (mn.parameters != null) {
                        mn.parameters = null;
                    }
                }

                if (stripLines && !isMixin && mn.instructions != null) {
                    var it = mn.instructions.iterator();
                    while (it.hasNext()) {
                        var insn = it.next();
                        if (insn instanceof LineNumberNode) {
                            it.remove();
                        }
                    }
                }

                if (isMixin && "<init>".equals(mn.name)) {
                    ensureMixinConstructorLines(mn);
                }
            }
            classes++;
        }

        ctx.log().debug("sourceStrip touched " + classes + " classes");
    }

    private static void ensureMixinConstructorLines(MethodNode mn) {
        if (mn.instructions == null || mn.instructions.size() == 0) {
            return;
        }

        AbstractInsnNode superInit = null;
        boolean hasLineBeforeSuper = false;
        for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof LineNumberNode) {
                hasLineBeforeSuper = true;
            }
            if (insn.getOpcode() == Opcodes.INVOKESPECIAL
                    && insn instanceof MethodInsnNode min
                    && "<init>".equals(min.name)) {
                superInit = insn;
                break;
            }
        }

        if (!hasLineBeforeSuper) {
            LabelNode l0 = new LabelNode();
            mn.instructions.insert(new LineNumberNode(1, l0));
            mn.instructions.insert(l0);
        }

        if (superInit != null && superInit.getNext() != null) {
            boolean hasLineAfterSuper = false;
            for (AbstractInsnNode insn = superInit.getNext(); insn != null; insn = insn.getNext()) {
                if (insn instanceof LineNumberNode) {
                    hasLineAfterSuper = true;
                    break;
                }
            }
            if (!hasLineAfterSuper && superInit.getNext().getOpcode() != Opcodes.RETURN) {
                LabelNode l1 = new LabelNode();
                mn.instructions.insert(superInit, new LineNumberNode(2, l1));
                mn.instructions.insert(superInit, l1);
            }
        }
    }

    private static boolean isTypeToken(ClassNode cn) {
        if (cn.name != null && (cn.name.endsWith("TypeToken") || cn.name.endsWith("TypeReference"))) {
            return true;
        }
        if (cn.superName != null
                && (cn.superName.endsWith("TypeToken") || cn.superName.endsWith("TypeReference"))) {
            return true;
        }
        if (cn.interfaces != null) {
            for (String iface : cn.interfaces) {
                if (iface.endsWith("TypeToken") || iface.endsWith("TypeReference")) {
                    return true;
                }
            }
        }
        return false;
    }
}