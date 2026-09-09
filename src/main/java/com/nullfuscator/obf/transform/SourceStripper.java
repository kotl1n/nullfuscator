package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

public final class SourceStripper implements Transformer {

    @Override public String id() { return "sourceStrip"; }
    @Override public String description() { return "strip debug/source metadata"; }

    @Override
    public void transform(ObfContext ctx) {
        boolean stripLines = ctx.config().section(id()).getBoolean("stripLineNumbers", true);
        boolean stripVars  = ctx.config().section(id()).getBoolean("stripLocalVars", true);
        boolean stripSignatures = ctx.config().section(id()).getBoolean("stripSignatures", false);
        int classes = 0;
        for (ClassNode cn : ctx.targets(id())) {
            if (ctx.isExempt(id(), cn)) continue;
            cn.sourceFile = null;
            cn.sourceDebug = null;
            boolean preserveSchema = cn.fields.stream().anyMatch(GsonSchemaTransformer::hasName);
            if (stripSignatures && !preserveSchema) {
                cn.signature = null;
                for (var fn : cn.fields) fn.signature = null;
                if (cn.recordComponents != null)
                    for (var rc : cn.recordComponents) rc.signature = null;
            }
            for (MethodNode mn : cn.methods) {
                if (stripSignatures && !preserveSchema) mn.signature = null;
                if (stripVars) {
                    mn.localVariables = null;
                    if (mn.parameters != null) mn.parameters = null;
                }
                if (stripLines && mn.instructions != null) {
                    var it = mn.instructions.iterator();
                    while (it.hasNext()) {
                        var insn = it.next();
                        if (insn instanceof org.objectweb.asm.tree.LineNumberNode) it.remove();
                    }
                }
            }
            classes++;
        }
        ctx.log().debug("sourceStrip touched " + classes + " classes");
    }
}
