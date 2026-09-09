package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.ExemptMatcher;
import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.FieldNode;
import java.util.ArrayList;

/** Explicit opt-in for schemas using Gson's default field naming policy. */
public final class GsonSchemaTransformer implements Transformer {
    public static final String NAME = "Lcom/google/gson/annotations/SerializedName;";
    @Override public String id() { return "gsonSchema"; }
    @Override public String description() { return "preserve selected Gson JSON field names"; }
    public static boolean hasName(FieldNode field) {
        return field.visibleAnnotations != null
                && field.visibleAnnotations.stream().anyMatch(a -> NAME.equals(a.desc));
    }
    public static boolean isGsonAnnotation(String desc) {
        return NAME.equals(desc) || "Lcom/google/gson/annotations/Expose;".equals(desc)
                || "Lcom/google/gson/annotations/Since;".equals(desc)
                || "Lcom/google/gson/annotations/Until;".equals(desc);
    }
    @Override public void transform(ObfContext ctx) {
        var include = new ExemptMatcher(ctx.config().section(id()).getStringList("include"));
        if (include.isEmpty()) throw new IllegalArgumentException("gsonSchema requires explicit include selectors");
        int count = 0;
        for (var cn : ctx.targets(id())) {
            if (!include.matches(cn.name)) continue;
            if ((cn.access & (Opcodes.ACC_ENUM | Opcodes.ACC_RECORD | Opcodes.ACC_INTERFACE)) != 0) continue;
            for (var field : cn.fields) {
                if ((field.access & (Opcodes.ACC_STATIC | Opcodes.ACC_TRANSIENT | Opcodes.ACC_SYNTHETIC)) != 0
                        || hasName(field)) continue;
                if (field.visibleAnnotations == null) field.visibleAnnotations = new ArrayList<>();
                var annotation = new AnnotationNode(NAME);
                annotation.visit("value", field.name);
                field.visibleAnnotations.add(annotation);
                count++;
            }
        }
        ctx.log().info("gsonSchema: pinned " + count + " JSON field names");
    }
}
