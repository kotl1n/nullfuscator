package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class AnnotationSanitizerTransformer implements Transformer {

    @Override
    public String id() {
        return "annotationSanitizer";
    }

    @Override
    public String description() {
        return "remove selected runtime annotation metadata";
    }

    @Override
    public void transform(ObfContext ctx) {
        Set<String> descriptors = new HashSet<>();
        for (String value : ctx.config().section(id()).getStringList("descriptors")) {
            if (value == null || value.isBlank()) {
                continue;
            }
            descriptors.add(normalize(value));
        }
        if (descriptors.isEmpty()) {
            return;
        }

        int classes = 0;
        int annotations = 0;
        for (ClassNode cn : ctx.targets(id())) {
            int removed = remove(cn.visibleAnnotations, descriptors)
                    + remove(cn.invisibleAnnotations, descriptors);
            if (removed > 0) {
                classes++;
                annotations += removed;
            }
        }

        if (annotations > 0) {
            ctx.log().debug("annotationSanitizer removed " + annotations
                    + " annotations from " + classes + " classes");
        }
    }

    private static int remove(List<AnnotationNode> annotations, Set<String> descriptors) {
        if (annotations == null) {
            return 0;
        }
        int before = annotations.size();
        annotations.removeIf(annotation -> descriptors.contains(annotation.desc));
        return before - annotations.size();
    }

    private static String normalize(String value) {
        String trimmed = value.trim();
        if (trimmed.startsWith("L") && trimmed.endsWith(";")) {
            return trimmed;
        }
        return "L" + trimmed.replace('.', '/') + ";";
    }
}