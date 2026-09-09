package com.nullfuscator.obf.core;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

public final class ExemptMatcher {

    private final List<Pattern> classPatterns = new ArrayList<>();
    private final List<Pattern> methodPatterns = new ArrayList<>();
    private final List<Pattern> annotationPatterns = new ArrayList<>();
    private final List<String> literalPrefixes = new ArrayList<>();

    public ExemptMatcher(List<String> patterns) {
        if (patterns == null) return;
        for (String p : patterns) {
            if (p == null || p.isEmpty()) continue;
            if (p.startsWith("class{") && p.endsWith("}")) {
                String rx = p.substring("class{".length(), p.length() - 1);
                classPatterns.add(Pattern.compile(rx));
            } else if (p.startsWith("method{") && p.endsWith("}")) {
                methodPatterns.add(Pattern.compile(p.substring("method{".length(), p.length() - 1)));
            } else if (p.startsWith("annotation{") && p.endsWith("}")) {
                annotationPatterns.add(Pattern.compile(p.substring("annotation{".length(), p.length() - 1)));
            } else if (p.startsWith("field{")) {
                // Field selectors are reserved for the keep-rule implementation.
            } else {
                literalPrefixes.add(p.replace('.', '/'));
            }
        }
    }

    public boolean matchesMethod(String owner, String name, String descriptor) {
        String qualified = owner + "#" + name + descriptor;
        for (Pattern p : methodPatterns) if (p.matcher(qualified).find()) return true;
        return false;
    }

    public boolean matchesAnnotations(ClassNode owner, MethodNode method) {
        if (annotationPatterns.isEmpty()) return false;
        if (matchesAnnotations(owner.visibleAnnotations) || matchesAnnotations(owner.invisibleAnnotations)) return true;
        return method != null && (matchesAnnotations(method.visibleAnnotations)
                || matchesAnnotations(method.invisibleAnnotations));
    }

    private boolean matchesAnnotations(List<AnnotationNode> annotations) {
        if (annotations == null) return false;
        for (AnnotationNode annotation : annotations) {
            String name = annotation.desc;
            if (name.startsWith("L") && name.endsWith(";")) name = name.substring(1, name.length() - 1);
            for (Pattern p : annotationPatterns) if (p.matcher(name).find()) return true;
        }
        return false;
    }

    public boolean matches(String internalName) {
        if (internalName == null) return false;
        for (Pattern p : classPatterns) {
            if (p.matcher(internalName).find()) return true;
        }
        for (String pref : literalPrefixes) {
            if (internalName.startsWith(pref)) return true;
        }
        return false;
    }

    public boolean isEmpty() {
        return classPatterns.isEmpty() && methodPatterns.isEmpty()
                && annotationPatterns.isEmpty() && literalPrefixes.isEmpty();
    }
}
