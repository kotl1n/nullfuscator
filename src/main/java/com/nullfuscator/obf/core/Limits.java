package com.nullfuscator.obf.core;

import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

public final class Limits {

    private Limits() {}

    public static final int MAX_GROW_INSNS = 4000;

    public static final int HUGE_CLASS_METHODS = 1000;

    public static boolean oversizeMethod(MethodNode mn) {
        return mn.instructions != null && mn.instructions.size() > MAX_GROW_INSNS;
    }

    public static boolean hugeClass(ClassNode cn) {
        return cn.methods != null && cn.methods.size() > HUGE_CLASS_METHODS;
    }
}
