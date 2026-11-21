package com.nullfuscator.obf;

import com.nullfuscator.obf.core.*;
import com.nullfuscator.obf.transform.AntiDeobfuscatorTransformer;
import com.nullfuscator.obf.util.*;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

public final class AntiDeobfRegression implements Opcodes {

    public static void main(String[] args) throws Exception {
        AntiDeobfuscatorTransformer transformer = new AntiDeobfuscatorTransformer();

        for (int seed = 0; seed < 30; seed++) {
            for (int level = 1; level <= 3; level++) {
                ObfContext ctx = new ObfContext(
                        ObfConfig.parse("antiDeobf { level:" + level
                                + ", trapRealMethods:true, honeypots:true, poisonInner:true, poisonSignatures:false, poisonAnnotations:true }"),
                        seed,
                        new ObfLog(false),
                        new NameGenerator(new String[] { "I", "l" }));

                ClassNode cn = new ClassNode();
                cn.name = "sample/TargetClass";
                cn.version = V17;
                cn.access = ACC_PUBLIC;
                cn.superName = "java/lang/Object";

                MethodNode m1 = new MethodNode(ACC_PUBLIC | ACC_STATIC, "compute", "(II)I", null, null);
                m1.instructions.add(new VarInsnNode(ILOAD, 0));
                m1.instructions.add(new VarInsnNode(ILOAD, 1));
                m1.instructions.add(new InsnNode(IADD));
                m1.instructions.add(new InsnNode(IRETURN));
                cn.methods.add(m1);

                MethodNode m2 = new MethodNode(ACC_PUBLIC, "hello", "(Ljava/lang/String;)Ljava/lang/String;", null, null);
                m2.instructions.add(new VarInsnNode(ALOAD, 1));
                m2.instructions.add(new InsnNode(ARETURN));
                cn.methods.add(m2);

                FieldNode f1 = new FieldNode(ACC_PUBLIC, "value", "I", null, 42);
                cn.fields.add(f1);

                ctx.putClass(cn);
                ctx.initializePolicies();
                transformer.transform(ctx);

                ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
                cn.accept(cw);
                byte[] bytes = cw.toByteArray();
                if (bytes.length == 0) {
                    throw new IllegalStateException("Empty bytes produced");
                }
            }
        }
        System.out.println("PASS anti-deobf regression with COMPUTE_FRAMES");
    }
}
