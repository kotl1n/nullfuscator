package com.nullfuscator.obf;

import com.nullfuscator.obf.core.*;
import com.nullfuscator.obf.transform.AntiAiTransformer;
import com.nullfuscator.obf.util.*;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import java.util.*;

/**
 * Differential JVM execution, edge values, and useful-helper regression.
 *
 * NOTE / ВНИМАНИЕ:
 * antiAI является экспериментальной (тестовой) функцией и может работать не так, как задумано.
 * antiAI is an experimental / test feature and may not work as intended.
 */
public final class AntiAiRegression implements Opcodes {
    public static void main(String[] args) throws Exception {
        int checks = 0;
        for (int seed = 0; seed < 30; seed++) {
            for (int level = 1; level <= 3; level++) {
                ObfContext ctx = new ObfContext(ObfConfig.parse("antiAI { level:" + level
                        + ", decoyMethods:8, constantEncodingPercent:100 }"), seed,
                        new ObfLog(false), new NameGenerator(new String[]{"a", "b"}));
                ClassNode cn = new ClassNode();
                cn.name = "AntiFixture"; cn.version = seed % 3 == 0 ? V1_8 : V17;
                cn.access = ACC_PUBLIC | (seed % 3 == 1 ? ACC_INTERFACE | ACC_ABSTRACT : 0);
                cn.superName = "java/lang/Object";
                Random rnd = new Random(seed);
                long[] edges = {0, 1, -1, Integer.MIN_VALUE, Integer.MAX_VALUE,
                        Long.MIN_VALUE, Long.MAX_VALUE, 0xffffffffL, 0x80000000L, 127, 128, -129, 32767};
                List<Object> expected = new ArrayList<>();
                for (int i = 0; i < 120; i++) {
                    boolean wide = i % 2 == 0;
                    long value = i / 2 < edges.length ? edges[i / 2] : rnd.nextLong();
                    MethodNode mn = new MethodNode(ACC_PUBLIC | ACC_STATIC, "m" + i,
                            wide ? "()J" : "()I", null, null);
                    Object constant;
                    if (wide) constant = Long.valueOf(value); else constant = Integer.valueOf((int)value);
                    expected.add(constant);
                    if (!wide && (int)value >= -1 && (int)value <= 5)
                        mn.instructions.add(new InsnNode(ICONST_0 + (int)value));
                    else if (!wide && (int)value >= Byte.MIN_VALUE && (int)value <= Byte.MAX_VALUE)
                        mn.instructions.add(new IntInsnNode(BIPUSH, (int)value));
                    else if (!wide && (int)value >= Short.MIN_VALUE && (int)value <= Short.MAX_VALUE)
                        mn.instructions.add(new IntInsnNode(SIPUSH, (int)value));
                    else if (wide && (value == 0 || value == 1))
                        mn.instructions.add(new InsnNode(LCONST_0 + (int)value));
                    else mn.instructions.add(new LdcInsnNode(constant));
                    mn.instructions.add(new InsnNode(wide ? LRETURN : IRETURN));
                    cn.methods.add(mn);
                }
                ctx.putClass(cn);
                new AntiAiTransformer().transform(ctx);
                GrowthRegression.check(cn.methods.size() > 120, "missing live helpers");
                for (MethodNode mn : cn.methods) for (AbstractInsnNode insn : mn.instructions) {
                    GrowthRegression.check(insn.getOpcode() != POP, "discarded helper result");
                }
                Class<?> loaded = GrowthRegression.loader(ctx).loadClass(cn.name);
                for (int i = 0; i < 120; i++) {
                    GrowthRegression.check(expected.get(i).equals(loaded.getMethod("m" + i).invoke(null)),
                            "seed=" + seed + " level=" + level + " method=" + i);
                    checks++;
                }
                // Replacing the deepest helper by identity must change a real result.
                MethodNode helper = cn.methods.get(cn.methods.size() - 1);
                helper.instructions.clear();
                helper.instructions.add(new VarInsnNode(ILOAD, 0));
                helper.instructions.add(new InsnNode(IRETURN));
                Class<?> broken = GrowthRegression.loader(ctx).loadClass(cn.name);
                int first = level == 1 ? 1 : 0;
                GrowthRegression.check(!expected.get(first).equals(broken.getMethod("m" + first).invoke(null)),
                        "helper removal did not affect observable result");
            }
        }
        System.out.println("PASS antiAI: " + checks + " differential values, 30 seeds, levels 1-3, Java 8 classes / Java 17 interfaces, live-helper mutation");
    }
}
