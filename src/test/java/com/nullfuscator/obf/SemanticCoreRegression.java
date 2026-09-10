package com.nullfuscator.obf;

import com.nullfuscator.obf.core.ObfConfig;
import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Limits;
import com.nullfuscator.obf.transform.SemanticCoreTransformer;
import com.nullfuscator.obf.util.NameGenerator;
import com.nullfuscator.obf.util.ObfLog;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.Objects;
import java.util.Random;

public final class SemanticCoreRegression implements Opcodes {
    public static void main(String[] args) throws Exception {
        verifyInstructionLimit();
        int checks = 0;
        int transformed = 0;
        int[] edges = {0, 1, -1, 2, -2, Integer.MIN_VALUE, Integer.MAX_VALUE, 0x55555555, 0xaaaaaaaa};
        for (int seed = 0; seed < 48; seed++) {
            ObfContext original = context(seed);
            ObfContext protectedContext = context(seed);
            ClassNode source = fixture("SemanticFixture" + seed, seed);
            ClassNode copy = new ClassNode();
            source.accept(copy);
            original.putClass(source);
            protectedContext.putClass(copy);

            new SemanticCoreTransformer().transform(protectedContext);
            Class<?> before = GrowthRegression.loader(original).loadClass(source.name);
            Class<?> after = GrowthRegression.loader(protectedContext).loadClass(copy.name);
            for (MethodNode protectedMethod : protectedContext.getClass(copy.name).methods) {
                MethodNode originalMethod = source.methods.stream()
                        .filter(method -> method.name.equals(protectedMethod.name)).findFirst().orElseThrow();
                GrowthRegression.check(protectedContext.isSemanticCoreMethod(protectedMethod),
                        protectedMethod.name + " was not protected");
                GrowthRegression.check(protectedMethod.instructions.size() > originalMethod.instructions.size(),
                        protectedMethod.name + " did not expand");
                transformed++;
                Class<?>[] parameters = protectedMethod.desc.equals("(I)I")
                        ? new Class<?>[]{int.class} : new Class<?>[]{int.class, int.class};
                for (int left : edges) for (int right : edges) {
                    Object[] arguments = parameters.length == 1
                            ? new Object[]{Math.floorMod(left, 64)} : new Object[]{left, right};
                    Object expected = before.getMethod(protectedMethod.name, parameters).invoke(null, arguments);
                    Object actual = after.getMethod(protectedMethod.name, parameters).invoke(null, arguments);
                    GrowthRegression.check(Objects.equals(expected, actual), "seed=" + seed + " method="
                            + protectedMethod.name + " left=" + left + " right=" + right
                            + " expected=" + expected + " actual=" + actual);
                    checks++;
                }
                Random random = new Random(seed * 31L + protectedMethod.name.hashCode());
                for (int sample = 0; sample < 120; sample++) {
                    int left = random.nextInt(), right = random.nextInt();
                    Object[] arguments = parameters.length == 1
                            ? new Object[]{Math.floorMod(left, 64)} : new Object[]{left, right};
                    Object expected = before.getMethod(protectedMethod.name, parameters).invoke(null, arguments);
                    Object actual = after.getMethod(protectedMethod.name, parameters).invoke(null, arguments);
                    GrowthRegression.check(Objects.equals(expected, actual), "random seed=" + seed
                            + " method=" + protectedMethod.name);
                    checks++;
                }
            }
        }
        System.out.println("PASS semanticCore: " + transformed + " methods, " + checks
                + " differential executions over arithmetic, bitwise, domain-transition, branch, and loop fixtures");
    }

    private static ObfContext context(int seed) {
        return new ObfContext(ObfConfig.parse("semanticCore { enabled:true, percent:100, minOperations:2, maxMethods:7 }"),
                seed, new ObfLog(false), new NameGenerator(new String[]{"a", "b"}));
    }

    private static void verifyInstructionLimit() {
        ClassNode node = new ClassNode();
        node.version = V17; node.access = ACC_PUBLIC; node.name = "SemanticLimit"; node.superName = "java/lang/Object";
        MethodNode method = new MethodNode(ACC_PUBLIC | ACC_STATIC, "large", "(I)I", null, null);
        for (int i = 0; i < 1900; i++) {
            method.instructions.add(new InsnNode(ICONST_1));
            method.instructions.add(new InsnNode(POP));
        }
        method.instructions.add(new VarInsnNode(ILOAD, 0));
        for (int i = 0; i < 3; i++) {
            method.instructions.add(new InsnNode(ICONST_1));
            method.instructions.add(new InsnNode(IADD));
        }
        method.instructions.add(new InsnNode(IRETURN));
        node.methods.add(method);

        ObfContext context = context(0);
        context.putClass(node);
        new SemanticCoreTransformer().transform(context);
        GrowthRegression.check(!context.isSemanticCoreMethod(method),
                "semanticCore exceeded its " + Limits.MAX_GROW_INSNS + " instruction limit");
    }

    private static ClassNode fixture(String name, int seed) {
        ClassNode node = new ClassNode();
        node.version = V17; node.access = ACC_PUBLIC; node.name = name; node.superName = "java/lang/Object";
        MethodNode method = new MethodNode(ACC_PUBLIC | ACC_STATIC, "run", "(II)I", null, null);
        int first = seed * 0x45d9f3b;
        int second = Integer.rotateLeft(seed * 0x119de1f3, 7);
        method.instructions.add(new VarInsnNode(ILOAD, 0));
        method.instructions.add(new LdcInsnNode(first));
        method.instructions.add(new InsnNode(IADD));
        method.instructions.add(new VarInsnNode(ISTORE, 2));
        method.instructions.add(new VarInsnNode(ILOAD, 2));
        method.instructions.add(new VarInsnNode(ILOAD, 1));
        method.instructions.add(new InsnNode(IMUL));
        method.instructions.add(new LdcInsnNode(second));
        method.instructions.add(new InsnNode(ISUB));
        method.instructions.add(new InsnNode(INEG));
        method.instructions.add(new InsnNode(IRETURN));
        node.methods.add(method);

        MethodNode bitwise = new MethodNode(ACC_PUBLIC | ACC_STATIC, "bits", "(II)I", null, null);
        bitwise.instructions.add(new VarInsnNode(ILOAD, 0));
        bitwise.instructions.add(new LdcInsnNode(first));
        bitwise.instructions.add(new InsnNode(IXOR));
        bitwise.instructions.add(new VarInsnNode(ISTORE, 2));
        bitwise.instructions.add(new VarInsnNode(ILOAD, 2));
        bitwise.instructions.add(new VarInsnNode(ILOAD, 1));
        bitwise.instructions.add(new InsnNode(IAND));
        bitwise.instructions.add(new LdcInsnNode(second));
        bitwise.instructions.add(new InsnNode(IOR));
        bitwise.instructions.add(new InsnNode(IRETURN));
        node.methods.add(bitwise);

        LabelNode lower = new LabelNode();
        MethodNode branching = new MethodNode(ACC_PUBLIC | ACC_STATIC, "branch", "(II)I", null, null);
        branching.instructions.add(new VarInsnNode(ILOAD, 0));
        branching.instructions.add(new VarInsnNode(ILOAD, 1));
        branching.instructions.add(new JumpInsnNode(IF_ICMPLE, lower));
        branching.instructions.add(new VarInsnNode(ILOAD, 0));
        branching.instructions.add(new VarInsnNode(ILOAD, 1));
        branching.instructions.add(new InsnNode(ISUB));
        branching.instructions.add(new InsnNode(INEG));
        branching.instructions.add(new InsnNode(IRETURN));
        branching.instructions.add(lower);
        branching.instructions.add(new VarInsnNode(ILOAD, 1));
        branching.instructions.add(new VarInsnNode(ILOAD, 0));
        branching.instructions.add(new InsnNode(ISUB));
        branching.instructions.add(new InsnNode(INEG));
        branching.instructions.add(new InsnNode(IRETURN));
        node.methods.add(branching);

        LabelNode loop = new LabelNode();
        LabelNode done = new LabelNode();
        MethodNode looping = new MethodNode(ACC_PUBLIC | ACC_STATIC, "loop", "(I)I", null, null);
        LabelNode entry = new LabelNode();
        looping.instructions.add(entry);
        looping.instructions.add(new InsnNode(ICONST_0));
        looping.instructions.add(new VarInsnNode(ISTORE, 1));
        looping.instructions.add(new InsnNode(ICONST_0));
        looping.instructions.add(new VarInsnNode(ISTORE, 2));
        looping.instructions.add(loop);
        looping.instructions.add(new VarInsnNode(ILOAD, 2));
        looping.instructions.add(new VarInsnNode(ILOAD, 0));
        looping.instructions.add(new JumpInsnNode(IF_ICMPGE, done));
        looping.instructions.add(new VarInsnNode(ILOAD, 1));
        looping.instructions.add(new VarInsnNode(ILOAD, 2));
        looping.instructions.add(new InsnNode(IADD));
        looping.instructions.add(new VarInsnNode(ISTORE, 1));
        looping.instructions.add(new IincInsnNode(2, 1));
        looping.instructions.add(new JumpInsnNode(GOTO, loop));
        looping.instructions.add(done);
        looping.instructions.add(new VarInsnNode(ILOAD, 1));
        looping.instructions.add(new InsnNode(IRETURN));
        node.methods.add(looping);

        LabelNode zero = new LabelNode();
        MethodNode unaryBranch = new MethodNode(ACC_PUBLIC | ACC_STATIC, "zero", "(I)I", null, null);
        unaryBranch.instructions.add(new VarInsnNode(ILOAD, 0));
        unaryBranch.instructions.add(new JumpInsnNode(IFEQ, zero));
        unaryBranch.instructions.add(new VarInsnNode(ILOAD, 0));
        unaryBranch.instructions.add(new InsnNode(ICONST_1));
        unaryBranch.instructions.add(new InsnNode(IADD));
        unaryBranch.instructions.add(new InsnNode(INEG));
        unaryBranch.instructions.add(new InsnNode(IRETURN));
        unaryBranch.instructions.add(zero);
        unaryBranch.instructions.add(new VarInsnNode(ILOAD, 0));
        unaryBranch.instructions.add(new InsnNode(ICONST_1));
        unaryBranch.instructions.add(new InsnNode(ISUB));
        unaryBranch.instructions.add(new InsnNode(INEG));
        unaryBranch.instructions.add(new InsnNode(IRETURN));
        node.methods.add(unaryBranch);

        MethodNode mixed = new MethodNode(ACC_PUBLIC | ACC_STATIC, "mixed", "(II)I", null, null);
        mixed.instructions.add(new VarInsnNode(ILOAD, 0));
        mixed.instructions.add(new LdcInsnNode(first));
        mixed.instructions.add(new InsnNode(IADD));
        mixed.instructions.add(new VarInsnNode(ILOAD, 1));
        mixed.instructions.add(new LdcInsnNode(second));
        mixed.instructions.add(new InsnNode(IXOR));
        mixed.instructions.add(new InsnNode(IAND));
        mixed.instructions.add(new VarInsnNode(ILOAD, 0));
        mixed.instructions.add(new InsnNode(IADD));
        mixed.instructions.add(new VarInsnNode(ILOAD, 1));
        mixed.instructions.add(new InsnNode(IOR));
        mixed.instructions.add(new LdcInsnNode(3));
        mixed.instructions.add(new InsnNode(IUSHR));
        mixed.instructions.add(new InsnNode(IRETURN));
        node.methods.add(mixed);

        MethodNode stack = new MethodNode(ACC_PUBLIC | ACC_STATIC, "stack", "(I)I", null, null);
        stack.instructions.add(new VarInsnNode(ILOAD, 0));
        stack.instructions.add(new InsnNode(DUP));
        stack.instructions.add(new InsnNode(ICONST_2));
        stack.instructions.add(new InsnNode(IADD));
        stack.instructions.add(new InsnNode(IADD));
        stack.instructions.add(new InsnNode(IRETURN));
        node.methods.add(stack);
        return node;
    }
}
