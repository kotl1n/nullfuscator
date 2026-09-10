package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.Limits;
import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.HashSet;
import java.util.Random;
import java.util.Set;


public final class SemanticCoreTransformer implements Transformer, Opcodes {
    @Override public String id() { return "semanticCore"; }
    @Override public String description() {
        return "keep supported integer semantics in a method-specific encoded domain";
    }

    @Override
    public void transform(ObfContext ctx) {
        int percent = clamp(ctx.config().section(id()).getInt("percent", 35), 0, 100);
        int minOperations = Math.max(1, ctx.config().section(id()).getInt("minOperations", 3));
        int maxMethods = Math.max(1, ctx.config().section(id()).getInt("maxMethods", 64));
        if (percent == 0) return;

        Random random = ctx.random();
        int transformed = 0;
        int encodedOperations = 0;
        outer:
        for (ClassNode owner : ctx.targets(id())) {
            if (Limits.hugeClass(owner)) continue;
            for (MethodNode method : owner.methods) {
                if (ctx.isHotPath(owner, method)) continue;
                Candidate candidate = candidate(method);
                if (candidate == null || candidate.operations < minOperations || random.nextInt(100) >= percent) continue;
                if (estimatedSize(method, candidate.domain) > Limits.MAX_GROW_INSNS) continue;

                if (candidate.domain == Domain.AFFINE) {
                    rewriteAffine(method, random.nextInt() | 1, random.nextInt(), random.nextInt());
                } else {
                    rewriteXor(method, random.nextInt());
                }
                ctx.markSemanticCoreMethod(method);
                transformed++;
                encodedOperations += candidate.operations;
                if (transformed >= maxMethods) break outer;
            }
        }
        ctx.log().debug("semanticCore: protected=" + transformed
                + " methods, encodedOperations=" + encodedOperations);
    }

    private static Candidate candidate(MethodNode method) {
        int forbidden = ACC_ABSTRACT | ACC_NATIVE | ACC_SYNTHETIC | ACC_BRIDGE | ACC_SYNCHRONIZED;
        if ((method.access & forbidden) != 0 || (method.access & ACC_STATIC) == 0) return null;
        if (method.name.charAt(0) == '<' || method.instructions == null || method.instructions.size() == 0) return null;
        if (method.tryCatchBlocks != null && !method.tryCatchBlocks.isEmpty()) return null;
        if (Type.getReturnType(method.desc).getSort() != Type.INT) return null;

        Type[] arguments = Type.getArgumentTypes(method.desc);
        for (Type argument : arguments) if (argument.getSort() != Type.INT) return null;

        Set<Integer> initializedLocals = new HashSet<>();
        for (int slot = 0; slot < arguments.length; slot++) initializedLocals.add(slot);
        int operations = 0;
        boolean returns = false;
        boolean affine = false;
        boolean xor = false;
        for (AbstractInsnNode instruction : method.instructions.toArray()) {
            int opcode = instruction.getOpcode();
            if (opcode < 0 || opcode == NOP) continue;
            if (instruction instanceof VarInsnNode variable) {
                if (opcode == ILOAD) {
                    if (!initializedLocals.contains(variable.var)) return null;
                    continue;
                }
                if (opcode == ISTORE) {
                    initializedLocals.add(variable.var);
                    continue;
                }
                return null;
            }
            if (instruction instanceof IincInsnNode increment) {
                if (increment.var < 0 || !initializedLocals.contains(increment.var)) return null;
                affine = true;
                operations++;
                continue;
            }
            if (instruction instanceof JumpInsnNode) {
                if (opcode == GOTO) continue;
                if (!isIntegerBranch(opcode)) return null;
                affine = true;
                continue;
            }

            if (opcode == DUP || opcode == DUP_X1 || opcode == DUP_X2
                    || opcode == SWAP || opcode == POP) continue;
            if (constantValue(instruction) != null) continue;
            Domain operationDomain = switch (opcode) {
                case IADD, ISUB, IMUL, INEG, ISHL, ISHR, IUSHR -> Domain.AFFINE;
                case IXOR, IAND, IOR -> Domain.XOR;
                default -> null;
            };
            if (operationDomain != null) {
                if (operationDomain == Domain.AFFINE) affine = true;
                else xor = true;
                operations++;
                continue;
            }
            if (opcode == IRETURN) {
                returns = true;
                continue;
            }
            return null;
        }
        if (!returns || (!affine && !xor)) return null;
        return new Candidate(affine ? Domain.AFFINE : Domain.XOR, operations);
    }


    private static int estimatedSize(MethodNode method, Domain domain) {
        int estimate = method.instructions.size();
        for (AbstractInsnNode instruction : method.instructions.toArray()) {
            int replacement = replacementSize(instruction, domain);
            if (replacement != 0) estimate += replacement - 1;
        }
        return estimate + Type.getArgumentTypes(method.desc).length * 6;
    }


    private static int replacementSize(AbstractInsnNode instruction, Domain domain) {
        int opcode = instruction.getOpcode();
        if (instruction instanceof IincInsnNode) return 4;
        if (instruction instanceof JumpInsnNode && isIntegerBranch(opcode)) {
            return opcode >= IF_ICMPEQ && opcode <= IF_ICMPLE ? 10 : 5;
        }
        if (constantValue(instruction) != null) return 3;
        if (domain == Domain.XOR) {
            return switch (opcode) {
                case IXOR, IRETURN -> 3;
                case IAND, IOR -> 15;
                case ISHL, ISHR, IUSHR -> 11;
                default -> 0;
            };
        }
        return switch (opcode) {
            case IADD, ISUB -> 3;
            case IMUL -> 10;
            case INEG -> 4;
            case IXOR -> 23;
            case IAND, IOR -> 35;
            case ISHL, ISHR, IUSHR -> 15;
            case IRETURN -> 5;
            default -> 0;
        };
    }

    private static void rewriteAffine(MethodNode method, int multiplier, int offset, int xorKey) {
        int inverse = inverseOdd32(multiplier);
        int temporaryLeft = nextTemporaryLocal(method);
        int temporaryRight = temporaryLeft + 1;
        method.maxLocals += 2;
        AbstractInsnNode[] original = method.instructions.toArray();
        InsnList prologue = new InsnList();
        for (int slot = 0; slot < Type.getArgumentTypes(method.desc).length; slot++) {
            prologue.add(new VarInsnNode(ILOAD, slot));
            prologue.add(pushInt(multiplier));
            prologue.add(new InsnNode(IMUL));
            prologue.add(pushInt(offset));
            prologue.add(new InsnNode(IADD));
            prologue.add(new VarInsnNode(ISTORE, slot));
        }

        method.instructions.insert(prologue);

        for (AbstractInsnNode instruction : original) {
            InsnList replacement = instruction instanceof JumpInsnNode jump && isIntegerBranch(jump.getOpcode())
                    ? branch(jump, offset, inverse) : switch (instruction.getOpcode()) {
                        case IADD -> add(offset);
                        case ISUB -> subtract(offset);
                        case IMUL -> multiply(offset, inverse);
                        case INEG -> negate(offset);
                        case ISHL, ISHR, IUSHR -> shiftThroughRaw(instruction.getOpcode(), multiplier, offset, inverse);
                        case IXOR, IAND, IOR -> bitwiseThroughXor(instruction.getOpcode(), multiplier, offset, inverse,
                                xorKey, temporaryLeft, temporaryRight);
                        case IRETURN -> decode(offset, inverse);
                        default -> encodedConstant(instruction, multiplier, offset, xorKey);
                    };
            if (instruction instanceof IincInsnNode increment) {
                replacement = increment(offset, multiplier, increment);
            }
            if (replacement == null) continue;
            method.instructions.insertBefore(instruction, replacement);
            method.instructions.remove(instruction);
        }
    }

    private static void rewriteXor(MethodNode method, int key) {
        int temporaryLeft = nextTemporaryLocal(method);
        int temporaryRight = temporaryLeft + 1;
        method.maxLocals += 2;
        AbstractInsnNode[] original = method.instructions.toArray();
        InsnList prologue = new InsnList();
        for (int slot = 0; slot < Type.getArgumentTypes(method.desc).length; slot++) {
            prologue.add(new VarInsnNode(ILOAD, slot));
            prologue.add(pushInt(key));
            prologue.add(new InsnNode(IXOR));
            prologue.add(new VarInsnNode(ISTORE, slot));
        }
        method.instructions.insert(prologue);

        for (AbstractInsnNode instruction : original) {
            InsnList replacement = switch (instruction.getOpcode()) {
                case IXOR -> xor(key);
                case IAND -> and(key, temporaryLeft, temporaryRight);
                case IOR -> or(key, temporaryLeft, temporaryRight);
                case ISHL, ISHR, IUSHR -> shiftThroughRawXor(instruction.getOpcode(), key);
                case IRETURN -> xorDecode(key);
                default -> xorConstant(instruction, key, key * 0x9E3779B9);
            };
            if (replacement == null) continue;
            method.instructions.insertBefore(instruction, replacement);
            method.instructions.remove(instruction);
        }
    }

    private static InsnList add(int offset) {
        InsnList out = new InsnList();
        out.add(new InsnNode(IADD));
        out.add(pushInt(-offset));
        out.add(new InsnNode(IADD));
        return out;
    }

    private static InsnList subtract(int offset) {
        InsnList out = new InsnList();
        out.add(new InsnNode(ISUB));
        out.add(pushInt(offset));
        out.add(new InsnNode(IADD));
        return out;
    }

    private static InsnList multiply(int offset, int inverse) {
        InsnList out = new InsnList();
        out.add(pushInt(offset)); out.add(new InsnNode(ISUB));
        out.add(new InsnNode(SWAP));
        out.add(pushInt(offset)); out.add(new InsnNode(ISUB));
        out.add(new InsnNode(IMUL));
        out.add(pushInt(inverse)); out.add(new InsnNode(IMUL));
        out.add(pushInt(offset)); out.add(new InsnNode(IADD));
        return out;
    }

    private static InsnList negate(int offset) {
        InsnList out = new InsnList();
        out.add(pushInt(offset + offset)); out.add(new InsnNode(SWAP)); out.add(new InsnNode(ISUB));
        return out;
    }

    private static InsnList decode(int offset, int inverse) {
        InsnList out = new InsnList();
        out.add(pushInt(offset)); out.add(new InsnNode(ISUB));
        out.add(pushInt(inverse)); out.add(new InsnNode(IMUL)); out.add(new InsnNode(IRETURN));
        return out;
    }

    private static InsnList increment(int offset, int multiplier, IincInsnNode increment) {
        InsnList out = new InsnList();
        out.add(new VarInsnNode(ILOAD, increment.var));
        out.add(pushInt(multiplier * increment.incr));
        out.add(new InsnNode(IADD));
        out.add(new VarInsnNode(ISTORE, increment.var));
        return out;
    }
    private static InsnList bitwiseThroughXor(int opcode, int multiplier, int offset, int inverse, int xorKey,
                                               int temporaryLeft, int temporaryRight) {
        InsnList out = new InsnList();
        affineToXor(out, offset, inverse, xorKey);
        out.add(new InsnNode(SWAP));
        affineToXor(out, offset, inverse, xorKey);
        out.add(new InsnNode(SWAP));
        switch (opcode) {
            case IXOR -> {
                out.add(new InsnNode(IXOR));
                out.add(pushInt(xorKey)); out.add(new InsnNode(IXOR));
            }
            case IAND -> appendMaskedAnd(out, xorKey, temporaryLeft, temporaryRight);
            case IOR -> appendMaskedOr(out, xorKey, temporaryLeft, temporaryRight);
            default -> throw new IllegalArgumentException("unsupported bitwise opcode: " + opcode);
        }
        xorToAffine(out, multiplier, offset, xorKey);
        return out;
    }

    private static void affineToXor(InsnList out, int offset, int inverse, int xorKey) {
        decodeValue(out, offset, inverse);
        out.add(pushInt(xorKey)); out.add(new InsnNode(IXOR));
    }

    private static void xorToAffine(InsnList out, int multiplier, int offset, int xorKey) {
        out.add(pushInt(xorKey)); out.add(new InsnNode(IXOR));
        out.add(pushInt(multiplier)); out.add(new InsnNode(IMUL));
        out.add(pushInt(offset)); out.add(new InsnNode(IADD));
    }

    private static InsnList branch(JumpInsnNode jump, int offset, int inverse) {
        InsnList out = new InsnList();
        if (jump.getOpcode() >= IF_ICMPEQ && jump.getOpcode() <= IF_ICMPLE) {
            decodeValue(out, offset, inverse);
            out.add(new InsnNode(SWAP));
            decodeValue(out, offset, inverse);
            out.add(new InsnNode(SWAP));
        } else {
            decodeValue(out, offset, inverse);
        }
        out.add(new JumpInsnNode(jump.getOpcode(), jump.label));
        return out;
    }

    private static void decodeValue(InsnList out, int offset, int inverse) {
        out.add(pushInt(offset)); out.add(new InsnNode(ISUB));
        out.add(pushInt(inverse)); out.add(new InsnNode(IMUL));
    }

    private static InsnList xor(int key) {
        InsnList out = new InsnList();
        out.add(new InsnNode(IXOR)); out.add(pushInt(key)); out.add(new InsnNode(IXOR));
        return out;
    }

    private static InsnList and(int key, int temporaryLeft, int temporaryRight) {
        InsnList out = new InsnList();
        appendMaskedAnd(out, key, temporaryLeft, temporaryRight);
        return out;
    }

    private static InsnList or(int key, int temporaryLeft, int temporaryRight) {
        InsnList out = new InsnList();
        appendMaskedOr(out, key, temporaryLeft, temporaryRight);
        return out;
    }

    private static void appendMaskedAnd(InsnList out, int key, int temporaryLeft, int temporaryRight) {
        appendMaskedBinary(out, IAND, key, temporaryLeft, temporaryRight);
    }


    private static void appendMaskedOr(InsnList out, int key, int temporaryLeft, int temporaryRight) {
        appendMaskedBinary(out, IOR, key, temporaryLeft, temporaryRight);
    }

    private static void appendMaskedBinary(InsnList out, int opcode, int key, int temporaryLeft, int temporaryRight) {
        out.add(new VarInsnNode(ISTORE, temporaryRight));
        out.add(new VarInsnNode(ISTORE, temporaryLeft));
        out.add(new VarInsnNode(ILOAD, temporaryLeft));
        out.add(new VarInsnNode(ILOAD, temporaryRight));
        out.add(new InsnNode(opcode));
        appendMaskedTerm(out, temporaryLeft, key);
        appendMaskedTerm(out, temporaryRight, key);
    }

    private static void appendMaskedTerm(InsnList out, int local, int key) {
        out.add(new VarInsnNode(ILOAD, local));
        out.add(pushInt(key));
        out.add(new InsnNode(IAND));
        out.add(new InsnNode(IXOR));
    }

    private static InsnList xorDecode(int key) {
        InsnList out = new InsnList();
        out.add(pushInt(key)); out.add(new InsnNode(IXOR)); out.add(new InsnNode(IRETURN));
        return out;
    }

    private static InsnList shiftThroughRaw(int opcode, int multiplier, int offset, int inverse) {
        InsnList out = new InsnList();
        decodeValue(out, offset, inverse);
        out.add(new InsnNode(SWAP));
        decodeValue(out, offset, inverse);
        out.add(new InsnNode(SWAP));
        out.add(new InsnNode(opcode));
        out.add(pushInt(multiplier)); out.add(new InsnNode(IMUL));
        out.add(pushInt(offset)); out.add(new InsnNode(IADD));
        return out;
    }

    private static InsnList shiftThroughRawXor(int opcode, int key) {
        InsnList out = new InsnList();
        out.add(pushInt(key)); out.add(new InsnNode(IXOR));
        out.add(new InsnNode(SWAP));
        out.add(pushInt(key)); out.add(new InsnNode(IXOR));
        out.add(new InsnNode(SWAP));
        out.add(new InsnNode(opcode));
        out.add(pushInt(key)); out.add(new InsnNode(IXOR));
        return out;
    }

    private static InsnList encodedConstant(AbstractInsnNode instruction, int multiplier, int offset, int salt) {
        Integer value = constantValue(instruction);
        if (value == null) return null;
        InsnList out = new InsnList();
        appendSplit(out, multiplier * value + offset, salt ^ value);
        return out;
    }

    private static InsnList xorConstant(AbstractInsnNode instruction, int key, int salt) {
        Integer value = constantValue(instruction);
        if (value == null) return null;
        InsnList out = new InsnList();
        appendSplit(out, value ^ key, salt ^ value);
        return out;
    }
    private static void appendSplit(InsnList out, int value, int salt) {
        int left = salt * 0x45D9F3B;
        out.add(pushInt(left));
        out.add(pushInt(value - left));
        out.add(new InsnNode(IADD));
    }

    private static Integer constantValue(AbstractInsnNode instruction) {
        if (instruction instanceof LdcInsnNode ldc && ldc.cst instanceof Integer value) return value;
        if (instruction instanceof IntInsnNode immediate
                && (immediate.getOpcode() == BIPUSH || immediate.getOpcode() == SIPUSH)) return immediate.operand;
        int opcode = instruction.getOpcode();
        return opcode >= ICONST_M1 && opcode <= ICONST_5 ? opcode - ICONST_0 : null;
    }

    private static boolean isIntegerBranch(int opcode) {
        return (opcode >= IFEQ && opcode <= IFLE) || (opcode >= IF_ICMPEQ && opcode <= IF_ICMPLE);
    }
    private static int inverseOdd32(int multiplier) {
        int inverse = multiplier;
        for (int i = 0; i < 5; i++) inverse *= 2 - multiplier * inverse;
        return inverse;
    }

    private static AbstractInsnNode pushInt(int value) {
        if (value >= -1 && value <= 5) return new InsnNode(ICONST_0 + value);
        if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) return new IntInsnNode(BIPUSH, value);
        if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) return new IntInsnNode(SIPUSH, value);
        return new LdcInsnNode(value);
    }

    private static int clamp(int value, int low, int high) { return Math.max(low, Math.min(high, value)); }

    private static int nextTemporaryLocal(MethodNode method) {
        int next = Math.max(method.maxLocals, Type.getArgumentTypes(method.desc).length);
        for (AbstractInsnNode instruction : method.instructions) {
            if (instruction instanceof VarInsnNode variable) next = Math.max(next, variable.var + 1);
            if (instruction instanceof IincInsnNode increment) next = Math.max(next, increment.var + 1);
        }
        return next;
    }

    private enum Domain { AFFINE, XOR }
    private record Candidate(Domain domain, int operations) { }
}
