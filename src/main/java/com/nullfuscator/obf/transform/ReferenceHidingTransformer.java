package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.Limits;
import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.SimpleRemapper;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Random;
import java.util.Set;

public final class ReferenceHidingTransformer implements Transformer {

    private static final char SEP = 1;

    private static final int MAX_PER_CLASS = 800;
    private static final String BOOT_SRC = "com/nullfuscator/obf/runtime/RefBootstrap";
    private static final String BOOT_DESC =
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
          + "Ljava/lang/invoke/MethodType;Ljava/lang/String;IIIII)Ljava/lang/invoke/CallSite;";
    private static final int SECRET_MARKER = 0x13579BDF;
    private static final int SECRET2_MARKER = 0x2468ACE1;
    private static final int MODE_MARKER = 0x10203047;

    @Override public String id() { return "referenceHiding"; }
    @Override public String description() { return "hide call targets behind encrypted invokedynamic"; }

    @Override
    public void transform(ObfContext ctx) {
        ctx.initializePolicies();
        int percent = Math.max(0, Math.min(100,
                ctx.config().section(id()).getInt("hidePercent", 50)));
        if (percent == 0) return;

        int poolSize = ctx.config().section(id()).getInt("bootstrapPoolSize", 8);
        if (poolSize < 0 || poolSize > 64)
            throw new IllegalArgumentException("referenceHiding.bootstrapPoolSize must be 0..64");
        int variantsPerTarget = ctx.config().section(id()).getInt("variantsPerTarget", 2);
        if (variantsPerTarget < 1 || variantsPerTarget > 16)
            throw new IllegalArgumentException("referenceHiding.variantsPerTarget must be 1..16");
        // Small inputs do not amortize a new carrier. Keep their existing class budget.
        List<ClassNode> targets = ctx.targets(id());
        if (targets.size() <= poolSize) poolSize = 0;
        if (poolSize > 0 && ctx.report() != null && ctx.report().baseline() != null) {
            var budget = ctx.config().section("budgets");
            int maximum = budget.getInt("maxClassGrowthPercent", -1);
            if (maximum >= 0) {
                long initial = ctx.report().baseline().totals().classes();
                long headroom = initial + initial * maximum / 100
                        + budget.getInt("classGrowthAllowance", 0) - ctx.classes().size();
                poolSize = (int) Math.min(poolSize, Math.max(0, headroom));
            }
        }
        SharedBootstrap[] pool = new SharedBootstrap[poolSize];
        Random rnd = ctx.random();
        int replaced = 0, bootstraps = 0, oversizedPayloads = 0;
        for (ClassNode cn : targets) {
            if (ctx.isDispersionCarrier(cn)) continue;
            if (Limits.hugeClass(cn)) continue;
            if ((cn.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION | Opcodes.ACC_MODULE)) != 0) continue;

            // Repeated calls to the same target share bounded encrypted CP entries.
            // The cache is per caller: lookup privileges and caller-bound keys stay intact.
            Map<CallTarget, List<InvokeDynamicInsnNode>> sites = new HashMap<>();
            int classHidden = 0;
            Handle bsm = null;
            int secret = 0, secret2 = 0, mode = 0;
            classLoop:
            for (MethodNode mn : new java.util.ArrayList<>(cn.methods)) {
                if (!ctx.isInputMethod(mn) || ctx.isHotPath(cn, mn)) continue;
                if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) continue;
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                if (mn.name.equals("<init>") || mn.name.equals("<clinit>")) continue;
                if (Limits.oversizeMethod(mn)) continue;
                for (AbstractInsnNode insn : mn.instructions.toArray()) {
                    if (classHidden >= MAX_PER_CLASS) break classLoop;
                    if (!(insn instanceof MethodInsnNode min) || !eligible(min)) continue;
                    if (rnd.nextInt(100) >= percent) continue;

                    CallTarget target = new CallTarget(min.getOpcode(), min.owner, min.name, min.desc, min.itf);
                    List<InvokeDynamicInsnNode> variants = sites.computeIfAbsent(target,
                            ignored -> new java.util.ArrayList<>());
                    if (variants.size() >= variantsPerTarget) {
                        InvokeDynamicInsnNode cached = variants.get(rnd.nextInt(variants.size()));
                        mn.instructions.set(min, new InvokeDynamicInsnNode(cached.name, cached.desc,
                                cached.bsm, cached.bsmArgs));
                        replaced++;
                        classHidden++;
                        continue;
                    }

                    int kind = switch (min.getOpcode()) {
                        case Opcodes.INVOKESTATIC    -> 0;
                        case Opcodes.INVOKEINTERFACE -> 2;
                        case Opcodes.INVOKESPECIAL   -> 3;
                        default                      -> 1;
                    };

                    String receiver = (kind == 3) ? cn.name : min.owner;
                    String indyDesc = (kind == 0) ? min.desc : prependReceiver(receiver, min.desc);
                    int keyA = rnd.nextInt();
                    int keyB = rnd.nextInt();
                    int mul = rnd.nextInt() | 1;
                    int add = rnd.nextInt();
                    int nonce = rnd.nextInt();
                    String callSiteName = "r" + Integer.toUnsignedString(rnd.nextInt(), 36);

                    if (bsm == null) {
                        int slot = poolSize == 0 ? -1 : bootstraps % poolSize;
                        SharedBootstrap shared = slot < 0 ? null : pool[slot];
                        if (shared == null) {
                            secret = rnd.nextInt();
                            secret2 = rnd.nextInt();
                            mode = rnd.nextInt(8);
                            ClassNode host = cn;
                            if (slot >= 0) {
                                host = new ClassNode();
                                host.version = Opcodes.V1_7;
                                host.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER;
                                host.superName = "java/lang/Object";
                                do host.name = ctx.names().nextClass(cn.name + "$");
                                while (ctx.getClass(host.name) != null
                                        || ctx.resources().containsKey(host.name + ".class"));
                            }
                            InjectedBootstrap boot = injectBootstrap(ctx, host, secret, secret2, mode);
                            if (boot == null) throw new IllegalStateException("reference bootstrap resource missing");
                            shared = new SharedBootstrap(new Handle(Opcodes.H_INVOKESTATIC,
                                    host.name, boot.entryName(), BOOT_DESC, false), secret, secret2, mode);
                            if (slot >= 0) {
                                ctx.putClass(host);
                                pool[slot] = shared;
                            }
                        }
                        bsm = shared.handle();
                        secret = shared.secret();
                        secret2 = shared.secret2();
                        mode = shared.mode();
                        bootstraps++;
                    }
                    int key = mix(keyA, keyB, callSiteName.hashCode(), cn.name.hashCode(),
                            indyDesc.hashCode(), nonce, secret, secret2, mode);
                    String payload = (char) ('0' + kind) + "" + SEP + min.owner + SEP + min.name;
                    String enc = crypt(payload, key, mul, add, nonce, mode);
                    if (!fitsConstantPoolUtf8(enc)) {
                        oversizedPayloads++;
                        continue;
                    }
                    InvokeDynamicInsnNode indy = new InvokeDynamicInsnNode(
                            callSiteName, indyDesc, bsm,
                            enc, Integer.valueOf(keyA), Integer.valueOf(keyB),
                            Integer.valueOf(mul), Integer.valueOf(add), Integer.valueOf(nonce));
                    variants.add(indy);
                    mn.instructions.set(min, indy);
                    replaced++;
                    classHidden++;
                }
            }

            if (classHidden > 0 && (cn.version & 0xFFFF) < 51) cn.version = 51;
        }
        if (oversizedPayloads > 0) ctx.log().warn("referenceHiding: kept " + oversizedPayloads
                + " calls whose encrypted names exceed the constant-pool UTF-8 limit");
        ctx.log().debug("referenceHiding: hid " + replaced + " calls using "
                + bootstraps + " protected classes; bootstrap bodies="
                + (poolSize == 0 ? bootstraps : Math.min(poolSize, bootstraps)));
    }

    private static boolean fitsConstantPoolUtf8(String value) {
        // Compact ciphertext contains only U+0000..U+00FF (one or two MUTF-8 bytes).
        if (value.length() <= 65535 / 2) return true;
        int bytes = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            bytes += c == 0 || c >= 128 ? 2 : 1;
            if (bytes > 65535) return false;
        }
        return true;
    }

    private record CallTarget(int opcode, String owner, String name, String desc, boolean itf) { }

    private record SharedBootstrap(Handle handle, int secret, int secret2, int mode) { }

    private static boolean eligible(MethodInsnNode min) {
        int op = min.getOpcode();
        if (op != Opcodes.INVOKESTATIC && op != Opcodes.INVOKEVIRTUAL
                && op != Opcodes.INVOKEINTERFACE && op != Opcodes.INVOKESPECIAL) return false;
        if (min.name.charAt(0) == '<') return false;
        if (min.owner.charAt(0) == '[') return false;
        if (min.owner.equals("java/lang/invoke/MethodHandle")
                || min.owner.equals("java/lang/invoke/VarHandle")) return false;
        return true;
    }

    private static String prependReceiver(String owner, String desc) {
        Type[] args = Type.getArgumentTypes(desc);
        StringBuilder sb = new StringBuilder("(");
        sb.append('L').append(owner).append(';');
        for (Type a : args) sb.append(a.getDescriptor());
        sb.append(')').append(Type.getReturnType(desc).getDescriptor());
        return sb.toString();
    }

    private static InjectedBootstrap injectBootstrap(ObfContext ctx, ClassNode target,
                                                      int secret, int secret2, int mode) {
        byte[] bytes;
        try (InputStream in = ReferenceHidingTransformer.class
                .getResourceAsStream("/com/nullfuscator/obf/runtime/RefBootstrap.class")) {
            if (in == null) return null;
            bytes = in.readAllBytes();
        } catch (IOException e) { return null; }
        ClassNode raw = new ClassNode();
        new ClassReader(bytes).accept(raw, 0);
        ClassNode renamed = new ClassNode();
        raw.accept(new ClassRemapper(renamed, new SimpleRemapper(BOOT_SRC, target.name)));
        for (MethodNode mn : renamed.methods) {
            if (!mn.desc.equals("()I") || !mn.name.startsWith("embedded")) continue;
            for (AbstractInsnNode in : mn.instructions.toArray()) {
                if (in instanceof LdcInsnNode ldc && ldc.cst instanceof Integer value) {
                    if (value == SECRET_MARKER) ldc.cst = Integer.valueOf(secret);
                    else if (value == SECRET2_MARKER) ldc.cst = Integer.valueOf(secret2);
                    else if (value == MODE_MARKER) ldc.cst = Integer.valueOf(mode);
                }
            }
        }
        for (MethodNode mn : renamed.methods) {
            if (mn.name.equals("nextState") && mn.desc.equals("(IIIII)I")) {
                specializeNextState(mn, mode);
            }
        }

        Map<String, String> privateNames = new HashMap<>();
        Set<String> reserved = new HashSet<>();
        for (MethodNode mn : target.methods) reserved.add(mn.name + mn.desc);
        for (MethodNode mn : renamed.methods) {
            if (mn.name.charAt(0) == '<') continue;
            String fresh;
            do fresh = ctx.names().nextRandom(ctx.random(), 7 + ctx.random().nextInt(7));
            while (reserved.contains(fresh + mn.desc));
            reserved.add(fresh + mn.desc);
            privateNames.put(mn.name + mn.desc, fresh);
        }
        String entry = privateNames.get("bootstrap" + BOOT_DESC);
        for (MethodNode mn : renamed.methods) {
            String mapped = privateNames.get(mn.name + mn.desc);
            if (mapped != null) mn.name = mapped;
            for (AbstractInsnNode in : mn.instructions.toArray()) {
                if (!(in instanceof MethodInsnNode call) || !call.owner.equals(target.name)) continue;
                String callMapped = privateNames.get(call.name + call.desc);
                if (callMapped != null) call.name = callMapped;
            }
        }
        for (MethodNode mn : renamed.methods) if (mn.name.charAt(0) != '<') target.methods.add(mn);
        return entry == null ? null : new InjectedBootstrap(entry);
    }

    private static void specializeNextState(MethodNode mn, int mode) {
        InsnList il = new InsnList();
        switch (mode & 7) {
            case 0 -> {
                il.add(new VarInsnNode(Opcodes.ILOAD, 0)); il.add(new VarInsnNode(Opcodes.ILOAD, 1));
                il.add(new InsnNode(Opcodes.IMUL)); il.add(new VarInsnNode(Opcodes.ILOAD, 2));
                il.add(new InsnNode(Opcodes.IADD)); il.add(new VarInsnNode(Opcodes.ILOAD, 4));
                il.add(new InsnNode(Opcodes.IADD)); rotate(il, "rotateLeft", 5);
            }
            case 1 -> {
                il.add(new VarInsnNode(Opcodes.ILOAD, 0)); il.add(new VarInsnNode(Opcodes.ILOAD, 1));
                il.add(new InsnNode(Opcodes.IXOR)); il.add(new VarInsnNode(Opcodes.ILOAD, 2));
                il.add(new InsnNode(Opcodes.IADD)); il.add(new VarInsnNode(Opcodes.ILOAD, 4));
                il.add(new InsnNode(Opcodes.IADD)); rotate(il, "rotateRight", 7);
            }
            case 2 -> {
                il.add(new VarInsnNode(Opcodes.ILOAD, 0)); il.add(new VarInsnNode(Opcodes.ILOAD, 2));
                il.add(new InsnNode(Opcodes.IADD)); rotate(il, "rotateLeft", 11);
                il.add(new VarInsnNode(Opcodes.ILOAD, 1)); il.add(new InsnNode(Opcodes.IXOR));
                il.add(new VarInsnNode(Opcodes.ILOAD, 4)); il.add(new InsnNode(Opcodes.IXOR));
            }
            case 3 -> {
                il.add(new VarInsnNode(Opcodes.ILOAD, 0)); rotate(il, "rotateRight", 3);
                il.add(new VarInsnNode(Opcodes.ILOAD, 1)); il.add(new InsnNode(Opcodes.IADD));
                il.add(new VarInsnNode(Opcodes.ILOAD, 2)); il.add(new VarInsnNode(Opcodes.ILOAD, 4));
                il.add(new InsnNode(Opcodes.IADD)); il.add(new InsnNode(Opcodes.IXOR));
            }
            case 4 -> {
                il.add(new VarInsnNode(Opcodes.ILOAD, 0)); il.add(new VarInsnNode(Opcodes.ILOAD, 2));
                il.add(new InsnNode(Opcodes.IXOR)); il.add(new VarInsnNode(Opcodes.ILOAD, 4));
                il.add(new InsnNode(Opcodes.IXOR)); rotate(il, "rotateLeft", 9);
                il.add(new VarInsnNode(Opcodes.ILOAD, 1)); il.add(new InsnNode(Opcodes.IADD));
            }
            case 5 -> {
                il.add(new VarInsnNode(Opcodes.ILOAD, 0)); il.add(new VarInsnNode(Opcodes.ILOAD, 1));
                il.add(new VarInsnNode(Opcodes.ILOAD, 4));
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "rotateLeft", "(II)I", false));
                il.add(new InsnNode(Opcodes.IADD)); il.add(new VarInsnNode(Opcodes.ILOAD, 2));
                il.add(new InsnNode(Opcodes.IXOR));
            }
            case 6 -> {
                il.add(new VarInsnNode(Opcodes.ILOAD, 0)); il.add(new VarInsnNode(Opcodes.ILOAD, 1));
                il.add(new InsnNode(Opcodes.ICONST_1)); il.add(new InsnNode(Opcodes.IOR));
                il.add(new InsnNode(Opcodes.IMUL)); rotate(il, "rotateRight", 13);
                il.add(new VarInsnNode(Opcodes.ILOAD, 2)); il.add(new InsnNode(Opcodes.IADD));
                il.add(new VarInsnNode(Opcodes.ILOAD, 4)); il.add(new InsnNode(Opcodes.IADD));
            }
            default -> {
                il.add(new VarInsnNode(Opcodes.ILOAD, 0)); il.add(new VarInsnNode(Opcodes.ILOAD, 1));
                il.add(new InsnNode(Opcodes.IADD)); il.add(new VarInsnNode(Opcodes.ILOAD, 4));
                il.add(new InsnNode(Opcodes.IADD)); rotate(il, "rotateLeft", 17);
                il.add(new VarInsnNode(Opcodes.ILOAD, 2)); il.add(new InsnNode(Opcodes.IXOR));
            }
        }
        il.add(new InsnNode(Opcodes.IRETURN));
        mn.instructions = il;
        mn.tryCatchBlocks = new java.util.ArrayList<>();
        mn.localVariables = null;
        mn.maxLocals = 5;
        mn.maxStack = 4;
    }

    private static void rotate(InsnList il, String name, int distance) {
        il.add(new LdcInsnNode(distance));
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", name, "(II)I", false));
    }

    private static int mix(int a, int b, int n, int c, int t, int nonce,
                           int secret, int secret2, int mode) {
        int h = secret ^ Integer.rotateLeft(secret2, mode & 31);
        h = Integer.rotateLeft(h + a, 7) ^ b;
        h = (h ^ n) * 0x85EBCA6B;
        h = Integer.rotateLeft(h + c, 13) ^ t ^ nonce;
        h ^= h >>> 16;
        h *= 0xC2B2AE35;
        return h ^ (h >>> 13);
    }

    private static String crypt(String s, int key, int mul, int add, int nonce, int mode) {
        // Encode UTF-16 code units in 1..3 bytes, preserving even isolated surrogates.
        // ASCII descriptors no longer produce two bytes of random entropy per character.
        char[] bytes = new char[s.length() * 3];
        int length = 0;
        for (int i = 0; i < s.length(); i++) {
            int c = s.charAt(i);
            if (c < 0x80) bytes[length++] = (char) c;
            else if (c < 0x800) {
                bytes[length++] = (char) (0xc0 | (c >>> 6));
                bytes[length++] = (char) (0x80 | (c & 63));
            } else {
                bytes[length++] = (char) (0xe0 | (c >>> 12));
                bytes[length++] = (char) (0x80 | ((c >>> 6) & 63));
                bytes[length++] = (char) (0x80 | (c & 63));
            }
        }
        int k = key;
        for (int i = 0; i < length; i++) {
            int lo = k & 255;
            int hi = (k >>> 16) & 255;
            int v = bytes[i];
            int mask = Integer.rotateLeft(k ^ nonce, (mode + i) & 31) & 255;
            int r = ((k >>> 27) + mode + i) & 7;
            v ^= lo;
            v = ((v << r) | (v >>> (8 - r))) & 255;
            v = (v + hi) & 255;
            bytes[i] = (char) (v ^ mask);
            k = nextState(k, mul, add, mode, i);
        }
        return new String(bytes, 0, length);
    }

    private static int nextState(int k, int mul, int add, int mode, int i) {
        return switch (mode & 7) {
            case 0 -> Integer.rotateLeft(k * mul + add + i, 5);
            case 1 -> Integer.rotateRight((k ^ mul) + add + i, 7);
            case 2 -> Integer.rotateLeft(k + add, 11) ^ mul ^ i;
            case 3 -> (Integer.rotateRight(k, 3) + mul) ^ (add + i);
            case 4 -> Integer.rotateLeft(k ^ add ^ i, 9) + mul;
            case 5 -> (k + Integer.rotateLeft(mul, i & 31)) ^ add;
            case 6 -> Integer.rotateRight(k * (mul | 1), 13) + add + i;
            default -> Integer.rotateLeft(k + mul + i, 17) ^ add;
        };
    }

    private record InjectedBootstrap(String entryName) { }
}
