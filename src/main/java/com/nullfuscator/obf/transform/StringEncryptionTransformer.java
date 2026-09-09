package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static org.objectweb.asm.Opcodes.*;

public final class StringEncryptionTransformer implements Transformer {

    private static final String DECODER_DESC = "(Ljava/lang/String;I)Ljava/lang/String;";
    private static final String CONDY_BSM_DESC = "(Ljava/lang/invoke/MethodHandles$Lookup;"
            + "Ljava/lang/String;Ljava/lang/Class;II[Ljava/lang/String;)Ljava/lang/String;";
    // A UTF-16 code unit takes at most three bytes in class-file modified UTF-8.
    private static final int CIPHER_CHUNK_CHARS = 65535 / 3;

    @Override public String id() { return "stringEncryption"; }
    @Override public String description() { return "encrypt string constants with per-site rolling XOR keys"; }

    @Override
    public void transform(ObfContext ctx) {
        boolean polymorphic = "POLYMORPHIC".equalsIgnoreCase(
                ctx.config().section(id()).getString("type", "STANDARD"));
        int touchedClasses = 0;
        int encrypted = 0;
        int concats = 0;
        int constValues = 0;
        int stateBound = 0;
        int cachedConstants = 0;

        for (ClassNode cn : ctx.targets(id())) {
            if (ctx.isHotClass(cn)) continue;
            boolean isInterface = (cn.access & ACC_INTERFACE) != 0;

            int majorVersion = cn.version & 0xFFFF;
            if (isInterface && majorVersion < V1_8) continue;
            boolean cacheConstants = majorVersion >= V11;
            if (com.nullfuscator.obf.core.Limits.hugeClass(cn)) continue;

            List<Hit> hits = new ArrayList<>();
            List<ConcatHit> concatHits = new ArrayList<>();
            for (MethodNode mn : cn.methods) {
                if (ctx.isHotPath(cn, mn)) continue;
                if ((mn.access & (ACC_ABSTRACT | ACC_NATIVE)) != 0) continue;
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                if (com.nullfuscator.obf.core.Limits.oversizeMethod(mn)) continue;
                for (AbstractInsnNode insn : mn.instructions.toArray()) {
                    if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof String) {
                        hits.add(new Hit(mn, ldc));
                    } else if (insn instanceof InvokeDynamicInsnNode indy && isEncryptableConcat(indy)) {
                        concatHits.add(new ConcatHit(mn, indy));
                    }
                }
            }
            boolean hasFieldConstants = cn.fields.stream().anyMatch(f -> f.value instanceof String);
            if (hits.isEmpty() && concatHits.isEmpty() && !hasFieldConstants) continue;

            // Input methods may already use the same alphabet as generated helpers.
            for (MethodNode method : cn.methods) ctx.names().reserve(method.name);

            Random rnd = ctx.random();
            int familyCount = polymorphic ? 4 : 1;
            CipherFamily[] families = new CipherFamily[familyCount];
            String[] decoderNames = new String[familyCount];
            String[] bootstrapNames = new String[familyCount];
            List<MethodNode> familyMethods = new ArrayList<>();
            for (int family = 0; family < familyCount; family++) {
                int charMul = rnd.nextInt() | 1;
                families[family] = new CipherFamily(family, rnd.nextInt() | 1,
                        rnd.nextInt(), charMul, inverse16(charMul));
                decoderNames[family] = ctx.names().next();
                MethodNode decoder = buildDecoder(decoderNames[family], families[family]);
                if (isInterface && majorVersion == V1_8)
                    decoder.access = (decoder.access & ~ACC_PRIVATE) | ACC_PUBLIC;
                familyMethods.add(decoder);
                if (cacheConstants) {
                    bootstrapNames[family] = ctx.names().next();
                    familyMethods.add(buildCondyBootstrap(bootstrapNames[family],
                            decoderNames[family], cn.name, isInterface));
                }
            }

            int[] condyOrdinal = { 0 };

            for (Hit hit : hits) {
                int key = rnd.nextInt();
                int familyIndex = rnd.nextInt(familyCount);
                CipherFamily family = families[familyIndex];
                String plain = (String) hit.ldc.cst;
                String cipher = crypt(plain, key, family);
                InsnList repl = new InsnList();
                ObfContext.StringStateBinding binding = ctx.stringState(hit.ldc);
                if (binding != null) {
                    pushCipher(repl, cipher);
                    pushSplitKey(repl, key, rnd);
                    repl.add(new VarInsnNode(ILOAD, binding.stateVar()));
                    repl.add(pushInt(binding.encodedState()));
                    repl.add(new InsnNode(IXOR));
                    repl.add(new InsnNode(IXOR));
                    stateBound++;
                    repl.add(new MethodInsnNode(INVOKESTATIC, cn.name,
                            decoderNames[familyIndex], DECODER_DESC, isInterface));
                } else {
                    pushEncrypted(repl, cn.name, decoderNames[familyIndex], bootstrapNames[familyIndex],
                            cipher, key, rnd, isInterface, condyOrdinal);
                }
                hit.mn.instructions.insertBefore(hit.ldc, repl);
                hit.mn.instructions.remove(hit.ldc);
                encrypted++;
            }

            for (ConcatHit ch : concatHits) {
                InsnList repl = desugarConcat(ch.mn, ch.indy, cn.name, decoderNames, bootstrapNames,
                        families, rnd, isInterface, condyOrdinal);
                if (repl == null) continue;
                ch.mn.instructions.insertBefore(ch.indy, repl);
                ch.mn.instructions.remove(ch.indy);
                concats++;
            }
            cachedConstants += condyOrdinal[0];

            if (cn.fields != null) {
                for (FieldNode fn : cn.fields) {
                    if (!(fn.value instanceof String s)) continue;
                    if ((fn.access & ACC_STATIC) != 0) {
                        MethodNode clinit = findOrCreateClinit(cn);
                        if (clinit == null || com.nullfuscator.obf.core.Limits.oversizeMethod(clinit)) {
                            continue;
                        }
                        int key = rnd.nextInt();
                        int familyIndex = rnd.nextInt(familyCount);
                        CipherFamily family = families[familyIndex];
                        InsnList init = new InsnList();
                        pushCipher(init, crypt(s, key, family));
                        pushSplitKey(init, key, rnd);
                        init.add(new MethodInsnNode(INVOKESTATIC, cn.name,
                                decoderNames[familyIndex], DECODER_DESC, isInterface));
                        init.add(new FieldInsnNode(PUTSTATIC, cn.name, fn.name, "Ljava/lang/String;"));
                        clinit.instructions.insert(init);
                    }
                    fn.value = null;
                    constValues++;
                }
            }
            java.util.Set<String> used = new java.util.HashSet<>();
            for (MethodNode method : cn.methods) {
                for (AbstractInsnNode insn : method.instructions) {
                    if (insn instanceof MethodInsnNode call && call.owner.equals(cn.name))
                        used.add(call.name);
                    if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof ConstantDynamic constant
                            && constant.getBootstrapMethod().getOwner().equals(cn.name))
                        used.add(constant.getBootstrapMethod().getName());
                }
            }
            for (int family = 0; family < familyCount; family++)
                if (used.contains(bootstrapNames[family])) used.add(decoderNames[family]);
            for (MethodNode method : familyMethods)
                if (used.contains(method.name)) cn.methods.add(method);
            touchedClasses++;
        }
        ctx.log().pass(id(), "encrypted " + encrypted + " strings + " + concats
                + " concatenations + " + constValues + " field constants across "
                + touchedClasses + " classes, " + stateBound + " state-bound ("
                + cachedConstants + " constant-pool cached, "
                + (polymorphic ? "polymorphic" : "standard") + ")");
    }

    private static MethodNode findOrCreateClinit(ClassNode cn) {
        for (MethodNode m : cn.methods) {
            if (m.name.equals("<clinit>") && m.desc.equals("()V")) return m;
        }
        MethodNode clinit = new MethodNode(ASM9, ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.instructions = new InsnList();
        clinit.instructions.add(new InsnNode(RETURN));
        cn.methods.add(clinit);
        return clinit;
    }

    private static final String SCF = "java/lang/invoke/StringConcatFactory";

    private static final char TAG_ARG = 1, TAG_CONST = 2;

    private static boolean isEncryptableConcat(InvokeDynamicInsnNode indy) {
        if (indy.bsm == null || !SCF.equals(indy.bsm.getOwner())
                || !"makeConcatWithConstants".equals(indy.bsm.getName())) return false;
        Object[] a = indy.bsmArgs;
        if (a.length < 1 || !(a[0] instanceof String recipe)) return false;
        for (int i = 1; i < a.length; i++) if (!(a[i] instanceof String)) return false;
        boolean hasLiteral = false;
        for (int i = 0; i < recipe.length(); i++) {
            char c = recipe.charAt(i);
            if (c != TAG_ARG && c != TAG_CONST) { hasLiteral = true; break; }
        }
        return hasLiteral || a.length > 1;
    }

    private InsnList desugarConcat(MethodNode mn, InvokeDynamicInsnNode indy,
                                   String owner, String[] decoderNames, String[] bootstrapNames,
                                   CipherFamily[] families, Random rnd, boolean itf,
                                   int[] condyOrdinal) {
        Type[] args = Type.getArgumentTypes(indy.desc);
        int[] slot = new int[args.length];
        int cur = mn.maxLocals;
        for (int i = 0; i < args.length; i++) { slot[i] = cur; cur += args[i].getSize(); }
        mn.maxLocals = Math.max(mn.maxLocals, cur);

        InsnList il = new InsnList();

        for (int i = args.length - 1; i >= 0; i--) {
            il.add(new VarInsnNode(args[i].getOpcode(ISTORE), slot[i]));
        }
        il.add(new TypeInsnNode(NEW, "java/lang/StringBuilder"));
        il.add(new InsnNode(DUP));
        il.add(new MethodInsnNode(INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false));

        String recipe = (String) indy.bsmArgs[0];
        int argCursor = 0, constCursor = 1;
        StringBuilder lit = new StringBuilder();
        for (int p = 0; p < recipe.length(); p++) {
            char c = recipe.charAt(p);
            if (c == TAG_ARG || c == TAG_CONST) {
                flushLiteral(il, lit, owner, decoderNames, bootstrapNames, families, rnd, itf,
                        condyOrdinal);
                if (c == TAG_ARG) {
                    Type t = args[argCursor];
                    il.add(new VarInsnNode(t.getOpcode(ILOAD), slot[argCursor]));
                    il.add(appendCall(t));
                    argCursor++;
                } else {
                    String s = (String) indy.bsmArgs[constCursor++];
                    encryptedAppend(il, s, owner, decoderNames, bootstrapNames, families, rnd, itf,
                            condyOrdinal);
                }
            } else {
                lit.append(c);
            }
        }
        flushLiteral(il, lit, owner, decoderNames, bootstrapNames, families, rnd, itf, condyOrdinal);
        il.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/StringBuilder",
                "toString", "()Ljava/lang/String;", false));
        return il;
    }

    private void flushLiteral(InsnList il, StringBuilder lit, String owner,
                              String[] decoderNames, String[] bootstrapNames, CipherFamily[] families,
                              Random rnd, boolean itf, int[] condyOrdinal) {
        if (lit.length() == 0) return;
        encryptedAppend(il, lit.toString(), owner, decoderNames, bootstrapNames, families, rnd, itf,
                condyOrdinal);
        lit.setLength(0);
    }

    private void encryptedAppend(InsnList il, String s, String owner,
                                 String[] decoderNames, String[] bootstrapNames, CipherFamily[] families,
                                 Random rnd, boolean itf, int[] condyOrdinal) {
        int key = rnd.nextInt();
        int familyIndex = rnd.nextInt(families.length);
        pushEncrypted(il, owner, decoderNames[familyIndex], bootstrapNames[familyIndex],
                crypt(s, key, families[familyIndex]), key, rnd, itf, condyOrdinal);
        il.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/StringBuilder",
                "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
    }

    private static MethodInsnNode appendCall(Type t) {
        String desc = switch (t.getSort()) {
            case Type.BOOLEAN -> "(Z)Ljava/lang/StringBuilder;";
            case Type.CHAR    -> "(C)Ljava/lang/StringBuilder;";
            case Type.BYTE, Type.SHORT, Type.INT -> "(I)Ljava/lang/StringBuilder;";
            case Type.LONG    -> "(J)Ljava/lang/StringBuilder;";
            case Type.FLOAT   -> "(F)Ljava/lang/StringBuilder;";
            case Type.DOUBLE  -> "(D)Ljava/lang/StringBuilder;";
            default           -> "(Ljava/lang/Object;)Ljava/lang/StringBuilder;";
        };
        return new MethodInsnNode(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", desc, false);
    }

    private static String crypt(String s, int key, CipherFamily family) {
        char[] c = s.toCharArray();
        int k = key;
        for (int i = 0; i < c.length; i++) {
            int low = k & 0xFFFF;
            int high = (k >>> 16) & 0xFFFF;
            int value = c[i];
            value = switch (family.mode) {
                case 1 -> ((value ^ low) + high) & 0xFFFF;
                case 2 -> rotateLeft16(value ^ low, ((k >>> 27) & 15) + 1);
                case 3 -> (((value ^ low) * family.charMul) + high) & 0xFFFF;
                default -> value ^ low;
            };
            c[i] = (char) value;
            k = Integer.rotateLeft(k ^ value, 5) * family.rollMul + family.rollAdd;
        }
        return new String(c);
    }

    private static MethodNode buildDecoder(String name, CipherFamily family) {
        MethodNode dec = new MethodNode(ASM9,
                ACC_PRIVATE | ACC_STATIC | ACC_SYNTHETIC, name, DECODER_DESC, null, null);

        InsnList il = new InsnList();
        LabelNode start = new LabelNode();
        LabelNode end = new LabelNode();

        il.add(new VarInsnNode(ALOAD, 0));
        il.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/String", "toCharArray", "()[C", false));
        il.add(new VarInsnNode(ASTORE, 2));

        il.add(new VarInsnNode(ILOAD, 1));
        il.add(new VarInsnNode(ISTORE, 3));

        il.add(new InsnNode(ICONST_0));
        il.add(new VarInsnNode(ISTORE, 4));

        il.add(start);

        il.add(new VarInsnNode(ILOAD, 4));
        il.add(new VarInsnNode(ALOAD, 2));
        il.add(new InsnNode(ARRAYLENGTH));
        il.add(new JumpInsnNode(IF_ICMPGE, end));

        if (family.mode == 2) {

            il.add(new VarInsnNode(ILOAD, 3));
            il.add(pushInt(27));
            il.add(new InsnNode(IUSHR));
            il.add(pushInt(15));
            il.add(new InsnNode(IAND));
            il.add(new InsnNode(ICONST_1));
            il.add(new InsnNode(IADD));
            il.add(new VarInsnNode(ISTORE, 5));
        }

        il.add(new VarInsnNode(ALOAD, 2));
        il.add(new VarInsnNode(ILOAD, 4));
        il.add(new VarInsnNode(ALOAD, 2));
        il.add(new VarInsnNode(ILOAD, 4));
        il.add(new InsnNode(CALOAD));
        il.add(new InsnNode(DUP));
        il.add(new VarInsnNode(ISTORE, 7));
        emitDecodeChar(il, family);
        il.add(new InsnNode(I2C));
        il.add(new InsnNode(CASTORE));

        il.add(new VarInsnNode(ILOAD, 3));
        il.add(new VarInsnNode(ILOAD, 7));
        il.add(new InsnNode(IXOR));
        il.add(pushInt(5));
        il.add(new MethodInsnNode(INVOKESTATIC, "java/lang/Integer", "rotateLeft", "(II)I", false));
        il.add(pushInt(family.rollMul));
        il.add(new InsnNode(IMUL));
        il.add(pushInt(family.rollAdd));
        il.add(new InsnNode(IADD));
        il.add(new VarInsnNode(ISTORE, 3));

        il.add(new IincInsnNode(4, 1));
        il.add(new JumpInsnNode(GOTO, start));

        il.add(end);

        il.add(new VarInsnNode(ALOAD, 2));
        il.add(new MethodInsnNode(INVOKESTATIC, "java/lang/String", "valueOf", "([C)Ljava/lang/String;", false));

        il.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/String", "intern", "()Ljava/lang/String;", false));
        il.add(new InsnNode(ARETURN));

        dec.instructions = il;
        return dec;
    }

    private static MethodNode buildCondyBootstrap(String name, String decoderName,
                                                   String owner, boolean itf) {
        MethodNode bootstrap = new MethodNode(ASM9,
                ACC_PRIVATE | ACC_STATIC | ACC_SYNTHETIC | ACC_VARARGS,
                name, CONDY_BSM_DESC, null, new String[] { "java/lang/Throwable" });
        InsnList il = bootstrap.instructions;
        il.add(new LdcInsnNode(""));
        il.add(new VarInsnNode(ALOAD, 5));
        il.add(new MethodInsnNode(INVOKESTATIC, "java/lang/String", "join",
                "(Ljava/lang/CharSequence;[Ljava/lang/CharSequence;)Ljava/lang/String;", false));
        il.add(new VarInsnNode(ILOAD, 3));
        il.add(new VarInsnNode(ILOAD, 4));
        il.add(new InsnNode(IXOR));
        il.add(new MethodInsnNode(INVOKESTATIC, owner, decoderName, DECODER_DESC, itf));
        il.add(new InsnNode(ARETURN));
        return bootstrap;
    }

    private static LdcInsnNode cachedStringConstant(String owner, String bootstrapName,
                                                     String cipher, int key, Random rnd,
                                                     boolean itf, int ordinal) {
        int mask = rnd.nextInt();
        Handle bootstrap = new Handle(H_INVOKESTATIC, owner, bootstrapName,
                CONDY_BSM_DESC, itf);
        List<String> chunks = cipherChunks(cipher);
        Object[] arguments = new Object[chunks.size() + 2];
        arguments[0] = key ^ mask;
        arguments[1] = mask;
        for (int i = 0; i < chunks.size(); i++) arguments[i + 2] = chunks.get(i);
        ConstantDynamic constant = new ConstantDynamic("s$" + ordinal,
                "Ljava/lang/String;", bootstrap, arguments);
        return new LdcInsnNode(constant);
    }

    private static List<String> cipherChunks(String cipher) {
        List<String> chunks = new ArrayList<>();
        for (int start = 0; start < cipher.length(); start += CIPHER_CHUNK_CHARS)
            chunks.add(cipher.substring(start, Math.min(cipher.length(), start + CIPHER_CHUNK_CHARS)));
        if (chunks.isEmpty()) chunks.add("");
        return chunks;
    }

    private static void pushCipher(InsnList il, String cipher) {
        List<String> chunks = cipherChunks(cipher);
        if (chunks.size() == 1) {
            il.add(new LdcInsnNode(chunks.get(0)));
            return;
        }
        il.add(new TypeInsnNode(NEW, "java/lang/StringBuilder"));
        il.add(new InsnNode(DUP));
        il.add(new MethodInsnNode(INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false));
        for (String chunk : chunks) {
            il.add(new LdcInsnNode(chunk));
            il.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                    "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
        }
        il.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/StringBuilder", "toString",
                "()Ljava/lang/String;", false));
    }

    private static void pushEncrypted(InsnList il, String owner, String decoder, String bootstrap,
                                      String cipher, int key, Random rnd, boolean itf, int[] ordinal) {
        if (bootstrap != null) {
            il.add(cachedStringConstant(owner, bootstrap, cipher, key, rnd, itf, ordinal[0]++));
        } else {
            pushCipher(il, cipher);
            pushSplitKey(il, key, rnd);
            il.add(new MethodInsnNode(INVOKESTATIC, owner, decoder, DECODER_DESC, itf));
        }
    }

    private static void emitDecodeChar(InsnList il, CipherFamily family) {
        switch (family.mode) {
            case 1 -> {
                il.add(new VarInsnNode(ILOAD, 3));
                il.add(pushInt(16));
                il.add(new InsnNode(IUSHR));
                il.add(pushInt(0xFFFF));
                il.add(new InsnNode(IAND));
                il.add(new InsnNode(ISUB));
                il.add(pushInt(0xFFFF));
                il.add(new InsnNode(IAND));
                pushLowKeyXor(il);
            }
            case 2 -> {

                il.add(new VarInsnNode(ISTORE, 6));
                il.add(new VarInsnNode(ILOAD, 6));
                il.add(new VarInsnNode(ILOAD, 5));
                il.add(new InsnNode(IUSHR));
                il.add(new VarInsnNode(ILOAD, 6));
                il.add(pushInt(16));
                il.add(new VarInsnNode(ILOAD, 5));
                il.add(new InsnNode(ISUB));
                il.add(new InsnNode(ISHL));
                il.add(new InsnNode(IOR));
                il.add(pushInt(0xFFFF));
                il.add(new InsnNode(IAND));
                pushLowKeyXor(il);
            }
            case 3 -> {
                il.add(new VarInsnNode(ILOAD, 3));
                il.add(pushInt(16));
                il.add(new InsnNode(IUSHR));
                il.add(pushInt(0xFFFF));
                il.add(new InsnNode(IAND));
                il.add(new InsnNode(ISUB));
                il.add(pushInt(family.charInverse));
                il.add(new InsnNode(IMUL));
                il.add(pushInt(0xFFFF));
                il.add(new InsnNode(IAND));
                pushLowKeyXor(il);
            }
            default -> pushLowKeyXor(il);
        }
    }

    private static void pushLowKeyXor(InsnList il) {
        il.add(new VarInsnNode(ILOAD, 3));
        il.add(pushInt(0xFFFF));
        il.add(new InsnNode(IAND));
        il.add(new InsnNode(IXOR));
    }

    private static AbstractInsnNode pushInt(int v) {
        if (v >= -1 && v <= 5) return new InsnNode(ICONST_0 + v);
        if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) return new IntInsnNode(BIPUSH, v);
        if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) return new IntInsnNode(SIPUSH, v);
        return new LdcInsnNode(Integer.valueOf(v));
    }

    private static void pushSplitKey(InsnList il, int key, Random rnd) {
        int mask = rnd.nextInt();
        il.add(pushInt(key ^ mask));
        il.add(pushInt(mask));
        il.add(new InsnNode(IXOR));
    }

    private static int rotateLeft16(int value, int distance) {
        int v = value & 0xFFFF;
        return ((v << distance) | (v >>> (16 - distance))) & 0xFFFF;
    }

    private static int inverse16(int odd) {
        int x = odd;
        x *= 2 - odd * x;
        x *= 2 - odd * x;
        x *= 2 - odd * x;
        x *= 2 - odd * x;
        return x & 0xFFFF;
    }

    private record Hit(MethodNode mn, LdcInsnNode ldc) { }
    private record ConcatHit(MethodNode mn, InvokeDynamicInsnNode indy) { }
    private record CipherFamily(int mode, int rollMul, int rollAdd,
                                int charMul, int charInverse) { }
}
