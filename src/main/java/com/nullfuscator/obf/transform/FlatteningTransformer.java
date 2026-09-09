package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.Limits;
import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeMap;

public final class FlatteningTransformer implements Transformer {

    @Override public String id() { return "flatten"; }
    @Override public String description() { return "flatten control flow into a switch dispatcher"; }

    private static final Map<LabelNode, LabelNode> NO_LABELS = new HashMap<>();

    @Override
    public void transform(ObfContext ctx) {
        int percent = Math.max(0, Math.min(100, ctx.config().section(id()).getInt("percent", 100)));
        if (percent == 0) return;
        Random rnd = ctx.random();
        int flattened = 0;
        for (ClassNode cn : ctx.targets(id())) {
            for (MethodNode mn : cn.methods) {
                if (ctx.isHotPath(cn, mn)) continue;
                if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) continue;
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                if (mn.name.equals("<init>")) continue;
                if (mn.tryCatchBlocks != null && !mn.tryCatchBlocks.isEmpty()) continue;
                if (Limits.oversizeMethod(mn)) continue;
                if (rnd.nextInt(100) >= percent) continue;
                try {
                    if (flatten(ctx, cn, mn, rnd)) flattened++;
                } catch (RuntimeException | org.objectweb.asm.tree.analysis.AnalyzerException e) {

                }
            }
        }
        ctx.log().debug("flatten: " + flattened + " methods flattened");
    }

    private boolean flatten(ObfContext ctx, ClassNode cn, MethodNode mn, Random rnd)
            throws org.objectweb.asm.tree.analysis.AnalyzerException {
        String owner = cn.name;
        boolean allowReferenceLocals = ctx.config().section(id())
                .getBoolean("allowReferenceLocals", false);
        AbstractInsnNode[] arr = mn.instructions.toArray();
        int n = arr.length;

        for (AbstractInsnNode in : arr) {
            int op = in.getOpcode();
            if (op == Opcodes.TABLESWITCH || op == Opcodes.LOOKUPSWITCH
                    || op == Opcodes.JSR || op == Opcodes.RET) return false;
        }

        Map<AbstractInsnNode, Integer> index = new IdentityHashMap<>();
        for (int i = 0; i < n; i++) index.put(arr[i], i);

        Frame<BasicValue>[] frames = new Analyzer<BasicValue>(new CtxVerifier(ctx, cn)).analyze(owner, mn);

        Set<Integer> leaders = new HashSet<>();
        leaders.add(0);
        for (int i = 0; i < n; i++) {
            AbstractInsnNode in = arr[i];
            if (in instanceof JumpInsnNode j) {
                leaders.add(index.get(j.label));
                if (i + 1 < n) leaders.add(i + 1);
            } else if (isExit(in.getOpcode()) && i + 1 < n) {
                leaders.add(i + 1);
            }
        }
        List<Integer> sortedLeaders = new ArrayList<>(leaders);
        java.util.Collections.sort(sortedLeaders);

        List<int[]> blocks = new ArrayList<>();
        for (int b = 0; b < sortedLeaders.size(); b++) {
            int start = sortedLeaders.get(b);
            int end = (b + 1 < sortedLeaders.size()) ? sortedLeaders.get(b + 1) : n;
            blocks.add(new int[] { start, end });
            int fr = firstReal(arr, start, end);
            if (fr < 0) continue;
            Frame<BasicValue> f = frames[fr];
            if (f == null) return false;
            if (f.getStackSize() != 0) return false;
        }
        if (blocks.size() < 3) return false;

        final int origMaxLocals = mn.maxLocals;
        int[] cat = new int[origMaxLocals];
        for (Frame<BasicValue> f : frames) {
            if (f == null) continue;
            for (int s2 = 0; s2 < f.getLocals() && s2 < origMaxLocals; s2++) {
                int c = catOf(f.getLocal(s2));
                if (c == 0) continue;
                if (cat[s2] == 0) cat[s2] = c;
                else if (cat[s2] != c) return false;
            }
        }
        int paramSlots = (org.objectweb.asm.Type.getArgumentsAndReturnSizes(mn.desc) >> 2);
        if ((mn.access & Opcodes.ACC_STATIC) != 0) paramSlots -= 1;

        if (!allowReferenceLocals) {
            for (int slot = paramSlots; slot < origMaxLocals; slot++) {
                if (cat[slot] == 5) return false;
            }
        }

        Map<LabelNode, Integer> labelBlock = new HashMap<>();
        for (int b = 0; b < blocks.size(); b++) {
            int s = blocks.get(b)[0], e = blocks.get(b)[1];
            for (int i = s; i < e; i++) {
                if (arr[i] instanceof LabelNode ln) labelBlock.put(ln, b);
                else break;
            }
        }

        int[] state = new int[blocks.size()];
        Set<Integer> used = new HashSet<>();
        for (int b = 0; b < blocks.size(); b++) {
            int s; do { s = rnd.nextInt(); } while (!used.add(s));
            state[b] = s;
        }

        int stateKey = rnd.nextInt();
        int stateRotation = 1 + rnd.nextInt(31);

        int stateVar = mn.maxLocals;
        int newMaxLocals = mn.maxLocals + 1;
        LabelNode dispatch = new LabelNode();
        LabelNode dflt = new LabelNode();
        LabelNode[] blockLabel = new LabelNode[blocks.size()];
        for (int b = 0; b < blocks.size(); b++) blockLabel[b] = new LabelNode();

        InsnList out = new InsnList();

        for (int s2 = paramSlots; s2 < origMaxLocals; ) {
            switch (cat[s2]) {
                case 1 -> { out.add(new InsnNode(Opcodes.ICONST_0)); out.add(new VarInsnNode(Opcodes.ISTORE, s2)); s2 += 1; }
                case 2 -> { out.add(new InsnNode(Opcodes.FCONST_0)); out.add(new VarInsnNode(Opcodes.FSTORE, s2)); s2 += 1; }
                case 3 -> { out.add(new InsnNode(Opcodes.LCONST_0)); out.add(new VarInsnNode(Opcodes.LSTORE, s2)); s2 += 2; }
                case 4 -> { out.add(new InsnNode(Opcodes.DCONST_0)); out.add(new VarInsnNode(Opcodes.DSTORE, s2)); s2 += 2; }
                case 5 -> { out.add(new InsnNode(Opcodes.ACONST_NULL)); out.add(new VarInsnNode(Opcodes.ASTORE, s2)); s2 += 1; }
                default -> s2 += 1;
            }
        }

        out.add(pushInt(encodeState(state[0], stateKey, stateRotation)));
        out.add(new VarInsnNode(Opcodes.ISTORE, stateVar));
        out.add(new JumpInsnNode(Opcodes.GOTO, dispatch));

        out.add(dispatch);
        out.add(new VarInsnNode(Opcodes.ILOAD, stateVar));
        out.add(pushInt(stateRotation));
        out.add(new org.objectweb.asm.tree.MethodInsnNode(
                Opcodes.INVOKESTATIC, "java/lang/Integer", "rotateRight", "(II)I", false));
        out.add(pushInt(stateKey));
        out.add(new InsnNode(Opcodes.IXOR));
        TreeMap<Integer, LabelNode> sw = new TreeMap<>();
        for (int b = 0; b < blocks.size(); b++) sw.put(state[b], blockLabel[b]);

        int decoys = 2 + rnd.nextInt(4);
        for (int i = 0; i < decoys; i++) {
            int bogus;
            do { bogus = rnd.nextInt(); } while (sw.containsKey(bogus));
            sw.put(bogus, dflt);
        }
        int[] keys = new int[sw.size()];
        LabelNode[] labs = new LabelNode[sw.size()];
        int ki = 0;
        for (Map.Entry<Integer, LabelNode> en : sw.entrySet()) { keys[ki] = en.getKey(); labs[ki] = en.getValue(); ki++; }
        out.add(new LookupSwitchInsnNode(dflt, keys, labs));

        List<Integer> order = new ArrayList<>();
        for (int b = 0; b < blocks.size(); b++) order.add(b);
        java.util.Collections.shuffle(order, rnd);

        for (int b : order) {
            int s = blocks.get(b)[0], e = blocks.get(b)[1];
            out.add(blockLabel[b]);
            int lastReal = lastReal(arr, s, e);
            int term = (lastReal >= 0) ? arr[lastReal].getOpcode() : -1;
            boolean isJump = lastReal >= 0 && arr[lastReal] instanceof JumpInsnNode;
            boolean isExit = lastReal >= 0 && isExit(term);

            for (int i = s; i < e; i++) {
                AbstractInsnNode in = arr[i];
                if (!isReal(in)) continue;
                if (isJump && i == lastReal) continue;
                AbstractInsnNode copy = in.clone(NO_LABELS);
                out.add(copy);
                if (copy instanceof LdcInsnNode ldc && ldc.cst instanceof String) {
                    ctx.bindStringState(ldc, stateVar,
                            encodeState(state[b], stateKey, stateRotation));
                }
            }

            if (isExit) {

            } else if (isJump && term == Opcodes.GOTO) {
                Integer tgt = labelBlock.get(((JumpInsnNode) arr[lastReal]).label);
                if (tgt == null) return false;
                out.add(pushInt(encodeState(state[tgt], stateKey, stateRotation)));
                out.add(new VarInsnNode(Opcodes.ISTORE, stateVar));
                out.add(new JumpInsnNode(Opcodes.GOTO, dispatch));
            } else if (isJump) {

                Integer tgt = labelBlock.get(((JumpInsnNode) arr[lastReal]).label);
                int fall = blockOfIndex(blocks, e);
                if (tgt == null || fall < 0) return false;
                LabelNode take = new LabelNode();
                out.add(new JumpInsnNode(term, take));
                out.add(pushInt(encodeState(state[fall], stateKey, stateRotation)));
                out.add(new VarInsnNode(Opcodes.ISTORE, stateVar));
                out.add(new JumpInsnNode(Opcodes.GOTO, dispatch));
                out.add(take);
                out.add(pushInt(encodeState(state[tgt], stateKey, stateRotation)));
                out.add(new VarInsnNode(Opcodes.ISTORE, stateVar));
                out.add(new JumpInsnNode(Opcodes.GOTO, dispatch));
            } else {

                int fall = blockOfIndex(blocks, e);
                if (fall < 0) return false;
                out.add(pushInt(encodeState(state[fall], stateKey, stateRotation)));
                out.add(new VarInsnNode(Opcodes.ISTORE, stateVar));
                out.add(new JumpInsnNode(Opcodes.GOTO, dispatch));
            }
        }

        out.add(dflt);
        out.add(new TypeInsnNode(Opcodes.NEW, "java/lang/RuntimeException"));
        out.add(new InsnNode(Opcodes.DUP));
        out.add(new org.objectweb.asm.tree.MethodInsnNode(
                Opcodes.INVOKESPECIAL, "java/lang/RuntimeException", "<init>", "()V", false));
        out.add(new InsnNode(Opcodes.ATHROW));

        MethodNode probe = new MethodNode(Opcodes.ASM9, mn.access, mn.name, mn.desc, mn.signature, null);
        probe.instructions = out;
        probe.tryCatchBlocks = new java.util.ArrayList<>();
        probe.maxLocals = newMaxLocals;
        probe.maxStack = mn.maxStack + 16;
        try {
            new Analyzer<>(new CtxVerifier(ctx, cn)).analyze(cn.name, probe);
        } catch (Throwable verifyFailure) {
            return false;
        }

        mn.maxLocals = newMaxLocals;
        mn.instructions = out;
        return true;
    }

    static final class CtxVerifier extends org.objectweb.asm.tree.analysis.SimpleVerifier {
        private static final org.objectweb.asm.Type OBJ =
                org.objectweb.asm.Type.getObjectType("java/lang/Object");
        private final ObfContext ctx;

        CtxVerifier(ObfContext ctx, ClassNode cn) {
            super(Opcodes.ASM9, org.objectweb.asm.Type.getObjectType(cn.name),
                    cn.superName == null ? null : org.objectweb.asm.Type.getObjectType(cn.superName),
                    cn.interfaces == null ? java.util.List.of()
                            : cn.interfaces.stream().map(org.objectweb.asm.Type::getObjectType).toList(),
                    (cn.access & Opcodes.ACC_INTERFACE) != 0);
            this.ctx = ctx;
        }

        private ClassNode node(org.objectweb.asm.Type t) {
            return t.getSort() == org.objectweb.asm.Type.OBJECT ? ctx.getClass(t.getInternalName()) : null;
        }

        @Override protected Class<?> getClass(org.objectweb.asm.Type t) {

            try { return super.getClass(t); } catch (Throwable e) { return Object.class; }
        }

        @Override protected boolean isInterface(org.objectweb.asm.Type t) {
            ClassNode c = node(t);
            if (c != null) return (c.access & Opcodes.ACC_INTERFACE) != 0;
            try { return super.isInterface(t); } catch (Throwable e) { return false; }
        }

        @Override protected org.objectweb.asm.Type getSuperClass(org.objectweb.asm.Type t) {
            ClassNode c = node(t);
            if (c != null) return c.superName == null ? null : org.objectweb.asm.Type.getObjectType(c.superName);
            try { return super.getSuperClass(t); } catch (Throwable e) { return OBJ; }
        }

        @Override protected boolean isAssignableFrom(org.objectweb.asm.Type t, org.objectweb.asm.Type u) {
            if (t.equals(u) || t.equals(OBJ)) return true;
            boolean tObj = t.getSort() == org.objectweb.asm.Type.OBJECT;
            boolean uObj = u.getSort() == org.objectweb.asm.Type.OBJECT;
            if (tObj && uObj) {
                if (reachable(t.getInternalName(), u.getInternalName())) return true;

                if (node(t) == null || node(u) == null) {
                    try { return super.isAssignableFrom(t, u); } catch (Throwable e) { return true; }
                }
                return false;
            }
            try { return super.isAssignableFrom(t, u); } catch (Throwable e) { return true; }
        }

        private boolean reachable(String target, String from) {
            java.util.ArrayDeque<String> q = new java.util.ArrayDeque<>();
            java.util.Set<String> seen = new java.util.HashSet<>();
            q.add(from);
            int guard = 0;
            while (!q.isEmpty() && guard++ < 4000) {
                String cur = q.poll();
                if (!seen.add(cur)) continue;
                if (cur.equals(target)) return true;
                ClassNode c = ctx.getClass(cur);
                if (c == null) continue;
                if (c.superName != null) q.add(c.superName);
                if (c.interfaces != null) q.addAll(c.interfaces);
            }
            return false;
        }
    }

    private static int blockOfIndex(List<int[]> blocks, int startIdx) {
        for (int b = 0; b < blocks.size(); b++) if (blocks.get(b)[0] == startIdx) return b;
        return -1;
    }

    private static int firstReal(AbstractInsnNode[] arr, int s, int e) {
        for (int i = s; i < e; i++) if (isReal(arr[i])) return i;
        return -1;
    }

    private static int lastReal(AbstractInsnNode[] arr, int s, int e) {
        for (int i = e - 1; i >= s; i--) if (isReal(arr[i])) return i;
        return -1;
    }

    private static boolean isReal(AbstractInsnNode in) {
        return in.getOpcode() >= 0;
    }

    private static boolean isExit(int op) {
        return (op >= Opcodes.IRETURN && op <= Opcodes.RETURN) || op == Opcodes.ATHROW;
    }

    private static int catOf(BasicValue v) {
        if (v == null || v == BasicValue.UNINITIALIZED_VALUE) return 0;
        if (v == BasicValue.INT_VALUE) return 1;
        if (v == BasicValue.FLOAT_VALUE) return 2;
        if (v == BasicValue.LONG_VALUE) return 3;
        if (v == BasicValue.DOUBLE_VALUE) return 4;
        if (v.isReference()) return 5;
        return 0;
    }

    private static AbstractInsnNode pushInt(int v) {
        if (v >= -1 && v <= 5) return new InsnNode(Opcodes.ICONST_0 + v);
        if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) return new IntInsnNode(Opcodes.BIPUSH, v);
        if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) return new IntInsnNode(Opcodes.SIPUSH, v);
        return new LdcInsnNode(Integer.valueOf(v));
    }

    private static int encodeState(int state, int key, int rotation) {
        return Integer.rotateLeft(state ^ key, rotation);
    }
}
