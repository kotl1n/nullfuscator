package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

public final class MethodExtractionTransformer implements Transformer {
    @Override public String id() { return "methodExtraction"; }
    @Override public String description() { return "extract static domain methods without leaving proxy bridges"; }

    @Override
    public void transform(ObfContext ctx) {
        var sec = ctx.config().section(id());
        int percent = clamp(sec.getInt("percent", 100), 0, 100);
        int maxMethods = Math.max(1, sec.getInt("maxMethods", 128));
        int carrierCount = clamp(sec.getInt("carriers", 16), 3, 48);
        int minInstructions = Math.max(4, sec.getInt("minInstructions", 8));
        if (percent == 0 || ctx.isModularJar()) return;

        List<ClassNode> targets = ctx.targets(id());
        List<ClassNode> carriers = makeCarriers(ctx, targets, carrierCount);
        String main = Remapping.mainClassInternalName(ctx);
        Random rnd = ctx.random();
        Map<String, Destination> moved = new HashMap<>();
        Set<String> subclassed = new HashSet<>();
        for (ClassNode cn : ctx.classMap().values()) if (cn.superName != null) subclassed.add(cn.superName);
        int count = 0, instructions = 0;

        outer:
        for (ClassNode owner : targets) {
            if (owner.name.equals(main)) continue;
            if ((owner.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION
                    | Opcodes.ACC_ENUM | Opcodes.ACC_MODULE)) != 0) continue;
            for (MethodNode mn : new ArrayList<>(owner.methods)) {
                if (ctx.isHotPath(owner, mn)) continue;
                if (!eligible(owner, mn, minInstructions, subclassed) || rnd.nextInt(100) >= percent) continue;
                if ((mn.access & Opcodes.ACC_STATIC) == 0) owner.access |= Opcodes.ACC_FINAL;
                ClassNode carrier = carriers.get(rnd.nextInt(carriers.size()));
                String oldName = mn.name;
                String oldDesc = mn.desc;
                String newDesc = (mn.access & Opcodes.ACC_STATIC) != 0
                        ? oldDesc : prependReceiver(owner.name, oldDesc);
                String fresh = "x" + ctx.names().nextRandom(rnd, 8 + rnd.nextInt(9));
                moved.put(key(owner.name, oldName, oldDesc), new Destination(carrier.name, fresh, newDesc));
                owner.methods.remove(mn);
                mn.name = fresh;
                mn.desc = newDesc;
                mn.access = (mn.access & ~(Opcodes.ACC_PRIVATE | Opcodes.ACC_PROTECTED
                        | Opcodes.ACC_SYNCHRONIZED)) | Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC;
                carrier.methods.add(mn);
                count++;
                instructions += mn.instructions.size();
                if (count >= maxMethods) break outer;
            }
        }

        if (moved.isEmpty()) {
            for (ClassNode carrier : carriers) ctx.removeClass(carrier.name);
            ctx.log().debug("methodExtraction: no eligible methods");
            return;
        }
        for (ClassNode cn : ctx.classMap().values()) for (MethodNode mn : cn.methods) {
            for (AbstractInsnNode in : mn.instructions.toArray()) {
                if (in instanceof MethodInsnNode call) {
                    Destination d = resolve(call.owner, call.name, call.desc, moved, ctx.classMap());
                    if (d != null) {
                        call.owner = d.owner; call.name = d.name; call.desc = d.desc;
                        call.itf = false; call.setOpcode(Opcodes.INVOKESTATIC);
                    }
                } else if (in instanceof LdcInsnNode ldc && ldc.cst instanceof Handle h) {
                    ldc.cst = remapHandle(h, moved, ctx.classMap());
                } else if (in instanceof LdcInsnNode ldc && ldc.cst instanceof ConstantDynamic cd) {
                    ldc.cst = remapCondy(cd, moved, ctx.classMap());
                } else if (in instanceof InvokeDynamicInsnNode indy) {
                    indy.bsm = remapHandle(indy.bsm, moved, ctx.classMap());
                    for (int i = 0; i < indy.bsmArgs.length; i++) {
                        Object a = indy.bsmArgs[i];
                        if (a instanceof Handle h) indy.bsmArgs[i] = remapHandle(h, moved, ctx.classMap());
                        else if (a instanceof ConstantDynamic cd) indy.bsmArgs[i] = remapCondy(cd, moved, ctx.classMap());
                    }
                }
            }
        }
        ctx.log().debug("methodExtraction: removed and relocated " + count
                + " definitions (" + instructions + " instructions) into " + carriers.size() + " carriers");
    }

    private static boolean eligible(ClassNode owner, MethodNode mn, int min, Set<String> subclassed) {
        if (MethodRenamer.isAgentEntrypoint(mn)) return false;
        int bad = Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE | Opcodes.ACC_SYNCHRONIZED
                | Opcodes.ACC_BRIDGE;
        if ((mn.access & bad) != 0) return false;
        if (mn.name.charAt(0) == '<' || mn.name.equals("main")) return false;
        if (mn.name.equals("equals") || mn.name.equals("hashCode") || mn.name.equals("toString")) return false;
        if ((mn.access & Opcodes.ACC_STATIC) == 0
                && (!"java/lang/Object".equals(owner.superName)
                || (owner.interfaces != null && !owner.interfaces.isEmpty())
                || subclassed.contains(owner.name))) return false;
        if (mn.instructions == null || mn.instructions.size() < min) return false;
        if ((mn.visibleAnnotations != null && !mn.visibleAnnotations.isEmpty())
                || (mn.invisibleAnnotations != null && !mn.invisibleAnnotations.isEmpty())) return false;
        return !com.nullfuscator.obf.core.Limits.oversizeMethod(mn);
    }

    private static List<ClassNode> makeCarriers(ObfContext ctx, List<ClassNode> inputs, int count) {
        int version = Opcodes.V1_8;
        for (ClassNode cn : inputs) version = Math.max(version, cn.version & 0xFFFF);
        List<ClassNode> out = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            ClassNode cn = new ClassNode();
            cn.version = version;
            cn.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER;
            cn.name = ctx.names().nextRandomClass("a/x/", ctx.random(), 9 + i % 8);
            cn.superName = "java/lang/Object";
            cn.methods = new ArrayList<>();
            ctx.putClass(cn);
            out.add(cn);
        }
        return out;
    }

    private static Handle remapHandle(Handle h, Map<String, Destination> moved,
                                      Map<String, ClassNode> classes) {
        Destination d = resolve(h.getOwner(), h.getName(), h.getDesc(), moved, classes);
        if (d == null) return h;
        return new Handle(Opcodes.H_INVOKESTATIC, d.owner, d.name, d.desc, false);
    }

    private static ConstantDynamic remapCondy(ConstantDynamic cd, Map<String, Destination> moved,
                                               Map<String, ClassNode> classes) {
        Object[] args = new Object[cd.getBootstrapMethodArgumentCount()];
        for (int i = 0; i < args.length; i++) {
            Object a = cd.getBootstrapMethodArgument(i);
            args[i] = a instanceof Handle h ? remapHandle(h, moved, classes)
                    : a instanceof ConstantDynamic nested ? remapCondy(nested, moved, classes) : a;
        }
        return new ConstantDynamic(cd.getName(), cd.getDescriptor(),
                remapHandle(cd.getBootstrapMethod(), moved, classes), args);
    }

    private static Destination resolve(String owner, String name, String desc,
                                       Map<String, Destination> moved, Map<String, ClassNode> classes) {
        String current = owner;
        while (current != null) {
            Destination d = moved.get(key(current, name, desc));
            if (d != null) return d;
            ClassNode cn = classes.get(current);
            current = cn == null ? null : cn.superName;
        }
        return null;
    }

    private static String key(String owner, String name, String desc) {
        return owner + '\u0001' + name + '\u0001' + desc;
    }
    private static String prependReceiver(String owner, String desc) {
        StringBuilder b = new StringBuilder("(L").append(owner).append(';');
        for (Type arg : Type.getArgumentTypes(desc)) b.append(arg.getDescriptor());
        return b.append(')').append(Type.getReturnType(desc).getDescriptor()).toString();
    }
    private record Destination(String owner, String name, String desc) { }
    private static int clamp(int v, int lo, int hi) { return Math.max(lo, Math.min(hi, v)); }
}
