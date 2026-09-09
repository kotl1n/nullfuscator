package com.nullfuscator.obf.core;

import com.nullfuscator.obf.util.NameGenerator;
import com.nullfuscator.obf.util.ObfLog;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.Opcodes;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

public final class ObfContext {

    private final Map<String, ClassNode> classes = new LinkedHashMap<>();
    private final Map<String, byte[]> resources = new LinkedHashMap<>();
    private final ObfConfig config;
    private final Random random;
    private final long seed;
    private final ObfLog log;
    private final NameGenerator names;
    private final ObfMapping mapping = new ObfMapping();
    private final Map<LdcInsnNode, StringStateBinding> stringStates = new IdentityHashMap<>();
    private final Set<String> dispersionCarriers = new HashSet<>();
    private final Map<String, String> originalNames = new LinkedHashMap<>();
    private final Map<MethodNode, String> originalMethods = new IdentityHashMap<>();
    private final Set<AbstractInsnNode> encodedNumbers = java.util.Collections.newSetFromMap(new IdentityHashMap<>());
    private final Set<MethodNode> inputMethods = java.util.Collections.newSetFromMap(new IdentityHashMap<>());
    private ExemptMatcher hotPaths;
    private IntegrityPlan integrityPlan;
    private RunReport report;
    private long inputJarBytes;

    public ObfContext(ObfConfig config, long seed, ObfLog log, NameGenerator names) {
        this.config = config;
        this.seed = seed;
        this.random = new Random(seed);
        this.log = log;
        this.names = names;
    }

    public Collection<ClassNode> classes() { return classes.values(); }
    public Map<String, ClassNode> classMap() { return classes; }
    public ClassNode getClass(String internalName) { return classes.get(internalName); }

    public void putClass(ClassNode cn) { classes.put(cn.name, cn); }

    public void removeClass(String internalName) { classes.remove(internalName); }

    public void reindex() {
        List<ClassNode> all = new ArrayList<>(classes.values());
        classes.clear();
        for (ClassNode cn : all) classes.put(cn.name, cn);
    }

    public List<ClassNode> snapshot() { return new ArrayList<>(classes.values()); }

    public Map<String, byte[]> resources() { return resources; }

    public ObfConfig config() { return config; }

    public boolean isExempt(String sectionId, ClassNode cn) {
        return cn == null || config.section(sectionId).isExempt(cn.name)
                || config.section(sectionId).isExempt(originalName(cn.name));
    }

    public String originalName(String name) { return originalNames.getOrDefault(name, name); }

    public void remapOriginalNames(Map<String, String> renames) {
        Map<String, String> updated = new LinkedHashMap<>();
        for (String name : classes.keySet())
            updated.put(renames.getOrDefault(name, name), originalName(name));
        originalNames.clear();
        originalNames.putAll(updated);
    }

    public void transferMethodOrigins(ClassNode oldNode, ClassNode newNode) {
        int count = Math.min(oldNode.methods.size(), newNode.methods.size());
        for (int i = 0; i < count; i++) {
            MethodNode oldMethod = oldNode.methods.get(i);
            MethodNode newMethod = newNode.methods.get(i);
            transferInputMethod(oldMethod, newMethod);
            originalMethods.put(newMethod, originalMethods.getOrDefault(oldMethod,
                    oldMethod.name + oldMethod.desc));
        }
    }

    public IntegrityPlan integrityPlan() { return integrityPlan; }
    public void integrityPlan(IntegrityPlan plan) { integrityPlan = plan; }

    public List<ClassNode> targets(String sectionId) {
        ObfConfig.Section s = config.section(sectionId);
        List<ClassNode> out = new ArrayList<>();
        for (ClassNode cn : classes.values()) {

            boolean moduleInfo = "module-info".equals(cn.name)
                    || (cn.access & Opcodes.ACC_MODULE) != 0;
            if (!moduleInfo && !isExempt(sectionId, cn)) out.add(cn);
        }
        return out;
    }

    public boolean isModularJar() {
        ClassNode module = classes.get("module-info");
        if (module != null) return true;
        for (ClassNode cn : classes.values()) {
            if ((cn.access & Opcodes.ACC_MODULE) != 0) return true;
        }
        return false;
    }

    public Random random() { return random; }
    public long seed() { return seed; }
    public ObfLog log() { return log; }
    public NameGenerator names() { return names; }
    public ObfMapping mapping() { return mapping; }
    public RunReport report() { return report; }
    public void report(RunReport value) { report = value; }
    public long inputJarBytes() { return inputJarBytes; }
    public void inputJarBytes(long value) { inputJarBytes = value; }

    public String methodOrigin(ClassNode cn, MethodNode mn) {
        return originalName(cn.name) + "#" + originalMethods.getOrDefault(mn, mn.name + mn.desc);
    }

    /** Numeric encoding is consumed by antiAI before the first remapping pass. */
    public void markEncodedNumber(AbstractInsnNode instruction) { encodedNumbers.add(instruction); }
    public boolean isEncodedNumber(AbstractInsnNode instruction) { return encodedNumbers.contains(instruction); }
    public void clearEncodedNumbers() { encodedNumbers.clear(); }

    public boolean isInputMethod(MethodNode method) {
        if (hotPaths == null) initializePolicies();
        return inputMethods.contains(method);
    }

    public void transferInputMethod(MethodNode source, MethodNode target) {
        if (inputMethods.contains(source)) inputMethods.add(target);
    }

    public void initializePolicies() {
        if (hotPaths != null) return;
        hotPaths = new ExemptMatcher(config.section("hotPaths").getStringList("exclude"));
        for (ClassNode cn : classes.values())
            for (MethodNode mn : cn.methods) {
                originalMethods.putIfAbsent(mn, mn.name + mn.desc);
                inputMethods.add(mn);
            }
    }

    /** Hot paths use original class/method identities and survive class remapping. */
    public boolean isHotPath(ClassNode cn, MethodNode mn) {
        if (hotPaths == null) initializePolicies();
        String owner = originalName(cn.name);
        String method = originalMethods.getOrDefault(mn, mn.name + mn.desc);
        int descriptor = method.indexOf('(');
        String name = descriptor < 0 ? mn.name : method.substring(0, descriptor);
        String desc = descriptor < 0 ? mn.desc : method.substring(descriptor);
        return hotPaths.matches(owner) || hotPaths.matchesMethod(owner, name, desc)
                || hotPaths.matchesAnnotations(cn, mn);
    }

    public boolean isHotClass(ClassNode cn) {
        if (hotPaths == null) initializePolicies();
        return hotPaths.matches(originalName(cn.name)) || hotPaths.matchesAnnotations(cn, null);
    }

    public void markDispersionCarrier(ClassNode cn) { dispersionCarriers.add(cn.name); }

    public boolean isDispersionCarrier(ClassNode cn) {
        return cn != null && dispersionCarriers.contains(cn.name);
    }

    public void remapDispersionCarriers(Map<String, String> classMap) {
        Set<String> remapped = new HashSet<>();
        for (String oldName : dispersionCarriers)
            remapped.add(classMap.getOrDefault(oldName, oldName));
        dispersionCarriers.clear();
        dispersionCarriers.addAll(remapped);
    }

    public void bindStringState(LdcInsnNode site, int stateVar, int encodedState) {
        stringStates.put(site, new StringStateBinding(stateVar, encodedState));
    }

    public StringStateBinding stringState(LdcInsnNode site) { return stringStates.get(site); }

    public record StringStateBinding(int stateVar, int encodedState) { }
}
