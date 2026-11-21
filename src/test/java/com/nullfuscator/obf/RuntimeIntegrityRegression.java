package com.nullfuscator.obf;

import com.nullfuscator.obf.core.*;
import com.nullfuscator.obf.runtime.IntegrityGuard;
import com.nullfuscator.obf.transform.RuntimeIntegrityTransformer;
import com.nullfuscator.obf.util.*;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.*;

public final class RuntimeIntegrityRegression implements Opcodes {

    private static void check(boolean value, String message) {
        if (!value) {
            throw new AssertionError(message);
        }
    }

    public static void main(String[] args) throws Exception {
        testEndToEndIntegrity();
        System.out.println("PASS runtime integrity verification and tamper detection");
    }

    private static void testEndToEndIntegrity() throws Exception {
        ClassNode target = new ClassNode();
        target.version = V17;
        target.access = ACC_PUBLIC;
        target.name = "sample/TargetApp";
        target.superName = "java/lang/Object";

        MethodNode m = new MethodNode(ACC_PUBLIC | ACC_STATIC, "work", "()V", null, null);
        m.instructions.add(new InsnNode(RETURN));
        target.methods.add(m);

        ObfConfig config = ObfConfig.parse("runtimeIntegrity { enabled: true, \"include\": [ \"sample/TargetApp\" ] }");
        ObfContext ctx = new ObfContext(config, 42, new ObfLog(false), new NameGenerator(new String[] { "I", "l" }));
        ctx.putClass(target);

        RuntimeIntegrityTransformer transformer = new RuntimeIntegrityTransformer();
        transformer.transform(ctx);

        IntegrityPlan plan = ctx.integrityPlan();
        check(plan != null, "IntegrityPlan must not be null");
        check(plan.classes().contains("sample/TargetApp"), "TargetApp must be protected");
        check(!plan.guards().isEmpty(), "Guards must be generated");

        Map<String, byte[]> bytecode = new HashMap<>();
        for (ClassNode cn : ctx.classes()) {
            ClassWriter cw = new ClassWriter(0);
            cn.accept(cw);
            bytecode.put(cn.name, cw.toByteArray());
        }

        byte[] index = plan.seal(bytecode);
        check(index != null && index.length > 0, "Sealed manifest must not be empty");

        Map<String, byte[]> resources = new HashMap<>();
        resources.put(plan.resource(), index);
        for (var entry : bytecode.entrySet()) {
            resources.put(entry.getKey() + ".class", entry.getValue());
        }

        ClassLoader cl = new ClassLoader(RuntimeIntegrityRegression.class.getClassLoader()) {
            @Override
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                String path = name.replace('.', '/') + ".class";
                byte[] bytes = resources.get(path);
                if (bytes != null) {
                    return defineClass(name, bytes, 0, bytes.length);
                }
                return super.findClass(name);
            }

            @Override
            public InputStream getResourceAsStream(String name) {
                if (name.startsWith("/")) {
                    name = name.substring(1);
                }
                byte[] bytes = resources.get(name);
                if (bytes != null) {
                    return new ByteArrayInputStream(bytes);
                }
                return super.getResourceAsStream(name);
            }
        };

        for (String guardName : plan.guards()) {
            Class<?> guardClass = cl.loadClass(guardName.replace('/', '.'));
            Method checkM = guardClass.getDeclaredMethod("check");
            checkM.setAccessible(true);
            checkM.invoke(null);
        }

        byte[] tamperedTarget = resources.get("sample/TargetApp.class").clone();
        tamperedTarget[tamperedTarget.length - 1] ^= 1;
        resources.put("sample/TargetApp.class", tamperedTarget);

        boolean tamperedDetected = false;
        String firstGuard = plan.guards().iterator().next();
        Class<?> freshGuardClass = cl.loadClass(firstGuard.replace('/', '.'));
        try {
            Method reset = freshGuardClass.getDeclaredMethod("check");
            reset.setAccessible(true);
            java.lang.reflect.Field initField = freshGuardClass.getDeclaredField("initialized");
            initField.setAccessible(true);
            initField.set(null, false);
            reset.invoke(null);
        } catch (Exception e) {
            tamperedDetected = true;
        }
        check(tamperedDetected, "Tampered target class must be detected");
    }
}
