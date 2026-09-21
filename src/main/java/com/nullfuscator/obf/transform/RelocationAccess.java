package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.ObfContext;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

final class RelocationAccess implements AutoCloseable {
    private final ObfContext ctx;
    private final URLClassLoader loader;
    private final Map<String, ClassNode> dependencies = new HashMap<>();

    RelocationAccess(ObfContext ctx) throws IOException {
        this.ctx = ctx;
        URL[] urls = new URL[ctx.config().libs().size()];
        for (int i = 0; i < urls.length; i++) {
            urls[i] = Path.of(ctx.config().libs().get(i)).toUri().toURL();
        }
        loader = new URLClassLoader(urls, RelocationAccess.class.getClassLoader());
    }

    boolean canMove(ClassNode owner, MethodNode method) {
        if ((method.access & Opcodes.ACC_SYNCHRONIZED) != 0
                || !typeAccessible(Type.getMethodType(method.desc))) return false;
        if ((method.access & Opcodes.ACC_STATIC) == 0 && !classAccessible(owner.name)) return false;
        for (TryCatchBlockNode block : method.tryCatchBlocks) {
            if (block.type != null && !classAccessible(block.type)) return false;
        }
        for (AbstractInsnNode insn : method.instructions) {
            if (insn instanceof MethodInsnNode call) {
                if (call.getOpcode() == Opcodes.INVOKESPECIAL && !call.name.equals("<init>")) return false;
                if (!memberAccessible(call.owner, call.name, call.desc, true)) return false;
            } else if (insn instanceof FieldInsnNode field) {
                if (!memberAccessible(field.owner, field.name, field.desc, false)) return false;
                if (field.getOpcode() == Opcodes.PUTFIELD || field.getOpcode() == Opcodes.PUTSTATIC) {
                    Integer flags = memberAccess(field.owner, field.name, field.desc, false, new HashSet<>());
                    if (flags == null || (flags & Opcodes.ACC_FINAL) != 0) return false;
                }
            } else if (insn instanceof TypeInsnNode type) {
                if (!classAccessible(type.desc)) return false;
            } else if (insn instanceof MultiANewArrayInsnNode array) {
                if (!typeAccessible(Type.getType(array.desc))) return false;
            } else if (insn instanceof LdcInsnNode ldc) {
                if (!constantAccessible(ldc.cst)) return false;
            } else if (insn instanceof InvokeDynamicInsnNode) {
                return false;
            }
        }
        return true;
    }

    private boolean constantAccessible(Object value) {
        if (value instanceof Type type) return typeAccessible(type);
        if (value instanceof Handle handle) {
            if (handle.getTag() == Opcodes.H_INVOKESPECIAL) return false;
            return memberAccessible(handle.getOwner(), handle.getName(), handle.getDesc(),
                    handle.getTag() > Opcodes.H_PUTSTATIC);
        }
        if (value instanceof ConstantDynamic) return false;
        return true;
    }

    private boolean memberAccessible(String owner, String name, String desc, boolean method) {
        if (!classAccessible(owner) || !typeAccessible(Type.getType(desc))) return false;
        Integer flags = memberAccess(owner, name, desc, method, new HashSet<>());
        return flags != null && (flags & Opcodes.ACC_PUBLIC) != 0;
    }

    private Integer memberAccess(String owner, String name, String desc, boolean method, Set<String> seen) {
        if (!seen.add(owner)) return null;
        ClassNode node = node(owner);
        if (node == null) return null;
        if (method) {
            for (MethodNode candidate : node.methods) {
                if (candidate.name.equals(name) && candidate.desc.equals(desc)) return candidate.access;
            }
        } else {
            for (FieldNode candidate : node.fields) {
                if (candidate.name.equals(name) && candidate.desc.equals(desc)) return candidate.access;
            }
        }
        if (name.equals("<init>")) return null;
        if (!method) {
            for (String itf : node.interfaces) {
                Integer flags = memberAccess(itf, name, desc, false, seen);
                if (flags != null) return flags;
            }
        }
        if (node.superName != null) {
            Integer flags = memberAccess(node.superName, name, desc, method, seen);
            if (flags != null) return flags;
        }
        if (method) {
            for (String itf : node.interfaces) {
                Integer flags = memberAccess(itf, name, desc, true, seen);
                if (flags != null) return flags;
            }
        }
        return null;
    }

    private boolean typeAccessible(Type type) {
        return switch (type.getSort()) {
            case Type.OBJECT -> classAccessible(type.getInternalName());
            case Type.ARRAY -> typeAccessible(type.getElementType());
            case Type.METHOD -> {
                boolean accessible = typeAccessible(type.getReturnType());
                for (Type argument : type.getArgumentTypes()) accessible &= typeAccessible(argument);
                yield accessible;
            }
            default -> true;
        };
    }

    private boolean classAccessible(String name) {
        if (name.startsWith("[")) return typeAccessible(Type.getType(name));
        ClassNode node = node(name);
        return node != null && (node.access & Opcodes.ACC_PUBLIC) != 0;
    }

    private ClassNode node(String name) {
        ClassNode owned = ctx.getClass(name);
        if (owned != null) return owned;
        if (dependencies.containsKey(name)) return dependencies.get(name);
        ClassNode result = null;
        try (InputStream in = loader.getResourceAsStream(name + ".class")) {
            if (in != null) {
                result = new ClassNode();
                new ClassReader(in).accept(result,
                        ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
            }
        } catch (IOException | RuntimeException e) {
            result = null;
        }
        dependencies.put(name, result);
        return result;
    }

    @Override
    public void close() throws IOException {
        loader.close();
    }
}
