package com.nullfuscator.obf.core;

import com.nullfuscator.obf.runtime.IntegrityGuard;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;

/** Sealed only after frame computation and every bytecode pass have completed. */
public record IntegrityPlan(String resource, Set<String> classes, Set<String> guards) {
    public byte[] seal(Map<String, byte[]> bytecode) {
        StringBuilder index = new StringBuilder();
        classes.stream().sorted().forEach(name -> {
            byte[] bytes = bytecode.get(name);
            if (bytes == null) throw new IllegalStateException("Missing protected class: " + name);
            byte[] canonical = bytes.clone();
            if (guards.contains(name)) IntegrityGuard.normalize(canonical);
            index.append(hash(canonical)).append(' ').append(name).append(".class\n");
        });
        byte[] manifest = index.toString().getBytes(StandardCharsets.UTF_8);
        byte[] root = hash(manifest).getBytes(StandardCharsets.US_ASCII);
        byte[] marker = ("nullfuscator-integrity-root:" + "0".repeat(64)).getBytes(StandardCharsets.US_ASCII);
        for (String name : guards) {
            byte[] bytes = bytecode.get(name);
            int patched = 0;
            for (int i = 3; i <= bytes.length - marker.length; i++) {
                if (bytes[i - 3] != 1 || bytes[i - 2] != 0 || bytes[i - 1] != marker.length) continue;
                boolean match = true;
                for (int j = 0; j < marker.length; j++) if (bytes[i+j] != marker[j]) { match = false; break; }
                if (match) { System.arraycopy(root, 0, bytes, i + 21, root.length); patched++; }
            }
            if (patched != 1) throw new IllegalStateException("Invalid integrity template: " + name);
        }
        return manifest;
    }

    private static String hash(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }
}
