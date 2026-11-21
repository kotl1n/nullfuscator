package com.nullfuscator.obf.runtime;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/** Template copied per build. Checks archive resources, not the JVM's live class definitions. */
public final class IntegrityGuard {

    private static final String PREFIX = "nullfuscator-integrity-root:";
    private static volatile boolean initialized;
    private static volatile boolean failed;
    private static volatile long deadline;
    private static String[] entries;
    private static int cursor;

    private IntegrityGuard() {
    }

    public static void check() {
        if (failed) {
            throw new SecurityException("Application integrity check failed");
        }
        if (initialized && System.nanoTime() - deadline < 0) {
            return;
        }

        synchronized (IntegrityGuard.class) {
            if (failed) {
                throw new SecurityException("Application integrity check failed");
            }
            if (initialized && System.nanoTime() - deadline < 0) {
                return;
            }

            try {
                byte[] index = read("@NULLFUSCATOR_INDEX@", 4 * 1024 * 1024);
                String expected = "nullfuscator-integrity-root:0000000000000000000000000000000000000000000000000000000000000000";
                if (!hex(digest(index)).equals(expected.substring(PREFIX.length()))) {
                    throw new SecurityException("Integrity index changed");
                }

                if (!initialized) {
                    entries = new String(index, StandardCharsets.UTF_8).split("\n");
                    for (String entry : entries) {
                        if (entry.isEmpty() || entry.isBlank()) {
                            continue;
                        }
                        verify(entry);
                    }
                } else {
                    verify(entries[cursor++ % entries.length]);
                    if (cursor == entries.length) {
                        cursor = 0;
                    }
                }

                deadline = System.nanoTime() + 5_000_000_000L;
                initialized = true;
            } catch (Exception e) {
                failed = true;
                throw new SecurityException("Application integrity check failed", e);
            }
        }
    }

    private static void verify(String entry) throws Exception {
        int separator = entry.indexOf(' ');
        if (separator != 64) {
            throw new SecurityException("Invalid integrity index");
        }
        String path = entry.substring(65);
        byte[] bytes = read(path, 32 * 1024 * 1024);
        // Only verifier entries are canonicalized; application constants are all hashed.
        if (path.startsWith("a/integrity/")) {
            normalize(bytes);
        }
        if (!hex(digest(bytes)).equals(entry.substring(0, 64))) {
            throw new SecurityException("Protected class changed");
        }
    }

    private static byte[] read(String path, int limit) throws Exception {
        try (InputStream in = IntegrityGuard.class.getResourceAsStream("/".concat(path))) {
            if (in == null) {
                throw new SecurityException("Protected resource missing");
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int n;
            while ((n = in.read(buffer)) != -1) {
                if (out.size() > limit - n) {
                    throw new SecurityException("Protected resource too large");
                }
                out.write(buffer, 0, n);
            }
            return out.toByteArray();
        }
    }

    public static void normalize(byte[] bytes) {
        byte[] prefix = PREFIX.getBytes(StandardCharsets.US_ASCII);
        int markerLen = prefix.length + 64;
        for (int i = 0; i <= bytes.length - markerLen; i++) {
            boolean match = true;
            for (int j = 0; j < prefix.length; j++) {
                if (bytes[i + j] != prefix[j]) {
                    match = false;
                    break;
                }
            }
            if (!match) {
                continue;
            }

            if (i < 3 || bytes[i - 3] != 1 || bytes[i - 2] != 0 || (bytes[i - 1] & 0xFF) != markerLen) {
                continue;
            }
            for (int j = 0; j < 64; j++) {
                bytes[i + prefix.length + j] = '0';
            }
        }
    }

    private static byte[] digest(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    private static String hex(byte[] bytes) {
        char[] alphabet = "0123456789abcdef".toCharArray();
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            out[i * 2] = alphabet[(bytes[i] & 255) >>> 4];
            out[i * 2 + 1] = alphabet[bytes[i] & 15];
        }
        return new String(out);
    }
}