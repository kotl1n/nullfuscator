package com.nullfuscator.obf.util;

import java.util.HashSet;
import java.util.Random;
import java.util.Set;

public final class NameGenerator {
    private static final int RANDOM_ATTEMPT_LIMIT = 64;
    private final String[] tokens;
    private final Set<String> used = new HashSet<>();
    private long counter = 0;

    public NameGenerator(String[] tokens) {
        if (tokens == null || tokens.length == 0)
            tokens = new String[] { "I", "l", "1", "lI" };
        this.tokens = tokens;
    }

    public synchronized String next() {
        String s;
        do { s = encode(counter++); } while (!used.add(s));
        return s;
    }

    public synchronized String nextClass(String prefix) {
        String p = (prefix == null) ? "" : prefix;
        String s;
        do { s = p + encode(counter++); } while (!used.add(s));
        return s;
    }

    public synchronized String nextRandom(Random random, int maxDepth) {
        int depth = Math.max(1, Math.min(32, maxDepth));
        // Short opaque names become saturated in large archives.  Keeping the
        // retry budget bounded prevents a quadratic slowdown while next()
        // still supplies a collision-free opaque fallback.
        for (int attempt = 0; attempt < RANDOM_ATTEMPT_LIMIT; attempt++) {
            int width = 1 + random.nextInt(depth);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < width; i++) sb.append(tokens[random.nextInt(tokens.length)]);
            String candidate = sb.toString();
            if (used.add(candidate)) return candidate;
        }
        return next();
    }

    public synchronized String nextRandomClass(String prefix, Random random, int maxDepth) {
        String p = prefix == null ? "" : prefix;
        int depth = Math.max(1, Math.min(32, maxDepth));
        for (int attempt = 0; attempt < RANDOM_ATTEMPT_LIMIT; attempt++) {
            int width = 1 + random.nextInt(depth);
            StringBuilder sb = new StringBuilder(p);
            for (int i = 0; i < width; i++) sb.append(tokens[random.nextInt(tokens.length)]);
            String candidate = sb.toString();
            if (used.add(candidate)) return candidate;
        }
        return nextClass(p);
    }

    public synchronized void reserve(String name) { used.add(name); }

    private String encode(long n) {
        int base = tokens.length;
        StringBuilder sb = new StringBuilder();
        n++;
        while (n > 0) {
            long idx = (n - 1) % base;
            sb.append(tokens[(int) idx]);
            n = (n - 1) / base;
        }
        return sb.toString();
    }
}
