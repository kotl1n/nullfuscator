package com.nullfuscator.obf.runtime;

import java.lang.management.ManagementFactory;

public final class DebugCheck {

    private DebugCheck() {}

    private static volatile int cached = 0;
    private static volatile long deadline;

    private static boolean rejectAgents() { return false; }

    public static boolean detected() {
        int c = cached;
        if (c == 0 || (c != 1 && System.nanoTime() - deadline >= 0)) {
            c = compute() ? 1 : 2;
            deadline = System.nanoTime() + 5_000_000_000L;
            cached = c;
        }
        return c == 1;
    }

    private static boolean compute() {
        try {
            for (String s : ManagementFactory.getRuntimeMXBean().getInputArguments()) {

                if (s.contains("jdwp") || s.contains("-Xdebug") || s.contains("-Xrunjdwp")) {
                    return true;
                }
                if (rejectAgents() && (s.startsWith("-javaagent:") || s.startsWith("-agentpath:")
                        || s.startsWith("-agentlib:"))) return true;
            }
        } catch (Throwable ignored) {

        }
        return false;
    }
}
