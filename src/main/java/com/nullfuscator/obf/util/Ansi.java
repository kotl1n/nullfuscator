package com.nullfuscator.obf.util;

public final class Ansi {
    private static volatile boolean enabled = initColorSupport();

    private Ansi() {}

    private static boolean initColorSupport() {
        if (System.getenv("NO_COLOR") != null) return false;
        String term = System.getenv("TERM");
        if ("dumb".equalsIgnoreCase(term)) return false;
        return System.console() != null;
    }

    public static void setEnabled(boolean value) {
        enabled = value;
    }

    public static boolean isEnabled() {
        return enabled;
    }

    private static String color(String code, String text) {
        return enabled ? "\u001B[" + code + "m" + text + "\u001B[0m" : text;
    }

    public static String bold(String text) { return color("1", text); }
    public static String dim(String text) { return color("2", text); }
    public static String red(String text) { return color("31", text); }
    public static String green(String text) { return color("32", text); }
    public static String yellow(String text) { return color("33", text); }
    public static String blue(String text) { return color("34", text); }
    public static String magenta(String text) { return color("35", text); }
    public static String cyan(String text) { return color("36", text); }
    public static String boldCyan(String text) { return color("1;36", text); }
    public static String boldGreen(String text) { return color("1;32", text); }
}
