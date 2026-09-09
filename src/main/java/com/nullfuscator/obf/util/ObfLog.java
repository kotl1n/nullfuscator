package com.nullfuscator.obf.util;

public final class ObfLog {
    private final boolean verbose;
    public ObfLog(boolean verbose) { this.verbose = verbose; }

    public void info(String msg)  { System.err.println("[*] " + msg); }
    public void warn(String msg)  { System.err.println("[!] " + msg); }
    public void error(String msg) { System.err.println("[x] " + msg); }
    public void debug(String msg) { if (verbose) System.err.println("    " + msg); }
    public void pass(String id, String detail) {
        System.err.println("[+] " + id + (detail == null || detail.isEmpty() ? "" : " — " + detail));
    }
}
