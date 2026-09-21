package com.nullfuscator.obf.util;

public final class ObfLog {

    private final boolean verbose;
    private final boolean quiet;

    public ObfLog(boolean verbose) {
        this(verbose, false);
    }

    public ObfLog(boolean verbose, boolean quiet) {
        this.verbose = verbose;
        this.quiet = quiet;
    }

    public void info(String msg) {
        if (!quiet) System.err.println("[*] " + msg);
    }

    public void warn(String msg) {
        System.err.println("[!] " + msg);
    }

    public void error(String msg) {
        System.err.println("[x] " + msg);
    }

    public void debug(String msg) {
        if (verbose && !quiet) {
            System.err.println("    " + msg);
        }
    }

    public void pass(String id, String detail) {
        if (!quiet) System.err.println("[+] " + id + (detail == null || detail.isEmpty() ? "" : " — " + detail));
    }
}
