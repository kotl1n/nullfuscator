package com.nullfuscator.obf.core;

/** Versioned separately from the mapping format so retrace can stay compatible. */
public final class BuildInfo {
    public static final String VERSION = "0.1.0";
    public static final int MAPPING_FORMAT = 2;

    private BuildInfo() { }
}
