package com.nullfuscator.obf;

import com.nullfuscator.obf.core.ObfConfig;

import java.util.List;

public final class ConfigRegression {
    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }

    public static void main(String[] args) {
        ObfConfig config = ObfConfig.parse("""
                defaults {
                  exempt = [ "class{^shared/}" ]
                  naming { chars = [ "x", "y" ], depth = 7 }
                }
                classRenamer { enabled = true, depth = 3 }
                methodRenamer { enabled = true, exempt = [ "class{^local/}" ] }
                """);

        var classes = config.section("classRenamer");
        var methods = config.section("methodRenamer");
        var fields = config.section("fieldRenamer");

        check(classes.isExempt("shared/Example"), "global exemption missing");
        check(methods.isExempt("shared/Example"), "global exemption not inherited");
        check(methods.isExempt("local/Example"), "local exemption not merged");
        check(classes.getInt("depth", 0) == 3, "local naming value did not override default");
        check(methods.getInt("depth", 0) == 7, "naming default missing");
        check(methods.getStringList("chars").equals(List.of("x", "y")), "naming chars missing");
        check(!fields.present(), "defaults made an absent section present");

        ObfConfig legacy = ObfConfig.parse("fieldRenamer { enabled = true, exempt = [ \"class{^legacy/}\" ] }");
        check(legacy.section("fieldRenamer").isExempt("legacy/Example"), "legacy exemption failed");
        check(legacy.section("fieldRenamer").enabled(), "legacy section failed");

        System.out.println("PASS config defaults, overrides and legacy compatibility");
    }
}
