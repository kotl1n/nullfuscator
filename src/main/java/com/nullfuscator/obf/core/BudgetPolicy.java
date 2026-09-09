package com.nullfuscator.obf.core;

import java.util.List;

/** Enforces configured growth and coverage budgets before installing output. */
public final class BudgetPolicy {
    private BudgetPolicy() { }

    public static void verifyStructure(ObfContext ctx) {
        RunReport report = ctx.report();
        if (report == null || report.baseline() == null || report.result() == null) return;
        var before = report.baseline().totals();
        var after = report.result().totals();
        var budget = ctx.config().section("budgets");
        check("class count", before.classes(), after.classes(), budget.getInt("maxClassGrowthPercent", -1),
                budget.getInt("classGrowthAllowance", 0));
        check("method count", before.methods(), after.methods(), budget.getInt("maxMethodGrowthPercent", -1),
                budget.getInt("methodGrowthAllowance", 0));
        check("instruction count", before.instructions(), after.instructions(),
                budget.getInt("maxInstructionGrowthPercent", -1),
                budget.getInt("instructionGrowthAllowance", 0));
        verifyCoverage(ctx, report);
    }

    public static void verifyJar(ObfContext ctx, long outputBytes) {
        if (ctx.report() != null) ctx.report().outputJarBytes(outputBytes);
        check("JAR bytes", ctx.inputJarBytes(), outputBytes,
                ctx.config().section("budgets").getInt("maxJarGrowthPercent", -1),
                ctx.config().section("budgets").getInt("jarGrowthAllowanceBytes", 0));
    }

    private static void verifyCoverage(ObfContext ctx, RunReport report) {
        var section = ctx.config().section("coverage");
        List<String> required = section.getStringList("required");
        if (required.isEmpty()) return;
        ExemptMatcher selectors = new ExemptMatcher(required);
        int total = 0, changed = 0;
        for (String key : report.baseline().methods().keySet()) {
            int hash = key.indexOf('#');
            int desc = key.indexOf('(', hash + 1);
            if (hash < 0 || desc < 0) continue;
            String owner = key.substring(0, hash);
            String name = key.substring(hash + 1, desc);
            String descriptor = key.substring(desc);
            if (!selectors.matches(owner) && !selectors.matchesMethod(owner, name, descriptor)) continue;
            total++;
            if (report.changedMethods().contains(key)) changed++;
        }
        if (total == 0) throw new IllegalArgumentException("coverage.required matched no input methods");
        int minimum = section.getInt("minPercent", 1);
        int actual = (int) ((changed * 100L) / total);
        if (actual < minimum) throw new IllegalStateException("required coverage is " + actual
                + "% (" + changed + "/" + total + "), below " + minimum + "%");
    }

    private static void check(String label, long before, long after, int maximumPercent, long allowance) {
        if (maximumPercent < 0 || after <= before) return;
        long growth = after - before;
        long allowed = allowance + before * maximumPercent / 100;
        if (growth > allowed) throw new IllegalStateException(label + " grew by " + growth
                + "; configured allowance is " + allowed + " (" + maximumPercent
                + "% plus " + allowance + ")");
    }
}
