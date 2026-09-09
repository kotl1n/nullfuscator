package com.nullfuscator.obf.core;

import java.util.List;

public final class ObfEngine {

    private final List<Transformer> pipeline;

    public ObfEngine(List<Transformer> pipeline) { this.pipeline = pipeline; }

    public void run(ObfContext ctx) {
        ctx.initializePolicies();
        RunReport report = ctx.report();
        RunReport.Snapshot initial = report == null ? null : report.capture(ctx);
        RunReport.Snapshot current = initial;
        if (report != null) report.baseline(initial);
        ctx.log().info("pipeline: " + pipeline.size() + " passes, "
                + ctx.classes().size() + " classes, seed=" + ctx.seed());
        for (Transformer t : pipeline) {
            if (!t.isEnabled(ctx)) {
                ctx.log().debug("skip " + t.id() + " (disabled)");
                continue;
            }
            long start = System.nanoTime();
            RunReport.Snapshot before = current;
            try {
                t.transform(ctx);
                long ms = (System.nanoTime() - start) / 1_000_000;
                if (report != null) {
                    RunReport.Snapshot after = report.captureLight(ctx);
                    report.pass(t.id(), ms, before, after);
                    current = after;
                }
                ctx.log().pass(t.id(), t.description() + " (" + ms + "ms)");
            } catch (RuntimeException e) {
                ctx.log().error("pass " + t.id() + " failed: " + e);
                throw e;
            }
        }
        if (report != null) report.result(report.capture(ctx));
    }
}
