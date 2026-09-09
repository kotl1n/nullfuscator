package com.nullfuscator.obf.core;

public interface Transformer {

    String id();

    default String description() { return id(); }

    default boolean isEnabled(ObfContext ctx) {
        return ctx.config().section(id()).enabled();
    }

    void transform(ObfContext ctx);
}
