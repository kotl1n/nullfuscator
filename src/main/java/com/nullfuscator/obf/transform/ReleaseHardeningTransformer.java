package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public final class ReleaseHardeningTransformer implements Transformer {

    private static final Pattern FABRIC_DESCRIPTION = Pattern.compile(
            "(?s)(\\\"description\\\"\\s*:\\s*)\\\"(?:\\\\.|[^\\\"\\\\])*\\\"");

    @Override
    public String id() {
        return "releaseHardening";
    }

    @Override
    public String description() {
        return "strip Maven metadata and Fabric descriptions";
    }

    @Override
    public void transform(ObfContext ctx) {
        var section = ctx.config().section(id());
        int removed = 0;

        if (section.getBoolean("stripMavenMetadata", true)) {
            List<String> paths = new ArrayList<>();
            for (String path : ctx.resources().keySet()) {
                if (path.startsWith("META-INF/maven/") || path.startsWith("META-INF/proguard/")) {
                    paths.add(path);
                }
            }
            for (String path : paths) {
                ctx.resources().remove(path);
                removed++;
            }
        }

        boolean descriptionStripped = false;
        if (section.getBoolean("stripFabricDescription", true)) {
            for (Map.Entry<String, byte[]> entry : ctx.resources().entrySet()) {
                String path = entry.getKey();
                if (!path.equals("fabric.mod.json") && !path.endsWith("/fabric.mod.json")) {
                    continue;
                }

                String original = new String(entry.getValue(), StandardCharsets.UTF_8);
                String updated = FABRIC_DESCRIPTION.matcher(original).replaceFirst("$1\\\"\\\"");
                if (!original.equals(updated)) {
                    entry.setValue(updated.getBytes(StandardCharsets.UTF_8));
                    descriptionStripped = true;
                }
            }
        }

        if (removed > 0 || descriptionStripped) {
            ctx.log().debug("releaseHardening removed " + removed
                    + " dependency metadata entries"
                    + (descriptionStripped ? " and Fabric descriptions" : ""));
        }
    }
}