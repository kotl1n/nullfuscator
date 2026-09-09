package com.nullfuscator.obf.core;

import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;
import com.typesafe.config.ConfigParseOptions;
import com.typesafe.config.ConfigValueFactory;

import java.io.File;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public final class ObfConfig {

    private final Config root;
    private final Set<File> sourceFiles;
    private final Map<String, Section> sections = new ConcurrentHashMap<>();

    private ObfConfig(Config root) { this(root, Set.of()); }

    private ObfConfig(Config root, Set<File> sourceFiles) {
        this.root = root;
        this.sourceFiles = Set.copyOf(sourceFiles);
    }

    public Set<File> sourceFiles() { return sourceFiles; }

    public static ObfConfig load(File hocon) {
        Set<File> sources = new HashSet<>();
        Config config = loadConfig(hocon.getAbsoluteFile(), new HashSet<>(), sources).resolve();
        return new ObfConfig(config, sources);
    }

    private static Config loadConfig(File file, Set<File> loading, Set<File> sources) {
        if (!loading.add(file)) throw new IllegalArgumentException("configuration inheritance cycle at " + file);
        sources.add(file);
        Config own = ConfigFactory.parseFile(file,
                ConfigParseOptions.defaults().setAllowMissing(false));
        for (var entry : own.entrySet()) {
            String filename = entry.getValue().origin().filename();
            if (filename != null) sources.add(new File(filename));
        }
        if (own.hasPath("baseConfig")) {
            File base = new File(file.getParentFile(), own.getString("baseConfig")).getAbsoluteFile();
            own = own.withFallback(loadConfig(base, loading, sources));
        }
        loading.remove(file);
        return own;
    }

    public static ObfConfig empty() {
        return new ObfConfig(ConfigFactory.empty());
    }

    public static ObfConfig parse(String hocon) {
        return new ObfConfig(ConfigFactory.parseString(hocon).resolve());
    }

    public Config raw() { return root; }

    public ObfConfig withAdditionalLibs(List<String> additional) {
        if (additional.isEmpty()) return this;
        List<String> merged = new java.util.ArrayList<>(libs());
        for (String path : additional) if (!merged.contains(path)) merged.add(path);
        return new ObfConfig(root.withValue("libs", ConfigValueFactory.fromIterable(merged)), sourceFiles);
    }

    public List<String> libs() {
        if (root.hasPath("libs")) {
            try { return root.getStringList("libs"); } catch (RuntimeException ignored) {}
        }
        return Collections.emptyList();
    }

    public Section section(String id) {
        return sections.computeIfAbsent(id, key -> new Section(
                root.hasPath(key) ? root.getConfig(key) : ConfigFactory.empty()));
    }

    public static final class Section {
        private final Config c;
        private final ExemptMatcher exempt;

        Section(Config c) {
            this.c = c;
            List<String> ex = c.hasPath("exempt")
                    ? safeStringList(c, "exempt") : Collections.emptyList();
            this.exempt = new ExemptMatcher(ex);
        }

        public boolean enabled() { return getBoolean("enabled", false); }

        public boolean present() { return !c.isEmpty(); }

        public int getInt(String path, int def) {
            return c.hasPath(path) ? c.getInt(path) : def;
        }

        public boolean getBoolean(String path, boolean def) {
            return c.hasPath(path) ? c.getBoolean(path) : def;
        }

        public String getString(String path, String def) {
            return c.hasPath(path) ? c.getString(path) : def;
        }

        public List<String> getStringList(String path) {
            return c.hasPath(path) ? safeStringList(c, path) : Collections.emptyList();
        }

        public boolean isExempt(String internalName) {
            return exempt.matches(internalName);
        }

        public ExemptMatcher exempt() { return exempt; }

        public Config raw() { return c; }

        private static List<String> safeStringList(Config c, String path) {
            try { return c.getStringList(path); }
            catch (RuntimeException e) { return Collections.emptyList(); }
        }
    }
}
