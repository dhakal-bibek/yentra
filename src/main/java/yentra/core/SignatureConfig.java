package yentra.core;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Immutable snapshot of the signature rules. Read on every request, written rarely
 * (only when the user changes settings). Using an immutable snapshot lets the hot
 * path read with no synchronization — see {@link YentraEngine#configRef}.
 */
public final class SignatureConfig {

    public enum Preset {
        DEFAULT("Default — method + host + path + sorted param names + status"),
        REQUEST_SMUGGLING("Request smuggling — method + host + path only"),
        IDOR("IDOR / Auth — method + host + path + sorted param names (ignore values)"),
        XSS("XSS — method + host + path + sorted param names + body param names"),
        SQLI("SQLi — method + host + path + sorted param names"),
        SSRF("SSRF — method + host + path + url-param names"),
        OPEN_REDIRECT("Open redirect — host + path + sorted param names"),
        SSTI("SSTI — method + host + path + sorted param names"),
        PATH_TRAVERSAL("Path traversal — method + host + path-prefix + sorted param names"),
        STRICT("Strict — full method + url + sorted param names + values + status"),
        CUSTOM("Custom");

        public final String label;
        Preset(String label) { this.label = label; }
        @Override public String toString() { return label; }
    }

    public final Preset preset;
    public final boolean includeMethod;
    public final boolean includeHost;
    public final boolean includePort;
    public final boolean includeScheme;
    public final boolean includePath;
    public final boolean normalizeNumericPathSegments; // /users/123 -> /users/{n}
    public final boolean includeQueryParamNames;
    public final boolean includeQueryParamValues;
    public final boolean includeBodyParamNames;
    public final boolean includeBodyParamValues;
    public final boolean includeStatusCode;
    public final boolean includeContentType;
    /** Limit dedupe to in-scope only. */
    public final boolean inScopeOnly;
    /** Skip static-looking resources (css, js, images, fonts). */
    public final boolean skipStatic;
    /** Header names to include in signature (lowercased). */
    public final Set<String> includeHeaders;

    private SignatureConfig(Builder b) {
        this.preset = b.preset;
        this.includeMethod = b.includeMethod;
        this.includeHost = b.includeHost;
        this.includePort = b.includePort;
        this.includeScheme = b.includeScheme;
        this.includePath = b.includePath;
        this.normalizeNumericPathSegments = b.normalizeNumericPathSegments;
        this.includeQueryParamNames = b.includeQueryParamNames;
        this.includeQueryParamValues = b.includeQueryParamValues;
        this.includeBodyParamNames = b.includeBodyParamNames;
        this.includeBodyParamValues = b.includeBodyParamValues;
        this.includeStatusCode = b.includeStatusCode;
        this.includeContentType = b.includeContentType;
        this.inScopeOnly = b.inScopeOnly;
        this.skipStatic = b.skipStatic;
        this.includeHeaders = Collections.unmodifiableSet(new LinkedHashSet<>(b.includeHeaders));
    }

    public static SignatureConfig forPreset(Preset p) {
        Builder b = new Builder().preset(p);
        switch (p) {
            case REQUEST_SMUGGLING -> b
                    .includeMethod(true).includeHost(true).includePath(true)
                    .includeQueryParamNames(false).includeQueryParamValues(false)
                    .includeBodyParamNames(false).includeBodyParamValues(false)
                    .includeStatusCode(false);
            case IDOR -> b
                    .includeMethod(true).includeHost(true).includePath(true)
                    .normalizeNumericPathSegments(true)
                    .includeQueryParamNames(true).includeQueryParamValues(false)
                    .includeBodyParamNames(true).includeBodyParamValues(false);
            case XSS -> b
                    .includeMethod(true).includeHost(true).includePath(true)
                    .includeQueryParamNames(true).includeBodyParamNames(true)
                    .includeQueryParamValues(false).includeBodyParamValues(false);
            case SQLI -> b
                    .includeMethod(true).includeHost(true).includePath(true)
                    .includeQueryParamNames(true).includeBodyParamNames(true);
            case SSRF -> b
                    .includeMethod(true).includeHost(true).includePath(true)
                    .includeQueryParamNames(true);
            case OPEN_REDIRECT -> b
                    .includeMethod(false).includeHost(true).includePath(true)
                    .includeQueryParamNames(true);
            case SSTI -> b
                    .includeMethod(true).includeHost(true).includePath(true)
                    .includeQueryParamNames(true).includeBodyParamNames(true);
            case PATH_TRAVERSAL -> b
                    .includeMethod(true).includeHost(true).includePath(true)
                    .normalizeNumericPathSegments(true)
                    .includeQueryParamNames(true);
            case STRICT -> b
                    .includeMethod(true).includeHost(true).includePort(true).includeScheme(true)
                    .includePath(true)
                    .includeQueryParamNames(true).includeQueryParamValues(true)
                    .includeBodyParamNames(true).includeBodyParamValues(true)
                    .includeStatusCode(true).includeContentType(true);
            case DEFAULT -> b
                    .includeMethod(true).includeHost(true).includePath(true)
                    .includeQueryParamNames(true).includeBodyParamNames(true)
                    .includeStatusCode(true);
            case CUSTOM -> { /* leave defaults */ }
        }
        return b.build();
    }

    public Builder toBuilder() {
        return new Builder()
                .preset(preset)
                .includeMethod(includeMethod).includeHost(includeHost).includePort(includePort)
                .includeScheme(includeScheme).includePath(includePath)
                .normalizeNumericPathSegments(normalizeNumericPathSegments)
                .includeQueryParamNames(includeQueryParamNames).includeQueryParamValues(includeQueryParamValues)
                .includeBodyParamNames(includeBodyParamNames).includeBodyParamValues(includeBodyParamValues)
                .includeStatusCode(includeStatusCode).includeContentType(includeContentType)
                .inScopeOnly(inScopeOnly).skipStatic(skipStatic)
                .includeHeaders(includeHeaders);
    }

    public static final class Builder {
        private Preset preset = Preset.DEFAULT;
        private boolean includeMethod = true;
        private boolean includeHost = true;
        private boolean includePort = false;
        private boolean includeScheme = false;
        private boolean includePath = true;
        private boolean normalizeNumericPathSegments = false;
        private boolean includeQueryParamNames = true;
        private boolean includeQueryParamValues = false;
        private boolean includeBodyParamNames = true;
        private boolean includeBodyParamValues = false;
        private boolean includeStatusCode = true;
        private boolean includeContentType = false;
        private boolean inScopeOnly = false;
        private boolean skipStatic = true;
        private Set<String> includeHeaders = new LinkedHashSet<>();

        public Builder preset(Preset v) { preset = v; return this; }
        public Builder includeMethod(boolean v) { includeMethod = v; return this; }
        public Builder includeHost(boolean v) { includeHost = v; return this; }
        public Builder includePort(boolean v) { includePort = v; return this; }
        public Builder includeScheme(boolean v) { includeScheme = v; return this; }
        public Builder includePath(boolean v) { includePath = v; return this; }
        public Builder normalizeNumericPathSegments(boolean v) { normalizeNumericPathSegments = v; return this; }
        public Builder includeQueryParamNames(boolean v) { includeQueryParamNames = v; return this; }
        public Builder includeQueryParamValues(boolean v) { includeQueryParamValues = v; return this; }
        public Builder includeBodyParamNames(boolean v) { includeBodyParamNames = v; return this; }
        public Builder includeBodyParamValues(boolean v) { includeBodyParamValues = v; return this; }
        public Builder includeStatusCode(boolean v) { includeStatusCode = v; return this; }
        public Builder includeContentType(boolean v) { includeContentType = v; return this; }
        public Builder inScopeOnly(boolean v) { inScopeOnly = v; return this; }
        public Builder skipStatic(boolean v) { skipStatic = v; return this; }
        public Builder includeHeaders(Set<String> v) { includeHeaders = new LinkedHashSet<>(v); return this; }

        public SignatureConfig build() { return new SignatureConfig(this); }
    }
}
