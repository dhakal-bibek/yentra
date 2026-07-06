package yentra.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Immutable parsed snapshot of the user's header-override rules.
 *
 * <p>Read by the {@code HeaderOverrideHandler} hot path on every outgoing request — so we
 * keep it pure-immutable and the engine swaps the whole reference atomically via an
 * {@code AtomicReference}, same pattern as {@link SignatureConfig}.
 *
 * <p>One override line = one {@code Name: value} pair. Pasting multiple lines builds an
 * ordered map so the original input order is preserved when the user re-reads it.
 *
 * <p>Each rule has a per-instance {@link Mode} controlling whether missing headers are
 * added or left alone. Mode is parsed from a single set-wide toggle, not per-line, so the
 * UI stays simple.
 */
public final class HeaderOverrideSet {

    public enum Mode {
        /** Replace if present, add if missing. */
        REPLACE_OR_ADD,
        /** Replace if present, do nothing if missing. */
        REPLACE_ONLY
    }

    /** Header names that don't make sense to override (or that the runtime sets). */
    private static final Set<String> RESERVED = Set.of(
            "content-length", "transfer-encoding", "host"
    );

    private final List<String> orderedNames; // original case preserved for display
    private final Map<String, String> byLowerName; // lowercased name -> value
    private final Mode mode;
    private final boolean inScopeOnly;
    private final boolean enabled;

    private HeaderOverrideSet(List<String> orderedNames, Map<String, String> byLowerName,
                              Mode mode, boolean inScopeOnly, boolean enabled) {
        this.orderedNames = Collections.unmodifiableList(orderedNames);
        this.byLowerName = Collections.unmodifiableMap(byLowerName);
        this.mode = mode;
        this.inScopeOnly = inScopeOnly;
        this.enabled = enabled;
    }

    public static HeaderOverrideSet empty() {
        return new HeaderOverrideSet(List.of(), Map.of(), Mode.REPLACE_OR_ADD, false, false);
    }

    public boolean isEnabled()        { return enabled && !byLowerName.isEmpty(); }
    public boolean inScopeOnly()      { return inScopeOnly; }
    public Mode mode()                { return mode; }
    public int size()                 { return byLowerName.size(); }
    public List<String> displayNames() { return orderedNames; }
    public Map<String, String> byLowerName() { return byLowerName; }

    /**
     * Parse from a raw paste-box string. Lines that don't match {@code Name: value}
     * are returned in {@code errors} so the UI can surface them. Blank lines and
     * comment lines starting with {@code #} are skipped silently.
     */
    public static HeaderOverrideSet parse(String raw, Mode mode, boolean inScopeOnly,
                                          boolean enabled, List<String> errors) {
        List<String> order = new ArrayList<>();
        Map<String, String> map = new LinkedHashMap<>();
        if (raw == null || raw.isBlank()) {
            return new HeaderOverrideSet(order, map, mode, inScopeOnly, enabled);
        }
        int lineNo = 0;
        for (String line : raw.split("\\r?\\n")) {
            lineNo++;
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) continue;
            int colon = trimmed.indexOf(':');
            if (colon <= 0 || colon == trimmed.length() - 1) {
                errors.add("Line " + lineNo + ": expected 'Name: value' — got '" + trimmed + "'");
                continue;
            }
            String name = trimmed.substring(0, colon).trim();
            String value = trimmed.substring(colon + 1).trim();
            if (name.isEmpty()) {
                errors.add("Line " + lineNo + ": empty header name");
                continue;
            }
            String lower = name.toLowerCase(Locale.ROOT);
            if (RESERVED.contains(lower)) {
                errors.add("Line " + lineNo + ": '" + name + "' is reserved and will be ignored");
                continue;
            }
            if (!map.containsKey(lower)) {
                order.add(name);
            }
            map.put(lower, value);
        }
        return new HeaderOverrideSet(order, map, mode, inScopeOnly, enabled);
    }

    /** Render the parsed rules back to user-editable text — useful when reloading state. */
    public String render() {
        StringBuilder sb = new StringBuilder();
        for (String name : orderedNames) {
            String v = byLowerName.get(name.toLowerCase(Locale.ROOT));
            sb.append(name).append(": ").append(v == null ? "" : v).append('\n');
        }
        return sb.toString();
    }
}
