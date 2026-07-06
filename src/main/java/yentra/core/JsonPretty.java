package yentra.core;

/**
 * Dependency-free JSON helpers used by the "Body Only" response tab and the AI export: strip the
 * common XSSI guards and structurally re-indent JSON. There's no bundled JSON library — {@link
 * #pretty} is a small, robust re-indenter that preserves key order and values and respects string
 * literals / {@code \\} escapes, so colons, commas and braces inside strings are left untouched.
 */
public final class JsonPretty {

    private JsonPretty() { }

    private static final String INDENT = "  ";

    /** True if the trimmed body starts like a JSON object or array. */
    public static boolean looksLikeJson(String body) {
        if (body == null) return false;
        String b = body.strip();
        return b.startsWith("{") || b.startsWith("[");
    }

    /** Strips the common anti-JSON-hijacking guards (XSSI prefixes) from the start of a body. */
    public static String stripXssiGuards(String body) {
        if (body == null) return "";
        String[] guards = {
                "^\\s*for\\s*\\(\\s*;\\s*;\\s*\\)\\s*;\\s*",   // for(;;);
                "^\\s*while\\s*\\(\\s*1\\s*\\)\\s*;\\s*",        // while(1);
                "^\\s*\\)\\]\\}'\\s*",                            // )]}'
                "^\\s*/\\*\\*/\\s*"                                // /**/
        };
        for (String g : guards) {
            body = body.replaceFirst(g, "");
        }
        return body;
    }

    /**
     * Strips XSSI guards, then pretty-prints when the result is JSON; otherwise returns the
     * guard-stripped, trimmed text unchanged. Never throws.
     */
    public static String prettyBody(String rawBody) {
        String body = stripXssiGuards(rawBody == null ? "" : rawBody).strip();
        if (!looksLikeJson(body)) {
            return body;
        }
        String pretty = pretty(body);
        return pretty != null ? pretty : body;   // re-indent bailed (not well-formed) → leave as-is
    }

    /**
     * Re-indents JSON with two-space indentation, preserving key order and values. Structural only
     * (it doesn't parse value types), but it respects string literals and {@code \\} escapes. Returns
     * {@code null} when the text isn't a balanced JSON object/array, so callers can fall back to the
     * original bytes rather than emit something mangled.
     */
    public static String pretty(String json) {
        if (json == null) return null;
        String s = json.strip();
        if (s.isEmpty() || (s.charAt(0) != '{' && s.charAt(0) != '[')) return null;

        StringBuilder out = new StringBuilder(s.length() + s.length() / 4 + 16);
        int indent = 0;
        boolean inString = false;
        boolean escaped = false;

        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);

            if (inString) {
                out.append(c);
                if (escaped) {
                    escaped = false;
                } else if (c == '\\') {
                    escaped = true;
                } else if (c == '"') {
                    inString = false;
                }
                continue;
            }

            switch (c) {
                case '"' -> {
                    inString = true;
                    out.append(c);
                }
                case '{', '[' -> {
                    int j = skipWs(s, i + 1);
                    if (j < s.length() && s.charAt(j) == matching(c)) {
                        out.append(c).append(s.charAt(j));   // keep empty {} / [] on one line
                        i = j;
                    } else {
                        out.append(c);
                        indent++;
                        newline(out, indent);
                    }
                }
                case '}', ']' -> {
                    indent--;
                    if (indent < 0) return null;             // unbalanced close
                    newline(out, indent);
                    out.append(c);
                }
                case ',' -> {
                    out.append(c);
                    newline(out, indent);
                }
                case ':' -> out.append(": ");
                case ' ', '\t', '\n', '\r' -> { /* drop insignificant whitespace */ }
                default -> out.append(c);
            }
        }
        if (inString || indent != 0) return null;            // unterminated string / unbalanced braces
        return out.toString();
    }

    private static char matching(char open) {
        return open == '{' ? '}' : ']';
    }

    private static int skipWs(String s, int i) {
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                break;
            }
            i++;
        }
        return i;
    }

    private static void newline(StringBuilder out, int indent) {
        out.append('\n');
        for (int k = 0; k < indent; k++) {
            out.append(INDENT);
        }
    }
}
