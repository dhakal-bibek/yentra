package yentra.proxy;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import yentra.core.YentraEngine;

import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Two responsibilities, both keyed by the proxy <em>listener port</em> traffic
 * arrives on (useful for multi-account IDOR/BOLA testing — one port = "attacker",
 * another = "victim"):
 *
 * <ol>
 *   <li><b>Header injection</b> — as a {@link ProxyRequestHandler}, it stamps the
 *       configured headers into matching requests (an existing header of the same
 *       name is replaced) and tags the Notes column with the role + port.</li>
 *   <li><b>Highlight colour policy</b> — the static {@link #colorFor} methods are
 *       the single source of truth for proxy-history row colours. Colour depends on
 *       both the listener port and the dedupe verdict: a per-port rule overrides the
 *       default dedupe colours. The dedupe handler (live) and the history re-stamper
 *       both call into here so the two paths stay consistent.</li>
 * </ol>
 *
 * <p>Why colour lives here and not on the request: the verdict (unique/dupe) isn't
 * known until the response is classified, so colouring is applied by the dedupe
 * response handler — which reads {@link #colorFor} below. The request handler only
 * injects headers + the note.
 *
 * <p>Ported from the Jython "Port Highlighter" extension onto the Montoya API. To
 * change the mapping, edit {@link #PORT_RULES} and rebuild.
 */
public final class PortHighlightHandler implements ProxyRequestHandler {

    /** Per-port config: the unique/dupe highlight colours and the headers to inject. */
    public record PortRule(HighlightColor uniqueColor, HighlightColor dupeColor, Map<String, String> headers) {}

    // ── CONFIG: listener port -> rule ────────────────────────────────────────
    // Colours are per verdict: (unique, dupe). Headers are injected into requests.
    public static final Map<Integer, PortRule> PORT_RULES = Map.of(
            8082, new PortRule(HighlightColor.GREEN, HighlightColor.YELLOW, Map.of("X-AI-Use", "attacker")),
            8083, new PortRule(HighlightColor.RED,   HighlightColor.GRAY,   Map.of("X-AI-Use", "victim"))
    );
    // Default dedupe colours for traffic on any other port:
    private static final HighlightColor DEFAULT_UNIQUE = HighlightColor.YELLOW;
    private static final HighlightColor DEFAULT_DUPE   = HighlightColor.GRAY;
    // ─────────────────────────────────────────────────────────────────────────

    /** Trailing ":<port>" of a listener like "127.0.0.1:8082" or "[::]:8082". */
    private static final Pattern PORT_TAIL = Pattern.compile(":(\\d{1,5})$");

    private final MontoyaApi api;

    public PortHighlightHandler(MontoyaApi api) {
        this.api = api;
    }

    // ── Highlight colour policy (called by YentraProxyHandler + HistoryStamper) ──

    /**
     * The row colour for a verdict on a given listener port: the port rule's
     * unique/dupe colour if one exists, otherwise the default dedupe colour.
     */
    public static HighlightColor colorFor(int port, YentraEngine.Verdict verdict) {
        PortRule rule = PORT_RULES.get(port);
        if (rule != null) {
            if (verdict == YentraEngine.Verdict.UNIQUE) return rule.uniqueColor();
            if (verdict == YentraEngine.Verdict.DUPE)   return rule.dupeColor();
        }
        return switch (verdict) {
            case UNIQUE   -> DEFAULT_UNIQUE;
            case DUPE     -> DEFAULT_DUPE;
            case SKIPPED  -> HighlightColor.NONE;
            case OVERFLOW -> HighlightColor.ORANGE;
        };
    }

    /** Same, parsing the port from a proxy listener interface like "127.0.0.1:8082". */
    public static HighlightColor colorFor(String listenerInterface, YentraEngine.Verdict verdict) {
        return colorFor(parsePort(listenerInterface), verdict);
    }

    // ── Role ports (attacker/victim) — cross-identity dedupe ──────────────────

    /** True if this listener port is one of the tagged role ports (attacker/victim). */
    public static boolean isRolePort(int port) {
        return PORT_RULES.containsKey(port);
    }

    /** Same, parsing the port from a listener interface like "127.0.0.1:8082". */
    public static boolean isRolePort(String listenerInterface) {
        return isRolePort(parsePort(listenerInterface));
    }

    /**
     * Every header name this handler injects across the role ports (e.g. {@code X-AI-Use}). The dedupe
     * engine strips these before computing a cross-identity signature, so the attacker/victim tag never
     * splits the count.
     */
    public static Set<String> injectedHeaderNames() {
        Set<String> names = new LinkedHashSet<>();
        for (PortRule r : PORT_RULES.values()) {
            names.addAll(r.headers().keySet());
        }
        return names;
    }

    // ── Header injection (request side) ──────────────────────────────────────

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest request) {
        try {
            int port = parsePort(request.listenerInterface());
            PortRule rule = PORT_RULES.get(port);
            if (rule == null) {
                return ProxyRequestReceivedAction.continueWith(request);
            }

            HttpRequest modified = request;
            for (Map.Entry<String, String> h : rule.headers().entrySet()) {
                modified = modified.hasHeader(h.getKey())
                        ? modified.withUpdatedHeader(h.getKey(), h.getValue())
                        : modified.withAddedHeader(h.getKey(), h.getValue());
            }

            // Note only — the colour is applied later, verdict-aware, by the dedupe handler.
            Annotations existing = request.annotations();
            Annotations annotations = (existing == null ? Annotations.annotations() : existing)
                    .withNotes(noteFor(rule, port));
            return ProxyRequestReceivedAction.continueWith(modified, annotations);
        } catch (RuntimeException e) {
            // Never let a bug here block traffic.
            api.logging().logToError("[yentra] port highlight failed: " + e);
            return ProxyRequestReceivedAction.continueWith(request);
        }
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest request) {
        return ProxyRequestToBeSentAction.continueWith(request);
    }

    /** Returns the listener port, or -1 if it can't be parsed / isn't one of ours. */
    private static int parsePort(String listenerInterface) {
        if (listenerInterface == null) return -1;
        Matcher m = PORT_TAIL.matcher(listenerInterface);
        if (!m.find()) return -1;
        try {
            return Integer.parseInt(m.group(1));
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /** Short Notes-column tag like "[attacker] port 8082" (role = first header value). */
    private static String noteFor(PortRule rule, int port) {
        String role = rule.headers().isEmpty()
                ? "port"
                : rule.headers().values().iterator().next();
        return "[" + role + "] port " + port;
    }
}
