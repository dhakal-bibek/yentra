package yentra.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

/**
 * Core dedupe engine. Thread-safe and lock-free on the hot path.
 *
 * <p>Memory model:
 * <ul>
 *   <li>{@link #configRef} is an immutable snapshot; reads are wait-free.</li>
 *   <li>{@link #seen} maps 128-bit signatures to occurrence counts. A signature is
 *       16 bytes; the counter is one int. With the default cap (200k) that's ~10MB
 *       of map overhead — negligible vs Burp's own history footprint.</li>
 *   <li>{@link #seenCap} bounds growth. Once reached, new signatures are reported
 *       as OVERFLOW rather than tracked — prevents unbounded memory growth on
 *       very large engagements.</li>
 * </ul>
 */
public final class YentraEngine {

    public enum Verdict {
        UNIQUE,    // first time we see this signature
        DUPE,      // seen before
        SKIPPED,   // out of scope / static / disabled tool
        OVERFLOW   // exceeded cap — not tracked
    }

    public record Result(Verdict verdict, Signature signature, int count) {
        public String shortLabel() {
            return switch (verdict) {
                case UNIQUE   -> "UNIQUE";
                case DUPE     -> "DUPE x" + count;
                case SKIPPED  -> "SKIP";
                case OVERFLOW -> "OVRF";
            };
        }
    }

    private static final Pattern NUMERIC_SEGMENT = Pattern.compile("^\\d+$");
    private static final Pattern UUID_SEGMENT = Pattern.compile(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    private static final Pattern HEX_SEGMENT = Pattern.compile("^[0-9a-fA-F]{16,}$");
    private static final String[] STATIC_SUFFIXES = {
            ".png", ".svg", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
            ".css", ".scss", ".js", ".mjs", ".map",
            ".woff", ".woff2", ".ttf", ".eot", ".otf",
            ".mp3", ".mp4", ".wav", ".avi", ".mov", ".m3u8"
    };
    /** Per-identity request headers dropped before a cross-identity signature (attacker/victim share a count). */
    private static final String[] IDENTITY_HEADERS = {"Cookie", "Authorization"};

    private final MontoyaApi api;
    private final AtomicReference<SignatureConfig> configRef;
    private final ConcurrentHashMap<Signature, AtomicInteger> seen = new ConcurrentHashMap<>(1024);
    private volatile int seenCap = 200_000;

    private final AtomicLong totalSeen = new AtomicLong();
    private final AtomicLong totalUnique = new AtomicLong();
    private final AtomicLong totalDupes = new AtomicLong();
    private final AtomicLong totalSkipped = new AtomicLong();

    private final ThreadLocal<MessageDigest> sha256 = ThreadLocal.withInitial(() -> {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    });

    public YentraEngine(MontoyaApi api, SignatureConfig initial) {
        this.api = api;
        this.configRef = new AtomicReference<>(initial);
    }

    public SignatureConfig config() {
        return configRef.get();
    }

    /** Swap the active config and reset the seen set so verdicts stay consistent. */
    public void updateConfig(SignatureConfig next) {
        configRef.set(next);
        reset();
    }

    public void setSeenCap(int cap) {
        this.seenCap = Math.max(1000, cap);
    }

    public int seenCap() {
        return seenCap;
    }

    public void reset() {
        seen.clear();
        totalSeen.set(0);
        totalUnique.set(0);
        totalDupes.set(0);
        totalSkipped.set(0);
    }

    public long totalSeen()    { return totalSeen.get(); }
    public long uniqueCount()  { return totalUnique.get(); }
    public long dupeCount()    { return totalDupes.get(); }
    public long skippedCount() { return totalSkipped.get(); }
    public int  trackedKeys()  { return seen.size(); }

    /**
     * Classify a request/response pair. May be called concurrently from any thread.
     */
    public Result classify(HttpRequest request, HttpResponse response) {
        totalSeen.incrementAndGet();
        SignatureConfig cfg = configRef.get();

        if (cfg.inScopeOnly && !api.scope().isInScope(request.url())) {
            totalSkipped.incrementAndGet();
            return new Result(Verdict.SKIPPED, null, 0);
        }
        if (cfg.skipStatic && isStaticAsset(request)) {
            totalSkipped.incrementAndGet();
            return new Result(Verdict.SKIPPED, null, 0);
        }

        Signature sig = computeSignature(request, response, cfg);

        if (seen.size() >= seenCap && !seen.containsKey(sig)) {
            return new Result(Verdict.OVERFLOW, sig, 0);
        }

        AtomicInteger existing = seen.putIfAbsent(sig, new AtomicInteger(1));
        if (existing == null) {
            totalUnique.incrementAndGet();
            return new Result(Verdict.UNIQUE, sig, 1);
        }
        int n = existing.incrementAndGet();
        totalDupes.incrementAndGet();
        return new Result(Verdict.DUPE, sig, n);
    }

    /**
     * Classify with an <b>identity-agnostic</b> signature, for multi-identity (attacker/victim) testing.
     * The request's {@code Cookie} / {@code Authorization} and the given tag headers are dropped, and the
     * response is ignored (no status / Content-Type), so the <em>same request</em> sent by different
     * logins through the attacker and victim proxies shares one count — first = UNIQUE, second+ = DUPE xN.
     * Everything else (method / host / path / param names per the active config) is unchanged.
     */
    public Result classifyCrossIdentity(HttpRequest request, Set<String> stripHeaderNames) {
        HttpRequest req = request;
        for (String name : IDENTITY_HEADERS) {
            if (req.hasHeader(name)) req = req.withRemovedHeader(name);
        }
        if (stripHeaderNames != null) {
            for (String name : stripHeaderNames) {
                if (req.hasHeader(name)) req = req.withRemovedHeader(name);
            }
        }
        return classify(req, null); // null response → status & Content-Type excluded from the signature
    }

    private static boolean isStaticAsset(HttpRequest req) {
        String path = req.pathWithoutQuery();
        if (path == null) return false;
        String lower = path.toLowerCase();
        for (String suf : STATIC_SUFFIXES) {
            if (lower.endsWith(suf)) return true;
        }
        return false;
    }

    /**
     * Compute a signature without touching the seen-set or counters. Used by the
     * context-menu action to dedupe a user selection without polluting live stats.
     */
    public Signature signatureFor(HttpRequest req, HttpResponse resp) {
        return computeSignature(req, resp, configRef.get());
    }

    private Signature computeSignature(HttpRequest req, HttpResponse resp, SignatureConfig cfg) {
        MessageDigest md = sha256.get();
        md.reset();
        Hasher h = new Hasher(md);

        if (cfg.includeMethod) {
            h.field("M", req.method());
        }
        if (cfg.includeScheme && req.httpService() != null) {
            h.field("S", req.httpService().secure() ? "https" : "http");
        }
        if (cfg.includeHost && req.httpService() != null) {
            h.field("H", req.httpService().host().toLowerCase());
        }
        if (cfg.includePort && req.httpService() != null) {
            h.field("P", Integer.toString(req.httpService().port()));
        }
        if (cfg.includePath) {
            h.field("p", normalizePath(req.pathWithoutQuery(), cfg.normalizeNumericPathSegments));
        }
        if (cfg.includeQueryParamNames || cfg.includeQueryParamValues
                || cfg.includeBodyParamNames || cfg.includeBodyParamValues) {
            addParams(h, req, cfg);
        }
        // Always fold a digest of the raw body into the signature when body params are enabled.
        // This ensures requests with different body content (e.g. {"id":1} vs {"id":2}) always
        // get distinct signatures, even when includeBodyParamValues is off or Montoya can't parse
        // the body into individual parameters. Without this, two POSTs to the same endpoint with
        // different JSON bodies collapse into one signature — a false DUPE.
        if (cfg.includeBodyParamNames || cfg.includeBodyParamValues) {
            addBodyDigest(h, req);
        }
        if (!cfg.includeHeaders.isEmpty()) {
            addHeaders(h, req, cfg);
        }
        if (cfg.includeContentType && resp != null) {
            String ct = resp.headerValue("Content-Type");
            if (ct != null) {
                int semi = ct.indexOf(';');
                h.field("c", (semi >= 0 ? ct.substring(0, semi) : ct).trim().toLowerCase());
            }
        }
        if (cfg.includeStatusCode && resp != null) {
            h.field("s", Integer.toString(resp.statusCode()));
        }

        byte[] digest = md.digest();
        long hi = bytesToLong(digest, 0);
        long lo = bytesToLong(digest, 8);
        return new Signature(hi, lo);
    }

    private static String normalizePath(String path, boolean normalizeIds) {
        if (path == null || path.isEmpty() || !normalizeIds) return path == null ? "" : path;
        String[] segs = path.split("/", -1);
        StringBuilder sb = new StringBuilder(path.length());
        for (int i = 0; i < segs.length; i++) {
            if (i > 0) sb.append('/');
            String s = segs[i];
            if (NUMERIC_SEGMENT.matcher(s).matches()) {
                sb.append("{n}");
            } else if (UUID_SEGMENT.matcher(s).matches()) {
                sb.append("{uuid}");
            } else if (HEX_SEGMENT.matcher(s).matches()) {
                sb.append("{hex}");
            } else {
                sb.append(s);
            }
        }
        return sb.toString();
    }

    private static void addParams(Hasher h, HttpRequest req, SignatureConfig cfg) {
        List<ParsedHttpParameter> params;
        try {
            params = req.parameters();
        } catch (RuntimeException e) {
            // Some malformed requests can throw on parameter parsing; degrade gracefully.
            return;
        }
        if (params == null || params.isEmpty()) return;

        // Collect param "tokens" then sort so order doesn't affect signature.
        List<String> queryTokens = new ArrayList<>(8);
        List<String> bodyTokens = new ArrayList<>(8);
        List<String> cookieTokens = new ArrayList<>(4);

        // A param is in the signature if its names OR its values toggle is on (values implies the name);
        // ticking "values" alone used to be a no-op because inclusion was gated on the names flag only.
        boolean wantQuery = cfg.includeQueryParamNames || cfg.includeQueryParamValues;
        boolean wantBody  = cfg.includeBodyParamNames  || cfg.includeBodyParamValues;

        for (ParsedHttpParameter p : params) {
            HttpParameterType type = p.type();
            String name = p.name();
            if (name == null) continue;

            boolean isQuery = type == HttpParameterType.URL;
            boolean isBody = type == HttpParameterType.BODY || type == HttpParameterType.JSON
                    || type == HttpParameterType.XML || type == HttpParameterType.MULTIPART_ATTRIBUTE;
            boolean isCookie = type == HttpParameterType.COOKIE;

            if (isQuery && wantQuery) {
                queryTokens.add(cfg.includeQueryParamValues ? name + "=" + safeValue(p) : name);
            } else if (isBody && wantBody) {
                bodyTokens.add(cfg.includeBodyParamValues ? name + "=" + safeValue(p) : name);
            } else if (isCookie && wantBody) {
                // Treat cookies as part of body-param toggle by convention. Off by default
                // because cookies often vary per session and would inflate uniqueness.
                cookieTokens.add(name);
            }
        }

        Collections.sort(queryTokens);
        Collections.sort(bodyTokens);
        Collections.sort(cookieTokens);

        for (String t : queryTokens) h.field("q", t);
        for (String t : bodyTokens)  h.field("b", t);
        for (String t : cookieTokens) h.field("k", t);
    }

    private static String safeValue(ParsedHttpParameter p) {
        String v = p.value();
        if (v == null) return "";
        // Cap value length so huge JSON blobs don't dominate digest cost.
        return v.length() > 256 ? v.substring(0, 256) : v;
    }

    /** Cap on how many body bytes are hashed — enough to distinguish requests, cheap on the hot path. */
    private static final int BODY_DIGEST_CAP = 4096;

    /**
     * Folds a digest of the raw request body into the signature. This is the backstop that
     * guarantees two requests with different bodies never collide into a false DUPE, regardless
     * of whether Montoya parsed the body into parameters or whether value-inclusion is on.
     * Only the first {@value #BODY_DIGEST_CAP} bytes are hashed — enough to distinguish any
     * realistic pair of API calls while keeping the hash cost negligible.
     */
    private static void addBodyDigest(Hasher h, HttpRequest req) {
        try {
            String body = req.bodyToString();
            if (body == null || body.isEmpty()) {
                h.field("B", "");
                return;
            }
            int len = Math.min(body.length(), BODY_DIGEST_CAP);
            h.field("B", Integer.toHexString(body.substring(0, len).hashCode()));
        } catch (RuntimeException e) {
            h.field("B", "err");
        }
    }

    private static void addHeaders(Hasher h, HttpRequest req, SignatureConfig cfg) {
        for (String name : cfg.includeHeaders) {
            String v = req.headerValue(name);
            if (v != null) h.field("h:" + name, v);
        }
    }

    private static long bytesToLong(byte[] b, int off) {
        return ((long) (b[off]     & 0xff) << 56)
             | ((long) (b[off + 1] & 0xff) << 48)
             | ((long) (b[off + 2] & 0xff) << 40)
             | ((long) (b[off + 3] & 0xff) << 32)
             | ((long) (b[off + 4] & 0xff) << 24)
             | ((long) (b[off + 5] & 0xff) << 16)
             | ((long) (b[off + 6] & 0xff) << 8)
             |  ((long) (b[off + 7] & 0xff));
    }

    private static final class Hasher {
        private final MessageDigest md;
        private static final byte[] SEP = new byte[]{0x1f};
        private static final byte[] REC = new byte[]{0x1e};

        Hasher(MessageDigest md) { this.md = md; }

        void field(String tag, String value) {
            md.update(tag.getBytes(StandardCharsets.UTF_8));
            md.update(SEP);
            if (value != null) md.update(value.getBytes(StandardCharsets.UTF_8));
            md.update(REC);
        }
    }
}
