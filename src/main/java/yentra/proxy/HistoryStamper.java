package yentra.proxy;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import yentra.core.YentraEngine;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Walks {@code api.proxy().history()} and stamps existing entries with the dedupe
 * verdict. Runs on a background thread (caller's responsibility). Cancellable via
 * the supplied {@link AtomicBoolean}.
 *
 * <p>Why this works on existing entries: {@link Annotations#setNotes(String)} and
 * {@link Annotations#setHighlightColor(HighlightColor)} are <em>mutating</em>
 * setters on the live annotations object Burp keeps for each history record.
 * Calling them updates the row in place — Burp's HTTP-history table picks up the
 * change.
 */
public final class HistoryStamper {

    public interface Progress {
        /** Called from the worker thread. Implementations should marshal to EDT themselves. */
        void onProgress(int done, int total, YentraEngine.Result lastResult);
        void onFinished(int totalProcessed, int stamped, int skipped, boolean cancelled);
    }

    private final MontoyaApi api;
    private final YentraEngine engine;
    private final AtomicBoolean colorize;
    private final AtomicBoolean preserveNotes;

    public HistoryStamper(MontoyaApi api, YentraEngine engine,
                          AtomicBoolean colorize, AtomicBoolean preserveNotes) {
        this.api = api;
        this.engine = engine;
        this.colorize = colorize;
        this.preserveNotes = preserveNotes;
    }

    /**
     * Stamps every entry currently in proxy history. Reset the engine's seen-set
     * before calling if you want clean counts; otherwise existing in-memory state
     * is preserved (live traffic already classified during this session keeps its
     * verdict context).
     */
    public void stampAll(AtomicBoolean cancel, Progress progress) {
        List<ProxyHttpRequestResponse> history;
        try {
            history = api.proxy().history();
        } catch (RuntimeException e) {
            api.logging().logToError("[yentra] failed to read proxy history: " + e);
            progress.onFinished(0, 0, 0, false);
            return;
        }
        int total = history.size();
        int stamped = 0;
        int skipped = 0;
        int i = 0;
        boolean cancelled = false;

        // Heartbeat: don't call onProgress on every single row for very large histories —
        // batch UI updates to keep EDT happy.
        int reportEvery = Math.max(1, total / 200);

        for (ProxyHttpRequestResponse entry : history) {
            if (cancel.get()) { cancelled = true; break; }
            i++;
            YentraEngine.Result result;
            try {
                if (!entry.hasResponse()) { skipped++; continue; }
                // Match the live handler: role-port (attacker/victim) entries dedupe across identities.
                if (PortHighlightHandler.isRolePort(entry.listenerPort())) {
                    result = engine.classifyCrossIdentity(
                            entry.finalRequest(), PortHighlightHandler.injectedHeaderNames());
                } else {
                    result = engine.classify(entry.finalRequest(), entry.response());
                }
            } catch (RuntimeException e) {
                api.logging().logToError("[yentra] classify-history failed for entry "
                        + entry.id() + ": " + e);
                skipped++;
                continue;
            }

            try {
                applyAnnotations(entry, result);
                stamped++;
            } catch (RuntimeException e) {
                api.logging().logToError("[yentra] failed to stamp entry "
                        + entry.id() + ": " + e);
                skipped++;
            }

            if (i % reportEvery == 0) {
                progress.onProgress(i, total, result);
            }
        }
        progress.onFinished(i, stamped, skipped, cancelled);
    }

    private void applyAnnotations(ProxyHttpRequestResponse entry, YentraEngine.Result r) {
        Annotations a = entry.annotations();
        if (a == null) return; // shouldn't happen, but defensive

        String existing = a.hasNotes() ? a.notes() : "";
        String tag = YentraProxyHandler.NOTE_PREFIX + " " + r.shortLabel();
        String next;
        if (preserveNotes.get() && !existing.isEmpty() && !existing.contains(YentraProxyHandler.NOTE_PREFIX)) {
            next = tag + " | " + existing;
        } else {
            String stripped = stripYentraNote(existing);
            next = stripped.isEmpty() ? tag : tag + " | " + stripped;
        }
        a.setNotes(next);
        if (colorize.get()) {
            // Port- and verdict-aware colour, consistent with the live proxy handler.
            a.setHighlightColor(PortHighlightHandler.colorFor(entry.listenerPort(), r.verdict()));
        }
    }

    private static String stripYentraNote(String notes) {
        if (notes == null || notes.isEmpty()) return "";
        if (!notes.startsWith(YentraProxyHandler.NOTE_PREFIX)) return notes;
        int sep = notes.indexOf(" | ");
        return sep < 0 ? "" : notes.substring(sep + 3);
    }

    /** Convenience: run on a daemon thread. */
    public Thread runAsync(AtomicBoolean cancel, Progress progress) {
        Thread t = new Thread(() -> stampAll(cancel, progress), "yentra-history-stamper");
        t.setDaemon(true);
        t.start();
        return t;
    }

    public enum RevertMode {
        /** Remove our [YENTRA] note prefix only. Leave highlight alone. */
        NOTES_ONLY,
        /** Clear highlight on rows whose notes are ours. Leave notes alone. */
        HIGHLIGHTS_ONLY,
        /** Both. */
        NOTES_AND_HIGHLIGHTS
    }

    /**
     * Walk proxy history and undo our annotations. Conservatively, a row is "ours"
     * iff its current notes start with our {@code [YENTRA]} prefix — that prevents
     * us from wiping highlights set by other extensions on rows we never touched.
     */
    public void revertAll(RevertMode mode, AtomicBoolean cancel, Progress progress) {
        List<ProxyHttpRequestResponse> history;
        try {
            history = api.proxy().history();
        } catch (RuntimeException e) {
            api.logging().logToError("[yentra] failed to read proxy history: " + e);
            progress.onFinished(0, 0, 0, false);
            return;
        }
        int total = history.size();
        int touched = 0;
        int skipped = 0;
        int i = 0;
        boolean cancelled = false;
        int reportEvery = Math.max(1, total / 200);

        for (ProxyHttpRequestResponse entry : history) {
            if (cancel.get()) { cancelled = true; break; }
            i++;
            Annotations a;
            try {
                a = entry.annotations();
            } catch (RuntimeException e) {
                skipped++;
                continue;
            }
            if (a == null) { skipped++; continue; }
            String notes = a.hasNotes() ? a.notes() : "";
            boolean isOurs = notes != null && notes.startsWith(YentraProxyHandler.NOTE_PREFIX);
            if (!isOurs) { skipped++; }
            try {
                boolean changed = false;
                if (isOurs && (mode == RevertMode.NOTES_ONLY || mode == RevertMode.NOTES_AND_HIGHLIGHTS)) {
                    String remainder = stripYentraNote(notes);
                    a.setNotes(remainder);
                    changed = true;
                }
                if (isOurs && (mode == RevertMode.HIGHLIGHTS_ONLY || mode == RevertMode.NOTES_AND_HIGHLIGHTS)) {
                    a.setHighlightColor(HighlightColor.NONE);
                    changed = true;
                }
                if (changed) touched++;
            } catch (RuntimeException e) {
                api.logging().logToError("[yentra] revert failed for entry "
                        + entry.id() + ": " + e);
                skipped++;
            }
            if (i % reportEvery == 0) {
                progress.onProgress(i, total, null);
            }
        }
        progress.onFinished(i, touched, skipped, cancelled);
    }

    public Thread revertAsync(RevertMode mode, AtomicBoolean cancel, Progress progress) {
        Thread t = new Thread(() -> revertAll(mode, cancel, progress), "yentra-history-reverter");
        t.setDaemon(true);
        t.start();
        return t;
    }
}
