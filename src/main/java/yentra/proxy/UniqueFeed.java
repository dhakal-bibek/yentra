package yentra.proxy;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * In-memory fan-out of freshly-classified {@code UNIQUE} proxy requests, from
 * {@link YentraProxyHandler} (publisher) to the live "Yentra Live" view (subscriber).
 *
 * <p>This is the <b>authoritative</b> live path. Unlike the history poll, it does <em>not</em>
 * re-read {@code [YENTRA]} notes back out of Proxy history — so it keeps working even when another
 * extension overwrites the Notes column, when annotations don't round-trip, or when an in-scope /
 * stale-jar mishap leaves history un-collectable. The view still polls history as a back-fill for
 * entries that predate it; the two paths dedupe each other by the proxy message id (and, as a
 * belt-and-braces, by request identity in the view).
 */
public final class UniqueFeed {

    /** Receives each unique request/response and the proxy message id it was seen on ({@code -1} if unknown). */
    public interface Listener {
        void onUnique(HttpRequestResponse rr, int proxyId);
    }

    private final List<Listener> listeners = new CopyOnWriteArrayList<>();

    /** Subscribe; returns an unsubscribe action to call on view dispose / extension unload. */
    public Runnable subscribe(Listener l) {
        listeners.add(l);
        return () -> listeners.remove(l);
    }

    /** Publish a unique to all current subscribers. Never throws — classification must not be blocked. */
    public void publish(HttpRequestResponse rr, int proxyId) {
        if (rr == null) return;
        for (Listener l : listeners) {
            try {
                l.onUnique(rr, proxyId);
            } catch (RuntimeException ignored) {
                // a slow / broken subscriber must never break the proxy hot path
            }
        }
    }
}
