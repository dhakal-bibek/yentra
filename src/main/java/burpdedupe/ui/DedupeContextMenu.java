package burpdedupe.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.organizer.OrganizerItem;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.InvocationType;
import burpdedupe.core.DedupeEngine;
import burpdedupe.core.HeaderOverrideSet;
import burpdedupe.core.Signature;
import burpdedupe.proxy.DedupeProxyHandler;
import burpdedupe.proxy.HistoryStamper;

import java.net.MalformedURLException;
import java.net.URL;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * Adds a right-click "Dedupe" submenu to HTTP history (and any other context that
 * exposes selected request/responses).
 *
 * <p>The menu's single action filters the user's selection down to unique requests
 * by signature, optionally applies the user's header overrides, and ships each
 * result to Burp Organizer.
 *
 * <p>Why filter at click-time (instead of relying on the existing {@code [DEDUPE]}
 * notes): the user may have multi-selected before stamping ran, or stamps may have
 * been written under a different signature config. Recomputing against the current
 * config is the source of truth.
 */
public final class DedupeContextMenu implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final DedupeEngine engine;
    private final HistoryStamper stamper;
    private final Supplier<HeaderOverrideSet> overridesSupplier;

    public DedupeContextMenu(MontoyaApi api, DedupeEngine engine,
                             HistoryStamper stamper,
                             Supplier<HeaderOverrideSet> overridesSupplier) {
        this.api = api;
        this.engine = engine;
        this.stamper = stamper;
        this.overridesSupplier = overridesSupplier;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        if (selected == null || selected.isEmpty()) return List.of();
        // Only show in places where it makes sense — proxy history is the primary one.
        // Site map table also exposes the same data, so allow it too.
        InvocationType inv = event.invocationType();
        if (inv != InvocationType.PROXY_HISTORY
                && inv != InvocationType.SITE_MAP_TABLE
                && inv != InvocationType.SITE_MAP_TREE) {
            return List.of();
        }

        JMenu submenu = new JMenu("Dedupe");

        JMenuItem liveUnique = new JMenuItem("Live unique window (auto-collects [DEDUPE] UNIQUE)");
        liveUnique.addActionListener(e -> openLiveUnique());
        submenu.add(liveUnique);

        JMenuItem showUnique = new JMenuItem(
                "Show only unique requests from selection (" + selected.size() + ") — Ctrl+9");
        showUnique.addActionListener(e -> showUniqueRequests(selected));
        submenu.add(showUnique);

        JMenuItem sendUnique = new JMenuItem(
                "Send unique to Organizer (" + selected.size() + " selected)");
        sendUnique.addActionListener(e -> sendUniqueToOrganizer(selected));
        submenu.add(sendUnique);

        submenu.addSeparator();

        JMenuItem removeHostFromScope = new JMenuItem("Remove host from scope");
        removeHostFromScope.addActionListener(e -> removeFromScope(selected, true));

        JMenuItem removePathFromScope = new JMenuItem("Remove path from scope");
        removePathFromScope.addActionListener(e -> removeFromScope(selected, false));
        submenu.add(removeHostFromScope);
        submenu.add(removePathFromScope);

        return List.of(submenu);
    }

    private void sendUniqueToOrganizer(List<HttpRequestResponse> selected) {
        // Snapshot the overrides once so the user can't race the worker by editing
        // the paste box mid-flight.
        HeaderOverrideSet overrides = overridesSupplier.get();

        // Work on a copy — Burp may reuse the underlying list elsewhere.
        List<HttpRequestResponse> snapshot = new ArrayList<>(selected);

        Thread t = new Thread(() -> {
            // If none of the selected rows have been stamped yet, run a full stamp
            // pass over proxy history before doing anything else. That way the user
            // can see the [DEDUPE] notes for the rows they just acted on (and the
            // rest of their history). If at least one selected row is already
            // stamped, assume the user knows the state and skip.
            if (needsInitialStamp(snapshot)) {
                api.logging().logToOutput(
                        "[burp-dedupe] no [DEDUPE] notes on selection — stamping history first");
                AtomicBoolean cancel = new AtomicBoolean(false);
                stamper.stampAll(cancel, new HistoryStamper.Progress() {
                    public void onProgress(int done, int total, DedupeEngine.Result r) {}
                    public void onFinished(int totalProcessed, int stamped, int skipped, boolean cancelled) {
                        api.logging().logToOutput("[burp-dedupe] pre-send stamp complete: "
                                + "processed=" + totalProcessed + " stamped=" + stamped
                                + (skipped > 0 ? " skipped=" + skipped : ""));
                    }
                });
            }

            // Snapshot existing Organizer ids so we can find the items we add.
            // Montoya has no "collection" concept (Organizer is a flat list), so the
            // closest we can get to grouping is stamping the Notes column of each
            // new item with a shared batch label.
            String batchLabel = "Dedupe @ " + LocalDateTime.now()
                    .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            Set<Integer> preexistingIds = snapshotOrganizerIds();

            Set<Signature> seenLocal = new HashSet<>(Math.max(16, snapshot.size()));
            int unique = 0;
            int dupes = 0;
            int skipped = 0;
            int errors = 0;
            for (HttpRequestResponse rr : snapshot) {
                if (rr == null || rr.request() == null) { skipped++; continue; }

                // Honor existing [DEDUPE] stamps if present — they reflect the
                // engine's global view of history, which is more authoritative
                // than re-deduping just the selection. If a row was marked DUPE
                // earlier (because an identical request was seen first), we still
                // want to skip it even though it might be the only one of its
                // signature in *this particular* selection.
                String existingVerdict = readDedupeVerdict(rr);
                if (existingVerdict != null) {
                    if (existingVerdict.startsWith("DUPE")
                            || existingVerdict.equals("SKIP")
                            || existingVerdict.equals("OVRF")) {
                        dupes++;
                        continue;
                    }
                    // UNIQUE — fall through and send. Still add to seenLocal so
                    // a selection containing the same UNIQUE row twice (rare,
                    // but possible via filter views) doesn't double-send.
                }

                Signature sig;
                try {
                    sig = engine.signatureFor(rr.request(), rr.response());
                } catch (RuntimeException ex) {
                    api.logging().logToError("[burp-dedupe] signature failed: " + ex);
                    errors++;
                    continue;
                }
                if (!seenLocal.add(sig)) { dupes++; continue; }

                HttpRequest req = rr.request();
                if (overrides != null && overrides.isEnabled()) {
                    req = applyOverrides(req, overrides);
                }
                try {
                    api.organizer().sendToOrganizer(req);
                    unique++;
                } catch (RuntimeException ex) {
                    api.logging().logToError("[burp-dedupe] organizer send failed: " + ex);
                    errors++;
                }
            }

            int tagged = tagNewOrganizerItems(preexistingIds, batchLabel, unique);

            final int u = unique, d = dupes, s = skipped, er = errors, tg = tagged;
            SwingUtilities.invokeLater(() -> api.logging().logToOutput(
                    "[burp-dedupe] sent to Organizer — unique=" + u
                            + " dupes-filtered=" + d
                            + (s > 0 ? " skipped=" + s : "")
                            + (er > 0 ? " errors=" + er : "")
                            + (overrides != null && overrides.isEnabled()
                                    ? " (overrides applied: " + overrides.size() + " header(s))"
                                    : "")
                            + " | tagged=" + tg + " as '" + batchLabel + "'"));
        }, "burp-dedupe-organizer-send");
        t.setDaemon(true);
        t.start();
    }

    /**
     * Opens the <b>live</b> unique-requests window — it auto-collects every HTTP-history entry stamped
     * {@code [DEDUPE] UNIQUE} and keeps updating as you browse (no selection needed). This is the
     * Ctrl+9 target; the menu item and the Dedupe-tab button open it too.
     */
    public void openLiveUnique() {
        SwingUtilities.invokeLater(() -> UniqueRequestsViewer.openLive(api));
    }

    /**
     * Opens a window listing <em>only the unique</em> requests from the selection, with read-only
     * request/response viewers. The Montoya API can't filter Burp's own HTTP-history table, so we
     * present the deduplicated set in our own window instead (see {@link UniqueRequestsViewer}).
     *
     * <p>Uniques are picked exactly as {@link #sendUniqueToOrganizer} picks what to send: an existing
     * {@code [DEDUPE]} verdict wins (DUPE/SKIP/OVRF are dropped); otherwise the signature is recomputed
     * and only the first occurrence of each signature in the selection is kept.
     *
     * <p>Public because it's the shared target of both the right-click action and the <b>Ctrl+9</b>
     * hot-key (registered in {@code BurpDedupeExtension}).
     */
    public void showUniqueRequests(List<HttpRequestResponse> selected) {
        if (selected == null || selected.isEmpty()) {
            SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(null,
                    "Select one or more HTTP-history (or Site map) rows first.",
                    "Dedupe — Unique requests", JOptionPane.INFORMATION_MESSAGE));
            return;
        }
        List<HttpRequestResponse> snapshot = new ArrayList<>(selected);

        Thread t = new Thread(() -> {
            List<HttpRequestResponse> uniques = new ArrayList<>();
            Set<Signature> seenLocal = new HashSet<>(Math.max(16, snapshot.size()));
            int dupes = 0, skipped = 0, errors = 0;

            for (HttpRequestResponse rr : snapshot) {
                if (rr == null || rr.request() == null) { skipped++; continue; }

                String verdict = readDedupeVerdict(rr);
                if (verdict != null
                        && (verdict.startsWith("DUPE") || verdict.equals("SKIP") || verdict.equals("OVRF"))) {
                    dupes++; continue;
                }
                // UNIQUE stamp, or no stamp: recompute and dedupe within the selection.
                // signatureFor() doesn't touch the engine's live counters.
                Signature sig;
                try {
                    sig = engine.signatureFor(rr.request(), rr.response());
                } catch (RuntimeException ex) {
                    api.logging().logToError("[burp-dedupe] signature failed: " + ex);
                    errors++; continue;
                }
                if (!seenLocal.add(sig)) { dupes++; continue; }
                uniques.add(rr);
            }

            final int d = dupes, s = skipped, er = errors;
            SwingUtilities.invokeLater(() -> {
                api.logging().logToOutput("[burp-dedupe] show unique — unique=" + uniques.size()
                        + " dupes=" + d + (s > 0 ? " skipped=" + s : "") + (er > 0 ? " errors=" + er : ""));
                if (uniques.isEmpty()) {
                    JOptionPane.showMessageDialog(null, "No unique requests in the selection.",
                            "Dedupe — Unique requests", JOptionPane.INFORMATION_MESSAGE);
                    return;
                }
                new UniqueRequestsViewer(api, uniques);
            });
        }, "burp-dedupe-show-unique");
        t.setDaemon(true);
        t.start();
    }

    /**
     * Returns true if no row in the selection has been stamped by us yet. We treat
     * a row as "stamped" iff its current notes start with {@code [DEDUPE]} — same
     * heuristic used by {@code HistoryStamper.revertAll}, so we stay consistent
     * about what counts as "ours".
     */
    /**
     * Parse the dedupe verdict word from a row's notes. Returns {@code "UNIQUE"},
     * {@code "DUPE x42"} (with the count suffix preserved), {@code "SKIP"},
     * {@code "OVRF"}, or {@code null} if no [DEDUPE] stamp is present.
     */
    private static String readDedupeVerdict(HttpRequestResponse rr) {
        try {
            Annotations a = rr.annotations();
            if (a == null || !a.hasNotes()) return null;
            String notes = a.notes();
            if (notes == null || !notes.startsWith(DedupeProxyHandler.NOTE_PREFIX)) return null;
            // Format: "[DEDUPE] VERDICT[ | other notes]"
            int start = DedupeProxyHandler.NOTE_PREFIX.length();
            if (start >= notes.length() || notes.charAt(start) != ' ') return null;
            int sep = notes.indexOf(" | ", start);
            String verdict = (sep < 0 ? notes.substring(start + 1) : notes.substring(start + 1, sep)).trim();
            return verdict.isEmpty() ? null : verdict;
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private static boolean needsInitialStamp(List<HttpRequestResponse> selection) {
        for (HttpRequestResponse rr : selection) {
            if (rr == null) continue;
            try {
                Annotations a = rr.annotations();
                if (a == null || !a.hasNotes()) continue;
                String notes = a.notes();
                if (notes != null && notes.startsWith(DedupeProxyHandler.NOTE_PREFIX)) {
                    return false;
                }
            } catch (RuntimeException ignored) {
                // Continue checking other rows — don't fail the whole action on one bad entry.
            }
        }
        return true;
    }

    private static HttpRequest applyOverrides(HttpRequest req, HeaderOverrideSet set) {
        HttpRequest out = req;
        for (Map.Entry<String, String> e : set.byLowerName().entrySet()) {
            String lower = e.getKey();
            String value = e.getValue();
            String displayName = displayNameFor(set, lower);
            if (out.hasHeader(lower)) {
                out = out.withUpdatedHeader(displayName, value);
            } else if (set.mode() == HeaderOverrideSet.Mode.REPLACE_OR_ADD) {
                out = out.withAddedHeader(HttpHeader.httpHeader(displayName, value));
            }
        }
        return out;
    }

    private static String displayNameFor(HeaderOverrideSet set, String lower) {
        for (String n : set.displayNames()) {
            if (n.toLowerCase().equals(lower)) return n;
        }
        return lower;
    }

    /**
     * Snapshot the IDs of items already in Organizer so we can identify the ones
     * we add. Best-effort — if Organizer is unavailable we just skip tagging.
     */
    private Set<Integer> snapshotOrganizerIds() {
        Set<Integer> ids = new HashSet<>();
        try {
            for (OrganizerItem item : api.organizer().items()) {
                ids.add(item.id());
            }
        } catch (RuntimeException ignored) {}
        return ids;
    }

    /**
     * Stamp the Notes of every new Organizer item (id not in {@code preexisting})
     * with {@code label}. Returns how many we tagged.
     *
     * <p>Why this instead of a real "Collection": Montoya's Organizer API doesn't
     * expose Collections to extensions — see source of {@code Organizer.java}
     * on GitHub. The Notes column is the closest visible grouping primitive we
     * have. Sort Organizer by Notes and your batch clusters together.
     */
    private int tagNewOrganizerItems(Set<Integer> preexisting, String label, int expectNewCount) {
        if (expectNewCount <= 0) return 0;
        int tagged = 0;
        try {
            for (OrganizerItem item : api.organizer().items()) {
                if (preexisting.contains(item.id())) continue;
                Annotations a;
                try {
                    a = item.annotations();
                } catch (RuntimeException ignored) {
                    continue;
                }
                if (a == null) continue;
                String existing = a.hasNotes() ? a.notes() : "";
                String combined = existing.isEmpty() ? label : label + " | " + existing;
                try {
                    a.setNotes(combined);
                    tagged++;
                } catch (RuntimeException ignored) {}
            }
        } catch (RuntimeException ex) {
            api.logging().logToError("[burp-dedupe] organizer tag failed: " + ex);
        }
        return tagged;
    }

    private void removeFromScope(List<HttpRequestResponse> selected, boolean hostOnly) {
        LinkedHashSet<String> urls = new LinkedHashSet<>();
        for (HttpRequestResponse rr : selected) {
            if (rr == null || rr.request() == null) continue;
            String scopeUrl = scopeUrlFor(rr.request(), hostOnly);
            if (scopeUrl != null) urls.add(scopeUrl);
        }
        if (urls.isEmpty()) return;

        String label = hostOnly ? "host(s)" : "path prefix(es)";
        int answer = JOptionPane.showConfirmDialog(null,
                "Exclude the following " + label + " from Target scope?\n\n"
                        + urls.stream().collect(Collectors.joining("\n")),
                "Dedupe — Remove from scope", JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.WARNING_MESSAGE);
        if (answer != JOptionPane.OK_OPTION) return;

        int done = 0;
        for (String url : urls) {
            try {
                api.scope().excludeFromScope(url);
                done++;
            } catch (RuntimeException ex) {
                api.logging().logToError("[burp-dedupe] scope exclude failed for " + url + ": " + ex);
            }
        }
        api.logging().logToOutput("[burp-dedupe] excluded " + done + " " + label + " from scope.");
    }

    public static String scopeUrlFor(HttpRequest req, boolean hostOnly) {
        try {
            URL url = new URL(req.url());
            String scheme = url.getProtocol();
            String host = url.getHost();
            int port = url.getPort();
            String portPart = port == -1 ? "" : ":" + port;
            if (hostOnly) {
                return scheme + "://" + host + portPart + "/";
            }
            String path = url.getPath();
            if (path == null || path.isEmpty() || path.equals("/")) {
                return scheme + "://" + host + portPart + "/";
            }
            path = path.replaceAll("/+$", "");
            return scheme + "://" + host + portPart + path;
        } catch (MalformedURLException e) {
            try {
                HttpRequest req2 = req;
                String hostVal = null;
                for (HttpHeader h : req2.headers()) {
                    if ("Host".equalsIgnoreCase(h.name())) { hostVal = h.value(); break; }
                }
                if (hostVal == null) return null;
                String scheme = req2.httpService() != null && req2.httpService().secure() ? "https" : "http";
                String host = hostVal.contains(":") ? hostVal.substring(0, hostVal.indexOf(':')) : hostVal;
                int port = req2.httpService() != null ? req2.httpService().port() : -1;
                String portPart = (port == -1 || port == 80 || port == 443) ? "" : ":" + port;
                if (hostOnly) {
                    return scheme + "://" + host + portPart + "/";
                }
                String path = req2.path();
                if (path == null || path.isEmpty() || path.equals("/")) {
                    return scheme + "://" + host + portPart + "/";
                }
                int qIdx = path.indexOf('?');
                if (qIdx >= 0) path = path.substring(0, qIdx);
                path = path.replaceAll("/+$", "");
                return scheme + "://" + host + portPart + path;
            } catch (RuntimeException ex2) {
                return null;
            }
        }
    }
}
