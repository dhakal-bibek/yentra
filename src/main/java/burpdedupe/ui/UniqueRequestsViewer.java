package burpdedupe.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.Preferences;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burpdedupe.core.JsonPretty;
import burpdedupe.proxy.DedupeProxyHandler;
import burpdedupe.proxy.UniqueFeed;

import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.InputMap;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.KeyStroke;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.WindowConstants;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;
import javax.swing.text.JTextComponent;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.KeyboardFocusManager;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Predicate;
import java.util.function.UnaryOperator;
import java.util.function.BiConsumer;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * A standalone window that lists <em>only the unique</em> requests from a selection,
 * styled to mirror Burp's HTTP-history table (same kind of columns, a Notes column
 * carrying our {@code [DEDUPE] …} verdict + {@code [attacker]/[victim] port N} tag, and
 * rows tinted by their Burp highlight colour). Read-only request/response viewers sit
 * beneath the table.
 *
 * <p>The toolbar has <b>Send to Repeater</b>, <b>Save for AI</b>, a <b>Magic Cookie</b> action
 * (reissue the selection with a user-supplied auth set swapped in — for same-request,
 * different-identity IDOR/BOLA checks), and a <b>filter</b> box that
 * matches across all columns (substring, or a regular expression when "regex" is
 * ticked). Full Bambda (Java-snippet) filtering isn't possible from an extension —
 * Montoya only exposes {@code bambda().importBambda(...)} to load a Bambda into Burp,
 * not to evaluate one — so this is a fast text/regex filter instead.
 *
 * <p>Must be constructed on the Swing EDT — it creates Montoya editor components.
 */
public final class UniqueRequestsViewer {

    private final MontoyaApi api;
    private final String baseTitle;
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final UniqueTableModel model;
    private final JTable table;
    private final JDialog frame;         // null in embedded (Burp suite-tab) mode; else a dialog owned by Burp's frame
    private final JPanel root;           // the content panel; becomes the tab body when embedded
    private final TableRowSorter<UniqueTableModel> sorter;
    private final JTextField filterField = new JTextField(26);
    private final JCheckBox regexBox = new JCheckBox("regex");
    private final JCheckBox inScopeBox = new JCheckBox("In-scope only");
    private final JCheckBox sharedOnlyBox = new JCheckBox("Shared only");
    private final JLabel status = new JLabel(" ");
    /** Live mode: proxy ids already collected, by either path (so neither push nor poll re-adds one). Concurrent: written from the proxy thread (push) and the poll thread. */
    private final Set<Integer> seenIds = ConcurrentHashMap.newKeySet();
    /** Live mode: cross-path dedup by request identity — guards against push/poll double-add and re-stamps that change the proxy id. */
    private final Set<String> liveKeys = ConcurrentHashMap.newKeySet();
    /** Live mode: ids examined and found NOT unique — skipped on later ticks; cleared periodically for late stamps. Thread-safe (poll + rescan run concurrently). */
    private final Set<Integer> examinedNonUnique = ConcurrentHashMap.newKeySet();
    /** Live mode: highest proxy history id we've scanned — lets incremental polls skip everything below it. */
    private volatile int maxScannedId = -1;
    /** Live mode: unsubscribe from the push feed on dispose/unload (null for the on-demand pop-up). */
    private Runnable feedUnsub;
    private int ticksUntilFullRescan = FULL_RESCAN_TICKS;
    private final AtomicBoolean polling = new AtomicBoolean(false);
    private Timer liveTimer;
    /** Consecutive live-poll failures; a stale API (extension reloaded) trips a self-stop. */
    private volatile int liveFailures = 0;
    private static final int MAX_LIVE_FAILURES = 3;
    private static final int POLL_INTERVAL_MS = 1500;  // smooth — 1.5s is snappy enough and won't thrash history()
    private static final int FULL_RESCAN_TICKS = 40;   // ~every 60s re-examine all entries (catches "Stamp history")

    /** Optional handler that forwards requests to the Live Share tab (request + response + caption). */
    private static volatile BiConsumer<HttpRequestResponse, String> shareHandler;

    /** When true every new UNIQUE that arrives is automatically forwarded to connected peers. */
    private static volatile boolean autoShare;

    /** Bounded executor for auto-sharing uniques to peers — prevents thread explosion under heavy traffic. */
    private static final ThreadPoolExecutor SHARE_EXECUTOR = new ThreadPoolExecutor(
            1, 2, 30, TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(100),
            r -> { Thread t = new Thread(r, "liveshare-auto"); t.setDaemon(true); return t; },
            new ThreadPoolExecutor.DiscardPolicy()
    );

    /** Set the handler invoked when a request should be shared. Pass {@code null} to unset. */
    public static void setShareHandler(BiConsumer<HttpRequestResponse, String> handler) {
        shareHandler = handler;
    }

    /** Toggle automatic sharing of every new unique request. */
    public static void setAutoShare(boolean active) {
        autoShare = active;
    }

    /** Live export: mirror every collected unique request to a file Claude Code can read. */
    private final JCheckBox cbLiveExport = new JCheckBox("Live export → file", false);
    private Timer exportDebounce;
    private static final Object EXPORT_LOCK = new Object();

    UniqueRequestsViewer(MontoyaApi api, List<HttpRequestResponse> uniques) {
        this(api, uniques, "Unique requests");
    }

    /** @param title the window subtitle, e.g. "Unique requests" or "Magic Cookie results". */
    UniqueRequestsViewer(MontoyaApi api, List<HttpRequestResponse> uniques, String title) {
        this(api, uniques, title, true);
    }

    /**
     * @param windowed {@code true} shows this in its own {@link JFrame} (the pop-up result windows and
     *                 the Ctrl+9 live window); {@code false} builds only the content panel for
     *                 embedding as a Burp suite tab — see {@link #component()} and {@link #embedLive}.
     */
    private UniqueRequestsViewer(MontoyaApi api, List<HttpRequestResponse> uniques, String title, boolean windowed) {
        this.api = api;
        this.baseTitle = title;
        this.requestEditor = api.userInterface().createHttpRequestEditor(); // editable — inline repeater
        this.responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        disableInputMethods(requestEditor.uiComponent());

        this.model = new UniqueTableModel();
        seedRows(uniques);  // precompute cells off the render path (EDT here, but seeds are small/empty)
        this.table = new JTable(model);
        this.sorter = new TableRowSorter<>(model);
        table.setRowSorter(sorter);
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);   // fixed widths + horizontal scroll, like Burp
        table.setDefaultRenderer(Object.class, new HighlightRenderer(model));
        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int viewRow = table.getSelectedRow();
            if (viewRow >= 0) showRow(table.convertRowIndexToModel(viewRow));
            scheduleLiveExport(); // refresh selection.http on selection change
        });
        applyColumnWidths(table);
        table.setComponentPopupMenu(buildTablePopup());

        JSplitPane editors = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                requestEditor.uiComponent(), responseEditor.uiComponent());
        editors.setResizeWeight(0.5);

        // Inline repeater: edit the request (left), Send, see the response (right) — no pop-up.
        JButton sendEdited = new JButton("Send ▶  (Ctrl+Space)");
        sendEdited.setToolTipText("<html>Send the request as edited on the left; the response shows on the right.<br>"
                + "Shortcut: <b>Ctrl+Space</b> (same as Burp Repeater).<br>"
                + "Also works: <b>Ctrl+Enter</b>.</html>");
        sendEdited.addActionListener(e -> sendEditedRequest());
        JPanel sendBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        sendBar.add(new JLabel("Repeater:"));
        sendBar.add(sendEdited);
        JPanel editorPanel = new JPanel(new BorderLayout());
        editorPanel.add(sendBar, BorderLayout.NORTH);
        editorPanel.add(editors, BorderLayout.CENTER);
        installSendKeys(editorPanel);          // Ctrl+Space / Ctrl+Enter → Send

        JSplitPane main = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table), editorPanel);
        main.setResizeWeight(0.35);

        status.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));

        this.root = new JPanel(new BorderLayout());
        root.add(buildToolbar(), BorderLayout.NORTH);
        root.add(main, BorderLayout.CENTER);
        root.add(status, BorderLayout.SOUTH);

        if (windowed) {
            // Parent pop-up windows to Burp's main frame (BApp Store guideline: SwingUtils.suiteFrame()),
            // as a modeless dialog so they ride with Burp across monitors instead of floating loose.
            java.awt.Frame owner = api.userInterface().swingUtils().suiteFrame();
            this.frame = new JDialog(owner, "Dedupe — " + baseTitle + " (" + model.getRowCount() + ")", false);
            frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
            frame.add(root);
            frame.setSize(1150, 760);
            frame.setLocationRelativeTo(owner);
            api.userInterface().applyThemeToComponent(frame.getRootPane());
        } else {
            this.frame = null;                               // embedded: this panel is a Burp suite tab
            api.userInterface().applyThemeToComponent(root);
        }

        if (model.getRowCount() != 0) {
            table.setRowSelectionInterval(0, 0); // shows the first request immediately
        }
        updateCount();
        if (frame != null) frame.setVisible(true);
    }

    /** The content panel — used when this viewer is embedded as a Burp suite tab ({@link #embedLive}). */
    Component component() {
        return root;
    }

    /** Updates the pop-up window title with the live count; a no-op when embedded as a Burp tab. */
    private void refreshTitle() {
        if (frame != null) frame.setTitle("Dedupe — " + baseTitle + " (" + model.getRowCount() + ")");
    }

    private JPanel buildToolbar() {
        JButton repeater = new JButton("Send to Repeater");
        repeater.setToolTipText("Send the selected request(s) to new Repeater tabs (named by method + path).");
        repeater.addActionListener(e -> sendSelectedToRepeater());

        JButton shareBtn = new JButton("Share");
        shareBtn.setToolTipText("<html>Share the selected request with connected peers.<br>"
                + "Open the <b>Dedupe Share</b> tab, start a server or connect to a friend first.</html>");
        shareBtn.addActionListener(e -> {
            List<HttpRequestResponse> sel = selectedRows();
            if (sel.isEmpty()) { status.setText("Select a request first."); return; }
            HttpRequestResponse rr = sel.get(0);
            if (rr == null || rr.request() == null) return;
            BiConsumer<HttpRequestResponse, String> handler = shareHandler;
            if (handler != null) {
                String caption = safeReqLine(rr.request());
                handler.accept(rr, caption);
                status.setText("Shared: " + caption);
            } else {
                status.setText("No Live Share — open the Dedupe Share tab, start a server or connect to a friend.");
            }
        });

        JButton save = new JButton("Save request(s) for AI");
        save.setToolTipText("Save the selected request(s) and their responses into one .http file "
                + "for Claude Code / AI to read. Ctrl/Cmd- or Shift-click to select several.");
        save.addActionListener(e -> saveSelectedRequests());

        JButton magic = new JButton("Magic Cookie");
        magic.setToolTipText("Resend the selected request(s) with your configured auth replacing the "
                + "original Cookie / Authorization (and any header you list); everything else unchanged. "
                + "Opens the results in a new window.");
        magic.addActionListener(e -> openMagicCookieDialog());

        JButton matchReplace = new JButton("Match & Replace");
        matchReplace.setToolTipText("IDOR/BOLA: replace an id or token in the path/query, body, or both, "
                + "then reissue the selected request(s) — watch the live results for an unexpected 200.");
        matchReplace.addActionListener(e -> openMatchReplaceDialog());

        JButton clear = new JButton("Clear");
        clear.setToolTipText("Empty this window — clears the collected rows. "
                + "(In the live window, new [DEDUPE] UNIQUE requests keep arriving after.)");
        clear.addActionListener(e -> clearView());

        Path exportDir = exportDir();
        cbLiveExport.setToolTipText("<html>Auto-writes to <code>" + exportDir + "</code>:<br>"
                + "• <b>live-unique.http</b> — every unique request, as it arrives<br>"
                + "• <b>selection.http</b> — your current selection, as you change it<br>"
                + "Point Claude Code at either path. On by default in the live window; untick to stop.</html>");
        cbLiveExport.addActionListener(e -> { if (cbLiveExport.isSelected()) scheduleLiveExport(); });
        api.logging().logToOutput("[burp-dedupe] live export dir: " + exportDir + " (live-unique.http, selection.http)");

        filterField.setToolTipText("Filter by any text in the request (path, query, headers, body), the "
                + "response body, or the columns (Host / Method / URL / Status / MIME / Notes). "
                + "Plain substring; tick 'regex' for a case-insensitive regular expression.");
        filterField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { applyFilter(); }
            @Override public void removeUpdate(DocumentEvent e) { applyFilter(); }
            @Override public void changedUpdate(DocumentEvent e) { applyFilter(); }
        });
        regexBox.setToolTipText("Treat the filter text as a regular expression (case-insensitive).");
        regexBox.addItemListener(e -> applyFilter());
        inScopeBox.setToolTipText("Show only requests whose URL is in Burp's Target scope. "
                + "Combines with the filter box; live rows are scoped as they arrive. "
                + "(Toggle to re-apply after changing scope.)");
        inScopeBox.addItemListener(e -> applyFilter());

        sharedOnlyBox.setToolTipText("Show only requests that arrived via Live Share from a peer. "
                + "Combines with the other filters.");
        sharedOnlyBox.addItemListener(e -> applyFilter());

        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        bar.add(repeater);
        bar.add(shareBtn);
        bar.add(inScopeBox);
        bar.add(sharedOnlyBox);
        bar.add(save);
        bar.add(magic);
        bar.add(matchReplace);
        bar.add(clear);
        bar.add(cbLiveExport);
        bar.add(new JLabel("    Filter:"));
        bar.add(filterField);
        bar.add(regexBox);
        return bar;
    }

    /**
     * Filters the table: optional <b>Shared only</b>, <b>In-scope only</b> gates,
     * AND the text box, which matches across all columns — substring by default,
     * regex when ticked, always case-insensitive. With none active, every row shows.
     */
    private void applyFilter() {
        List<RowFilter<Object, Object>> filters = new ArrayList<>(3);

        if (sharedOnlyBox.isSelected()) {
            filters.add(sharedRowFilter());
        }

        if (inScopeBox.isSelected()) {
            filters.add(scopeRowFilter());
        }

        String text = filterField.getText();
        if (text != null && !text.isEmpty()) {
            if (regexBox.isSelected()) {
                try {
                    Pattern p = Pattern.compile(text, Pattern.CASE_INSENSITIVE);
                    filters.add(searchRowFilter(blob -> p.matcher(blob).find()));
                } catch (PatternSyntaxException ex) {
                    status.setText("Invalid regex: " + ex.getMessage());
                    return;
                }
            } else {
                String needle = text.toLowerCase(Locale.ROOT);
                filters.add(searchRowFilter(blob -> blob.contains(needle)));
            }
        }

        sorter.setRowFilter(filters.isEmpty() ? null
                : filters.size() == 1 ? filters.get(0)
                : RowFilter.andFilter(filters));
        updateCount();
    }

    /**
     * A row filter that runs {@code test} against the row's precomputed search blob — the columns plus
     * the full request (path, query, headers, body) and response body — so the filter matches request
     * body and path text, not just the visible columns.
     */
    private RowFilter<Object, Object> searchRowFilter(Predicate<String> test) {
        return new RowFilter<>() {
            @Override public boolean include(Entry<? extends Object, ? extends Object> entry) {
                Object id = entry.getIdentifier();
                if (!(id instanceof Integer)) return true;
                String blob = model.searchAt((Integer) id);
                return blob != null && test.test(blob);
            }
        };
    }

    /** A row filter that keeps only requests that arrived via Live Share. */
    private RowFilter<Object, Object> sharedRowFilter() {
        return new RowFilter<>() {
            @Override public boolean include(Entry<? extends Object, ? extends Object> entry) {
                Object id = entry.getIdentifier();
                return id instanceof Integer && rowIsShared((Integer) id);
            }
        };
    }

    /** A row filter that keeps only rows whose request URL is in Burp's Target scope. */
    private RowFilter<Object, Object> scopeRowFilter() {
        return new RowFilter<>() {
            @Override public boolean include(Entry<? extends Object, ? extends Object> entry) {
                Object id = entry.getIdentifier();
                return id instanceof Integer && rowInScope((Integer) id);
            }
        };
    }

    /** True iff the model row is a shared request received via Live Share. */
    private boolean rowIsShared(int modelRow) {
        Row row = model.rowAt(modelRow);
        return row != null && row.shared;
    }

    /** True iff the model row's request URL is in Burp's Target scope. Uses the row's cached URL. */
    private boolean rowInScope(int modelRow) {
        String url = model.urlAt(modelRow);
        if (url == null || url.isEmpty()) return false;
        try {
            return api.scope().isInScope(url);
        } catch (RuntimeException e) {
            return false;
        }
    }

    private void updateCount() {
        status.setText("Showing " + table.getRowCount() + " of " + model.getRowCount() + " request(s).");
    }

    /**
     * Appends one streamed result and refreshes the table live — must be called on the EDT. The
     * Magic Cookie flow opens this window immediately (empty) and calls this as each response
     * returns, so rows appear one by one instead of all at once when the batch finishes.
     */
    void addResult(HttpRequestResponse rr) {
        if (rr == null) return;
        model.add(Row.of(rr));
        refreshTitle();
        if (model.getRowCount() == 1) {
            table.setRowSelectionInterval(0, 0); // show the first response the moment it lands
        }
        updateCount();
        scheduleLiveExport();
    }

    /** Bulk-appends precomputed rows with a single table refresh (EDT only). Used by the live back-fill. */
    void addResults(List<Row> rows) {
        if (rows == null || rows.isEmpty()) return;
        boolean wasEmpty = model.getRowCount() == 0;
        model.addAll(rows);
        refreshTitle();
        if (wasEmpty) {
            table.setRowSelectionInterval(0, 0);
        }
        updateCount();
        scheduleLiveExport();
    }

    /** Seeds the table from a caller-supplied list (constructor only); cells are computed here. */
    private void seedRows(List<HttpRequestResponse> seed) {
        if (seed == null || seed.isEmpty()) return;
        List<Row> rows = new ArrayList<>(seed.size());
        for (HttpRequestResponse rr : seed) {
            if (rr != null) rows.add(Row.of(rr));
        }
        model.addAll(rows);
    }

    /** Routes an event line to Burp's extension output (the in-window live log was removed). */
    void log(String line) {
        try {
            api.logging().logToOutput("[burp-dedupe] " + line);
        } catch (RuntimeException ignored) {
            // API gone (extension unloaded) — drop the line rather than crash the worker
        }
    }

    /**
     * Empties the table. In live mode {@code seenIds} is kept, so cleared rows don't reappear on the
     * next poll — only genuinely new {@code [DEDUPE] UNIQUE} entries arrive.
     */
    private void clearView() {
        int n = model.getRowCount();
        model.clear();
        refreshTitle();
        status.setText("Cleared " + n + " row(s).");
        scheduleLiveExport();
    }

    // ── Live feed: auto-collect HTTP-history rows marked [DEDUPE] UNIQUE ──────

    /**
     * Opens a <b>live</b> window that automatically collects every Proxy HTTP-history entry the
     * extension has marked <code>[DEDUPE] UNIQUE</code> in its Notes — and only those. It polls the
     * history (~1s) so new uniques appear on their own as you browse; the duplicates Burp already
     * folded away (<code>[DEDUPE] DUPE …</code>) never show, and uniques already in history are
     * collected the moment you open it. Closing the window stops the polling.
     *
     * <p>This re-reads the verdict the proxy handler already wrote — it does <em>not</em> recompute
     * signatures — so keep verdict stamping on (that's what writes the note). Must be called on the
     * Swing EDT.
     */
    static UniqueRequestsViewer openLive(MontoyaApi api) {
        UniqueRequestsViewer viewer = new UniqueRequestsViewer(api, new ArrayList<>(), "Live unique history");
        viewer.startLivePolling();
        return viewer;
    }

    /**
     * Builds the same live unique history as {@link #openLive}, but as an embeddable panel (no pop-up)
     * for registration as a Burp suite tab — get it via {@link #component()}. Polls Proxy history for
     * {@code [DEDUPE] UNIQUE} rows for the life of the extension. Must be called on the Swing EDT.
     */
    static UniqueRequestsViewer embedLive(MontoyaApi api, UniqueFeed feed) {
        UniqueRequestsViewer viewer = new UniqueRequestsViewer(api, new ArrayList<>(), "Live unique history", false);
        if (feed != null) {
            // Primary live path: UNIQUEs are pushed here straight from the proxy handler.
            viewer.feedUnsub = feed.subscribe(viewer::onLiveUnique);
        }
        viewer.startLivePolling(); // back-fill + safety net for entries that predate this view
        return viewer;
    }

    /**
     * Push path: a freshly-classified UNIQUE arrives directly from {@link DedupeProxyHandler} (on the
     * proxy thread, off the EDT). Dedupes by request identity, parses the row off the EDT, then
     * appends on the EDT. Never throws back into the proxy hot path.
     *
     * <p>{@code seenIds} is populated only <em>after</em> the row is successfully parsed and queued
     * for display — not before {@code claimLive}. Previously, adding the proxy id to {@code seenIds}
     * before {@code claimLive} meant that if {@code claimLive} rejected the entry (a false-positive
     * liveKey collision), the poll path would skip it forever, permanently losing a genuinely UNIQUE
     * request from both paths.
     */
    private void onLiveUnique(HttpRequestResponse rr, int proxyId) {
        String claimedKey = null;
        try {
            if (rr == null || rr.request() == null) return;
            String key = liveKey(rr);
            if (key != null) {
                if (!liveKeys.add(key)) return;          // already shown (e.g. just back-filled by the poll)
                claimedKey = key;                          // remember so we can undo on failure
            }
            Row row = Row.of(rr);                          // parse off the EDT
            // Row parsed successfully — now safe to mark as seen so the poll won't re-add it.
            if (proxyId >= 0) seenIds.add(proxyId);
            SwingUtilities.invokeLater(() -> {
                addResults(java.util.Collections.singletonList(row));
                log("UNIQUE  " + safeReqLine(rr.request()));
            });
            // Auto-forward to connected peers when live share is active.
            // Only forward real proxy entries (proxyId >= 0), not requests that arrived via
            // Live Share from another peer — otherwise we'd loop forever.
            if (autoShare && proxyId >= 0) {
                BiConsumer<HttpRequestResponse, String> handler = shareHandler;
                if (handler != null) {
                    String caption = safeReqLine(rr.request());
                    SHARE_EXECUTOR.execute(() -> handler.accept(rr, caption));
                }
            }
        } catch (RuntimeException e) {
            safeLogError("[burp-dedupe] live push add failed: " + e);
            // Row.of or invokeLater failed — undo the liveKey claim so the poll path can retry.
            // seenIds was not yet added (it comes after Row.of), so the poll will re-examine.
            if (claimedKey != null) {
                try { liveKeys.remove(claimedKey); } catch (RuntimeException ignored) {}
            }
        }
    }

    /** True iff {@code rr} is new to this live view (and claims it); false if an identical row is already shown. */
    private boolean claimLive(HttpRequestResponse rr) {
        String key = liveKey(rr);
        return key == null || liveKeys.add(key); // Set.add → true when newly added
    }

    /**
     * A lightweight identity key for cross-path dedup: method + URL + body hash + response status.
     *
     * <p>Previously this used only the body <em>length</em>, which was too coarse: two genuinely
     * different requests (same URL, same body length, but different body content — or same URL but
     * different response status codes when the role-port cross-identity path isn't active) collided
     * into one key. The second UNIQUE was silently rejected by {@link #claimLive} and, because
     * {@code seenIds} was already populated, permanently lost from both the push and poll paths.
     * Including a body content hash and the response status code makes false-positive collisions
     * effectively impossible while keeping the key cheap to compute.
     */
    private static String liveKey(HttpRequestResponse rr) {
        try {
            HttpRequest req = rr.request();
            if (req == null) return null;
            String method = req.method() == null ? "" : req.method();
            String url = req.url() == null ? "" : req.url();
            String bodyHash;
            int bodyLen;
            try {
                String body = req.bodyToString();
                bodyLen = body == null ? 0 : body.length();
                bodyHash = body == null ? "" : Integer.toHexString(body.hashCode());
            } catch (RuntimeException e) {
                bodyLen = -1;
                bodyHash = "err";
            }
            int status = -1;
            try {
                if (rr.hasResponse() && rr.response() != null) {
                    status = rr.response().statusCode();
                }
            } catch (RuntimeException e) {
                status = -2;
            }
            return method + " " + url + " #" + bodyLen + ":" + bodyHash + " " + status;
        } catch (RuntimeException e) {
            return null;
        }
    }

    private void startLivePolling() {
        log("Live unique history — push from the proxy handler, with a history back-fill poll…");
        cbLiveExport.setSelected(true);  // the live window auto-exports every unique by default
        scheduleLiveExport();            // create the (initially empty) export file right away
        liveTimer = new Timer(POLL_INTERVAL_MS, e -> pollHistory());
        liveTimer.setRepeats(true);
        liveTimer.start();
        pollHistory(); // immediate first pass picks up the uniques already in history

        if (frame != null) {                 // window mode: stop polling when the pop-up closes
            frame.addWindowListener(new WindowAdapter() {
                @Override public void windowClosed(WindowEvent e) {
                    if (liveTimer != null) liveTimer.stop();
                    unsubscribeFeed();
                }
            });
        }

        // If the extension is unloaded/reloaded while this view is still alive, the MontoyaApi goes
        // stale (api.proxy() becomes null) and every tick would NPE forever. Stop polling, drop the
        // feed subscription, and in window mode dispose the now-orphaned pop-up the moment that happens.
        try {
            api.extension().registerUnloadingHandler(() -> SwingUtilities.invokeLater(() -> {
                if (liveTimer != null) liveTimer.stop();
                unsubscribeFeed();
                if (frame != null) frame.dispose();
            }));
        } catch (RuntimeException ignored) {
            // best-effort; the per-poll self-stop is the safety net if this can't register
        }
    }

    /** Drops the push-feed subscription (idempotent; no-op for the on-demand pop-up). */
    private void unsubscribeFeed() {
        Runnable u = feedUnsub;
        feedUnsub = null;
        if (u != null) {
            try { u.run(); } catch (RuntimeException ignored) { /* best-effort */ }
        }
    }

    /**
     * Appends any Proxy-history entry whose Notes start with {@code [DEDUPE] UNIQUE} that we haven't
     * already collected. <b>Incremental:</b> ids already collected ({@code seenIds}) or already examined
     * and rejected ({@code examinedNonUnique}) are skipped with a cheap set lookup, so a steady tick only
     * does real work for genuinely new entries. Every {@link #FULL_RESCAN_TICKS} ticks the reject set is
     * cleared for one full re-examine, which catches rows the "Stamp existing history" pass marks unique
     * after the window opened. Each kept row's display cells are computed <em>here, off the EDT</em>
     * ({@link Row#of}), so the table never parses while painting. Runs off the EDT and never overlaps.
     */
    private void pollHistory() {
        if (!polling.compareAndSet(false, true)) return; // a scan is already in flight
        Thread t = new Thread(() -> {
            try {
                // A "full pass" re-examines every not-yet-collected entry: true on the very first poll
                // (the reject set is still empty) and on each periodic rescan tick. We take the verdict
                // census on a full pass so an empty feed can explain itself.
                boolean fullPass = examinedNonUnique.isEmpty();
                if (--ticksUntilFullRescan <= 0) {       // periodic full re-examine (late "Stamp history" marks)
                    examinedNonUnique.clear();
                    ticksUntilFullRescan = FULL_RESCAN_TICKS;
                    fullPass = true;
                }
                int scanFloor = fullPass ? -1 : maxScannedId; // incremental: skip ids we've already scanned past
                List<ProxyHttpRequestResponse> history = api.proxy().history();
                liveFailures = 0; // a good read clears the stale-API failure streak
                List<Row> batch = new ArrayList<>();
                int nUnique = 0, nDupe = 0, nSkip = 0, nOvrf = 0, nOther = 0, nNoNote = 0;
                for (ProxyHttpRequestResponse h : history) {
                    if (h == null || h.request() == null) continue;
                    int id = h.id();
                    if (id <= scanFloor) continue;          // incremental: we've already processed everything below the floor
                    if (id > maxScannedId) maxScannedId = id; // advance the high-water mark
                    if (seenIds.contains(id) || examinedNonUnique.contains(id)) continue; // already handled
                    try {
                        String cat = noteCategory(h.annotations());
                        switch (cat) {
                            case "UNIQUE" -> nUnique++;
                            case "DUPE"   -> nDupe++;
                            case "SKIP"   -> nSkip++;
                            case "OVRF"   -> nOvrf++;
                            case "OTHER"  -> nOther++;
                            default       -> nNoNote++;
                        }
                        if (!"UNIQUE".equals(cat)) {
                            // Only cache a verdict we actually recognise as non-unique (DUPE/SKIP/OVRF).
                            // "NONE" (no [DEDUPE] note) and "OTHER" (non-dedupe note, e.g. a role-port
                            // tag before the response handler stamped it) might not have been classified
                            // yet — don't cache them, so the next poll re-examines until a real verdict
                            // lands. This prevents genuinely UNIQUE requests from being hidden for up to
                            // a full rescan cycle (~30s) just because the poll beat the response handler.
                            if (!"NONE".equals(cat) && !"OTHER".equals(cat)) {
                                examinedNonUnique.add(id);
                            }
                            continue;
                        }
                        HttpResponse resp = h.hasResponse() && h.response() != null ? h.response() : HttpResponse.httpResponse();
                        HttpRequestResponse rr = HttpRequestResponse.httpRequestResponse(h.request(), resp, h.annotations());
                        boolean claimed = claimLive(rr);
                        // Mark as seen regardless of claimLive result: if claimed, the row is in the
                        // batch; if not, it was already added by the push path (genuine duplicate).
                        // With a robust liveKey, false-positive collisions are effectively impossible.
                        seenIds.add(id);
                        if (claimed) batch.add(Row.of(rr)); // skip if the push path already added it
                    } catch (RuntimeException perEntry) {
                        // One malformed entry must never abort the whole scan — which would otherwise be
                        // caught below as a poll "failure" and, after a few ticks, self-stop the feed.
                        examinedNonUnique.add(id);
                        safeLogError("[burp-dedupe] live scan skipped entry " + id + ": " + perEntry);
                    }
                }
                if (!batch.isEmpty()) {
                    if (autoShare) {
                        BiConsumer<HttpRequestResponse, String> handler = shareHandler;
                        if (handler != null) {
                            for (Row r : batch) {
                                try {
                                    String caption = safeReqLine(r.rr.request());
                                    SHARE_EXECUTOR.execute(() -> handler.accept(r.rr, caption));
                                } catch (RuntimeException ignored) {}
                            }
                        }
                    }
                    SwingUtilities.invokeLater(() -> {
                        addResults(batch);
                        if (batch.size() <= 12) {
                            for (Row r : batch) log("UNIQUE  " + safeReqLine(r.rr.request()));
                        } else {
                            log("Added " + batch.size() + " [DEDUPE] UNIQUE from history.");
                        }
                    });
                }
                if (fullPass) {
                    // Verdict census of the entries examined this pass. The live feed collects only
                    // [DEDUPE] UNIQUE rows, so when it stays empty the reason is almost always visible
                    // here: 0 UNIQUE because in-scope-only marked everything SKIP, no [DEDUPE] note at
                    // all (stamping off / a duplicate extension overwrote it), or empty history.
                    final int histSize = history.size();
                    final int cU = nUnique, cD = nDupe, cS = nSkip, cO = nOvrf, cX = nOther, cN = nNoNote;
                    log("live scan: " + histSize + " history entr" + (histSize == 1 ? "y" : "ies")
                            + ", new this pass UNIQUE=" + cU + " DUPE=" + cD + " SKIP=" + cS
                            + " OVRF=" + cO + " other=" + cX + " no-note=" + cN);
                    SwingUtilities.invokeLater(() -> {
                        if (model.getRowCount() == 0) {
                            status.setText(reasonForEmpty(histSize, cU, cD, cS, cO, cX, cN));
                        }
                    });
                }
            } catch (RuntimeException ex) {
                handleLivePollFailure(ex);
            } finally {
                polling.set(false);
            }
        }, "burp-dedupe-live-poll");
        t.setDaemon(true);
        t.start();
    }

    /**
     * A live poll threw — almost always because the {@link MontoyaApi} went stale (the extension was
     * unloaded/reloaded with this window still open), which makes {@code api.proxy()} null and would
     * otherwise NPE on every 1s tick forever. Log it safely (the API's logger may be dead too) and,
     * once a few consecutive ticks have failed, stop the timer so the window goes quiet instead of
     * flooding the error log. A later good read resets the streak.
     */
    private void handleLivePollFailure(RuntimeException ex) {
        int fails = ++liveFailures;
        safeLogError("[burp-dedupe] live history poll failed (" + fails + "/" + MAX_LIVE_FAILURES + "): " + ex);
        if (fails >= MAX_LIVE_FAILURES) {
            SwingUtilities.invokeLater(() -> {
                if (liveTimer != null) liveTimer.stop();
                status.setText("Live polling stopped — Burp API unavailable (extension reloaded?). "
                        + "Reopen the live window to resume.");
            });
        }
    }

    /** Logs to Burp's error output, falling back to stderr if the API is gone (e.g. after unload). */
    private void safeLogError(String msg) {
        try {
            api.logging().logToError(msg);
        } catch (RuntimeException ignored) {
            System.err.println(msg);
        }
    }

    /**
     * Categorises a history row's Notes by our verdict: {@code "UNIQUE"}, {@code "DUPE"}, {@code "SKIP"}
     * or {@code "OVRF"}; {@code "OTHER"} for a non-dedupe note, {@code "NONE"} for no note at all. Only
     * {@code "UNIQUE"} rows are collected by the live feed — the rest feed the diagnostic census in
     * {@link #pollHistory}.
     */
    private static String noteCategory(Annotations a) {
        try {
            if (a == null || !a.hasNotes()) return "NONE";
            String notes = a.notes();
            if (notes == null || notes.isEmpty()) return "NONE";
            if (!notes.startsWith(DedupeProxyHandler.NOTE_PREFIX)) return "OTHER";
            String rest = notes.substring(DedupeProxyHandler.NOTE_PREFIX.length()).trim();
            if (rest.startsWith("UNIQUE")) return "UNIQUE";
            if (rest.startsWith("DUPE"))   return "DUPE";
            if (rest.startsWith("SKIP"))   return "SKIP";
            if (rest.startsWith("OVRF"))   return "OVRF";
            return "OTHER";
        } catch (RuntimeException e) {
            return "NONE";
        }
    }

    /**
     * A plain-language reason the live feed is still empty, shown in the status bar after a full scan
     * collected nothing — turning an invisible config problem into a visible, actionable message.
     */
    private static String reasonForEmpty(int histSize, int unique, int dupe, int skip, int ovrf,
                                         int other, int noNote) {
        if (histSize == 0) {
            return "Live: proxy history is empty — browse the target through Burp's proxy first.";
        }
        if (unique > 0) {
            return "Live: found " + unique + " UNIQUE — collecting…"; // transient; next tick fills the table
        }
        int dedupeNotes = dupe + skip + ovrf;
        if (dedupeNotes == 0) {
            return "Live: " + histSize + " rows but none carry a [DEDUPE] verdict — enable "
                    + "\"Stamp Notes column with verdict\" in the Dedupe tab (or another extension is "
                    + "overwriting the Notes).";
        }
        if (skip > 0 && dupe == 0 && ovrf == 0) {
            return "Live: 0 UNIQUE — all " + skip + " classified rows are [DEDUPE] SKIP. Turn off "
                    + "\"In-scope only\" in the Dedupe tab (or set a matching Target scope), then Apply.";
        }
        return "Live: 0 UNIQUE of " + histSize + " rows (DUPE=" + dupe + " SKIP=" + skip
                + (ovrf > 0 ? " OVRF=" + ovrf : "") + "). If you expected uniques, check for a duplicate "
                + "Dedupe extension overwriting verdicts, then click \"Stamp existing history\".";
    }

    private void showRow(int modelRow) {
        Row row = model.rowAt(modelRow);
        if (row == null || row.rr == null) return;
        HttpRequestResponse rr = row.rr;
        requestEditor.setRequest(rr.request());
        responseEditor.setResponse(
                rr.hasResponse() && rr.response() != null ? rr.response() : HttpResponse.httpResponse());
    }

    /**
     * Inline repeater: sends whatever is currently in the (editable) request editor — including the
     * user's edits — via Burp's HTTP client, then shows the response on the right with a status /
     * length / timing line. Select a logged row to load it, tweak the request, then Send. Runs off the
     * EDT; reissued requests appear in Logger, not Proxy history (like Magic Cookie / Match &amp; Replace).
     */
    private void sendEditedRequest() {
        HttpRequest req;
        try {
            req = requestEditor.getRequest();
        } catch (RuntimeException ex) {
            status.setText("Couldn't read the edited request: " + ex.getMessage());
            return;
        }
        if (req == null || req.httpService() == null) {
            status.setText("Select a row first, then edit the request and Send.");
            return;
        }
        status.setText("Sending…");
        Thread t = new Thread(() -> {
            long t0 = System.currentTimeMillis();
            try {
                HttpRequestResponse out = api.http().sendRequest(req);
                long ms = System.currentTimeMillis() - t0;
                HttpResponse resp = out != null && out.hasResponse() ? out.response() : null;
                SwingUtilities.invokeLater(() -> {
                    responseEditor.setResponse(resp != null ? resp : HttpResponse.httpResponse());
                    status.setText(resp != null
                            ? "HTTP " + resp.statusCode() + "  •  " + resp.body().length() + " bytes  •  " + ms + " ms"
                            : "No response (" + ms + " ms).");
                });
                log("Repeater  " + safeReqLine(req) + "   ←   "
                        + (resp != null ? resp.statusCode() + " " + resp.body().length() + "b" : "(no response)"));
            } catch (RuntimeException ex) {
                SwingUtilities.invokeLater(() -> status.setText("Send failed: " + ex.getMessage()));
                api.logging().logToError("[burp-dedupe] inline repeater send failed: " + ex);
            }
        }, "burp-dedupe-repeater-send");
        t.setDaemon(true);
        t.start();
    }

    /**
     * Binds <b>Send</b> to Ctrl+Space and Ctrl+Enter. Ctrl+Space uses a
     * {@link KeyboardFocusManager} dispatcher plus {@code enableInputMethods(false)} on all nested
     * text components — this prevents macOS from consuming the keystroke for input-source switching,
     * the same way Burp Repeater makes it work.
     * Ctrl+Enter uses the standard {@code WHEN_IN_FOCUSED_WINDOW} input map as a fallback.
     */
    private void installSendKeys(JComponent c) {
        c.getActionMap().put("dedupe-send", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) {
                if (root.isShowing()) sendEditedRequest();
            }
        });
        InputMap im = c.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW);
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, KeyEvent.CTRL_DOWN_MASK), "dedupe-send");

        // When_IN_FOCUSED_WINDOW also catches Ctrl+Space if the OS doesn't intercept it.
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_SPACE, KeyEvent.CTRL_DOWN_MASK), "dedupe-send");

        // Fire before macOS Input Method framework consumes Ctrl+Space.
        KeyboardFocusManager.getCurrentKeyboardFocusManager().addKeyEventDispatcher(e -> {
            if (e.getID() != KeyEvent.KEY_PRESSED) return false;
            if (e.getKeyCode() != KeyEvent.VK_SPACE) return false;
            if ((e.getModifiersEx() & KeyEvent.CTRL_DOWN_MASK) == 0) return false;
            if (!root.isShowing()) return false;
            SwingUtilities.invokeLater(this::sendEditedRequest);
            return true;
        });
    }

    private static void disableInputMethods(Component c) {
        if (c instanceof JTextComponent) {
            ((JTextComponent) c).enableInputMethods(false);
        }
        if (c instanceof Container) {
            for (Component child : ((Container) c).getComponents()) {
                disableInputMethods(child);
            }
        }
    }

    /** All currently selected rows (in view order), skipping nulls. Empty if nothing is selected. */
    private List<HttpRequestResponse> selectedRows() {
        int[] viewRows = table.getSelectedRows();
        List<HttpRequestResponse> out = new ArrayList<>(viewRows.length);
        for (int vr : viewRows) {
            Row row = model.rowAt(table.convertRowIndexToModel(vr));
            if (row != null && row.rr != null) out.add(row.rr);
        }
        return out;
    }

    /** Sends each selected request to a new Repeater tab, named by its method + path. */
    private void sendSelectedToRepeater() {
        List<HttpRequestResponse> sel = selectedRows();
        if (sel.isEmpty()) { status.setText("Select one or more requests first."); return; }
        int sent = 0;
        try {
            for (HttpRequestResponse rr : sel) {
                HttpRequest req = rr.request();
                if (req == null) continue;
                api.repeater().sendToRepeater(req, repeaterCaption(req));
                sent++;
            }
            status.setText("Sent " + sent + " request(s) to Repeater.");
            log("Sent " + sent + " request(s) to Repeater.");
        } catch (RuntimeException ex) {
            api.logging().logToError("[burp-dedupe] send-to-Repeater failed: " + ex);
            status.setText("Sent " + sent + " then failed: " + ex.getMessage());
            log("Send to Repeater failed after " + sent + ": " + ex.getMessage());
        }
    }

    /** Repeater tab caption from the request, e.g. {@code "GET /test/lasd/something/234"}. */
    private static String repeaterCaption(HttpRequest req) {
        String caption = (safe(req::method) + " " + safe(req::path)).trim();
        if (caption.isEmpty()) return "dedupe";
        return caption.length() > 80 ? caption.substring(0, 80) : caption;
    }

    private JPopupMenu buildTablePopup() {
        JPopupMenu popup = new JPopupMenu();

        JMenuItem repeaterItem = new JMenuItem("Send to Repeater");
        repeaterItem.addActionListener(e -> sendSelectedToRepeater());
        popup.add(repeaterItem);

        JMenuItem shareItem = new JMenuItem("Share");
        shareItem.addActionListener(e -> {
            List<HttpRequestResponse> sel = selectedRows();
            if (sel.isEmpty()) { status.setText("Select a request first."); return; }
            HttpRequestResponse rr = sel.get(0);
            if (rr == null || rr.request() == null) return;
            BiConsumer<HttpRequestResponse, String> handler = shareHandler;
            if (handler != null) {
                String caption = safeReqLine(rr.request());
                handler.accept(rr, caption);
                status.setText("Shared: " + caption);
            } else {
                status.setText("No Live Share — open the Dedupe Share tab first.");
            }
        });
        popup.add(shareItem);

        popup.add(new JSeparator());

        JMenuItem removeHostFromScope = new JMenuItem("Remove host from scope");
        removeHostFromScope.addActionListener(e -> removeSelectedFromScope(true));
        popup.add(removeHostFromScope);

        JMenuItem removePathFromScope = new JMenuItem("Remove path from scope");
        removePathFromScope.addActionListener(e -> removeSelectedFromScope(false));
        popup.add(removePathFromScope);

        return popup;
    }

    private void removeSelectedFromScope(boolean hostOnly) {
        List<HttpRequestResponse> sel = selectedRows();
        if (sel.isEmpty()) { status.setText("Select one or more requests first."); return; }

        java.util.LinkedHashSet<String> urls = new java.util.LinkedHashSet<>();
        for (HttpRequestResponse rr : sel) {
            if (rr == null || rr.request() == null) continue;
            String scopeUrl = DedupeContextMenu.scopeUrlFor(rr.request(), hostOnly);
            if (scopeUrl != null) urls.add(scopeUrl);
        }
        if (urls.isEmpty()) return;

        String label = hostOnly ? "host(s)" : "path prefix(es)";
        int answer = JOptionPane.showConfirmDialog(table,
                "Exclude the following " + label + " from Target scope?\n\n"
                        + String.join("\n", urls),
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
        status.setText("Excluded " + done + " " + label + " from scope.");
        api.logging().logToOutput("[burp-dedupe] excluded " + done + " " + label + " from scope.");
    }

    /** Saves all selected requests (and their responses) into one .http file the user chooses. */
    private void saveSelectedRequests() {
        List<HttpRequestResponse> sel = selectedRows();
        if (sel.isEmpty()) { status.setText("Select one or more requests first."); return; }

        Preferences prefs = api.persistence().preferences();
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save " + sel.size() + " request(s) to one .http file");
        chooser.setCurrentDirectory(new File(System.getProperty("user.home", ".")));
        String defName = sel.size() == 1 ? suggestFileName(sel.get(0).request()) : "requests-" + sel.size() + ".http";
        chooser.setSelectedFile(new File(defName));

        // Option (remembered): write each response as body-only pretty JSON instead of the full raw response.
        JCheckBox prettyBody = new JCheckBox("Responses: body only, pretty JSON",
                boolDefault(prefs.getBoolean(PREF_SAVE_PRETTY_BODY), false));
        prettyBody.setToolTipText("Save each response as just its body, with JSON XSSI guards stripped and the "
                + "JSON pretty-printed (headers omitted) — cleaner for AI. Off = the full raw response.");
        chooser.setAccessory(prettyBody);

        if (chooser.showSaveDialog(table) != JFileChooser.APPROVE_OPTION) return;
        boolean bodyOnly = prettyBody.isSelected();
        prefs.setBoolean(PREF_SAVE_PRETTY_BODY, bodyOnly);

        File target = chooser.getSelectedFile();
        try {
            Files.writeString(target.toPath(),
                    "# burp-dedupe — " + sel.size() + " saved request(s) for AI"
                            + (bodyOnly ? " (responses: body only, pretty JSON)" : "") + "\n" + AI_PROTOCOL + "\n"
                            + buildHttpDump(sel, bodyOnly), StandardCharsets.UTF_8);
            status.setText("Saved " + sel.size() + " request(s) to " + target.getAbsolutePath());
            api.logging().logToOutput("[burp-dedupe] saved " + sel.size() + " request(s) to " + target.getAbsolutePath());
            log("Saved " + sel.size() + " request(s) to " + target.getName());
        } catch (IOException ex) {
            api.logging().logToError("[burp-dedupe] save requests failed: " + ex);
            status.setText("Save failed: " + ex.getMessage());
            log("Save failed: " + ex.getMessage());
        }
    }

    // ── Magic Cookie: reissue the selection with a swapped-in auth set ────────

    private static final String PREF_MAGIC_COOKIE = "burp-dedupe.magic-cookie.headers";

    /** Remembers the Save-for-AI "body only, pretty JSON" checkbox across saves/restarts. */
    private static final String PREF_SAVE_PRETTY_BODY = "burp-dedupe.save.pretty-body-only";

    /** Shown until an auth set is saved. Parses to zero headers (every line is a comment). */
    private static final String DEFAULT_MAGIC_HINT =
            "# Paste the auth headers to send with — one per line, as  Name: value\n"
          + "# They replace the request's Cookie / Authorization (and any header you list);\n"
          + "# everything else is sent unchanged. Lines starting with # are ignored.\n"
          + "#\n"
          + "# Cookie: session=...\n"
          + "# Authorization: Bearer ...\n";

    /**
     * Opens the Magic Cookie editor for the current selection. The user supplies a set of auth
     * headers (remembered across windows/restarts via Montoya preferences); on send, each selected
     * request is reissued with that auth swapped in — see {@link #applyMagicCookie} — and the
     * results open in their own window so original vs. swapped-identity responses can be compared.
     */
    private void openMagicCookieDialog() {
        List<HttpRequestResponse> sel = selectedRows();
        if (sel.isEmpty()) { status.setText("Select one or more requests first."); return; }

        Preferences prefs = api.persistence().preferences();
        String saved = prefs.getString(PREF_MAGIC_COOKIE);

        JTextArea area = new JTextArea(saved == null || saved.isBlank() ? DEFAULT_MAGIC_HINT : saved, 11, 52);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        area.setLineWrap(false);

        JLabel help = new JLabel("<html>One header per line — <b>Name: value</b>. These replace the "
                + "request's <b>Cookie</b> and <b>Authorization</b> (and any header you list); everything "
                + "else is sent unchanged.</html>");
        help.setBorder(BorderFactory.createEmptyBorder(0, 0, 6, 0));

        JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(table),
                "Magic Cookie — replace auth, then send");
        dialog.setModal(true);

        JButton send = new JButton("Send " + sel.size() + " request(s)");
        JButton cancel = new JButton("Cancel");
        cancel.addActionListener(ev -> dialog.dispose());
        send.addActionListener(ev -> {
            List<HttpHeader> headers = parseHeaders(area.getText());
            if (headers.isEmpty()) {
                JOptionPane.showMessageDialog(dialog, "Enter at least one auth header (Name: value).",
                        "Magic Cookie", JOptionPane.WARNING_MESSAGE);
                return;
            }
            prefs.setString(PREF_MAGIC_COOKIE, area.getText());
            dialog.dispose();
            sendWithMagicCookie(sel, headers);
        });

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        buttons.add(cancel);
        buttons.add(send);

        JPanel panel = new JPanel(new BorderLayout(0, 6));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        panel.add(help, BorderLayout.NORTH);
        panel.add(new JScrollPane(area), BorderLayout.CENTER);
        panel.add(buttons, BorderLayout.SOUTH);

        dialog.setContentPane(panel);
        dialog.getRootPane().setDefaultButton(send);
        api.userInterface().applyThemeToComponent(dialog.getRootPane());
        dialog.pack();
        dialog.setLocationRelativeTo(table);
        dialog.setVisible(true);
    }

    private void sendWithMagicCookie(List<HttpRequestResponse> selected, List<HttpHeader> headers) {
        StringBuilder names = new StringBuilder();
        for (HttpHeader h : headers) names.append(names.length() == 0 ? "" : ", ").append(h.name());
        streamReissue(selected, "Magic Cookie results",
                req -> applyMagicCookie(req, headers),
                "Magic Cookie — swapping auth (" + names + ") into " + selected.size() + " request(s)");
    }

    /**
     * Shared engine for the "reissue the selection with a per-request transform, stream results
     * live" actions (Magic Cookie, Match &amp; Replace). The results window opens <em>immediately</em>
     * (empty); each response is appended to its table as it returns, rather than all at once when the
     * batch finishes.
     *
     * <p>Requests go out via Burp's HTTP client ({@code api.http().sendRequest}), so they appear in
     * Logger, not Proxy history.
     */
    private void streamReissue(List<HttpRequestResponse> selected, String resultTitle,
                               UnaryOperator<HttpRequest> transform, String intro) {
        List<HttpRequestResponse> snapshot = new ArrayList<>(selected);
        status.setText(resultTitle + ": sending " + snapshot.size() + " request(s)…");

        // Open the live results window now (on the EDT); the worker feeds rows + log lines in live.
        UniqueRequestsViewer results = new UniqueRequestsViewer(api, new ArrayList<>(), resultTitle);
        results.log(intro);

        Thread t = new Thread(() -> {
            int sent = 0, failed = 0, skipped = 0;
            for (HttpRequestResponse rr : snapshot) {
                HttpRequest req = rr == null ? null : rr.request();
                if (req == null) { failed++; continue; }
                try {
                    // A transform that returns null means "nothing to change here" — e.g. the match
                    // id isn't in this request — so we don't reissue it. Only requests that actually
                    // changed are sent and shown.
                    HttpRequest modified = transform.apply(req);
                    if (modified == null) {
                        skipped++;
                    } else {
                        HttpRequestResponse out = api.http().sendRequest(modified);
                        results.log(logLine(modified, out));
                        SwingUtilities.invokeLater(() -> results.addResult(out)); // live: append as it lands
                        sent++;
                    }
                } catch (RuntimeException ex) {
                    results.log("ERROR  " + safeReqLine(req) + " — " + ex.getMessage());
                    api.logging().logToError("[burp-dedupe] " + resultTitle + " send failed: " + ex);
                    failed++;
                }
                final int s = sent, f = failed, sk = skipped;
                SwingUtilities.invokeLater(() -> status.setText(resultTitle + ": sent " + s
                        + (sk > 0 ? ", " + sk + " skipped" : "") + (f > 0 ? ", " + f + " failed" : "")
                        + " of " + snapshot.size() + "…"));
            }
            final int s = sent, f = failed, sk = skipped;
            results.log("done — sent " + s + (sk > 0 ? ", " + sk + " skipped (no match)" : "")
                    + (f > 0 ? ", " + f + " failed" : ""));
            SwingUtilities.invokeLater(() -> {
                status.setText(resultTitle + ": sent " + s + (sk > 0 ? ", " + sk + " skipped" : "")
                        + (f > 0 ? ", " + f + " failed" : "") + ".");
                api.logging().logToOutput("[burp-dedupe] " + resultTitle + " — sent " + s
                        + " skipped " + sk + " failed " + f);
            });
        }, "burp-dedupe-reissue");
        t.setDaemon(true);
        t.start();
    }

    /** One output line: the (possibly modified) request line, then the response status + length. */
    private static String logLine(HttpRequest req, HttpRequestResponse out) {
        String resp = (out != null && out.hasResponse() && out.response() != null)
                ? out.response().statusCode() + "  " + out.response().body().length() + "b"
                : "(no response)";
        return safeReqLine(req) + "   ←   " + resp;
    }

    private static String safeReqLine(HttpRequest req) {
        return (safe(req::method) + " " + safe(req::path)).trim();
    }

    /**
     * Returns {@code req} with its auth replaced by {@code headers}: the standard credential
     * carriers (Cookie, Authorization) and any header named in {@code headers} are removed first,
     * then the supplied headers are added — so the request goes out with only those credentials.
     * Method, path, body and every other header are left untouched.
     */
    private static HttpRequest applyMagicCookie(HttpRequest req, List<HttpHeader> headers) {
        Set<String> strip = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        strip.add("Cookie");
        strip.add("Authorization");
        for (HttpHeader h : headers) strip.add(h.name());

        HttpRequest out = req;
        for (String name : strip) {
            if (out.hasHeader(name)) out = out.withRemovedHeader(name);
        }
        for (HttpHeader h : headers) {
            out = out.withAddedHeader(h.name(), h.value());
        }
        return out;
    }

    /** Parses {@code Name: value} lines into headers (order preserved); blanks and #-comments skipped. */
    private static List<HttpHeader> parseHeaders(String text) {
        List<HttpHeader> out = new ArrayList<>();
        if (text == null) return out;
        for (String raw : text.split("\\R")) {
            String line = raw.strip();
            if (line.isEmpty() || line.startsWith("#")) continue;
            int colon = line.indexOf(':');
            if (colon <= 0) continue;                 // need a name before the colon
            String name = line.substring(0, colon).strip();
            String value = line.substring(colon + 1).strip();
            if (!name.isEmpty()) out.add(HttpHeader.httpHeader(name, value));
        }
        return out;
    }

    // ── Match & Replace (IDOR/BOLA): swap an id/token in path/body, then reissue ──

    private static final String PREF_MR_MATCH   = "burp-dedupe.match-replace.match";
    private static final String PREF_MR_REPLACE = "burp-dedupe.match-replace.replace";
    private static final String PREF_MR_PATH    = "burp-dedupe.match-replace.path";
    private static final String PREF_MR_BODY    = "burp-dedupe.match-replace.body";
    private static final String PREF_MR_REGEX   = "burp-dedupe.match-replace.regex";

    /**
     * Opens the Match &amp; Replace editor for the current selection — built for IDOR/BOLA: enter the
     * object id (or any token) to find and what to swap it for, choose whether to apply it to the
     * <b>path/query</b>, the <b>body</b>, or both, then reissue. Each reissued request streams into a
     * live results window (table + log) so an unexpected {@code 200} stands out. Settings are
     * remembered across windows/restarts via Montoya preferences.
     */
    private void openMatchReplaceDialog() {
        List<HttpRequestResponse> sel = selectedRows();
        if (sel.isEmpty()) { status.setText("Select one or more requests first."); return; }

        Preferences prefs = api.persistence().preferences();
        JTextField matchField = new JTextField(orEmpty(prefs.getString(PREF_MR_MATCH)), 22);
        JTextField replaceField = new JTextField(orEmpty(prefs.getString(PREF_MR_REPLACE)), 22);
        JCheckBox cbPath = new JCheckBox("Path / query", boolDefault(prefs.getBoolean(PREF_MR_PATH), true));
        JCheckBox cbBody = new JCheckBox("Body", boolDefault(prefs.getBoolean(PREF_MR_BODY), true));
        JCheckBox cbRegex = new JCheckBox("regex", boolDefault(prefs.getBoolean(PREF_MR_REGEX), false));

        JLabel help = new JLabel("<html>For <b>IDOR / BOLA</b>: replace an object id (or any token) in the "
                + "request's <b>path/query</b>, <b>body</b>, or both, then reissue. <b>Only requests that "
                + "actually contain the match are sent</b> (the rest are skipped); within each, everything "
                + "but the matched value is left unchanged. Watch the results for a <b>200</b> where another "
                + "identity's value should be denied.</html>");
        help.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0));

        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(2, 2, 2, 2);
        g.anchor = GridBagConstraints.WEST;
        g.gridx = 0; g.gridy = 0; form.add(new JLabel("Match:"), g);
        g.gridx = 1; g.weightx = 1; g.fill = GridBagConstraints.HORIZONTAL; form.add(matchField, g);
        g.gridx = 0; g.gridy = 1; g.weightx = 0; g.fill = GridBagConstraints.NONE; form.add(new JLabel("Replace:"), g);
        g.gridx = 1; g.weightx = 1; g.fill = GridBagConstraints.HORIZONTAL; form.add(replaceField, g);
        g.gridx = 0; g.gridy = 2; g.weightx = 0; g.fill = GridBagConstraints.NONE; form.add(new JLabel("Apply to:"), g);
        JPanel scope = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        scope.add(cbPath); scope.add(cbBody); scope.add(cbRegex);
        g.gridx = 1; form.add(scope, g);

        JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(table), "Match & Replace — IDOR");
        dialog.setModal(false);

        JButton send = new JButton("Replace & send");
        JButton cancel = new JButton("Cancel");
        cancel.addActionListener(ev -> dialog.dispose());
        send.addActionListener(ev -> {
            List<HttpRequestResponse> currentSel = selectedRows();
            if (currentSel.isEmpty()) { warn(dialog, "Select one or more requests first."); return; }
            String match = matchField.getText();
            if (match == null || match.isEmpty()) { warn(dialog, "Enter the text to match."); return; }
            boolean inPath = cbPath.isSelected();
            boolean inBody = cbBody.isSelected();
            if (!inPath && !inBody) { warn(dialog, "Pick at least one of Path/query or Body."); return; }
            boolean regex = cbRegex.isSelected();
            if (regex) {
                try { Pattern.compile(match); }
                catch (PatternSyntaxException ex) { warn(dialog, "Invalid regex: " + ex.getMessage()); return; }
            }
            String replace = replaceField.getText() == null ? "" : replaceField.getText();

            prefs.setString(PREF_MR_MATCH, match);
            prefs.setString(PREF_MR_REPLACE, replace);
            prefs.setBoolean(PREF_MR_PATH, inPath);
            prefs.setBoolean(PREF_MR_BODY, inBody);
            prefs.setBoolean(PREF_MR_REGEX, regex);

            String scopeLabel = (inPath && inBody) ? "path+body" : inPath ? "path/query" : "body";
            streamReissue(currentSel, "Match & Replace results",
                    req -> applyMatchReplace(req, match, replace, inPath, inBody, regex),
                    "Match & Replace — \"" + match + "\" -> \"" + replace + "\" in " + scopeLabel
                            + (regex ? " (regex)" : "") + " across " + currentSel.size() + " request(s)");
        });

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        buttons.add(cancel);
        buttons.add(send);

        JPanel panel = new JPanel(new BorderLayout(0, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        panel.add(help, BorderLayout.NORTH);
        panel.add(form, BorderLayout.CENTER);
        panel.add(buttons, BorderLayout.SOUTH);

        dialog.setContentPane(panel);
        dialog.getRootPane().setDefaultButton(send);
        api.userInterface().applyThemeToComponent(dialog.getRootPane());
        dialog.pack();
        dialog.setLocationRelativeTo(table);
        dialog.setVisible(true);
    }

    /**
     * Returns {@code req} with {@code match}→{@code replace} applied to the selected parts: the
     * path (which in Montoya includes the query string) and/or the body. Literal by default, or
     * regex when {@code regex} is set; {@link HttpRequest#withBody(String)} refreshes Content-Length.
     *
     * <p>Returns {@code null} if the match wasn't present in any selected part — i.e. nothing
     * changed. {@link #streamReissue} skips those, so only the requests that actually carried the id
     * (and therefore had it swapped) are reissued.
     */
    private static HttpRequest applyMatchReplace(HttpRequest req, String match, String replace,
                                                 boolean inPath, boolean inBody, boolean regex) {
        HttpRequest out = req;
        boolean changed = false;
        if (inPath) {
            String p = req.path();
            if (p != null && !p.isEmpty()) {
                String np = regex ? p.replaceAll(match, replace) : p.replace(match, replace);
                if (!np.equals(p)) { out = out.withPath(np); changed = true; }
            }
        }
        if (inBody) {
            String b = req.bodyToString();
            if (b != null && !b.isEmpty()) {
                String nb = regex ? b.replaceAll(match, replace) : b.replace(match, replace);
                if (!nb.equals(b)) { out = out.withBody(nb); changed = true; }
            }
        }
        return changed ? out : null; // null → match absent here; streamReissue won't reissue it
    }

    private static String orEmpty(String s) { return s == null ? "" : s; }

    private static boolean boolDefault(Boolean b, boolean def) { return b == null ? def : b; }

    private static void warn(Component parent, String msg) {
        JOptionPane.showMessageDialog(parent, msg, "Match & Replace", JOptionPane.WARNING_MESSAGE);
    }

    /** Builds the multi-request {@code .http} dump (each request + response in a ####-delimited section). */
    private static String buildHttpDump(List<HttpRequestResponse> rrs) {
        return buildHttpDump(rrs, false);
    }

    /**
     * Builds the multi-request {@code .http} dump (each request + response in a ####-delimited section,
     * each prefixed with its case manifest). When {@code prettyBodyOnlyResponses} is set, every response
     * is written as just its body — XSSI guards stripped and JSON pretty-printed — instead of the full
     * raw response, which is cleaner for an AI to read.
     */
    private static String buildHttpDump(List<HttpRequestResponse> rrs, boolean prettyBodyOnlyResponses) {
        StringBuilder sb = new StringBuilder();
        int n = 0;
        for (HttpRequestResponse rr : rrs) {
            if (rr == null || rr.request() == null) continue;
            HttpRequest req = rr.request();
            n++;
            sb.append("######################## #").append(n).append("  ")
                    .append(safe(req::method)).append(' ').append(safe(req::url));
            if (rr.hasResponse() && rr.response() != null) {
                sb.append("  -> ").append(safe(() -> Short.toString(rr.response().statusCode())));
            }
            sb.append(" ########################\n");
            sb.append(caseManifest(req, rr));
            sb.append("===== REQUEST =====\n").append(safe(() -> req.toByteArray().toString()));
            if (rr.hasResponse() && rr.response() != null) {
                if (prettyBodyOnlyResponses) {
                    sb.append("\n\n===== RESPONSE (body only, pretty JSON) =====\n")
                            .append(safe(() -> JsonPretty.prettyBody(rr.response().bodyToString())));
                } else {
                    sb.append("\n\n===== RESPONSE =====\n").append(safe(() -> rr.response().toByteArray().toString()));
                }
            }
            sb.append("\n\n");
        }
        return sb.toString();
    }

    // ── Case manifest: a per-request "case file" header for AI/agent consumption ──
    //    (Five-field format suggested by Timur Yessenov — see README Acknowledgements.)

    /** Request-body length above which the replay curl drops the inline body, to keep the manifest readable. */
    private static final int CURL_BODY_CAP = 4_000;

    /**
     * Prepended to every export file: each case carries a manifest, and the agent must read it and
     * explain the risk before mutating or sending the payload. Makes the discipline un-skippable.
     */
    private static final String AI_PROTOCOL =
            "# Each case below carries a CASE MANIFEST (source request, identity role, why it's unique,\n"
          + "# a replay command, and the expected safe failure). AI/agent: read a case's manifest and\n"
          + "# explain its risk BEFORE you modify or send its payload. Replay under a different identity\n"
          + "# expecting denial (401/403/404); an authorized-looking 200 for another identity's data is\n"
          + "# the finding.\n";

    /**
     * Builds the per-case manifest block (Timur Yessenov's idea): the five fields that turn a bare
     * request into a self-contained case file — source request, identity role, why it's unique, a
     * replay command, and the expected safe failure (the IDOR/BOLA oracle). Emitted as {@code #}-comment
     * lines so it rides in front of every block without being mistaken for the request itself.
     */
    private static String caseManifest(HttpRequest req, HttpRequestResponse rr) {
        String notes = notesText(rr);
        String role = resolveRole(req, notes);                 // attacker / victim / custom / null
        String port = firstGroup(notes, "port\\s+(\\d+)");
        boolean fromHeader = headerVal(req, "X-AI-Use") != null;

        String identity = role == null
                ? "unknown — no X-AI-Use header or [attacker]/[victim] tag"
                : role + "  (" + (fromHeader ? "X-AI-Use: " + role : "tagged [" + role + "]")
                        + (port != null ? ", proxy listener port " + port : "") + ")";

        String origStatus;
        try {
            origStatus = rr.hasResponse() && rr.response() != null
                    ? "original response " + rr.response().statusCode()
                    : "no original response captured";
        } catch (RuntimeException e) {
            origStatus = "original response unknown";
        }
        String oracle = role != null
                ? origStatus + "; replayed under a DIFFERENT identity this should be DENIED — expect "
                        + "401/403/404 (or an owner-scoped/empty result). A 200 returning the other "
                        + "identity's data is the finding."
                : origStatus + "; if this reaches another user's/object's data, a cross-identity replay "
                        + "should be denied (401/403/404). An authorized-looking 200 for a resource you "
                        + "shouldn't reach is the finding.";

        return "# --- CASE MANIFEST (read before touching payloads) ------------------------\n"
             + "# 1. Source request : " + safe(req::method) + " " + safe(req::url) + "\n"
             + "# 2. Identity role  : " + identity + "\n"
             + "# 3. Why unique     : " + whyUnique(notes) + "\n"
             + "# 4. Replay command : " + curlFor(req) + "\n"
             + "# 5. Expected safe  : " + oracle + "\n"
             + "# --------------------------------------------------------------------------\n";
    }

    /** Plain-language "why this earns its own case file", read from the dedupe verdict in the Notes. */
    private static String whyUnique(String notes) {
        String low = notes == null ? "" : notes.toLowerCase(Locale.ROOT);
        if (low.contains("unique")) {
            return "[DEDUPE] UNIQUE — first request with this signature (method + host + path + sorted "
                    + "param names + status, per the active preset); its duplicates were folded out.";
        }
        if (low.contains("dupe")) {
            return notes.trim() + " — a duplicate of an earlier request (in the export because it was selected).";
        }
        return "reissued/derived request (e.g. a Magic Cookie / Match & Replace result) — not a fresh dedupe verdict.";
    }

    /** A runnable {@code curl} replay of {@code req} (auth and body included); body dropped past {@link #CURL_BODY_CAP}. */
    private static String curlFor(HttpRequest req) {
        if (req == null) return "(no request)";
        StringBuilder sb = new StringBuilder(256);
        sb.append("curl -isSk -X ").append(safe(req::method)).append(' ').append(sq(safe(req::url)));
        try {
            for (HttpHeader h : req.headers()) {
                String name = h.name();
                if (name == null || name.isEmpty() || name.equalsIgnoreCase("Content-Length")) continue;
                sb.append(" -H ").append(sq(name + ": " + safe(h::value)));
            }
        } catch (RuntimeException ignored) {
            // headers unavailable — the curl still carries method/url
        }
        String body = safe(req::bodyToString);
        if (!body.isEmpty()) {
            if (body.length() > CURL_BODY_CAP) {
                sb.append("   # + ").append(body.length()).append("-byte body omitted — see the REQUEST block below");
            } else {
                sb.append(" --data-raw ").append(sq(body));
            }
        }
        return sb.toString();
    }

    /** Identity role: the {@code X-AI-Use} header if present, else the {@code [attacker]/[victim]} note tag, else null. */
    private static String resolveRole(HttpRequest req, String notes) {
        String hdr = headerVal(req, "X-AI-Use");
        if (hdr != null && !hdr.isBlank()) return hdr.trim().toLowerCase(Locale.ROOT);
        return noteRole(notes);
    }

    private static String noteRole(String notes) {
        if (notes == null) return null;
        String low = notes.toLowerCase(Locale.ROOT);
        if (low.contains("[attacker]")) return "attacker";
        if (low.contains("[victim]")) return "victim";
        return null;
    }

    /** First value of header {@code name} (case-insensitive) on {@code req}, or null — via {@code headers()} so it can't NPE on a missing accessor. */
    private static String headerVal(HttpRequest req, String name) {
        try {
            if (req == null) return null;
            for (HttpHeader h : req.headers()) {
                if (h.name() != null && h.name().equalsIgnoreCase(name)) return h.value();
            }
        } catch (RuntimeException ignored) {
            // no headers — treat as absent
        }
        return null;
    }

    /** First capturing group of {@code regex} in {@code s}, or null. */
    private static String firstGroup(String s, String regex) {
        if (s == null) return null;
        try {
            var m = Pattern.compile(regex).matcher(s);
            return m.find() ? m.group(1) : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** The row's Notes text (verdict + identity tag), null-safe. */
    private static String notesText(HttpRequestResponse rr) {
        try {
            Annotations a = rr == null ? null : rr.annotations();
            return a != null && a.hasNotes() && a.notes() != null ? a.notes() : "";
        } catch (RuntimeException e) {
            return "";
        }
    }

    /** Single-quotes a string for safe inclusion in a shell (curl) command. */
    private static String sq(String s) {
        if (s == null) return "''";
        return "'" + s.replace("'", "'\\''") + "'";
    }

    // ── Live export: mirror the current selection to ~/.burp-dedupe/<project>/selection.http ──

    /** (Re)schedules a debounced export so rapid selection changes coalesce into a single write. */
    private void scheduleLiveExport() {
        if (!cbLiveExport.isSelected()) return;
        if (exportDebounce == null) {
            exportDebounce = new Timer(300, e -> liveExportNow());
            exportDebounce.setRepeats(false);
        }
        exportDebounce.restart();
    }

    /**
     * Writes two files in the project's export dir (off the EDT): {@code live-unique.http} = every
     * collected unique request, and {@code selection.http} = the current selection.
     */
    private void liveExportNow() {
        if (!cbLiveExport.isSelected()) return;
        List<HttpRequestResponse> all = model.requests();         // every collected unique (EDT)
        List<HttpRequestResponse> sel = selectedRows();           // current selection (EDT)
        Path dir = exportDir();
        String project = exportProjectName();
        String ts = java.time.LocalTime.now().withNano(0).toString();
        Thread t = new Thread(() -> {
            try {
                synchronized (EXPORT_LOCK) {
                    Files.createDirectories(dir);
                    writeExport(dir.resolve("live-unique.http"),
                            "# burp-dedupe live export — project: " + project + " — " + ts + " — "
                                    + all.size() + " unique request(s)\n" + AI_PROTOCOL + "\n", all, "no requests yet");
                    writeExport(dir.resolve("selection.http"),
                            "# burp-dedupe selection — project: " + project + " — " + ts + " — "
                                    + sel.size() + " request(s)\n" + AI_PROTOCOL + "\n", sel, "nothing selected");
                }
                SwingUtilities.invokeLater(() -> status.setText(
                        "Live-exported " + all.size() + " unique / " + sel.size() + " selected to " + dir));
            } catch (IOException | RuntimeException ex) {
                api.logging().logToError("[burp-dedupe] live export failed: " + ex);
            }
        }, "burp-dedupe-live-export");
        t.setDaemon(true);
        t.start();
    }

    private static void writeExport(Path file, String header, List<HttpRequestResponse> rrs, String emptyNote)
            throws IOException {
        String content = rrs.isEmpty() ? header + "# (" + emptyNote + ")\n" : header + buildHttpDump(rrs);
        Files.writeString(file, content, StandardCharsets.UTF_8);
    }

    /** {@code ~/.burp-dedupe/<sanitized-project-name>/} — holds live-unique.http and selection.http. */
    private Path exportDir() {
        return Path.of(System.getProperty("user.home", "."), ".burp-dedupe", exportProjectName());
    }

    /** The current Burp project name, sanitised for use as a folder (fallback {@code "default"}). */
    private String exportProjectName() {
        String name;
        try {
            name = api.project().name();
        } catch (RuntimeException e) {
            name = null;
        }
        if (name == null || name.isBlank()) return "default";
        String safe = name.trim().replaceAll("[^a-zA-Z0-9._-]", "_");
        return safe.isBlank() ? "default" : safe;
    }

    /** A filesystem-safe default filename derived from the request's method/host/path. */
    private static String suggestFileName(HttpRequest req) {
        if (req == null) return "request.http";
        String method = safe(req::method);
        String host = safe(() -> req.httpService() != null ? req.httpService().host() : "");
        String path = safe(req::path);
        String base = (method + "_" + host + path).replaceAll("[^a-zA-Z0-9._-]", "_");
        if (base.length() > 80) base = base.substring(0, 80);
        return (base.isBlank() ? "request" : base) + ".http";
    }

    /** Null/exception-safe String accessor used when precomputing row cells and for status text. */
    private static String safe(java.util.function.Supplier<String> get) {
        try {
            String v = get.get();
            return v == null ? "" : v;
        } catch (RuntimeException e) {
            return "";
        }
    }

    private static void applyColumnWidths(JTable table) {
        int[] widths = {44, 180, 70, 360, 60, 80, 110, 280}; // #, Host, Method, URL, Status, Length, MIME, Notes
        for (int i = 0; i < widths.length && i < table.getColumnCount(); i++) {
            TableColumn col = table.getColumnModel().getColumn(i);
            col.setPreferredWidth(widths[i]);
        }
    }

    /** Tints each row with its Burp highlight colour (black text), like HTTP history. */
    private static final class HighlightRenderer extends DefaultTableCellRenderer {
        private final UniqueTableModel model;

        HighlightRenderer(UniqueTableModel model) { this.model = model; }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (!isSelected) {
                Color bg = awtFor(model.highlightAt(table.convertRowIndexToModel(row)));
                if (bg != null) {
                    c.setBackground(bg);
                    c.setForeground(Color.BLACK);
                } else {
                    c.setBackground(table.getBackground());
                    c.setForeground(table.getForeground());
                }
            }
            return c;
        }
    }

    /** Burp highlight colour -> a light, readable row tint. NONE -> no tint. */
    private static Color awtFor(HighlightColor h) {
        if (h == null) return null;
        return switch (h) {
            case RED     -> new Color(0xFF, 0xC8, 0xC8);
            case ORANGE  -> new Color(0xFF, 0xDD, 0xB0);
            case YELLOW  -> new Color(0xFF, 0xF6, 0xA8);
            case GREEN   -> new Color(0xC6, 0xF2, 0xC6);
            case CYAN    -> new Color(0xBF, 0xF0, 0xF0);
            case BLUE    -> new Color(0xCD, 0xD8, 0xFF);
            case PINK    -> new Color(0xFF, 0xD0, 0xE6);
            case MAGENTA -> new Color(0xF0, 0xC6, 0xF0);
            case GRAY    -> new Color(0xD8, 0xD8, 0xD8);
            case NONE    -> null;
        };
    }

    /** Shared requests (received via Live Share) get this highlight colour in the Dedupe Live table. */
    private static final HighlightColor SHARED_COLOR = HighlightColor.MAGENTA;

    /**
     * One captured row with its display cells, highlight colour and URL precomputed <em>off the EDT</em>
     * (in {@link #of}). The table then paints from plain fields and never parses a Montoya request or
     * response — which is what keeps scrolling and filtering buttery under a fast live feed.
     */
    private static final class Row {
        private static final int MAX_SEARCH_CHARS = 16_000;  // cap the per-row search blob (bounds memory)
        final HttpRequestResponse rr;
        final String[] cells;          // indices 1..7 used; column 0 ("#") is the live row number
        final HighlightColor color;
        final String url;              // cached for the In-scope filter (no per-keystroke re-parse)
        final String search;           // lowercased: columns + full request + some response body
        final boolean shared;          // true if this request arrived via Live Share

        private Row(HttpRequestResponse rr, String[] cells, HighlightColor color, String url, String search, boolean shared) {
            this.rr = rr;
            this.cells = cells;
            this.color = color;
            this.url = url;
            this.search = search;
            this.shared = shared;
        }

        /** Parses everything the table shows (and searches) once, here (call off the EDT for big batches). */
        static Row of(HttpRequestResponse rr) {
            HttpRequest req = rr.request();
            boolean hasResp = rr.hasResponse() && rr.response() != null;
            String[] c = new String[UniqueTableModel.COLS.length];
            c[1] = safe(() -> req != null && req.httpService() != null ? req.httpService().host() : "");
            c[2] = safe(() -> req != null ? req.method() : "");
            c[3] = safe(() -> req != null ? req.path() : "");
            c[4] = safe(() -> hasResp ? Short.toString(rr.response().statusCode()) : "");
            c[5] = safe(() -> hasResp ? Integer.toString(rr.response().body().length()) : "");
            c[6] = safe(() -> hasResp ? mimeOf(rr.response()) : "");
            c[7] = safe(() -> notesOf(rr));
            String url = safe(() -> req != null ? req.url() : "");
            HighlightColor color = colorOf(rr);
            return new Row(rr, c, color, url, buildSearchBlob(rr, req, hasResp, c), color == SHARED_COLOR);
        }

        /**
         * The lowercased text the filter searches: the visible columns plus the <b>full request</b>
         * (request line, headers and body — so path, query and request body all match) and as much of
         * the <b>response body</b> as the {@link #MAX_SEARCH_CHARS} budget allows. Built once, off the EDT.
         */
        private static String buildSearchBlob(HttpRequestResponse rr, HttpRequest req, boolean hasResp, String[] c) {
            StringBuilder sb = new StringBuilder(512);
            for (int i = 1; i < c.length; i++) {
                if (c[i] != null && !c[i].isEmpty()) sb.append(c[i]).append('\n');
            }
            sb.append(safe(() -> req != null ? req.toByteArray().toString() : ""));
            if (hasResp && sb.length() < MAX_SEARCH_CHARS) {
                sb.append('\n').append(safe(() -> rr.response().bodyToString()));
            }
            String blob = sb.length() > MAX_SEARCH_CHARS ? sb.substring(0, MAX_SEARCH_CHARS) : sb.toString();
            return blob.toLowerCase(Locale.ROOT);
        }

        private static String mimeOf(HttpResponse resp) {
            try {
                MimeType m = resp.mimeType();
                return m == null ? "" : m.description();
            } catch (RuntimeException e) {
                return "";
            }
        }

        private static String notesOf(HttpRequestResponse rr) {
            try {
                Annotations a = rr.annotations();
                return a != null && a.hasNotes() && a.notes() != null ? a.notes() : "";
            } catch (RuntimeException e) {
                return "";
            }
        }

        private static HighlightColor colorOf(HttpRequestResponse rr) {
            try {
                Annotations a = rr.annotations();
                HighlightColor h = a == null ? null : a.highlightColor();
                return h == null ? HighlightColor.NONE : h;
            } catch (RuntimeException e) {
                return HighlightColor.NONE;
            }
        }
    }

    /** Burp-history-like columns backed by precomputed {@link Row}s — {@code getValueAt} never parses. */
    private static final class UniqueTableModel extends AbstractTableModel {
        private static final String[] COLS = {"#", "Host", "Method", "URL", "Status", "Length", "MIME", "Notes"};
        private final List<Row> rows = new ArrayList<>();

        Row rowAt(int r) { return r >= 0 && r < rows.size() ? rows.get(r) : null; }

        HighlightColor highlightAt(int modelRow) {
            Row row = rowAt(modelRow);
            return row == null ? HighlightColor.NONE : row.color;
        }

        String urlAt(int modelRow) {
            Row row = rowAt(modelRow);
            return row == null ? null : row.url;
        }

        String searchAt(int modelRow) {
            Row row = rowAt(modelRow);
            return row == null ? null : row.search;
        }

        /** Snapshot of the backing requests (for Save / live export). */
        List<HttpRequestResponse> requests() {
            List<HttpRequestResponse> out = new ArrayList<>(rows.size());
            for (Row r : rows) out.add(r.rr);
            return out;
        }

        void add(Row row) {
            int i = rows.size();
            rows.add(row);
            fireTableRowsInserted(i, i);
        }

        void addAll(List<Row> batch) {
            if (batch.isEmpty()) return;
            int start = rows.size();
            rows.addAll(batch);
            fireTableRowsInserted(start, rows.size() - 1);
        }

        void clear() {
            rows.clear();
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }
        @Override public boolean isCellEditable(int r, int c) { return false; }

        @Override
        public Object getValueAt(int r, int c) {
            if (c == 0) return Integer.toString(r + 1);
            Row row = rowAt(r);
            return row == null ? "" : row.cells[c];
        }
    }
}
