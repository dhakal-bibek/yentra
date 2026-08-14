package yentra.ui;

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
import yentra.core.JsonPretty;
import yentra.proxy.YentraProxyHandler;
import yentra.proxy.UniqueFeed;

import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.InputMap;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JList;
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
import javax.swing.JToggleButton;
import javax.swing.JWindow;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.SwingConstants;
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
import java.awt.Toolkit;
import java.awt.AWTEvent;
import java.awt.KeyboardFocusManager;
import java.awt.event.ActionEvent;
import java.awt.event.KeyAdapter;
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
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Predicate;
import java.util.function.UnaryOperator;
import java.util.function.BiConsumer;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * A standalone window that lists <em>only the unique</em> requests from a selection,
 * styled to mirror Burp's HTTP-history table (same kind of columns, a Notes column
 * carrying our {@code [YENTRA] …} verdict + {@code [attacker]/[victim] port N} tag, and
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
    private final JToggleButton regexChip = new PremiumChip(".* regex", new Color(0x7C, 0x5C, 0xF3));
    private final JToggleButton scopeChip = new PremiumChip("In-scope", new Color(0x12, 0xB7, 0x6A));
    private final JToggleButton sharedChip = new PremiumChip("Shared", new Color(0xF5, 0x9E, 0x0B));
    private final JToggleButton hideOptionsChip = new PremiumChip("Hide HEAD/OPTIONS", new Color(0x99, 0x66, 0xCC));
    private final JLabel status = new JLabel(" ");
    /** Live mode: proxy ids already collected, by either path (so neither push nor poll re-adds one). Concurrent: written from the proxy thread (push) and the poll thread. */
    private final Set<Integer> seenIds = ConcurrentHashMap.newKeySet();
    /** Live mode: cross-path dedup by request identity — guards against push/poll double-add and re-stamps that change the proxy id. */
    private final Set<String> liveKeys = ConcurrentHashMap.newKeySet();
    /** Live mode: ids examined and found NOT unique — skipped on later ticks; cleared periodically for late stamps. Thread-safe (poll + rescan run concurrently). */
    private final Set<Integer> examinedNonUnique = ConcurrentHashMap.newKeySet();
    /** Live mode: highest proxy history id we've scanned — lets incremental polls skip everything below it. */
    private volatile int maxScannedId = -1;
    /** Live mode: set by {@link #resetAllLiveTracking()} so the next poll wipes {@code seenIds}/{@code liveKeys}/
     *  {@code examinedNonUnique}/{@code maxScannedId} and does a full re-scan of proxy history — applied on the
     *  poll thread (race-free) rather than the EDT so an in-flight scan can't re-populate the sets we just wiped. */
    private volatile boolean forceFullRescan = false;
    /**
     * Every active live viewer (the embedded "Yentra Live" tab + any Ctrl+9 pop-ups). "Reset stats" in
     * {@link YentraTab} walks this set so the proxy-history tracking resets everywhere, not just in the engine.
     * Entries are removed on close/unload so pop-ups don't leak.
     */
    private static final Set<UniqueRequestsViewer> LIVE_VIEWERS = ConcurrentHashMap.newKeySet();
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

    /** True only for a transport role allowed to originate shared requests. */
    private static volatile boolean sharingEnabled;

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

    public static void setSharingEnabled(boolean enabled) {
        sharingEnabled = enabled;
    }

    private static final boolean IS_MAC = System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("mac");

    /**
     * Theme-aware colour palette. Detects Burp's dark/light mode once per viewer
     * construction and swaps the active {@link #current} set so every component
     * (panels, table, buttons, chips, palette popup) stays readable in either mode.
     */
    static final class Theme {
        final Color bg, surface, border, accent, accentBg, text, muted;
        final Color send, sendHov, danger, ok, warn;
        final Color disabledFg, dangerPressed, defaultPressed, hoverBorder;
        final Color badgeFg, badgeBg, badgeBorder;
        final Color chipTextOn, chipTextOff;

        private Theme(Color bg, Color surface, Color border, Color accent, Color accentBg,
                      Color text, Color muted, Color send, Color sendHov, Color danger,
                      Color ok, Color warn, Color disabledFg, Color dangerPressed,
                      Color defaultPressed, Color hoverBorder, Color badgeFg, Color badgeBg,
                      Color badgeBorder, Color chipTextOn, Color chipTextOff) {
            this.bg = bg; this.surface = surface; this.border = border;
            this.accent = accent; this.accentBg = accentBg; this.text = text; this.muted = muted;
            this.send = send; this.sendHov = sendHov; this.danger = danger;
            this.ok = ok; this.warn = warn; this.disabledFg = disabledFg;
            this.dangerPressed = dangerPressed; this.defaultPressed = defaultPressed;
            this.hoverBorder = hoverBorder; this.badgeFg = badgeFg;
            this.badgeBg = badgeBg; this.badgeBorder = badgeBorder;
            this.chipTextOn = chipTextOn; this.chipTextOff = chipTextOff;
        }

        static final Theme LIGHT = new Theme(
                new Color(0xF7, 0xF8, 0xFA), new Color(0xFF, 0xFF, 0xFF), new Color(0xE2, 0xE5, 0xEA),
                new Color(0x4A, 0x6C, 0xF7), new Color(0xEE, 0xF1, 0xFE), new Color(0x1A, 0x1D, 0x24),
                new Color(0x88, 0x90, 0x9C), new Color(0x4A, 0x6C, 0xF7), new Color(0x39, 0x56, 0xD8),
                new Color(0xE5, 0x48, 0x4D), new Color(0x12, 0xB7, 0x6A), new Color(0xF5, 0x9E, 0x0B),
                new Color(0xC0, 0xC4, 0xCC), new Color(0xC0, 0x3A, 0x3F), new Color(0xE8, 0xEC, 0xF4),
                new Color(0xC0, 0xCB, 0xF7), new Color(0x6B, 0x7A, 0xF0), new Color(0xF0, 0xF3, 0xFE),
                new Color(0xD8, 0xDF, 0xFE), Color.WHITE, new Color(0x88, 0x90, 0x9C));

        static final Theme DARK = new Theme(
                new Color(0x1E, 0x21, 0x28), new Color(0x28, 0x2C, 0x36), new Color(0x3A, 0x40, 0x4D),
                new Color(0x7B, 0x9A, 0xFA), new Color(0x2A, 0x31, 0x44), new Color(0xE4, 0xE6, 0xEB),
                new Color(0x9B, 0xA1, 0xAD), new Color(0x6B, 0x8A, 0xFA), new Color(0x8A, 0xA2, 0xFB),
                new Color(0xFF, 0x6B, 0x6E), new Color(0x2D, 0xD4, 0xA8), new Color(0xFB, 0xBF, 0x24),
                new Color(0x4A, 0x50, 0x60), new Color(0x9A, 0x2D, 0x32), new Color(0x2A, 0x31, 0x44),
                new Color(0x4A, 0x55, 0x80), new Color(0x8A, 0xA2, 0xFB), new Color(0x2A, 0x31, 0x44),
                new Color(0x3A, 0x40, 0x60), Color.WHITE, new Color(0x9B, 0xA1, 0xAD));

        static Theme current = LIGHT;

        /** Luminance probe — call on a component that had {@code applyThemeToComponent} applied. */
        static boolean isDark(Color bg) {
            if (bg == null) return false;
            return (bg.getRed() * 299 + bg.getGreen() * 587 + bg.getBlue() * 114) / 1000 < 128;
        }
    }

    /** Live export: mirror every collected unique request to a file Claude Code can read. */
    private final JCheckBox cbLiveExport = new JCheckBox("Live export → file", false);
    private Timer exportDebounce;
    private Timer filterDebounce;
    private static final Object EXPORT_LOCK = new Object();

    private final java.util.List<RepeaterEntry> repeaterHistory = new ArrayList<>();
    private int historyPos = -1;
    /**
     * Identifies the request/response currently allowed to own the inline Repeater panes. Selecting
     * another row or starting another send invalidates an older in-flight send, so a slow response
     * cannot unexpectedly replace the newer request's response.
     */
    private final AtomicLong repeaterViewGeneration = new AtomicLong();
    private final JLabel responseInfo = new JLabel(" ");
    private final JLabel resultCounter = new JLabel("");
    private final JButton btnBack = new PremiumButton("◀", "nav");
    private final JButton btnForward = new PremiumButton("▶", "nav");
    private HttpRequest originalRequest;
    private JWindow filterPopup;

    private record RepeaterEntry(HttpRequest request, HttpResponse response, long elapsedMs) {}

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
        // Detect Burp's dark/light theme before building any UI so every colour picks correctly.
        JPanel probe = new JPanel();
        api.userInterface().applyThemeToComponent(probe);
        Theme.current = Theme.isDark(probe.getBackground()) ? Theme.DARK : Theme.LIGHT;
        this.requestEditor = api.userInterface().createHttpRequestEditor(); // editable — inline repeater
        this.responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        watchdogInputMethods();

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

        JPanel responsePanel = new JPanel(new BorderLayout());
        responseInfo.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, Theme.current.border),
                BorderFactory.createEmptyBorder(5, 10, 5, 10)));
        responseInfo.setFont(responseInfo.getFont().deriveFont(Font.BOLD, 12f));
        responseInfo.setForeground(Theme.current.text);
        responseInfo.setBackground(Theme.current.bg);
        responseInfo.setOpaque(true);
        responsePanel.add(responseInfo, BorderLayout.NORTH);
        responsePanel.add(responseEditor.uiComponent(), BorderLayout.CENTER);

        JSplitPane editors = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                requestEditor.uiComponent(), responsePanel);
        editors.setResizeWeight(0.5);
        editors.setBorder(BorderFactory.createEmptyBorder());

        btnBack.setToolTipText("Back (Alt+Left)");
        btnBack.setEnabled(false);
        btnBack.addActionListener(e -> navigateHistory(-1));

        btnForward.setToolTipText("Forward (Alt+Right)");
        btnForward.setEnabled(false);
        btnForward.addActionListener(e -> navigateHistory(1));

        JPanel editorPanel = new JPanel(new BorderLayout());
        editorPanel.setBackground(Theme.current.bg);

        KeyStroke altLeft = KeyStroke.getKeyStroke(KeyEvent.VK_LEFT, KeyEvent.ALT_DOWN_MASK);
        editorPanel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(altLeft, "history-back");
        editorPanel.getActionMap().put("history-back", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) { navigateHistory(-1); }
        });
        KeyStroke altRight = KeyStroke.getKeyStroke(KeyEvent.VK_RIGHT, KeyEvent.ALT_DOWN_MASK);
        editorPanel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(altRight, "history-forward");
        editorPanel.getActionMap().put("history-forward", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) { navigateHistory(1); }
        });

        JButton sendEdited = new PremiumButton("Send ▶", "primary");
        sendEdited.setToolTipText("<html>Send (Cmd+Space / Ctrl+Space).<br>"
                + (!IS_MAC ? "Also: Ctrl+Enter." : "")
                + "</html>");
        sendEdited.addActionListener(e -> sendEditedRequest());

        JButton resetBtn = new PremiumButton("↺ Reset", "default");
        resetBtn.setToolTipText("Reset the request to its original state (before editing).");
        resetBtn.addActionListener(e -> resetRequest());

        JLabel targetLabel = new JLabel("Target: ");
        targetLabel.setFont(targetLabel.getFont().deriveFont(Font.PLAIN, 11f));
        targetLabel.setForeground(Theme.current.muted);

        JLabel shortcutHint = new JLabel("⌘Space / Ctrl+Space");
        shortcutHint.setFont(shortcutHint.getFont().deriveFont(Font.PLAIN, 10f));
        shortcutHint.setForeground(Theme.current.muted);

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 3));
        toolbar.setBackground(Theme.current.bg);
        toolbar.add(btnBack);
        toolbar.add(btnForward);
        toolbar.add(Box.createHorizontalStrut(6));
        toolbar.add(sendEdited);
        toolbar.add(Box.createHorizontalStrut(2));
        toolbar.add(shortcutHint);
        toolbar.add(Box.createHorizontalStrut(10));
        toolbar.add(resetBtn);
        toolbar.add(Box.createHorizontalStrut(10));
        toolbar.add(targetLabel);
        toolbar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, Theme.current.border),
                BorderFactory.createEmptyBorder(3, 6, 3, 6)));

        editorPanel.add(toolbar, BorderLayout.NORTH);
        editorPanel.add(editors, BorderLayout.CENTER);
        installSendKeys(editorPanel);

        table.setRowHeight(28);
        table.setSelectionBackground(Theme.current.accentBg);
        table.setSelectionForeground(Theme.current.text);
        table.setGridColor(Theme.current.border);
        table.setShowGrid(false);
        table.setIntercellSpacing(new java.awt.Dimension(0, 0));
        table.getTableHeader().setFont(table.getTableHeader().getFont().deriveFont(Font.BOLD, 11f));
        table.getTableHeader().setBackground(Theme.current.bg);
        table.getTableHeader().setForeground(Theme.current.muted);
        table.getTableHeader().setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Theme.current.border));

        JSplitPane main = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table), editorPanel);
        main.setResizeWeight(0.35);
        main.setBorder(BorderFactory.createEmptyBorder());
        main.setDividerSize(6);

        status.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, Theme.current.border),
                BorderFactory.createEmptyBorder(5, 12, 5, 12)));
        status.setFont(status.getFont().deriveFont(Font.PLAIN, 11f));
        status.setForeground(Theme.current.muted);
        status.setBackground(Theme.current.bg);
        status.setOpaque(true);

        this.root = new JPanel(new BorderLayout());
        root.setBackground(Theme.current.bg);
        root.add(buildToolbar(), BorderLayout.NORTH);
        root.add(main, BorderLayout.CENTER);
        root.add(status, BorderLayout.SOUTH);

        if (windowed) {
            // Parent pop-up windows to Burp's main frame (BApp Store guideline: SwingUtils.suiteFrame()),
            // as a modeless dialog so they ride with Burp across monitors instead of floating loose.
            java.awt.Frame owner = api.userInterface().swingUtils().suiteFrame();
            this.frame = new JDialog(owner, "Yentra — " + baseTitle + " (" + model.getRowCount() + ")", false);
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
        if (frame != null) frame.setTitle("Yentra — " + baseTitle + " (" + model.getRowCount() + ")");
    }

    private JPanel buildToolbar() {
        JButton repeater = new PremiumButton("Send to Repeater", "default");
        repeater.setToolTipText("Send the selected request(s) to new Repeater tabs (named by method + path).");
        repeater.addActionListener(e -> sendSelectedToRepeater());

        JButton shareBtn = new PremiumButton("Share", "default");
        shareBtn.setToolTipText("<html>Share the selected request with connected peers.<br>"
                + "Open the <b>Yentra Share</b> tab, start a server or connect to a friend first.</html>");
        shareBtn.addActionListener(e -> {
            if (!sharingEnabled) {
                status.setText("Receive-only connection — only the host can share requests.");
                return;
            }
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
                status.setText("No Live Share — open the Yentra Share tab, start a server or connect to a friend.");
            }
        });

        JButton save = new PremiumButton("Save for AI", "default");
        save.setToolTipText("Save the selected request(s) and their responses into one .http file "
                + "for Claude Code / AI to read. Ctrl/Cmd- or Shift-click to select several.");
        save.addActionListener(e -> saveSelectedRequests());

        JButton magic = new PremiumButton("Magic Cookie", "default");
        magic.setToolTipText("Resend the selected request(s) with your configured auth replacing the "
                + "original Cookie / Authorization (and any header you list); everything else unchanged. "
                + "Opens the results in a new window.");
        magic.addActionListener(e -> openMagicCookieDialog());

        JButton matchReplace = new PremiumButton("Match & Replace", "default");
        matchReplace.setToolTipText("IDOR/BOLA: replace an id or token in the path/query, body, headers, "
                + "or any combination, then reissue the selected request(s) — watch the live results for "
                + "an unexpected 200. Tick Headers to re-swap a Magic-Cookie session/token.");
        matchReplace.addActionListener(e -> openMatchReplaceDialog());

        JButton convertBtn = new PremiumButton("JSON Convert Request To", "default");
        convertBtn.setToolTipText("<html>Convert selected JSON-body request to another HTTP method.<br>"
                + "POST/PUT/PATCH → change method only. GET → flatten JSON to query params.<br>"
                + "DELETE → keep body. Auto-sends and shows responses live.</html>");
        convertBtn.addActionListener(e -> {
            JPopupMenu methodMenu = new JPopupMenu();
            for (String m : new String[]{"GET", "POST", "PUT", "PATCH", "DELETE"}) {
                JMenuItem item = new JMenuItem(m);
                item.addActionListener(ev -> convertRequestTo(m));
                methodMenu.add(item);
            }
            methodMenu.addSeparator();
            JMenuItem allItem = new JMenuItem("All (GET+POST+PUT+PATCH+DELETE)");
            allItem.addActionListener(ev -> convertRequestToAll());
            methodMenu.add(allItem);
            methodMenu.show(convertBtn, 0, convertBtn.getHeight());
        });

        JButton respToReqBtn = new PremiumButton("JSON Convert Response To", "default");
        respToReqBtn.setToolTipText("<html>Take the JSON response body and generate a new request from it.<br>"
                + "Reuses the original request's path, host, cookies, and auth headers.<br>"
                + "GET → response JSON flattened to query params. Auto-sends live.</html>");
        respToReqBtn.addActionListener(e -> {
            JPopupMenu methodMenu = new JPopupMenu();
            for (String m : new String[]{"GET", "POST", "PUT", "PATCH", "DELETE"}) {
                JMenuItem item = new JMenuItem(m);
                item.addActionListener(ev -> responseToRequest(m));
                methodMenu.add(item);
            }
            methodMenu.addSeparator();
            JMenuItem allItem = new JMenuItem("All (GET+POST+PUT+PATCH+DELETE)");
            allItem.addActionListener(ev -> responseToRequestAll());
            methodMenu.add(allItem);
            methodMenu.show(respToReqBtn, 0, respToReqBtn.getHeight());
        });

        JButton clear = new PremiumButton("Clear", "danger");
        clear.setToolTipText("Empty this window — clears the collected rows. "
                + "(In the live window, new [YENTRA] UNIQUE requests keep arriving after.)");
        clear.addActionListener(e -> clearView());

        Path exportDir = exportDir();
        cbLiveExport.setToolTipText("<html>Auto-writes to <code>" + exportDir + "</code>:<br>"
                + "• <b>live-unique.http</b> — every unique request, as it arrives<br>"
                + "• <b>selection.http</b> — your current selection, as you change it<br>"
                + "Point Claude Code at either path. On by default in the live window; untick to stop.</html>");
        cbLiveExport.addActionListener(e -> { if (cbLiveExport.isSelected()) scheduleLiveExport(); });
        api.logging().logToOutput("[yentra] live export dir: " + exportDir + " (live-unique.http, selection.http)");

        filterField.setToolTipText("<html><b>Bambda-style filter</b> — prefix tokens + plain text:<br>"
                + "<b>m:GET</b> — method  |  <b>s:200</b> — status  |  <b>h:api</b> — host<br>"
                + "<b>url:/path</b> — URL  |  <b>body:token</b> — resp body  |  <b>req:data</b> — req body<br>"
                + "<b>hdr:Auth</b> — header  |  <b>mime:JSON</b> — MIME  |  <b>len:1024</b> — length<br>"
                + "<b>notes:UNIQUE</b> — notes  |  <b>u:</b> — unique  |  <b>d:</b> — dupe  |  <b>skip:</b> — skip<br>"
                + "<b>r:pattern</b> — regex  |  <b>>399</b> <b><=200</b> — status range<br>"
                + "Plain text → substring across everything. Tokens combine with AND.</html>");
        filterField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { applyFilter(); }
            @Override public void removeUpdate(DocumentEvent e) { applyFilter(); }
            @Override public void changedUpdate(DocumentEvent e) { applyFilter(); }
        });
        filterField.putClientProperty("JTextField.placeholderText", "Search requests…");
        filterField.putClientProperty("JTextField.showClearButton", true);
        installFilterAutocomplete();

        JPanel filterChips = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
        filterChips.setOpaque(false);

        regexChip.setToolTipText("Treat search as regular expression (case-insensitive).");
        regexChip.addItemListener(e -> applyFilter());

        scopeChip.setToolTipText("Show only requests in Target scope.");
        scopeChip.addItemListener(e -> applyFilter());

        sharedChip.setToolTipText("Selected: Live Share requests. Unselected: your local requests.");
        sharedChip.addItemListener(e -> applyFilter());

        hideOptionsChip.setSelected(true);
        hideOptionsChip.setToolTipText("Hide HEAD and OPTIONS requests (CORS preflight + connectivity checks).");
        hideOptionsChip.addItemListener(e -> applyFilter());

        filterChips.add(regexChip);
        filterChips.add(scopeChip);
        filterChips.add(sharedChip);
        filterChips.add(hideOptionsChip);

        resultCounter.setFont(resultCounter.getFont().deriveFont(Font.PLAIN, 11f));
        resultCounter.setForeground(Theme.current.muted);
        resultCounter.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 4));

        JPanel filterBar = new JPanel(new BorderLayout(4, 0));
        filterBar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Theme.current.border, 1, true),
                BorderFactory.createEmptyBorder(3, 10, 3, 6)));
        filterBar.setBackground(Theme.current.surface);
        filterBar.add(filterField, BorderLayout.CENTER);
        JPanel rightSide = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
        rightSide.setOpaque(false);
        rightSide.add(resultCounter);
        rightSide.add(filterChips);
        filterBar.add(rightSide, BorderLayout.EAST);
        filterBar.setPreferredSize(new java.awt.Dimension(500, 36));

        filterField.setBorder(BorderFactory.createEmptyBorder());
        filterField.setFont(filterField.getFont().deriveFont(13f));
        filterField.setBackground(filterBar.getBackground());
        filterField.setForeground(Theme.current.text);

        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 5));
        bar.setBackground(Theme.current.bg);
        bar.add(repeater);
        bar.add(shareBtn);
        bar.add(save);
        bar.add(magic);
        bar.add(matchReplace);
        bar.add(convertBtn);
        bar.add(respToReqBtn);
        bar.add(clear);
        bar.add(cbLiveExport);

        JPanel filterRow = new JPanel(new BorderLayout(8, 0));
        filterRow.setBackground(Theme.current.bg);
        filterRow.setBorder(BorderFactory.createEmptyBorder(2, 0, 2, 0));
        filterRow.add(filterBar, BorderLayout.CENTER);

        JPanel toolbarPanel = new JPanel();
        toolbarPanel.setLayout(new BoxLayout(toolbarPanel, BoxLayout.Y_AXIS));
        toolbarPanel.setBackground(Theme.current.bg);
        toolbarPanel.add(bar);
        toolbarPanel.add(filterRow);
        return toolbarPanel;
    }

    private static final class PremiumChip extends JToggleButton {
        private final Color onColor;
        private boolean hover;
        private int hovered = 0;

        PremiumChip(String text, Color selectedColor) {
            super(text);
            this.onColor = selectedColor;
            setFont(getFont().deriveFont(Font.PLAIN, 11f));
            setMargin(new java.awt.Insets(0, 0, 0, 0));
            setFocusPainted(false);
            setBorderPainted(false);
            setContentAreaFilled(false);
            setOpaque(false);
            setCursor(new java.awt.Cursor(java.awt.Cursor.HAND_CURSOR));
            addMouseListener(new java.awt.event.MouseAdapter() {
                @Override public void mouseEntered(java.awt.event.MouseEvent e) { hover = true; repaint(); }
                @Override public void mouseExited(java.awt.event.MouseEvent e) { hover = false; repaint(); }
            });
        }

        @Override protected void paintComponent(java.awt.Graphics g) {
            java.awt.Graphics2D g2 = (java.awt.Graphics2D) g.create();
            g2.setRenderingHint(java.awt.RenderingHints.KEY_ANTIALIASING, java.awt.RenderingHints.VALUE_ANTIALIAS_ON);
            int w = getWidth(), h = getHeight();
            int arc = h - 2;

            if (isSelected()) {
                g2.setColor(onColor);
                g2.fillRoundRect(0, 0, w - 1, h - 1, arc, arc);
                g2.setColor(Theme.current.chipTextOn);
            } else if (hover) {
                g2.setColor(new Color(onColor.getRed(), onColor.getGreen(), onColor.getBlue(), 30));
                g2.fillRoundRect(0, 0, w - 1, h - 1, arc, arc);
                g2.setColor(onColor);
                g2.drawRoundRect(0, 0, w - 1, h - 1, arc, arc);
                g2.setColor(onColor);
            } else {
                g2.setColor(Theme.current.surface);
                g2.fillRoundRect(0, 0, w - 1, h - 1, arc, arc);
                g2.setColor(Theme.current.border);
                g2.drawRoundRect(0, 0, w - 1, h - 1, arc, arc);
                g2.setColor(Theme.current.chipTextOff);
            }

            g2.setFont(getFont());
            java.awt.FontMetrics fm = g2.getFontMetrics();
            String text = getText();
            int tw = fm.stringWidth(text);
            int tx = (w - tw) / 2;
            int ty = (h - fm.getHeight()) / 2 + fm.getAscent();
            g2.drawString(text, tx, ty);
            g2.dispose();
        }

        @Override public java.awt.Dimension getPreferredSize() {
            java.awt.FontMetrics fm = getFontMetrics(getFont());
            int tw = fm.stringWidth(getText());
            return new java.awt.Dimension(tw + 24, 24);
        }
    }

    private static void styleButton(JButton btn) {
        btn.setFont(btn.getFont().deriveFont(Font.PLAIN, 12f));
        btn.setMargin(new java.awt.Insets(0, 0, 0, 0));
        btn.setFocusPainted(false);
        btn.setBorderPainted(false);
        btn.setContentAreaFilled(false);
        btn.setOpaque(false);
        btn.setForeground(Theme.current.text);
        btn.setCursor(new java.awt.Cursor(java.awt.Cursor.HAND_CURSOR));
    }

    private static void styleSendButton(JButton btn) {
        styleButton(btn);
        btn.setFont(btn.getFont().deriveFont(Font.BOLD, 12f));
    }

    private static void styleNavButton(JButton btn) {
        styleButton(btn);
        btn.setFont(btn.getFont().deriveFont(Font.PLAIN, 15f));
    }

    private static final class PremiumButton extends JButton {
        private final String type;
        private boolean hover, pressed;

        PremiumButton(String text, String type) {
            super(text);
            this.type = type;
            setFont(getFont().deriveFont(Font.PLAIN, 12f));
            setMargin(new java.awt.Insets(0, 0, 0, 0));
            setFocusPainted(false);
            setBorderPainted(false);
            setContentAreaFilled(false);
            setOpaque(false);
            setCursor(new java.awt.Cursor(java.awt.Cursor.HAND_CURSOR));
            addMouseListener(new java.awt.event.MouseAdapter() {
                @Override public void mouseEntered(java.awt.event.MouseEvent e) { hover = true; repaint(); }
                @Override public void mouseExited(java.awt.event.MouseEvent e) { hover = false; repaint(); }
                @Override public void mousePressed(java.awt.event.MouseEvent e) { pressed = true; repaint(); }
                @Override public void mouseReleased(java.awt.event.MouseEvent e) { pressed = false; repaint(); }
            });
        }

        @Override protected void paintComponent(java.awt.Graphics g) {
            java.awt.Graphics2D g2 = (java.awt.Graphics2D) g.create();
            g2.setRenderingHint(java.awt.RenderingHints.KEY_ANTIALIASING, java.awt.RenderingHints.VALUE_ANTIALIAS_ON);
            int w = getWidth(), h = getHeight();
            int arc = 8;

            Color bg, fg, border;
            if (!isEnabled()) {
                bg = Theme.current.bg;
                fg = Theme.current.disabledFg;
                border = Theme.current.border;
            } else if (type.equals("primary")) {
                bg = pressed ? Theme.current.sendHov : hover ? Theme.current.sendHov : Theme.current.send;
                fg = Color.WHITE;
                border = bg;
            } else if (type.equals("nav")) {
                bg = pressed ? Theme.current.accentBg : hover ? Theme.current.accentBg : Theme.current.surface;
                fg = pressed ? Theme.current.accent : hover ? Theme.current.accent : Theme.current.muted;
                border = hover ? Theme.current.accent : Theme.current.border;
            } else if (type.equals("danger")) {
                bg = pressed ? Theme.current.dangerPressed : hover ? Theme.current.danger : Theme.current.surface;
                fg = hover ? Color.WHITE : Theme.current.danger;
                border = hover ? Theme.current.danger : Theme.current.border;
            } else {
                bg = pressed ? Theme.current.defaultPressed : hover ? Theme.current.accentBg : Theme.current.surface;
                fg = hover ? Theme.current.accent : Theme.current.text;
                border = hover ? Theme.current.hoverBorder : Theme.current.border;
            }

            g2.setColor(bg);
            g2.fillRoundRect(0, 0, w - 1, h - 1, arc, arc);
            g2.setColor(border);
            g2.drawRoundRect(0, 0, w - 1, h - 1, arc, arc);

            g2.setColor(fg);
            g2.setFont(getFont());
            java.awt.FontMetrics fm = g2.getFontMetrics();
            String text = getText();
            int tw = fm.stringWidth(text);
            int tx = (w - tw) / 2;
            int ty = (h - fm.getHeight()) / 2 + fm.getAscent();
            g2.drawString(text, tx, ty);
            g2.dispose();
        }

        @Override public java.awt.Dimension getPreferredSize() {
            java.awt.FontMetrics fm = getFontMetrics(getFont());
            int tw = fm.stringWidth(getText());
            int pad = type.equals("primary") ? 32 : type.equals("nav") ? 20 : 28;
            int h = type.equals("primary") ? 34 : type.equals("nav") ? 30 : 32;
            return new java.awt.Dimension(tw + pad, h);
        }
    }

    private void installFilterAutocomplete() {
        filterField.addKeyListener(new KeyAdapter() {
            @Override public void keyPressed(KeyEvent e) {
                if (filterPopup == null || !filterPopup.isVisible()) {
                    if (e.getKeyCode() == KeyEvent.VK_DOWN && filterField.isFocusOwner()) {
                        showFilterPalette();
                    }
                    return;
                }
                int[] cur = new int[]{selectedCat, selectedItem};
                switch (e.getKeyCode()) {
                    case KeyEvent.VK_DOWN:
                        advanceSelection(1); e.consume(); break;
                    case KeyEvent.VK_UP:
                        advanceSelection(-1); e.consume(); break;
                    case KeyEvent.VK_ENTER:
                        if (cur[0] >= 0 && cur[1] >= 0) applyPaletteSelection(cur[0], cur[1]);
                        e.consume(); break;
                    case KeyEvent.VK_ESCAPE:
                        hideFilterPopup(); e.consume(); break;
                }
            }
        });
        filterField.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override public void focusLost(java.awt.event.FocusEvent e) {
                Timer t = new Timer(150, ev -> {
                    if (filterPopup == null || !filterPopup.isVisible()) return;
                    if (filterPopup.getMousePosition() != null) return;
                    if (filterField.isFocusOwner()) return;
                    hideFilterPopup();
                });
                t.setRepeats(false);
                t.start();
            }
        });
        filterField.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mouseClicked(java.awt.event.MouseEvent e) { showFilterPalette(); }
        });
    }

    private void advanceSelection(int delta) {
        if (paletteItems.isEmpty()) return;
        int ci = selectedCat, ii = selectedItem + delta;
        if (ci < 0) { ci = 0; ii = 0; }
        while (true) {
            if (ci < 0) ci = paletteItems.size() - 1;
            if (ci >= paletteItems.size()) ci = 0;
            java.util.List<PaletteItem> group = paletteItems.get(ci).items();
            if (group.isEmpty()) { ci += delta > 0 ? 1 : -1; ii = 0; continue; }
            if (ii < 0) { ci--; ii = Integer.MAX_VALUE; continue; }
            if (ii >= group.size()) { ci++; ii = 0; continue; }
            selectedCat = ci;
            selectedItem = ii;
            rebuildPalettePanel();
            return;
        }
    }

    private void applyPaletteSelection(int ci, int ii) {
        if (ci < 0 || ci >= paletteItems.size()) return;
        PaletteItem item = paletteItems.get(ci).items().get(ii);
        if (item.prefix() != null) {
            String current = filterField.getText().trim();
            int lastSpace = current.lastIndexOf(' ');
            String before = lastSpace >= 0 ? current.substring(0, lastSpace + 1) : "";
            String lastWord = lastSpace >= 0 ? current.substring(lastSpace + 1) : current;
            int colonIdx = lastWord.indexOf(':');
            if (colonIdx >= 0) {
                filterField.setText(current + " " + item.prefix());
            } else {
                filterField.setText(before + item.prefix());
            }
            if (item.prefix().endsWith(":") && !item.placeholder().isEmpty()) {
                hideFilterPopup();
                resizePopupForInline(item.prefix() + item.placeholder());
            } else {
                hideFilterPopup();
                applyFilter();
            }
        }
        filterField.requestFocus();
    }

    private void showFilterPalette() { buildPaletteItems(null); showPopupPanel(); }
    private void rebuildPalettePanel() { fillPalettePanelContent(); }

    private int selectedCat = -1, selectedItem = -1;
    private java.util.List<PaletteGroup> paletteItems = new ArrayList<>();
    private JPanel palettePanel;

    private record PaletteGroup(String label, java.util.List<PaletteItem> items) {}
    private record PaletteItem(String prefix, String label, String desc, String placeholder) {}

    private java.util.List<PaletteGroup> buildItems() { return CACHED_ITEMS; }
    private static final java.util.List<PaletteGroup> CACHED_ITEMS = createCachedItems();

    private static java.util.List<PaletteGroup> createCachedItems() {
        var items = new ArrayList<PaletteGroup>();
        items.add(new PaletteGroup("HTTP", java.util.List.of(
            new PaletteItem("m:", "Method", "Match HTTP method", "GET"),
            new PaletteItem("s:", "Status", "Match response status code", "200"),
            new PaletteItem("h:", "Host", "Match host substring", "api.example"),
            new PaletteItem("url:", "URL path", "Match URL path substring", "/api/v1/"),
            new PaletteItem("body:", "Response body", "Search response body content", "token")
        )));
        items.add(new PaletteGroup("Request", java.util.List.of(
            new PaletteItem("req:", "Request body", "Search request body content", "user_id"),
            new PaletteItem("hdr:", "Request header", "Match header value", "Authorization"),
            new PaletteItem("mime:", "MIME type", "Match response MIME type", "JSON"),
            new PaletteItem("len:", "Content length", "Match response body length", "1024")
        )));
        items.add(new PaletteGroup("Yentra", java.util.List.of(
            new PaletteItem("notes:", "Notes", "Search Notes column", "UNIQUE"),
            new PaletteItem("u:", "Unique only", "Show only [YENTRA] UNIQUE", "UNIQUE"),
            new PaletteItem("d:", "Duplicates", "Show only [YENTRA] DUPE", "DUPE"),
            new PaletteItem("skip:", "Skipped", "Show only [YENTRA] SKIP", "SKIP")
        )));
        items.add(new PaletteGroup("Advanced", java.util.List.of(
            new PaletteItem("r:", "Regex", "Regex across all columns + body", "\\d{3}"),
            new PaletteItem(null, "Status > code", "Status greater than", ">399"),
            new PaletteItem(null, "Status >= code", "Status greater or equal", ">=400"),
            new PaletteItem(null, "Status < code", "Status less than", "<300"),
            new PaletteItem(null, "Plain text", "Substring across everything", "search")
        )));
        return items;
    }

    private void buildPaletteItems(String filter) {
        paletteItems = buildItems();
        selectedCat = 0; selectedItem = 0;
        if (paletteItems.get(0).items().isEmpty()) advanceSelection(1);
    }

    private void showPopupPanel() {
        if (filterPopup == null) {
            filterPopup = new JWindow(SwingUtilities.getWindowAncestor(filterField));
            filterPopup.setFocusableWindowState(false);
        }
        palettePanel = new JPanel();
        palettePanel.setLayout(new BoxLayout(palettePanel, BoxLayout.Y_AXIS));
        palettePanel.setBackground(Theme.current.surface);
        palettePanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Theme.current.border, 1, true),
                BorderFactory.createEmptyBorder(8, 0, 4, 0)));
        fillPalettePanelContent();
        filterPopup.getContentPane().removeAll();
        JScrollPane scroll = new JScrollPane(palettePanel);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scroll.getVerticalScrollBar().setPreferredSize(new java.awt.Dimension(6, 0));
        filterPopup.add(scroll);
        filterPopup.pack();
        int w = Math.max(filterField.getWidth() + 4, 440);
        int h = Math.min(palettePanel.getPreferredSize().height + 8, 420);
        filterPopup.setSize(w, h);
        java.awt.Point p = filterField.getLocationOnScreen();
        filterPopup.setLocation(p.x, p.y + filterField.getHeight() + 4);
        filterPopup.setVisible(true);
    }

    private void resizePopupForInline(String hint) {
        palettePanel.removeAll();
        JPanel row = paletteRow(null, hint, null, false);
        palettePanel.add(row);
        palettePanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Theme.current.border, 1, true),
                BorderFactory.createEmptyBorder(8, 16, 8, 16)));
        filterPopup.pack();
        java.awt.Point p = filterField.getLocationOnScreen();
        filterPopup.setLocation(p.x, p.y + filterField.getHeight() + 4);
        filterPopup.setSize(Math.max(filterField.getWidth() + 4, 220), palettePanel.getPreferredSize().height);
    }

private void fillPalettePanelContent() {
        palettePanel.removeAll();
        paletteRows.clear();
        for (int gi = 0; gi < paletteItems.size(); gi++) {
            PaletteGroup group = paletteItems.get(gi);
            JPanel headerRow = new JPanel(new BorderLayout());
            headerRow.setBackground(Theme.current.surface);
            headerRow.setMaximumSize(new java.awt.Dimension(Integer.MAX_VALUE, 24));
            JLabel header = new JLabel("  " + group.label().toUpperCase());
            header.setFont(header.getFont().deriveFont(Font.BOLD, 10f));
            header.setForeground(Theme.current.muted);
            header.setBorder(BorderFactory.createEmptyBorder(gi > 0 ? 10 : 2, 16, 4, 0));
            headerRow.add(header, BorderLayout.WEST);
            palettePanel.add(headerRow);
            for (int ii = 0; ii < group.items().size(); ii++) {
                PaletteItem item = group.items().get(ii);
                boolean sel = gi == selectedCat && ii == selectedItem;
                JPanel row = paletteRow(item.prefix(), item.label(), item.desc(), sel);
                final int g = gi, i = ii;
                row.addMouseListener(new java.awt.event.MouseAdapter() {
                    @Override public void mouseClicked(java.awt.event.MouseEvent e) { applyPaletteSelection(g, i); }
                    @Override public void mouseEntered(java.awt.event.MouseEvent e) {
                        if (selectedCat == g && selectedItem == i) return;
                        int oldCat = selectedCat, oldItem = selectedItem;
                        selectedCat = g; selectedItem = i;
                        updatePaletteRow(oldCat, oldItem);
                        updatePaletteRow(g, i);
                    }
                });
                palettePanel.add(row);
                paletteRows.add(row);
            }
        }
        palettePanel.revalidate();
    }

    private final java.util.List<JPanel> paletteRows = new ArrayList<>();

    private void updatePaletteRow(int ci, int ii) {
        if (ci < 0 || ci >= paletteItems.size()) return;
        var items = paletteItems.get(ci).items();
        if (ii < 0 || ii >= items.size()) return;
        int idx = 0;
        for (int g = 0; g < ci; g++) idx += paletteItems.get(g).items().size();
        idx += ii;
        if (idx < paletteRows.size()) {
            JPanel row = paletteRows.get(idx);
            boolean sel = ci == selectedCat && ii == selectedItem;
            row.setBackground(sel ? Theme.current.accentBg : Theme.current.surface);
            updateRowForegrounds(row, sel);
        }
    }

    private void updateRowForegrounds(JPanel row, boolean selected) {
        for (Component c : row.getComponents()) {
            if (c instanceof JPanel) updateRowForegrounds((JPanel) c, selected);
            else if (c instanceof JLabel) {
                JLabel l = (JLabel) c;
                Color fg = l.getForeground();
                if (fg.equals(Theme.current.accent) || fg.equals(Theme.current.text)) {
                    l.setForeground(selected ? Theme.current.accent : Theme.current.text);
                }
            }
        }
    }
    private JPanel paletteRow(String left, String center, String desc, boolean selected) {
        JPanel row = new JPanel(new BorderLayout(10, 0));
        row.setBackground(selected ? Theme.current.accentBg : Theme.current.surface);
        row.setBorder(BorderFactory.createEmptyBorder(6, 16, 6, 16));
        row.setMaximumSize(new java.awt.Dimension(Integer.MAX_VALUE, 34));

        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        leftPanel.setOpaque(false);

        if (left != null) {
            JLabel badge = new JLabel(left);
            badge.setFont(new Font(Font.MONOSPACED, Font.BOLD, 12));
            badge.setForeground(selected ? Theme.current.accent : Theme.current.badgeFg);
            badge.setBackground(selected ? Theme.current.accentBg : Theme.current.badgeBg);
            badge.setOpaque(true);
            badge.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(selected ? Theme.current.accent : Theme.current.badgeBorder, 1, true),
                    BorderFactory.createEmptyBorder(1, 6, 1, 6)));
            leftPanel.add(badge);
        }

        JLabel c = new JLabel(center);
        c.setFont(c.getFont().deriveFont(Font.PLAIN, 13f));
        c.setForeground(selected ? Theme.current.accent : Theme.current.text);
        leftPanel.add(c);
        row.add(leftPanel, BorderLayout.WEST);

        if (desc != null) {
            JLabel r = new JLabel(desc);
            r.setFont(r.getFont().deriveFont(Font.PLAIN, 11f));
            r.setForeground(Theme.current.muted);
            row.add(r, BorderLayout.EAST);
        }
        return row;
    }

    private void hideFilterPopup() {
        if (filterPopup != null) { filterPopup.setVisible(false); }
        selectedCat = -1; selectedItem = -1;
    }

    /**
     * Bambda-style filter: parses prefix tokens from the search text, plus
     * chip toggles for scope/shared/regex. Supported prefixes:
     * <pre>
     *   m:GET  method:POST   — HTTP method
     *   s:200  status:404    — response status code
     *   h:api  host:example  — host substring
     *   url:path             — URL path substring
     *   body:token           — response body substring
     *   notes:unique         — Notes column substring
     *   r:pat   regex:pat    — regex match across search blob
     *   &gt;399 &gt;=400          — status code range
     * </pre>
     * Tokens are case-insensitive. Unprefixed text becomes substring search
     * across the full search blob (all columns + request + response body).
     */
    private void applyFilter() {
        if (filterDebounce == null) {
            filterDebounce = new Timer(80, e -> applyFilterNow());
            filterDebounce.setRepeats(false);
        }
        filterDebounce.restart();
    }

    private void applyFilterNow() {
        List<RowFilter<Object, Object>> filters = new ArrayList<>();

        // Shared is an ownership mode, not an optional narrowing filter: the two
        // states must never mix peer traffic with the receiver's local traffic.
        filters.add(ownershipRowFilter(sharedChip.isSelected()));
        if (scopeChip.isSelected()) {
            filters.add(scopeRowFilter());
        }
        if (hideOptionsChip.isSelected()) {
            filters.add(hideOptionsFilter());
        }

        String text = filterField.getText();
        if (text != null && !text.isEmpty()) {
            String lower = text.toLowerCase(Locale.ROOT);
            boolean regex = regexChip.isSelected();

            java.util.regex.Matcher tm = TOKEN_PATTERN.matcher(text);
            int lastEnd = 0;
            while (tm.find()) {
                if (tm.start() > lastEnd) {
                    addSubstringFilter(filters, text.substring(lastEnd, tm.start()), regex);
                }
                String prefix = tm.group(1).toLowerCase(Locale.ROOT);
                String value = tm.group(2);
                addTokenFilter(filters, prefix, value, regex);
                lastEnd = tm.end();
            }
            if (lastEnd < text.length()) {
                addSubstringFilter(filters, text.substring(lastEnd), regex);
            } else if (lastEnd == 0) {
                addSubstringFilter(filters, text, regex);
            }
        }

        sorter.setRowFilter(filters.isEmpty() ? null
                : filters.size() == 1 ? filters.get(0)
                : RowFilter.andFilter(filters));
        updateCount();
    }

    private static final java.util.regex.Pattern TOKEN_PATTERN =
            java.util.regex.Pattern.compile("(\\w+):\\s*([^\\s]+(?:\\s+[^\\s:]+(?=\\s+\\w+:|$))*)");

    private void addTokenFilter(List<RowFilter<Object, Object>> filters, String prefix, String value, boolean regex) {
        String v = value.toLowerCase(Locale.ROOT);
        switch (prefix) {
            case "m": case "method":
                filters.add(colFilter(2, v, regex)); break;
            case "s": case "status":
                filters.add(colFilter(4, v, regex)); break;
            case "h": case "host":
                filters.add(colFilter(1, v, regex)); break;
            case "url": case "path":
                filters.add(colFilter(3, v, regex)); break;
            case "body":
                filters.add(bodyRowFilter(v, regex)); break;
            case "req":
                filters.add(reqBodyRowFilter(v, regex)); break;
            case "hdr":
                filters.add(headerRowFilter(v, regex)); break;
            case "mime":
                filters.add(colFilter(6, v, regex)); break;
            case "len":
                filters.add(lengthRowFilter(v, regex)); break;
            case "notes":
                filters.add(colFilter(7, v, regex)); break;
            case "u":
                filters.add(colFilter(7, "unique", false)); break;
            case "d":
                filters.add(colFilter(7, "dupe", false)); break;
            case "skip":
                filters.add(colFilter(7, "skip", false)); break;
            case "r": case "regex":
                try {
                    Pattern p = Pattern.compile(value, Pattern.CASE_INSENSITIVE);
                    filters.add(searchRowFilter(blob -> p.matcher(blob).find()));
                } catch (PatternSyntaxException ex) {
                    status.setText("Invalid regex: " + ex.getMessage());
                }
                break;
            default:
                addSubstringFilter(filters, prefix + ":" + value, regex);
        }
    }

    private RowFilter<Object, Object> reqBodyRowFilter(String needle, boolean regex) {
        return new RowFilter<>() {
            @Override public boolean include(Entry<?, ?> entry) {
                Object id = entry.getIdentifier();
                if (!(id instanceof Integer)) return true;
                Row row = model.rowAt((Integer) id);
                if (row == null || row.rr == null || row.rr.request() == null) return false;
                try {
                    String body = row.rr.request().bodyToString();
                    if (body == null) return false;
                    String lower = body.toLowerCase(Locale.ROOT);
                    return regex ? lower.matches("(?i).*" + needle + ".*") : lower.contains(needle);
                } catch (RuntimeException e) { return false; }
            }
        };
    }

    private RowFilter<Object, Object> headerRowFilter(String needle, boolean regex) {
        return new RowFilter<>() {
            @Override public boolean include(Entry<?, ?> entry) {
                Object id = entry.getIdentifier();
                if (!(id instanceof Integer)) return true;
                Row row = model.rowAt((Integer) id);
                if (row == null || row.rr == null || row.rr.request() == null) return false;
                try {
                    for (HttpHeader h : row.rr.request().headers()) {
                        String hv = (h.name() + ": " + h.value()).toLowerCase(Locale.ROOT);
                        if (regex ? hv.matches("(?i).*" + needle + ".*") : hv.contains(needle)) return true;
                    }
                } catch (RuntimeException e) { return false; }
                return false;
            }
        };
    }

    private RowFilter<Object, Object> lengthRowFilter(String needle, boolean regex) {
        return new RowFilter<>() {
            @Override public boolean include(Entry<?, ?> entry) {
                Object id = entry.getIdentifier();
                if (!(id instanceof Integer)) return true;
                Row row = model.rowAt((Integer) id);
                if (row == null || row.cells[5] == null || row.cells[5].isEmpty()) return false;
                return regex ? row.cells[5].toLowerCase(Locale.ROOT).contains(needle)
                             : row.cells[5].contains(needle);
            }
        };
    }

    private void addSubstringFilter(List<RowFilter<Object, Object>> filters, String text, boolean regex) {
        String trimmed = text.trim();
        if (trimmed.isEmpty()) return;

        java.util.regex.Matcher cm = STATUS_COMPARE.matcher(trimmed);
        if (cm.matches()) {
            String op = cm.group(1);
            try {
                int threshold = Integer.parseInt(cm.group(2));
                filters.add(statusCompareFilter(op, threshold));
                return;
            } catch (NumberFormatException ignored) {}
        }

        if (regex) {
            try {
                Pattern p = Pattern.compile(trimmed, Pattern.CASE_INSENSITIVE);
                filters.add(searchRowFilter(blob -> p.matcher(blob).find()));
            } catch (PatternSyntaxException ex) {
                status.setText("Invalid regex: " + ex.getMessage());
            }
        } else {
            String needle = trimmed.toLowerCase(Locale.ROOT);
            filters.add(searchRowFilter(blob -> blob.contains(needle)));
        }
    }

    private static final java.util.regex.Pattern STATUS_COMPARE =
            java.util.regex.Pattern.compile("([><]=?)\\s*(\\d{3})");

    private RowFilter<Object, Object> colFilter(int col, String needle, boolean regex) {
        return new RowFilter<>() {
            @Override public boolean include(Entry<?, ?> entry) {
                Object id = entry.getIdentifier();
                if (!(id instanceof Integer)) return true;
                Row row = model.rowAt((Integer) id);
                if (row == null || row.cells[col] == null) return false;
                String val = row.cells[col].toLowerCase(Locale.ROOT);
                return regex ? val.matches("(?i).*" + needle + ".*") : val.contains(needle);
            }
        };
    }

    private RowFilter<Object, Object> bodyRowFilter(String needle, boolean regex) {
        return new RowFilter<>() {
            @Override public boolean include(Entry<?, ?> entry) {
                Object id = entry.getIdentifier();
                if (!(id instanceof Integer)) return true;
                Row row = model.rowAt((Integer) id);
                if (row == null || row.rr == null || !row.rr.hasResponse()) return false;
                try {
                    String body = row.rr.response().bodyToString();
                    if (body == null) return false;
                    String lower = body.toLowerCase(Locale.ROOT);
                    String n = needle.toLowerCase(Locale.ROOT);
                    return regex ? lower.matches("(?i).*" + n + ".*") : lower.contains(n);
                } catch (RuntimeException e) {
                    return false;
                }
            }
        };
    }

    private RowFilter<Object, Object> statusCompareFilter(String op, int threshold) {
        return new RowFilter<>() {
            @Override public boolean include(Entry<?, ?> entry) {
                Object id = entry.getIdentifier();
                if (!(id instanceof Integer)) return true;
                Row row = model.rowAt((Integer) id);
                if (row == null || row.cells[4] == null || row.cells[4].isEmpty()) return false;
                try {
                    int status = Integer.parseInt(row.cells[4]);
                    return switch (op) {
                        case ">" -> status > threshold;
                        case ">=" -> status >= threshold;
                        case "<" -> status < threshold;
                        case "<=" -> status <= threshold;
                        default -> false;
                    };
                } catch (NumberFormatException e) {
                    return false;
                }
            }
        };
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

    /** Keeps either received Live Share rows or local rows, never both. */
    private RowFilter<Object, Object> ownershipRowFilter(boolean shared) {
        return new RowFilter<>() {
            @Override public boolean include(Entry<? extends Object, ? extends Object> entry) {
                Object id = entry.getIdentifier();
                return id instanceof Integer && rowIsShared((Integer) id) == shared;
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

    private RowFilter<Object, Object> hideOptionsFilter() {
        return new RowFilter<>() {
            @Override public boolean include(Entry<? extends Object, ? extends Object> entry) {
                Object id = entry.getIdentifier();
                if (!(id instanceof Integer)) return true;
                Row row = model.rowAt((Integer) id);
                return row == null || row.cells[2] == null
                    || (!"OPTIONS".equalsIgnoreCase(row.cells[2]) && !"HEAD".equalsIgnoreCase(row.cells[2]));
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
        int total = model.getRowCount();
        int shown = table.getRowCount();
        resultCounter.setText(shown == total ? total + " results" : shown + " / " + total);
        status.setText("Showing " + shown + " of " + total + " request(s).");
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
            api.logging().logToOutput("[yentra] " + line);
        } catch (RuntimeException ignored) {
            // API gone (extension unloaded) — drop the line rather than crash the worker
        }
    }

    /**
     * Empties the table. In live mode {@code seenIds} is kept, so cleared rows don't reappear on the
     * next poll — only genuinely new {@code [YENTRA] UNIQUE} entries arrive.
     */
    private void clearView() {
        int n = model.getRowCount();
        model.clear();
        refreshTitle();
        status.setText("Cleared " + n + " row(s).");
        scheduleLiveExport();
    }

    // ── Live feed: auto-collect HTTP-history rows marked [YENTRA] UNIQUE ──────

    /**
     * Opens a <b>live</b> window that automatically collects every Proxy HTTP-history entry the
     * extension has marked <code>[YENTRA] UNIQUE</code> in its Notes — and only those. It polls the
     * history (~1s) so new uniques appear on their own as you browse; the duplicates Burp already
     * folded away (<code>[YENTRA] DUPE …</code>) never show, and uniques already in history are
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
     * {@code [YENTRA] UNIQUE} rows for the life of the extension. Must be called on the Swing EDT.
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
     * Push path: a freshly-classified UNIQUE arrives directly from {@link YentraProxyHandler} (on the
     * proxy thread, off the EDT). Dedups by request identity, parses the row off the EDT, then
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
            safeLogError("[yentra] live push add failed: " + e);
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
        LIVE_VIEWERS.add(this);     // registered so "Reset stats" can reach this viewer's proxy-history tracking
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
                    LIVE_VIEWERS.remove(this);
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
                LIVE_VIEWERS.remove(this);
                if (frame != null) frame.dispose();
            }));
        } catch (RuntimeException ignored) {
            // best-effort; the per-poll self-stop is the safety net if this can't register
        }
    }

    /**
     * Wipes every active live viewer's proxy-history tracking ({@code seenIds}, {@code liveKeys},
     * {@code examinedNonUnique}, {@code maxScannedId}) and its table, then re-scans from id 0 — so
     * "Reset stats" in {@link YentraTab} restarts the live counts too, not just the engine's. The
     * table is cleared on the EDT; the tracking wipe happens on the next poll thread (via
     * {@code forceFullRescan}) so a scan already in flight can't repopulate the sets under us. Safe
     * to call from any thread (no-op if no live viewer is open).
     */
    public static void resetAllLiveTracking() {
        for (UniqueRequestsViewer v : LIVE_VIEWERS) v.resetLiveTracking();
    }

    private void resetLiveTracking() {
        forceFullRescan = true;                    // applied at the top of the next poll (race-free)
        SwingUtilities.invokeLater(() -> {
            model.clear();
            refreshTitle();
            updateCount();
            scheduleLiveExport();
            status.setText("Proxy history tracking reset — re-scanning…");
        });
        pollHistory();                              // kick a scan now (skipped if one's already running)
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
     * Appends any Proxy-history entry whose Notes start with {@code [YENTRA] UNIQUE} that we haven't
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
                if (forceFullRescan) {                  // "Reset stats" → re-scan proxy history from scratch
                    forceFullRescan = false;
                    seenIds.clear();
                    liveKeys.clear();
                    examinedNonUnique.clear();
                    maxScannedId = -1;
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
                            // "NONE" (no [YENTRA] note) and "OTHER" (non-yentra note, e.g. a role-port
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
                        safeLogError("[yentra] live scan skipped entry " + id + ": " + perEntry);
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
                            log("Added " + batch.size() + " [YENTRA] UNIQUE from history.");
                        }
                    });
                }
                if (fullPass) {
                    // Verdict census of the entries examined this pass. The live feed collects only
                    // [YENTRA] UNIQUE rows, so when it stays empty the reason is almost always visible
                    // here: 0 UNIQUE because in-scope-only marked everything SKIP, no [YENTRA] note at
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
        }, "yentra-live-poll");
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
        safeLogError("[yentra] live history poll failed (" + fails + "/" + MAX_LIVE_FAILURES + "): " + ex);
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
     * or {@code "OVRF"}; {@code "OTHER"} for a non-yentra note, {@code "NONE"} for no note at all. Only
     * {@code "UNIQUE"} rows are collected by the live feed — the rest feed the diagnostic census in
     * {@link #pollHistory}.
     */
    private static String noteCategory(Annotations a) {
        try {
            if (a == null || !a.hasNotes()) return "NONE";
            String notes = a.notes();
            if (notes == null || notes.isEmpty()) return "NONE";
            if (!notes.startsWith(YentraProxyHandler.NOTE_PREFIX)) return "OTHER";
            String rest = notes.substring(YentraProxyHandler.NOTE_PREFIX.length()).trim();
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
        int yentraNotes = dupe + skip + ovrf;
        if (yentraNotes == 0) {
            return "Live: " + histSize + " rows but none carry a [YENTRA] verdict — enable "
                    + "\"Stamp Notes column with verdict\" in the Yentra tab (or another extension is "
                    + "overwriting the Notes).";
        }
        if (skip > 0 && dupe == 0 && ovrf == 0) {
            return "Live: 0 UNIQUE — all " + skip + " classified rows are [YENTRA] SKIP. Turn off "
                    + "\"In-scope only\" in the Yentra tab (or set a matching Target scope), then Apply.";
        }
        return "Live: 0 UNIQUE of " + histSize + " rows (DUPE=" + dupe + " SKIP=" + skip
                + (ovrf > 0 ? " OVRF=" + ovrf : "") + "). If you expected uniques, check for a duplicate "
                + "Yentra extension overwriting verdicts, then click \"Stamp existing history\".";
    }

    private void showRow(int modelRow) {
        Row row = model.rowAt(modelRow);
        if (row == null || row.rr == null) return;
        repeaterViewGeneration.incrementAndGet();
        HttpRequestResponse rr = row.rr;
        requestEditor.setRequest(rr.request());
        this.originalRequest = rr.request();
        boolean hasResp = rr.hasResponse() && rr.response() != null;
        HttpResponse resp = hasResp ? rr.response() : null;
        responseEditor.setResponse(resp != null ? resp : HttpResponse.httpResponse());
        showResponseInfo(resp, -1);
    }

    private void showResponseInfo(HttpResponse resp, long elapsedMs) {
        if (resp == null) {
            String text = "No response received";
            if (elapsedMs >= 0) text += "  |  " + elapsedMs + " ms";
            responseInfo.setText(text);
            responseInfo.setForeground(Theme.current.warn);
            return;
        }
        StringBuilder sb = new StringBuilder();
        int code = resp.statusCode();
        sb.append("HTTP ").append(code);
        String reason = resp.reasonPhrase();
        if (reason != null && !reason.isEmpty()) sb.append(" ").append(reason);
        sb.append("  |  ").append(formatBytes(resp.body().length()));
        if (elapsedMs >= 0) sb.append("  |  ").append(elapsedMs).append(" ms");
        responseInfo.setText(sb.toString());
        if (code >= 200 && code < 300) responseInfo.setForeground(Theme.current.ok);
        else if (code >= 300 && code < 400) responseInfo.setForeground(Theme.current.accent);
        else if (code >= 400 && code < 500) responseInfo.setForeground(Theme.current.warn);
        else if (code >= 500) responseInfo.setForeground(Theme.current.danger);
        else responseInfo.setForeground(Theme.current.text);
    }

    private static String formatBytes(int b) {
        if (b < 1024) return b + " bytes";
        if (b < 1024 * 1024) return String.format("%.1f KB", b / 1024.0);
        return String.format("%.1f MB", b / (1024.0 * 1024.0));
    }

    private void navigateHistory(int delta) {
        int newPos = historyPos + delta;
        if (newPos < 0 || newPos >= repeaterHistory.size()) return;
        repeaterViewGeneration.incrementAndGet();
        RepeaterEntry entry = repeaterHistory.get(newPos);
        requestEditor.setRequest(entry.request());
        responseEditor.setResponse(entry.response() != null ? entry.response() : HttpResponse.httpResponse());
        showResponseInfo(entry.response(), entry.elapsedMs());
        historyPos = newPos;
        updateHistoryButtons();
    }

    private void updateHistoryButtons() {
        btnBack.setEnabled(historyPos > 0);
        btnForward.setEnabled(historyPos < repeaterHistory.size() - 1);
        btnBack.repaint();
        btnForward.repaint();
    }

    private void resetRequest() {
        if (originalRequest != null) {
            repeaterViewGeneration.incrementAndGet();
            requestEditor.setRequest(originalRequest);
            status.setText("Request reset to original.");
        } else {
            status.setText("No original request to reset to — select a row first.");
        }
    }

    private void sendEditedRequest() {
        HttpRequest editorRequest;
        try {
            editorRequest = requestEditor.getRequest();
        } catch (RuntimeException ex) {
            status.setText("Couldn't read the edited request: " + ex.getMessage());
            return;
        }
        if (editorRequest == null || editorRequest.httpService() == null) {
            status.setText("Select a row first, then edit the request and Send.");
            return;
        }
        HttpRequest req = withCorrectContentLength(editorRequest);
        status.setText("Sending…");
        responseInfo.setText("Sending…");
        long viewGeneration = repeaterViewGeneration.incrementAndGet();
        Thread t = new Thread(() -> {
            long t0 = System.currentTimeMillis();
            try {
                HttpRequestResponse out = api.http().sendRequest(req);
                long ms = System.currentTimeMillis() - t0;
                HttpResponse resp = out != null && out.hasResponse() ? out.response() : null;
                SwingUtilities.invokeLater(() -> {
                    addRepeaterEntry(req, resp, ms);
                    if (repeaterViewGeneration.get() != viewGeneration) return;
                    responseEditor.setResponse(resp != null ? resp : HttpResponse.httpResponse());
                    showResponseInfo(resp, ms);
                    status.setText(resp != null ? "Done." : "No response received; check Burp Logger for connection details.");
                });
                log("Repeater  " + safeReqLine(req) + "   ←   "
                        + (resp != null ? resp.statusCode() + " " + resp.body().length() + "b" : "(no response)"));
            } catch (RuntimeException ex) {
                SwingUtilities.invokeLater(() -> {
                    if (repeaterViewGeneration.get() != viewGeneration) return;
                    responseInfo.setText("Send failed");
                    responseInfo.setForeground(Theme.current.danger);
                    status.setText("Send failed: " + ex.getMessage());
                });
                api.logging().logToError("[yentra] inline repeater send failed: " + ex);
            }
        }, "yentra-repeater-send");
        t.setDaemon(true);
        t.start();
    }

    /**
     * Keeps an explicitly present Content-Length consistent with edits made in the embedded request
     * editor. The length is calculated from Montoya's raw body bytes rather than Java characters,
     * which is essential for spaces, Unicode, and other multi-byte input. A request without a
     * Content-Length is left alone (HTTP/2 does not require one).
     */
    private static HttpRequest withCorrectContentLength(HttpRequest req) {
        if (req == null || !req.hasHeader("Content-Length")) return req;
        String actual = Integer.toString(req.body().length());
        String declared = req.headerValue("Content-Length");
        if (actual.equals(declared == null ? null : declared.trim())) return req;
        return req.withUpdatedHeader("Content-Length", actual);
    }

    private void addRepeaterEntry(HttpRequest req, HttpResponse resp, long ms) {
        while (repeaterHistory.size() > historyPos + 1) {
            repeaterHistory.remove(repeaterHistory.size() - 1);
        }
        repeaterHistory.add(new RepeaterEntry(req, resp, ms));
        historyPos = repeaterHistory.size() - 1;
        updateHistoryButtons();
    }

    /**
     * Binds <b>Send</b> to Cmd+Space, Ctrl+Space, and Ctrl+Enter.
     * Uses {@code EventQueue.push()} for Ctrl+Space interception plus
     * {@code WHEN_IN_FOCUSED_WINDOW} InputMap bindings.
     */
    private void installSendKeys(JComponent c) {
        c.getActionMap().put("dedupe-send", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) {
                if (root.isShowing()) sendEditedRequest();
            }
        });

        int cmd = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        InputMap im = c.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW);
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_SPACE, cmd), "dedupe-send");             // Cmd+Space (macOS) / Ctrl+Space (Win)
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_SPACE, KeyEvent.CTRL_DOWN_MASK), "dedupe-send"); // Ctrl+Space (always)
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, KeyEvent.CTRL_DOWN_MASK), "dedupe-send");  // Ctrl+Enter

        java.awt.EventQueue queue = Toolkit.getDefaultToolkit().getSystemEventQueue();
        queue.push(new java.awt.EventQueue() {
            @Override
            protected void dispatchEvent(AWTEvent event) {
                if (event instanceof KeyEvent) {
                    KeyEvent ke = (KeyEvent) event;
                    if (ke.getID() == KeyEvent.KEY_PRESSED
                            && ke.getKeyCode() == KeyEvent.VK_SPACE
                            && root.isShowing()) {
                        int mods = ke.getModifiersEx();
                        if ((mods & cmd) != 0 || (mods & KeyEvent.CTRL_DOWN_MASK) != 0) {
                            ke.consume();
                            sendEditedRequest();
                            return;
                        }
                    }
                }
                super.dispatchEvent(event);
            }
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

    /**
     * On macOS, CInputMethod swallows Ctrl+Space for input-source switching.

     * enableInputMethods(false) on the focused text component stops this
     * at the native level. Montoya editors lazily create their internal
     * text components, so we can't just call disableInputMethods once in
     * the constructor — we watch every focus change and re-apply when the
     * focus lands anywhere inside the request editor. A delayed initial
     * pass via invokeLater catches the editor's first creation.
     */
    private void watchdogInputMethods() {
        KeyboardFocusManager.getCurrentKeyboardFocusManager()
                .addPropertyChangeListener("permanentFocusOwner", evt -> {
                    Component focus = (Component) evt.getNewValue();
                    if (focus == null) return;
                    if (!root.isShowing()) return;
                    if (!SwingUtilities.isDescendingFrom(focus, requestEditor.uiComponent())) return;
                    disableInputMethods(focus);
                });
        SwingUtilities.invokeLater(() -> disableInputMethods(requestEditor.uiComponent()));
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
            api.logging().logToError("[yentra] send-to-Repeater failed: " + ex);
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
                status.setText("No Live Share — open the Yentra Share tab first.");
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
            String scopeUrl = YentraContextMenu.scopeUrlFor(rr.request(), hostOnly);
            if (scopeUrl != null) urls.add(scopeUrl);
        }
        if (urls.isEmpty()) return;

        String label = hostOnly ? "host(s)" : "path prefix(es)";
        int answer = JOptionPane.showConfirmDialog(table,
                "Exclude the following " + label + " from Target scope?\n\n"
                        + String.join("\n", urls),
                "Yentra — Remove from scope", JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.WARNING_MESSAGE);
        if (answer != JOptionPane.OK_OPTION) return;

        int done = 0;
        for (String url : urls) {
            try {
                api.scope().excludeFromScope(url);
                done++;
            } catch (RuntimeException ex) {
                api.logging().logToError("[yentra] scope exclude failed for " + url + ": " + ex);
            }
        }
        status.setText("Excluded " + done + " " + label + " from scope.");
        api.logging().logToOutput("[yentra] excluded " + done + " " + label + " from scope.");
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
                    "# yentra — " + sel.size() + " saved request(s) for AI"
                            + (bodyOnly ? " (responses: body only, pretty JSON)" : "") + "\n" + AI_PROTOCOL + "\n"
                            + buildHttpDump(sel, bodyOnly), StandardCharsets.UTF_8);
            status.setText("Saved " + sel.size() + " request(s) to " + target.getAbsolutePath());
            api.logging().logToOutput("[yentra] saved " + sel.size() + " request(s) to " + target.getAbsolutePath());
            log("Saved " + sel.size() + " request(s) to " + target.getName());
        } catch (IOException ex) {
            api.logging().logToError("[yentra] save requests failed: " + ex);
            status.setText("Save failed: " + ex.getMessage());
            log("Save failed: " + ex.getMessage());
        }
    }

    // ── Magic Cookie: reissue the selection with a swapped-in auth set ────────

    private static final String PREF_MAGIC_COOKIE = "yentra.magic-cookie.headers";

    /** Remembers the Save-for-AI "body only, pretty JSON" checkbox across saves/restarts. */
    private static final String PREF_SAVE_PRETTY_BODY = "yentra.save.pretty-body-only";

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
                    api.logging().logToError("[yentra] " + resultTitle + " send failed: " + ex);
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
                api.logging().logToOutput("[yentra] " + resultTitle + " — sent " + s
                        + " skipped " + sk + " failed " + f);
            });
        }, "yentra-reissue");
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

    private static final String PREF_MR_MATCH   = "yentra.match-replace.match";
    private static final String PREF_MR_REPLACE = "yentra.match-replace.replace";
    private static final String PREF_MR_PATH    = "yentra.match-replace.path";
    private static final String PREF_MR_BODY    = "yentra.match-replace.body";
    private static final String PREF_MR_HEADERS = "yentra.match-replace.headers";
    private static final String PREF_MR_REGEX   = "yentra.match-replace.regex";

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
        JCheckBox cbHeaders = new JCheckBox("Headers", boolDefault(prefs.getBoolean(PREF_MR_HEADERS), false));
        JCheckBox cbRegex = new JCheckBox("regex", boolDefault(prefs.getBoolean(PREF_MR_REGEX), false));

        JLabel help = new JLabel("<html>For <b>IDOR / BOLA</b>: replace an object id (or any token) in the "
                + "request's <b>path/query</b>, <b>body</b>, <b>headers</b>, or any combination, then reissue. "
                + "<b>Only requests that actually contain the match are sent</b> (the rest are skipped); within "
                + "each, everything but the matched value is left unchanged. <b>Headers</b> covers every header "
                + "value — Cookie, Authorization, X-User-Id, etc. — so a Magic-Cookie-swapped request can have its "
                + "session/token re-swapped here too. Watch the results for a <b>200</b> where another "
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
        scope.add(cbPath); scope.add(cbBody); scope.add(cbHeaders); scope.add(cbRegex);
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
            boolean inHeaders = cbHeaders.isSelected();
            if (!inPath && !inBody && !inHeaders) { warn(dialog, "Pick at least one of Path/query, Body, or Headers."); return; }
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
            prefs.setBoolean(PREF_MR_HEADERS, inHeaders);
            prefs.setBoolean(PREF_MR_REGEX, regex);

            String scopeLabel = scopeLabel(inPath, inBody, inHeaders);
            streamReissue(currentSel, "Match & Replace results",
                    req -> applyMatchReplace(req, match, replace, inPath, inBody, inHeaders, regex),
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
     * path (which in Montoya includes the query string), the body, and/or every header value. Literal
     * by default, or regex when {@code regex} is set; {@link HttpRequest#withBody(String)} refreshes
     * Content-Length. Header values are rewritten in place via {@link HttpRequest#withUpdatedHeader}.
     *
     * <p>Returns {@code null} if the match wasn't present in any selected part — i.e. nothing
     * changed. {@link #streamReissue} skips those, so only the requests that actually carried the id
     * (and therefore had it swapped) are reissued. This is why a Magic-Cookie result whose token lives
     * only in a header (Cookie / Authorization) was previously "not sent" unless Headers was ticked:
     * with no match in path or body, {@code null} came back and the request was skipped.
     */
    private static HttpRequest applyMatchReplace(HttpRequest req, String match, String replace,
                                                 boolean inPath, boolean inBody, boolean inHeaders, boolean regex) {
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
        if (inHeaders) {
            // Iterate the original headers so a withUpdatedHeader mid-loop doesn't shift the list
            // under us. withUpdatedHeader rewrites every header sharing the name — fine for the IDOR
            // case (Cookie / Authorization / X-User-Id are single-valued in practice).
            for (HttpHeader h : req.headers()) {
                String v = h.value();
                if (v == null || v.isEmpty()) continue;
                String nv = regex ? v.replaceAll(match, replace) : v.replace(match, replace);
                if (!nv.equals(v)) { out = out.withUpdatedHeader(h.name(), nv); changed = true; }
            }
        }
        return changed ? out : null; // null → match absent here; streamReissue won't reissue it
    }

    /** Short label for the log line, e.g. {@code "path+body"}, {@code "headers"}, {@code "path+headers"}. */
    private static String scopeLabel(boolean inPath, boolean inBody, boolean inHeaders) {
        StringBuilder sb = new StringBuilder();
        if (inPath)    sb.append(sb.length() == 0 ? "path/query" : "+path");
        if (inBody)    sb.append(sb.length() == 0 ? "body" : "+body");
        if (inHeaders) sb.append(sb.length() == 0 ? "headers" : "+headers");
        return sb.length() == 0 ? "none" : sb.toString();
    }

    private static String orEmpty(String s) { return s == null ? "" : s; }

    private static boolean boolDefault(Boolean b, boolean def) { return b == null ? def : b; }

    private static void warn(Component parent, String msg) {
        JOptionPane.showMessageDialog(parent, msg, "Match & Replace", JOptionPane.WARNING_MESSAGE);
    }

    // ── Convert Request To: JSON body → any HTTP method ──

    private void convertRequestTo(String targetMethod) {
        List<HttpRequestResponse> sel = selectedRows();
        if (sel.isEmpty()) { status.setText("Select one or more requests first."); return; }
        List<HttpRequest> convertedList = new ArrayList<>();
        for (HttpRequestResponse rr : sel) {
            if (rr == null || rr.request() == null) continue;
            HttpRequest out = convertMethod(rr.request(), targetMethod);
            if (out != null) convertedList.add(out);
        }
        if (convertedList.isEmpty()) {
            status.setText("No requests could be converted to " + targetMethod + ".");
            return;
        }
        streamConversions(convertedList, "Converted → " + targetMethod + "  (" + convertedList.size() + " req)");
    }

    private void convertRequestToAll() {
        List<HttpRequestResponse> sel = selectedRows();
        if (sel.isEmpty()) { status.setText("Select a request first."); return; }
        List<HttpRequest> convertedList = new ArrayList<>();
        String[] methods = {"GET", "POST", "PUT", "PATCH", "DELETE"};
        for (HttpRequestResponse rr : sel) {
            if (rr == null || rr.request() == null) continue;
            for (String m : methods) {
                HttpRequest out = convertMethod(rr.request(), m);
                if (out != null) convertedList.add(out);
            }
        }
        if (convertedList.isEmpty()) {
            status.setText("No requests could be converted.");
            return;
        }
        streamConversions(convertedList, "Converted → All methods  (" + convertedList.size() + " req)");
    }

    private void streamConversions(List<HttpRequest> requests, String title) {
        status.setText(title + ": sending " + requests.size() + " request(s)…");
        UniqueRequestsViewer results = new UniqueRequestsViewer(api, new ArrayList<>(), title);
        Thread t = new Thread(() -> {
            int sent = 0, failed = 0;
            for (HttpRequest req : requests) {
                try {
                    HttpRequestResponse out = api.http().sendRequest(req);
                    results.log(logLine(req, out));
                    SwingUtilities.invokeLater(() -> results.addResult(out));
                    sent++;
                } catch (RuntimeException ex) {
                    results.log("ERROR  " + safeReqLine(req) + " — " + ex.getMessage());
                    failed++;
                }
                final int s = sent, f = failed;
                SwingUtilities.invokeLater(() -> status.setText(title + ": sent " + s
                        + (f > 0 ? ", " + f + " failed" : "") + "…"));
            }
            final int s = sent, f = failed;
            results.log("done — sent " + s + (f > 0 ? ", " + f + " failed" : ""));
            SwingUtilities.invokeLater(() -> status.setText("Converted → " + title + ": " + s
                    + " sent" + (f > 0 ? ", " + f + " failed" : "") + "."));
        }, "yentra-convert-send");
        t.setDaemon(true);
        t.start();
    }

    private void responseToRequest(String targetMethod) {
        List<HttpRequest> generated = buildRequestsFromResponses(targetMethod);
        if (generated.isEmpty()) {
            status.setText("No requests with valid JSON responses selected.");
            return;
        }
        streamConversions(generated, "Response → " + targetMethod + "  (" + generated.size() + " req)");
    }

    private void responseToRequestAll() {
        List<HttpRequest> generated = buildRequestsFromResponses(null);
        if (generated.isEmpty()) {
            status.setText("No requests with valid JSON responses selected.");
            return;
        }
        streamConversions(generated, "Response → All  (" + generated.size() + " req)");
    }

    private List<HttpRequest> buildRequestsFromResponses(String singleMethod) {
        List<HttpRequestResponse> sel = selectedRows();
        String[] methods = singleMethod != null ? new String[]{singleMethod}
                : new String[]{"GET", "POST", "PUT", "PATCH", "DELETE"};
        List<HttpRequest> generated = new ArrayList<>();
        for (HttpRequestResponse rr : sel) {
            if (rr == null || rr.request() == null || !rr.hasResponse() || rr.response() == null) continue;
            String respBody = "";
            try { respBody = rr.response().bodyToString(); } catch (RuntimeException e) {}
            if (respBody == null || respBody.strip().isEmpty()) continue;
            String stripped = respBody.strip();
            if (!stripped.startsWith("{") && !stripped.startsWith("[")) continue;

            Object json = parseResponseJson(stripped);
            if (json == null) continue;

            HttpRequest base = rr.request();
            for (String m : methods) {
                HttpRequest out = buildReqFromResponse(base, json, stripped, m);
                if (out != null) generated.add(out);
            }
        }
        return generated;
    }

    private Object parseResponseJson(String stripped) {
        try { return parseJson(stripped); }
        catch (RuntimeException e) {
            try { return parseJson(sanitizeJson(stripped)); }
            catch (RuntimeException e2) { return extractJsonSegment(stripped); }
        }
    }

    private HttpRequest buildReqFromResponse(HttpRequest base, Object json, String raw, String method) {
        HttpRequest out;
        if ("GET".equalsIgnoreCase(method)) {
            List<KeyValue> flat = flattenJson(json);
            String qs = toQueryString(flat);
            String path = base.path();
            int qi = path.indexOf('?');
            String existingQs = qi >= 0 ? path.substring(qi + 1) : "";
            String basePath = qi >= 0 ? path.substring(0, qi) : path;
            String finalQs = existingQs.isEmpty() ? qs : existingQs + "&" + qs;
            out = base.withPath(basePath + (finalQs.isEmpty() ? "" : "?" + finalQs))
                .withMethod("GET").withBody("");
            if (out.hasHeader("Content-Type")) out = out.withRemovedHeader("Content-Type");
            if (out.hasHeader("Content-Length")) out = out.withRemovedHeader("Content-Length");
        } else {
            String pretty = prettyPrintJson(raw);
            out = base.withMethod(method.toUpperCase()).withBody(pretty);
            if (out.hasHeader("Content-Type")) out = out.withUpdatedHeader("Content-Type", "application/json");
            else out = out.withAddedHeader("Content-Type", "application/json");
        }
        return out;
    }

    private static String prettyPrintJson(String raw) {
        Object parsed = parseJson(raw.strip());
        return formatJsonValue(parsed, 0);
    }

    @SuppressWarnings("unchecked")
    private static String formatJsonValue(Object obj, int indent) {
        String pad = "  ".repeat(indent);
        String padInner = "  ".repeat(indent + 1);
        if (obj == null) return "null";
        if (obj instanceof Boolean) return obj.toString();
        if (obj instanceof Number) {
            double d = ((Number) obj).doubleValue();
            return d == Math.floor(d) && !Double.isInfinite(d) ? Long.toString((long) d) : obj.toString();
        }
        if (obj instanceof String) {
            return "\"" + ((String) obj).replace("\\", "\\\\").replace("\"", "\\\"")
                    .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + "\"";
        }
        if (obj instanceof java.util.List) {
            var list = (java.util.List<?>) obj;
            if (list.isEmpty()) return "[]";
            StringBuilder sb = new StringBuilder("[\n");
            for (int i = 0; i < list.size(); i++) {
                sb.append(padInner).append(formatJsonValue(list.get(i), indent + 1));
                if (i < list.size() - 1) sb.append(",");
                sb.append("\n");
            }
            return sb.append(pad).append("]").toString();
        }
        if (obj instanceof java.util.Map) {
            var map = (java.util.Map<String, Object>) obj;
            if (map.isEmpty()) return "{}";
            StringBuilder sb = new StringBuilder("{\n");
            int i = 0;
            for (var e : map.entrySet()) {
                sb.append(padInner).append("\"").append(e.getKey()).append("\": ")
                  .append(formatJsonValue(e.getValue(), indent + 1));
                if (++i < map.size()) sb.append(",");
                sb.append("\n");
            }
            return sb.append(pad).append("}").toString();
        }
        return String.valueOf(obj);
    }

    private HttpRequest convertMethod(HttpRequest req, String targetMethod) {
        String currentMethod = safe(() -> req.method().toUpperCase());
        if (currentMethod.equalsIgnoreCase(targetMethod)) return req;

        String body = safe(req::bodyToString);
        if (body.isEmpty()) {
            return swapMethod(req, targetMethod);
        }

        Object json = null;
        List<KeyValue> formPairs = null;
        String stripped = body.strip();
        boolean isJson = stripped.startsWith("{") || stripped.startsWith("[") || stripped.contains(":");
        boolean isForm = stripped.contains("=") && stripped.contains("&");

        if (isJson) {
            try {
                json = parseJson(stripped);
            } catch (RuntimeException e) {
                try { json = parseJson(sanitizeJson(stripped)); }
                catch (RuntimeException e2) { json = extractJsonSegment(stripped); }
            }
        } else if (isForm) {
            formPairs = flattenForm(stripped);
        }

        HttpRequest out = req;
        if ("GET".equalsIgnoreCase(targetMethod)) {
            String qs = null;
            if (json != null) {
                qs = toQueryString(flattenJson(json));
            } else if (formPairs != null) {
                qs = toQueryString(formPairs);
            }
            String path = out.path();
            int qi = path.indexOf('?');
            String existingQs = qi >= 0 ? path.substring(qi + 1) : "";
            String base = qi >= 0 ? path.substring(0, qi) : path;
            if (qs != null && !qs.isEmpty()) {
                out = out.withPath(base + "?" + (existingQs.isEmpty() ? qs : existingQs + "&" + qs));
            }
            out = out.withMethod("GET").withBody("");
            if (out.hasHeader("Content-Type")) out = out.withRemovedHeader("Content-Type");
            if (out.hasHeader("Content-Length")) out = out.withRemovedHeader("Content-Length");
        } else {
            out = swapMethod(out, targetMethod);
        }
        return out;
    }

    private static String sanitizeJson(String s) {
        s = s.replace('\'', '"');
        s = s.replaceAll(",\\s*]", "]");
        s = s.replaceAll(",\\s*}", "}");
        return s;
    }

    private static Object extractJsonSegment(String body) {
        if (body.contains("&&&")) {
            String[] parts = body.split("&&&");
            for (int i = parts.length - 1; i >= 0; i--) {
                String part = parts[i].strip();
                if (part.isEmpty()) continue;
                try { return parseJson(part); }
                catch (RuntimeException e) {
                    try { return parseJson(sanitizeJson(part)); }
                    catch (RuntimeException ignored) {}
                }
            }
        }
        return null;
    }

    private static HttpRequest swapMethod(HttpRequest req, String targetMethod) {
        String m = targetMethod.toUpperCase();
        if (!java.util.Set.of("GET", "POST", "PUT", "PATCH", "DELETE").contains(m)) return req;
        return req.withMethod(m);
    }

    // ── JSON parser (recursive descent, zero dependencies) ──

    private record KeyValue(String key, String value) {}

    private static Object parseJson(String s) {
        int[] i = new int[]{0};
        return parseValue(skipWs(s, i), i);
    }

    private static Object parseValue(String s, int[] i) {
        char c = s.charAt(i[0]);
        return switch (c) {
            case '{' -> parseObject(s, i);
            case '[' -> parseArray(s, i);
            case '"' -> parseString(s, i);
            case 't', 'f' -> parseBool(s, i);
            case 'n' -> parseNull(s, i);
            default -> parseNumber(s, i);
        };
    }

    private static java.util.Map<String, Object> parseObject(String s, int[] i) {
        var map = new java.util.LinkedHashMap<String, Object>();
        if (s.charAt(i[0]) != '{') throw new IllegalArgumentException("Expected {");
        i[0]++; skipWs(s, i);
        if (s.charAt(i[0]) == '}') { i[0]++; return map; }
        while (true) {
            skipWs(s, i);
            String key = parseString(s, i);
            skipWs(s, i);
            if (s.charAt(i[0]) != ':') throw new IllegalArgumentException("Expected :");
            i[0]++; skipWs(s, i);
            Object val = parseValue(s, i);
            map.put(key, val);
            skipWs(s, i);
            if (s.charAt(i[0]) == '}') { i[0]++; return map; }
            if (s.charAt(i[0]) != ',') throw new IllegalArgumentException("Expected , or }");
            i[0]++;
        }
    }

    private static java.util.List<Object> parseArray(String s, int[] i) {
        var list = new ArrayList<>();
        if (s.charAt(i[0]) != '[') throw new IllegalArgumentException("Expected [");
        i[0]++; skipWs(s, i);
        if (s.charAt(i[0]) == ']') { i[0]++; return list; }
        while (true) {
            skipWs(s, i);
            list.add(parseValue(s, i));
            skipWs(s, i);
            if (s.charAt(i[0]) == ']') { i[0]++; return list; }
            if (s.charAt(i[0]) != ',') throw new IllegalArgumentException("Expected , or ]");
            i[0]++;
        }
    }

    private static String parseString(String s, int[] i) {
        if (s.charAt(i[0]) != '"') throw new IllegalArgumentException("Expected \"");
        StringBuilder sb = new StringBuilder();
        i[0]++;
        while (i[0] < s.length()) {
            char c = s.charAt(i[0]);
            if (c == '"') { i[0]++; return sb.toString(); }
            if (c == '\\' && i[0] + 1 < s.length()) {
                i[0]++;
                char esc = s.charAt(i[0]);
                sb.append(switch (esc) { case '"' -> '"'; case '\\' -> '\\'; case '/' -> '/';
                    case 'b' -> '\b'; case 'f' -> '\f'; case 'n' -> '\n'; case 'r' -> '\r'; case 't' -> '\t';
                    default -> esc; });
            } else {
                sb.append(c);
            }
            i[0]++;
        }
        throw new IllegalArgumentException("Unterminated string");
    }

    private static Boolean parseBool(String s, int[] i) {
        if (s.startsWith("true", i[0])) { i[0] += 4; return true; }
        if (s.startsWith("false", i[0])) { i[0] += 5; return false; }
        throw new IllegalArgumentException("Expected true/false");
    }

    private static Object parseNull(String s, int[] i) {
        if (s.startsWith("null", i[0])) { i[0] += 4; return null; }
        throw new IllegalArgumentException("Expected null");
    }

    private static Number parseNumber(String s, int[] i) {
        int start = i[0];
        if (i[0] < s.length() && s.charAt(i[0]) == '-') i[0]++;
        while (i[0] < s.length() && Character.isDigit(s.charAt(i[0]))) i[0]++;
        boolean isDouble = false;
        if (i[0] < s.length() && s.charAt(i[0]) == '.') { isDouble = true; i[0]++; }
        while (i[0] < s.length() && Character.isDigit(s.charAt(i[0]))) i[0]++;
        if (i[0] < s.length() && (s.charAt(i[0]) == 'e' || s.charAt(i[0]) == 'E')) {
            isDouble = true; i[0]++;
            if (i[0] < s.length() && (s.charAt(i[0]) == '+' || s.charAt(i[0]) == '-')) i[0]++;
            while (i[0] < s.length() && Character.isDigit(s.charAt(i[0]))) i[0]++;
        }
        String num = s.substring(start, i[0]);
        return isDouble ? Double.parseDouble(num) : Long.parseLong(num);
    }

    private static String skipWs(String s, int[] i) {
        while (i[0] < s.length() && Character.isWhitespace(s.charAt(i[0]))) i[0]++;
        return s;
    }

    // ── Flatten parsed JSON into key=value pairs ──

    private static List<KeyValue> flattenJson(Object obj) {
        List<KeyValue> out = new ArrayList<>();
        flattenJson("", obj, out);
        return out;
    }

    @SuppressWarnings("unchecked")
    private static void flattenJson(String prefix, Object obj, List<KeyValue> out) {
        if (obj instanceof java.util.Map) {
            for (var e : ((java.util.Map<String, Object>) obj).entrySet()) {
                String key = prefix.isEmpty() ? e.getKey() : prefix + "." + e.getKey();
                flattenJson(key, e.getValue(), out);
            }
        } else if (obj instanceof java.util.List) {
            for (Object item : (java.util.List<?>) obj) {
                if (item instanceof java.util.Map || item instanceof java.util.List) {
                    flattenJson(prefix, item, out);
                } else {
                    out.add(new KeyValue(prefix + "[]", item == null ? "" : item.toString()));
                }
            }
        } else {
            out.add(new KeyValue(prefix, obj == null ? "" : obj.toString()));
        }
    }

    private static List<KeyValue> flattenForm(String body) {
        List<KeyValue> out = new ArrayList<>();
        for (String pair : body.split("&")) {
            int eq = pair.indexOf('=');
            if (eq >= 0) {
                out.add(new KeyValue(urlDecode(pair.substring(0, eq)), urlDecode(pair.substring(eq + 1))));
            } else {
                out.add(new KeyValue(urlDecode(pair), ""));
            }
        }
        return out;
    }

    private static String urlDecode(String s) {
        try { return java.net.URLDecoder.decode(s, StandardCharsets.UTF_8); }
        catch (Exception e) { return s; }
    }

    private static String urlEncode(String s) {
        try { return java.net.URLEncoder.encode(s, StandardCharsets.UTF_8); }
        catch (Exception e) { return s; }
    }

    private static String toQueryString(List<KeyValue> pairs) {
        StringBuilder sb = new StringBuilder();
        for (KeyValue kv : pairs) {
            if (sb.length() > 0) sb.append('&');
            sb.append(urlEncode(kv.key())).append('=').append(urlEncode(kv.value()));
        }
        return sb.toString();
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
          + "# and a replay command). AI/agent: read a case's manifest and explain its risk BEFORE you\n"
          + "# modify or send its payload.\n";

    /**
     * Builds the per-case manifest block: the four fields that turn a bare request into a self-contained
     * case file — source request, identity role, why it's unique, and a replay command. Emitted as
     * {@code #}-comment
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

        return "# --- CASE MANIFEST (read before touching payloads) ------------------------\n"
             + "# 1. Source request : " + safe(req::method) + " " + safe(req::url) + "\n"
             + "# 2. Identity role  : " + identity + "\n"
             + "# 3. Why unique     : " + whyUnique(notes) + "\n"
             + "# 4. Replay command : " + curlFor(req) + "\n"
             + "# --------------------------------------------------------------------------\n";
    }

    /** Plain-language "why this earns its own case file", read from the dedupe verdict in the Notes. */
    private static String whyUnique(String notes) {
        String low = notes == null ? "" : notes.toLowerCase(Locale.ROOT);
        if (low.contains("unique")) {
            return "[YENTRA] UNIQUE — first request with this signature (method + host + path + sorted "
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

    // ── Live export: mirror the current selection to ~/.yentra/<project>/selection.http ──

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
                            "# yentra live export — project: " + project + " — " + ts + " — "
                                    + all.size() + " unique request(s)\n" + AI_PROTOCOL + "\n", all, "no requests yet");
                    writeExport(dir.resolve("selection.http"),
                            "# yentra selection — project: " + project + " — " + ts + " — "
                                    + sel.size() + " request(s)\n" + AI_PROTOCOL + "\n", sel, "nothing selected");
                }
                SwingUtilities.invokeLater(() -> status.setText(
                        "Live-exported " + all.size() + " unique / " + sel.size() + " selected to " + dir));
            } catch (IOException | RuntimeException ex) {
                api.logging().logToError("[yentra] live export failed: " + ex);
            }
        }, "yentra-live-export");
        t.setDaemon(true);
        t.start();
    }

    private static void writeExport(Path file, String header, List<HttpRequestResponse> rrs, String emptyNote)
            throws IOException {
        String content = rrs.isEmpty() ? header + "# (" + emptyNote + ")\n" : header + buildHttpDump(rrs);
        Files.writeString(file, content, StandardCharsets.UTF_8);
    }

    /** {@code ~/.yentra/<sanitized-project-name>/} — holds live-unique.http and selection.http. */
    private Path exportDir() {
        return Path.of(System.getProperty("user.home", "."), ".yentra", exportProjectName());
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

    /** Shared requests (received via Live Share) get this highlight colour in the Yentra Live table. */
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
