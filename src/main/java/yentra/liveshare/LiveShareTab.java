package yentra.liveshare;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import yentra.proxy.UniqueFeed;
import yentra.ui.UniqueRequestsViewer;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.SocketException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public class LiveShareTab {
    private final MontoyaApi api;
    private final UniqueFeed liveFeed;
    private final JPanel root;
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;

    private final JTextField serverPortField = new JTextField("9999", 6);
    private final JButton startServerBtn = new JButton("Start Server");
    private final JLabel serverStatus = new JLabel("Stopped");

    private final JTextField connectHostField = new JTextField(15);
    private final JTextField connectPortField = new JTextField("9999", 6);
    private final JButton connectBtn = new JButton("Connect");
    private final JLabel clientStatus = new JLabel("Disconnected");

    private final JButton shareBtn = new JButton("Share this request");
    private final JCheckBox autoShareCb = new JCheckBox("Auto-share new uniques", true);
    private final JCheckBox reissueCb = new JCheckBox("Re-issue received → Proxy history", false);
    private final JTextField proxyPortField = new JTextField("8080", 5);
    private final DefaultListModel<LogEntry> logModel = new DefaultListModel<>();
    private final JList<LogEntry> logList = new JList<>(logModel);

    private ShareServer server;
    private ShareClient client;
    private UpnpPortMapper upnpMapper;
    private SshTunnel sshTunnel;
    private volatile HttpRequest currentRequest;

    /** Single-thread executor for re-issuing shared requests — bounds thread spawn and prevents Burp lag. */
    private final ThreadPoolExecutor reissueExecutor = new ThreadPoolExecutor(
            1, 1, 30, TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(50),   // max 50 queued; extras are dropped
            r -> { Thread t = new Thread(r, "liveshare-reissue"); t.setDaemon(true); return t; },
            new ThreadPoolExecutor.DiscardPolicy()  // silently drop if queue is full — never block the receiver
    );
    private final AtomicLong reissueDropped = new AtomicLong();

    private final JCheckBox useSshTunnelCb = new JCheckBox("Use SSH tunnel (serveo.net)", false);
    private final JLabel sshStatusLabel = new JLabel(" ");

    private RelayClient relayClient;
    private final JTextField relayUrlField = new JTextField("http://localhost:8080", 14);
    private final JTextField relayRoomField = new JTextField(8);
    private final JButton connectRelayBtn = new JButton("Connect");
    private final JLabel relayStatus = new JLabel("Disconnected");

    private static final String DEFAULT_HOST = "localhost";

    public LiveShareTab(MontoyaApi api, UniqueFeed liveFeed) {
        this.api = api;
        this.liveFeed = liveFeed;
        this.requestEditor = api.userInterface().createHttpRequestEditor();
        this.responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        this.root = buildUI();
    }

    public Component component() { return root; }

    private JPanel buildUI() {
        JPanel p = new JPanel(new BorderLayout(0, 6));
        p.setBorder(new EmptyBorder(8, 8, 8, 8));

        p.add(buildHeader(), BorderLayout.NORTH);
        p.add(buildCenter(), BorderLayout.CENTER);

        return p;
    }

    private Component buildHeader() {
        JPanel header = new JPanel();
        header.setLayout(new BoxLayout(header, BoxLayout.Y_AXIS));

        JLabel title = new JLabel("Live Share");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 14f));
        title.setAlignmentX(Component.LEFT_ALIGNMENT);
        header.add(title);
        header.add(Box.createVerticalStrut(8));

        // Server section
        JPanel serverPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        serverPanel.setBorder(BorderFactory.createTitledBorder("Host a server"));
        serverPortField.setToolTipText("Port for friends to connect to (default: 9999)");
        startServerBtn.addActionListener(e -> toggleServer());
        serverPanel.add(new JLabel("Port:"));
        serverPanel.add(serverPortField);
        serverPanel.add(startServerBtn);
        serverPanel.add(Box.createHorizontalStrut(8));
        serverStatus.setFont(serverStatus.getFont().deriveFont(Font.ITALIC, 11f));
        serverPanel.add(serverStatus);
        serverPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        header.add(serverPanel);

        header.add(Box.createVerticalStrut(4));

        // Client section
        JPanel clientPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        clientPanel.setBorder(BorderFactory.createTitledBorder("Connect to friend"));
        connectHostField.setText(DEFAULT_HOST);
        connectHostField.setToolTipText("Friend's IP address or hostname");
        connectPortField.setToolTipText("Friend's server port");
        connectBtn.addActionListener(e -> toggleClient());
        clientPanel.add(new JLabel("Host:"));
        clientPanel.add(connectHostField);
        clientPanel.add(new JLabel("Port:"));
        clientPanel.add(connectPortField);
        clientPanel.add(connectBtn);
        clientPanel.add(Box.createHorizontalStrut(8));
        clientStatus.setFont(clientStatus.getFont().deriveFont(Font.ITALIC, 11f));
        clientPanel.add(clientStatus);
        clientPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        header.add(clientPanel);

        // SSH tunnel section
        JPanel sshPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        sshPanel.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 0));
        useSshTunnelCb.setToolTipText("Creates a tunnel via serveo.net so friends over the internet can connect (no UPnP needed)");
        useSshTunnelCb.setEnabled(true);
        sshPanel.add(useSshTunnelCb);
        sshStatusLabel.setFont(sshStatusLabel.getFont().deriveFont(Font.ITALIC, 11f));
        sshStatusLabel.setForeground(Color.DARK_GRAY);
        sshPanel.add(sshStatusLabel);
        sshPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        header.add(sshPanel);
        header.add(Box.createVerticalStrut(4));

        // Relay section (Drop-style pull-based — works on any network)
        JPanel relayPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        relayPanel.setBorder(BorderFactory.createTitledBorder("Use relay (Drop-style)"));
        relayUrlField.setToolTipText("Relay server URL (default: http://localhost:8080)");
        relayRoomField.setToolTipText("Room ID — share this with your friend");
        relayRoomField.setText(randomRoomId());
        connectRelayBtn.addActionListener(e -> toggleRelay());
        relayPanel.add(new JLabel("URL:"));
        relayPanel.add(relayUrlField);
        relayPanel.add(new JLabel("Room:"));
        relayPanel.add(relayRoomField);
        relayPanel.add(connectRelayBtn);
        relayPanel.add(Box.createHorizontalStrut(4));
        relayStatus.setFont(relayStatus.getFont().deriveFont(Font.ITALIC, 11f));
        relayPanel.add(relayStatus);
        relayPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        header.add(relayPanel);

        header.add(Box.createVerticalStrut(4));

        // Status hint
        JLabel hint = new JLabel("When connected + auto-share on, new uniques in Yentra Live are sent to peers.");
        hint.setFont(hint.getFont().deriveFont(Font.PLAIN, 10f));
        hint.setForeground(Color.GRAY);
        hint.setAlignmentX(Component.LEFT_ALIGNMENT);
        hint.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 0));
        header.add(Box.createVerticalStrut(2));
        header.add(hint);

        return header;
    }

    private Component buildCenter() {
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        split.setResizeWeight(0.55);

        // Top: editors + share button
        JPanel top = new JPanel(new BorderLayout(4, 4));

        shareBtn.setFont(shareBtn.getFont().deriveFont(Font.BOLD));
        shareBtn.setEnabled(false);
        shareBtn.setToolTipText("Share the request in the editor above with all connected peers");
        shareBtn.addActionListener(e -> shareCurrentRequest());

        autoShareCb.setToolTipText("<html>When connected, every new [YENTRA] UNIQUE request in Yentra Live is "
                + "automatically forwarded to peers. Untick to share manually only.</html>");
        autoShareCb.addItemListener(e -> {
            UniqueRequestsViewer.setAutoShare(autoShareCb.isSelected() && isAnyConnectionActive());
        });

        reissueCb.setToolTipText("<html>Re-issues every received shared request <b>through Burp's local proxy</b> so it "
                + "appears in <b>Proxy HTTP history</b> alongside your own traffic. The request is actually sent "
                + "to the target server — the response is the target's live reply. Set the proxy listener port "
                + "below (default 8080).</html>");

        proxyPortField.setToolTipText("Local Burp proxy listener port (default 8080). The shared request is sent through this proxy so it appears in HTTP history.");

        JPanel shareBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        shareBar.add(new JLabel("Repeater:"));
        shareBar.add(shareBtn);
        shareBar.add(Box.createHorizontalStrut(8));
        shareBar.add(autoShareCb);
        shareBar.add(reissueCb);
        shareBar.add(new JLabel("Proxy:"));
        shareBar.add(proxyPortField);
        shareBar.add(Box.createHorizontalGlue());

        JSplitPane editors = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                requestEditor.uiComponent(), responseEditor.uiComponent());
        editors.setResizeWeight(0.5);

        top.add(shareBar, BorderLayout.NORTH);
        top.add(editors, BorderLayout.CENTER);

        // Bottom: received requests log
        JPanel bottom = new JPanel(new BorderLayout());
        bottom.setBorder(BorderFactory.createTitledBorder("Received shared requests"));
        logList.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        logList.setToolTipText("Double-click a request to open it in a Repeater tab");
        logList.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int idx = logList.locationToIndex(e.getPoint());
                    if (idx >= 0) {
                        LogEntry entry = logModel.getElementAt(idx);
                        entry.openInRepeater(api);
                    }
                }
            }
        });
        bottom.add(new JScrollPane(logList), BorderLayout.CENTER);

        split.setTopComponent(top);
        split.setBottomComponent(bottom);

        return split;
    }

    private void toggleServer() {
        if (server != null && server.isRunning()) {
            stopSharing();
            if (sshTunnel != null) {
                sshTunnel.stop();
                sshTunnel = null;
            }
            useSshTunnelCb.setEnabled(true);
            sshStatusLabel.setText(" ");
            startServerBtn.setText("Start Server");
            serverStatus.setText("Stopped");
            serverStatus.setForeground(Color.GRAY);
        } else {
            int port;
            try {
                port = Integer.parseInt(serverPortField.getText().trim());
                if (port < 1 || port > 65535) throw new NumberFormatException();
            } catch (NumberFormatException ex) {
                serverStatus.setText("Invalid port");
                serverStatus.setForeground(Color.RED);
                return;
            }

            if (client != null && client.isConnected()) client.disconnect();

            startServerBtn.setEnabled(false);
            serverStatus.setText("Starting on port " + port + "…");
            serverStatus.setForeground(new Color(0, 100, 0));

            final int fPort = port;
            new Thread(() -> {
                try {
                    ShareServer s = new ShareServer(api, fPort, this::onReceived, this::onServerActivity);
                    s.start();

                    // Attempt UPnP port forwarding so friends across the internet can connect.
                    String extra = "";
                    String publicIp = null;
                    UpnpPortMapper mapper = new UpnpPortMapper(fPort);
                    if (mapper.addMapping()) {
                        publicIp = mapper.publicIp();
                        extra = "  UPnP: " + (publicIp != null ? publicIp : "ok");
                        api.logging().logToOutput("[yentra] UPnP port " + fPort + " forwarded"
                                + (publicIp != null ? " → public IP " + publicIp : ""));
                    } else {
                        api.logging().logToOutput("[yentra] UPnP not available — "
                                + "friend needs LAN access or port forwarding");
                    }

                    // Start SSH tunnel if the user opted in (works across NAT without UPnP)
                    if (useSshTunnelCb.isSelected()) {
                        api.logging().logToOutput("[yentra] Starting SSH tunnel via serveo.net…");
                        SwingUtilities.invokeLater(() ->
                                sshStatusLabel.setText("Starting SSH tunnel via serveo.net…"));
                        SshTunnel tunnel = new SshTunnel(fPort);
                        tunnel.start();
                        sshTunnel = tunnel;
                        // Wait for tunnel readiness in a background thread (don't block server start)
                        new Thread(() -> {
                            if (tunnel.await(20)) {
                                String addr = tunnel.publicAddress();
                                if (addr != null) {
                                    api.logging().logToOutput("[yentra] SSH tunnel ready: " + addr);
                                    SwingUtilities.invokeLater(() -> {
                                        sshStatusLabel.setText("Public: " + addr);
                                        sshStatusLabel.setForeground(new Color(0, 128, 0));
                                        String current = serverStatus.getText();
                                        if (!current.contains("Public:")) {
                                            serverStatus.setText(current + "  Public: " + addr);
                                        }
                                    });
                                } else {
                                    String err = tunnel.errorMessage();
                                    SwingUtilities.invokeLater(() -> {
                                        sshStatusLabel.setText("Tunnel failed: "
                                                + (err != null ? err : "unknown error"));
                                        sshStatusLabel.setForeground(Color.RED);
                                    });
                                }
                            } else {
                                String err = tunnel.errorMessage();
                                SwingUtilities.invokeLater(() -> {
                                    sshStatusLabel.setText("Tunnel timeout: "
                                            + (err != null ? err : "no response from serveo.net"));
                                    sshStatusLabel.setForeground(Color.RED);
                                });
                            }
                        }, "liveshare-ssh-wait").start();
                    }

                    final String fExtra = extra;
                    final UpnpPortMapper fMapper = mapper;
                    final String fPublicIp = publicIp;
                    SwingUtilities.invokeLater(() -> {
                        server = s;
                        upnpMapper = fMapper;
                        useSshTunnelCb.setEnabled(false);
                        startServerBtn.setText("Stop Server");
                        startServerBtn.setEnabled(true);
                        serverStatus.setText("Running on port " + fPort + fExtra);
                        serverStatus.setForeground(new Color(0, 128, 0));
                        connectBtn.setEnabled(false);
                        connectHostField.setEnabled(false);
                        connectPortField.setEnabled(false);
                        enableSharing();
                        if (fPublicIp != null) {
                            api.logging().logToOutput("[yentra] Share this IP with your friend: " + fPublicIp);
                        }
                    });
                } catch (Exception ex) {
                    api.logging().logToError("[yentra] server start failed: " + ex);
                    SwingUtilities.invokeLater(() -> {
                        serverStatus.setText("Failed: " + (ex.getMessage() != null ? ex.getMessage() : ex.getClass().getSimpleName()));
                        serverStatus.setForeground(Color.RED);
                        startServerBtn.setText("Start Server");
                        startServerBtn.setEnabled(true);
                    });
                }
            }, "liveshare-start-server").start();
        }
    }

    private void toggleClient() {
        if (client != null && client.isConnected()) {
            stopSharing();
            client = null;
            connectBtn.setText("Connect");
            clientStatus.setText("Disconnected");
            clientStatus.setForeground(Color.GRAY);
            startServerBtn.setEnabled(true);
            serverPortField.setEnabled(true);
            return;
        }

        String host = connectHostField.getText().trim();
        int port;
        try {
            port = Integer.parseInt(connectPortField.getText().trim());
            if (port < 1 || port > 65535) throw new NumberFormatException();
        } catch (NumberFormatException ex) {
            clientStatus.setText("Invalid port");
            clientStatus.setForeground(Color.RED);
            return;
        }
        if (host.isEmpty()) {
            clientStatus.setText("Enter a host");
            clientStatus.setForeground(Color.RED);
            return;
        }

        if (server != null && server.isRunning()) {
            server.stop();
            server = null;
            startServerBtn.setText("Start Server");
            serverStatus.setText("Stopped");
        }

        // Disable the button, show "Connecting…" — socket connect runs off the EDT.
        connectBtn.setEnabled(false);
        clientStatus.setText("Connecting to " + host + ":" + port + "…");
        clientStatus.setForeground(new Color(0, 100, 0));

        final String fHost = host;
        final int fPort = port;
        new Thread(() -> {
            try {
                ShareClient c = new ShareClient(api, fHost, fPort, this::onReceived, this::onClientActivity);
                c.connect();
                SwingUtilities.invokeLater(() -> {
                    client = c;
                    connectBtn.setText("Disconnect");
                    connectBtn.setEnabled(true);
                    clientStatus.setText("Connected to " + fHost + ":" + fPort);
                    clientStatus.setForeground(new Color(0, 128, 0));
                    startServerBtn.setEnabled(false);
                    serverPortField.setEnabled(false);
                    enableSharing();
                });
            } catch (Exception ex) {
                String failMsg = (ex instanceof SocketException && ex.getMessage() != null
                        && ex.getMessage().contains("Connection refused"))
                        ? "Connection refused"
                        : "Failed: " + (ex.getMessage() != null ? ex.getMessage() : ex.getClass().getSimpleName());
                api.logging().logToError("[yentra] connect failed: " + ex);
                SwingUtilities.invokeLater(() -> {
                    clientStatus.setText(failMsg);
                    clientStatus.setForeground(Color.RED);
                    connectBtn.setText("Connect");
                    connectBtn.setEnabled(true);
                    startServerBtn.setEnabled(true);
                    serverPortField.setEnabled(true);
                });
            }
        }, "liveshare-connect").start();
    }

    private void toggleRelay() {
        if (relayClient != null && relayClient.isRunning()) {
            disconnectRelay();
            return;
        }

        String url = relayUrlField.getText().trim();
        String room = relayRoomField.getText().trim();
        if (url.isEmpty()) {
            relayStatus.setText("Enter relay URL");
            relayStatus.setForeground(Color.RED);
            return;
        }
        if (room.isEmpty()) {
            relayStatus.setText("Enter room ID");
            relayStatus.setForeground(Color.RED);
            return;
        }

        // Disconnect other modes
        if (server != null && server.isRunning()) toggleServer();
        if (client != null && client.isConnected()) toggleClient();

        connectRelayBtn.setEnabled(false);
        relayStatus.setText("Connecting to relay…");
        relayStatus.setForeground(new Color(0, 100, 0));

        final String fUrl = url;
        final String fRoom = room;
        new Thread(() -> {
            try {
                RelayClient rc = new RelayClient(api, fUrl, fRoom,
                        this::onReceived, this::onRelayActivity);
                if (rc.connect()) {
                    SwingUtilities.invokeLater(() -> {
                        relayClient = rc;
                        connectRelayBtn.setText("Disconnect");
                        connectRelayBtn.setEnabled(true);
                        relayStatus.setText("Relay: " + fRoom);
                        relayStatus.setForeground(new Color(0, 128, 0));
                        relayUrlField.setEnabled(false);
                        relayRoomField.setEnabled(false);
                        enableSharing();
                    });
                } else {
                    String msg = rc.statusMessage();
                    SwingUtilities.invokeLater(() -> {
                        relayStatus.setText(msg != null ? msg : "Relay unreachable");
                        relayStatus.setForeground(Color.RED);
                        connectRelayBtn.setText("Connect");
                        connectRelayBtn.setEnabled(true);
                    });
                }
            } catch (Exception ex) {
                api.logging().logToError("[yentra] relay connect failed: " + ex);
                SwingUtilities.invokeLater(() -> {
                    relayStatus.setText("Failed: " + ex.getMessage());
                    relayStatus.setForeground(Color.RED);
                    connectRelayBtn.setText("Connect");
                    connectRelayBtn.setEnabled(true);
                });
            }
        }, "liveshare-relay-connect").start();
    }

    private void disconnectRelay() {
        if (relayClient != null) {
            relayClient.disconnect();
            relayClient = null;
        }
        connectRelayBtn.setText("Connect");
        relayStatus.setText("Disconnected");
        relayStatus.setForeground(Color.GRAY);
        relayUrlField.setEnabled(true);
        relayRoomField.setEnabled(true);
        UniqueRequestsViewer.setAutoShare(false);
        updateShareButton();
    }

    /** True if any transport (server / client / relay) is currently connected. */
    private boolean isAnyConnectionActive() {
        return (server != null && server.isRunning())
                || (client != null && client.isConnected())
                || (relayClient != null && relayClient.isRunning());
    }

    /** Called by the share handler from UniqueRequestsViewer or from the network. */
    private void onReceived(HttpRequestResponse rr, String caption) {
        HttpRequest request = rr.request();
        HttpResponse response = rr.hasResponse() ? rr.response() : HttpResponse.httpResponse();

        // Extract any notes the sender attached (verdict + role tag).
        String notes = "";
        try {
            Annotations ann = rr.annotations();
            if (ann != null && ann.hasNotes() && ann.notes() != null) {
                notes = ann.notes();
            }
        } catch (RuntimeException ignored) {}

        // Push into the Yentra Live view so the receiver sees it in their live log,
        // with a distinct colour so shared requests are visually separate from local ones.
        // Preserve the sender's notes so the Notes column shows the verdict + role tag.
        if (liveFeed != null) {
            try {
                Annotations sharedAnn = notes.isEmpty()
                        ? Annotations.annotations(HighlightColor.MAGENTA)
                        : Annotations.annotations(notes);
                // Apply magenta highlight so shared rows stand out, even if the sender's
                // annotations carried a different colour.
                sharedAnn = sharedAnn.withHighlightColor(HighlightColor.MAGENTA);
                HttpRequestResponse shared = HttpRequestResponse.httpRequestResponse(
                        request, response, sharedAnn);
                liveFeed.publish(shared, -1);
            } catch (RuntimeException ignored) {}
        }

        SwingUtilities.invokeLater(() -> {
            requestEditor.setRequest(request);
            responseEditor.setResponse(response);
            LogEntry entry = new LogEntry(request, response, caption);
            logModel.addElement(entry);
            if (logModel.size() > 500) logModel.removeElementAt(0);
            logList.ensureIndexIsVisible(logModel.size() - 1);
        });

        // Optionally re-issue the shared request through Burp's local proxy so it
        // appears in Proxy HTTP history, and via Burp's HTTP client so it appears in Logger.
        // Uses a bounded single-thread executor to prevent thread explosion from lagging Burp.
        if (reissueCb.isSelected() && request.httpService() != null) {
            final HttpRequest fReq = request;
            final String fCaption = caption;
            int queueBefore = reissueExecutor.getQueue().size();
            reissueExecutor.execute(() -> {
                // Logger: send via Burp's HTTP client — Logger's "capture by tool" picks this up.
                try {
                    api.http().sendRequest(fReq);
                    api.logging().logToOutput("[yentra] Shared request → Logger: " + fCaption);
                } catch (RuntimeException ex) {
                    api.logging().logToError("[yentra] Re-issue to Logger failed: " + ex.getMessage());
                }
                // Proxy HTTP history: send through the local proxy listener.
                try {
                    int pPort;
                    try { pPort = Integer.parseInt(proxyPortField.getText().trim()); }
                    catch (NumberFormatException ex) { pPort = 8080; }
                    reissueThroughProxy(fReq, pPort);
                    api.logging().logToOutput("[yentra] Shared request → Proxy history: " + fCaption);
                } catch (RuntimeException ex) {
                    api.logging().logToError("[yentra] Re-issue to proxy history failed: " + ex.getMessage());
                }
            });
            if (queueBefore >= 50) {
                long dropped = reissueDropped.incrementAndGet();
                if (dropped % 10 == 1) {
                    api.logging().logToOutput("[yentra] Re-issue queue full — dropped " + dropped + " shared request(s).");
                }
            }
        }
    }

    private void enableSharing() {
        updateShareButton();
        UniqueRequestsViewer.setAutoShare(autoShareCb.isSelected());
        api.logging().logToOutput("[yentra] Live Share active — auto-sharing "
                + (autoShareCb.isSelected() ? "ON" : "OFF") + ".");
    }

    private void stopSharing() {
        if (server != null) {
            server.stop();
            if (upnpMapper != null) {
                upnpMapper.removeMapping();
                upnpMapper = null;
            }
            server = null;
        }
        if (sshTunnel != null) {
            sshTunnel.stop();
            sshTunnel = null;
        }
        if (client != null) { client.disconnect(); client = null; }
        if (relayClient != null) { relayClient.disconnect(); relayClient = null; }
        UniqueRequestsViewer.setAutoShare(false);
        updateShareButton();
        api.logging().logToOutput("[yentra] Live Share stopped.");
    }

    private void onServerActivity() {
        SwingUtilities.invokeLater(() -> {
            if (server != null) {
                int count = server.clientCount();
                serverStatus.setText("Running on port " + serverPortField.getText().trim()
                        + " (" + count + " client" + (count == 1 ? "" : "s") + ")");
            }
        });
    }

    private void onClientActivity() {
        SwingUtilities.invokeLater(() -> {
            if (client != null && client.isConnected()) {
                connectBtn.setText("Disconnect");
                clientStatus.setText("Connected to " + connectHostField.getText().trim()
                        + ":" + connectPortField.getText().trim());
                clientStatus.setForeground(new Color(0, 128, 0));
            } else {
                connectBtn.setText("Connect");
                clientStatus.setText("Disconnected");
                clientStatus.setForeground(Color.GRAY);
                startServerBtn.setEnabled(true);
                serverPortField.setEnabled(true);
                UniqueRequestsViewer.setAutoShare(false);
            }
            updateShareButton();
        });
    }

    private void onRelayActivity() {
        SwingUtilities.invokeLater(() -> {
            if (relayClient != null && relayClient.isRunning()) {
                relayStatus.setText("Relay: " + relayRoomField.getText().trim());
                relayStatus.setForeground(new Color(0, 128, 0));
            } else if (relayClient != null) {
                relayStatus.setText(relayClient.statusMessage());
                relayStatus.setForeground(Color.RED);
                connectRelayBtn.setText("Connect");
                connectRelayBtn.setEnabled(true);
                relayUrlField.setEnabled(true);
                relayRoomField.setEnabled(true);
                UniqueRequestsViewer.setAutoShare(false);
            }
            updateShareButton();
        });
    }

    private void updateShareButton() {
        boolean active = (server != null && server.isRunning())
                || (client != null && client.isConnected())
                || (relayClient != null && relayClient.isRunning());
        shareBtn.setEnabled(active && currentRequest != null);
    }

    public void setCurrentRequest(HttpRequest request) {
        this.currentRequest = request;
        SwingUtilities.invokeLater(() -> {
            if (request != null) requestEditor.setRequest(request);
            updateShareButton();
        });
    }

    private void shareCurrentRequest() {
        HttpRequest req = requestEditor.getRequest();
        if (req == null || req.httpService() == null) {
            JOptionPane.showMessageDialog(root,
                    "Load or edit a request first, then click Share.",
                    "Live Share", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        // The request editor has no response — share with an empty one.
        HttpRequestResponse rr = HttpRequestResponse.httpRequestResponse(req, HttpResponse.httpResponse());
        String caption = safeReqLine(req);
        doSend(rr, caption, true);
    }

    /** Forwards a request+response to connected peers without displaying locally. */
    public void shareImmediately(HttpRequestResponse rr, String caption) {
        doSend(rr, caption, false);
    }

    /** Runs the network send on a background thread so the EDT never blocks. */
    private void doSend(HttpRequestResponse rr, String caption, boolean logIt) {
        Thread t = new Thread(() -> {
            boolean sent = false;
            if (server != null && server.isRunning()) {
                server.broadcast(rr, caption);
                sent = true;
            } else if (client != null && client.isConnected()) {
                client.share(rr, caption);
                sent = true;
            } else if (relayClient != null && relayClient.isRunning()) {
                relayClient.share(rr, caption);
                sent = true;
            }
            if (sent && logIt) {
                api.logging().logToOutput("[yentra] Shared: " + caption);
            }
        }, "liveshare-send");
        t.setDaemon(true);
        t.start();
    }

    // ── Re-issue through the local proxy so the request lands in Proxy HTTP history ──

    /** A trust-all TLS context so HTTPS through Burp's MITM proxy works without cert errors. */
    private static volatile SSLContext trustAllSslContext;
    private static final TrustManager[] TRUST_ALL = { new X509TrustManager() {
        @Override public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }};
    private static SSLContext trustAllSsl() {
        if (trustAllSslContext != null) return trustAllSslContext;
        try {
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, TRUST_ALL, new java.security.SecureRandom());
            trustAllSslContext = sc;
            return sc;
        } catch (Exception e) {
            try {
                return SSLContext.getDefault();
            } catch (Exception ex) {
                throw new RuntimeException("No SSLContext available", ex);
            }
        }
    }

    /** Cached client keyed by proxy port — rebuilt only when the port changes. */
    private volatile java.net.http.HttpClient proxyClient;
    private volatile int proxyClientPort = -1;

    /**
     * Sends a shared request through Burp's local proxy listener using {@link java.net.http.HttpClient}.
     * The proxy records the transaction in Proxy HTTP history and forwards it to the target.
     * HTTPS is handled natively (CONNECT + TLS) by the JDK's HTTP client with a trust-all SSL
     * context so Burp's MITM certificate is accepted.
     */
    private void reissueThroughProxy(HttpRequest request, int proxyPort) {
        try {
            java.net.http.HttpClient client = proxyClientFor(proxyPort);

            // Build the JDK request from the Montoya request
            URI uri = URI.create(request.url());
            byte[] body = request.body().getBytes();
            java.net.http.HttpRequest.BodyPublisher bodyPublisher = body.length > 0
                    ? java.net.http.HttpRequest.BodyPublishers.ofByteArray(body)
                    : java.net.http.HttpRequest.BodyPublishers.noBody();

            java.net.http.HttpRequest.Builder rb = java.net.http.HttpRequest.newBuilder()
                    .uri(uri)
                    .method(request.method(), bodyPublisher);

            // Copy headers (skip restricted ones the JDK manages itself)
            for (HttpHeader h : request.headers()) {
                String name = h.name();
                if (name == null) continue;
                String lower = name.toLowerCase(Locale.ROOT);
                if (lower.equals("content-length") || lower.equals("host")
                        || lower.equals("connection") || lower.equals("transfer-encoding")) continue;
                try {
                    rb.header(name, h.value());
                } catch (IllegalArgumentException ignored) {
                    // JDK restricts certain header names — skip them
                }
            }

            // Send async with a 15s timeout — slow targets won't clog the re-issue queue.
            java.net.http.HttpRequest jreq = rb.timeout(java.time.Duration.ofSeconds(15)).build();
            try {
                java.net.http.HttpResponse<byte[]> resp = client.send(jreq,
                        java.net.http.HttpResponse.BodyHandlers.ofByteArray());
                api.logging().logToOutput("[yentra] Proxy re-issue: " + request.method() + " "
                        + request.url() + " -> " + resp.statusCode());
            } catch (java.net.http.HttpTimeoutException ignored) {
                api.logging().logToOutput("[yentra] Proxy re-issue timed out (15s): " + request.url());
            }
        } catch (Exception e) {
            throw new RuntimeException("proxy re-issue failed: " + e.getMessage(), e);
        }
    }

    /** Returns (or builds) an HttpClient configured with the given proxy port + trust-all SSL. */
    private java.net.http.HttpClient proxyClientFor(int proxyPort) {
        if (proxyClient != null && proxyClientPort == proxyPort) return proxyClient;
        SSLContext sc = trustAllSsl();
        javax.net.ssl.SSLParameters sslParams = sc.getDefaultSSLParameters();
        sslParams.setEndpointIdentificationAlgorithm(null); // disable hostname check (Burp MITM)
        java.net.http.HttpClient c = java.net.http.HttpClient.newBuilder()
                .proxy(ProxySelector.of(new InetSocketAddress("127.0.0.1", proxyPort)))
                .sslContext(sc)
                .sslParameters(sslParams)
                .connectTimeout(java.time.Duration.ofSeconds(10))
                .build();
        proxyClient = c;
        proxyClientPort = proxyPort;
        return c;
    }

    private static class LogEntry {
        final String method;
        final String url;
        final byte[] requestBytes;
        final byte[] responseBytes;
        final String caption;

        LogEntry(HttpRequest request, HttpResponse response, String caption) {
            this.method = request.method();
            this.url = request.url();
            this.requestBytes = request.toByteArray().getBytes();
            this.responseBytes = response != null ? response.toByteArray().getBytes() : new byte[0];
            this.caption = caption;
        }

        void openInRepeater(MontoyaApi api) {
            HttpRequest req = HttpRequest.httpRequest(ByteArray.byteArray(requestBytes));
            api.repeater().sendToRepeater(req, caption);
        }

        @Override
        public String toString() {
            return method + "  " + (url.length() > 100 ? url.substring(0, 100) + "..." : url);
        }
    }

    private static String safeReqLine(HttpRequest req) {
        try {
            String method = req.method() == null ? "" : req.method();
            String path = req.path() == null ? "" : req.path();
            String caption = (method + " " + path).trim();
            return caption.length() > 80 ? caption.substring(0, 80) : caption;
        } catch (RuntimeException e) {
            return "shared-request";
        }
    }

    private static String randomRoomId() {
        String chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder(8);
        ThreadLocalRandom rng = ThreadLocalRandom.current();
        for (int i = 0; i < 8; i++) {
            sb.append(chars.charAt(rng.nextInt(chars.length())));
        }
        return sb.toString();
    }
}
