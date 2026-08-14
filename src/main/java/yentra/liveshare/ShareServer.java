package yentra.liveshare;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.HttpService;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BiConsumer;

public class ShareServer {
    private final MontoyaApi api;
    private final int port;
    private final BiConsumer<HttpRequestResponse, String> onReceive;
    private final Runnable onClientChange;
    private ServerSocket serverSocket;
    private final List<ClientHandler> clients = new CopyOnWriteArrayList<>();
    private volatile boolean running;
    private Thread acceptThread;

    public ShareServer(MontoyaApi api, int port,
                       BiConsumer<HttpRequestResponse, String> onReceive,
                       Runnable onClientChange) {
        this.api = api;
        this.port = port;
        this.onReceive = onReceive;
        this.onClientChange = onClientChange;
    }

    public synchronized void start() throws IOException {
        if (running) return;
        // Reuse the port after a stop/restart and bind all interfaces so peers on
        // the LAN/VPN can reach the extension (the UI advertises the address).
        serverSocket = new ServerSocket();
        serverSocket.setReuseAddress(true);
        serverSocket.bind(new InetSocketAddress("0.0.0.0", port), 50);
        running = true;
        acceptThread = new Thread(this::acceptLoop, "liveshare-accept");
        acceptThread.setDaemon(true);
        acceptThread.start();
        api.logging().logToOutput("[yentra] Live Share server started on port " + port);
    }

    public synchronized void stop() {
        running = false;
        for (ClientHandler h : clients) h.close();
        clients.clear();
        try { if (serverSocket != null) serverSocket.close(); } catch (IOException ignored) {}
        if (acceptThread != null) acceptThread.interrupt();
        api.logging().logToOutput("[yentra] Live Share server stopped");
        if (onClientChange != null) onClientChange.run();
    }

    public boolean isRunning() { return running; }
    public int clientCount() { return clients.size(); }

    public void broadcast(HttpRequestResponse rr, String caption) {
        if (!running) return;
        byte[] msg = encodeMessage(rr, caption);
        if (msg == null) return;
        for (ClientHandler h : clients) {
            h.send(msg);
        }
    }

    /**
     * Wire format (all length-prefixed, big-endian):
     * <pre>
     *   [int reqLen][reqBytes]
     *   [int urlLen][urlBytes]
     *   [int capLen][capBytes]
     *   [int respLen][respBytes]      // 0 = no response
     *   [int notesLen][notesBytes]    // 0 = no notes (backward compatible)
     * </pre>
     * Fields after caption are optional — old receivers that stop reading after caption
     * simply ignore them. Each optional field is guarded by an availability check in
     * {@link #decodeMessage}.
     */
    public static byte[] encodeMessage(HttpRequestResponse rr, String caption) {
        try {
            HttpRequest request = rr.request();
            byte[] reqBytes = request.toByteArray().getBytes();
            String url = request.url() != null ? request.url() : "";
            byte[] urlBytes = url.getBytes(StandardCharsets.UTF_8);
            byte[] capBytes = caption.getBytes(StandardCharsets.UTF_8);
            byte[] respBytes;
            if (rr.hasResponse() && rr.response() != null) {
                respBytes = rr.response().toByteArray().getBytes();
            } else {
                respBytes = new byte[0];
            }
            String notes = "";
            try {
                Annotations ann = rr.annotations();
                if (ann != null && ann.hasNotes() && ann.notes() != null) {
                    notes = ann.notes();
                }
            } catch (RuntimeException ignored) {}
            byte[] notesBytes = notes.getBytes(StandardCharsets.UTF_8);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(bos);
            dos.writeInt(reqBytes.length);
            dos.write(reqBytes);
            dos.writeInt(urlBytes.length);
            dos.write(urlBytes);
            dos.writeInt(capBytes.length);
            dos.write(capBytes);
            dos.writeInt(respBytes.length);
            dos.write(respBytes);
            dos.writeInt(notesBytes.length);
            dos.write(notesBytes);
            return bos.toByteArray();
        } catch (IOException e) {
            return null;
        }
    }

    private void acceptLoop() {
        while (running) {
            try {
                Socket s = serverSocket.accept();
                ClientHandler h = new ClientHandler(s);
                clients.add(h);
                Thread t = new Thread(h, "liveshare-client-" + s.getPort());
                t.setDaemon(true);
                t.start();
                api.logging().logToOutput("[yentra] Live Share client connected: "
                        + s.getRemoteSocketAddress());
                if (onClientChange != null) onClientChange.run();
            } catch (IOException e) {
                if (running) {
                    api.logging().logToError("[yentra] accept failed: " + e);
                }
            }
        }
    }

    /** Parse a full URL into an HttpService (host, port, https). Returns null on failure. */
    static HttpService httpServiceFromUrl(String url) {
        try {
            java.net.URI uri = new java.net.URI(url);
            String host = uri.getHost();
            if (host == null || host.isEmpty()) return null;
            int port = uri.getPort();
            boolean useHttps = "https".equalsIgnoreCase(uri.getScheme());
            if (port < 0) port = useHttps ? 443 : 80;
            return HttpService.httpService(host, port, useHttps);
        } catch (Exception e) {
            return null;
        }
    }

    private class ClientHandler implements Runnable, Closeable {
        private final Socket socket;
        private final DataInputStream in;
        private final OutputStream out;

        ClientHandler(Socket socket) throws IOException {
            this.socket = socket;
            this.in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            this.out = socket.getOutputStream();
        }

        void send(byte[] msg) {
            try {
                synchronized (out) {
                    out.write(new byte[]{
                            (byte) (msg.length >>> 24),
                            (byte) (msg.length >>> 16),
                            (byte) (msg.length >>> 8),
                            (byte) msg.length
                    });
                    out.write(msg);
                    out.flush();
                }
            } catch (IOException e) {
                close();
            }
        }

        @Override
        public void run() {
            try {
                while (running && !socket.isClosed()) {
                    int msgLen = in.readInt();
                    byte[] payload = new byte[msgLen];
                    in.readFully(payload);
                    HttpRequestResponse rr = decodeMessage(payload);
                    if (rr == null) continue;

                    if (onReceive != null) {
                        String caption = extractCaption(payload);
                        onReceive.accept(rr, caption);
                    }

                    byte[] msg = payload;
                    for (ClientHandler h : clients) {
                        if (h != this) h.send(msg);
                    }
                }
            } catch (EOFException | SocketException ignored) {
            } catch (IOException e) {
                if (running) {
                    api.logging().logToError("[yentra] client handler: " + e);
                }
            } finally {
                close();
                clients.remove(this);
                if (onClientChange != null) onClientChange.run();
                api.logging().logToOutput("[yentra] Live Share client disconnected");
            }
        }

        @Override
        public void close() {
            try { socket.close(); } catch (IOException ignored) {}
        }
    }

    /**
     * Decodes a wire-format payload into an {@link HttpRequestResponse} (request + optional
     * response + optional notes/annotations). Returns null on failure.
     */
    static HttpRequestResponse decodeMessage(byte[] payload) {
        try {
            DataInputStream dis = new DataInputStream(new ByteArrayInputStream(payload));
            int reqLen = dis.readInt();
            byte[] reqBytes = new byte[reqLen];
            dis.readFully(reqBytes);
            int urlLen = dis.readInt();
            byte[] urlBytes = new byte[urlLen];
            dis.readFully(urlBytes);
            int capLen = dis.readInt();
            byte[] capBytes = new byte[capLen];
            dis.readFully(capBytes);

            String urlStr = new String(urlBytes, StandardCharsets.UTF_8);
            HttpRequest req = HttpRequest.httpRequest(ByteArray.byteArray(reqBytes));
            if (!urlStr.isEmpty()) {
                HttpService svc = httpServiceFromUrl(urlStr);
                if (svc != null) req = HttpRequest.httpRequest(svc, ByteArray.byteArray(reqBytes));
            }

            HttpResponse resp = null;
            // Response field may be absent (old sender) — check remaining bytes.
            if (dis.available() >= 4) {
                int respLen = dis.readInt();
                if (respLen > 0) {
                    byte[] respBytes = new byte[respLen];
                    dis.readFully(respBytes);
                    resp = HttpResponse.httpResponse(ByteArray.byteArray(respBytes));
                }
            }

            String notes = "";
            // Notes field may be absent (old sender) — check remaining bytes.
            if (dis.available() >= 4) {
                int notesLen = dis.readInt();
                if (notesLen > 0) {
                    byte[] notesBytes = new byte[notesLen];
                    dis.readFully(notesBytes);
                    notes = new String(notesBytes, StandardCharsets.UTF_8);
                }
            }

            Annotations ann = (notes != null && !notes.isEmpty())
                    ? Annotations.annotations(notes)
                    : null;

            if (resp != null) {
                return ann != null
                        ? HttpRequestResponse.httpRequestResponse(req, resp, ann)
                        : HttpRequestResponse.httpRequestResponse(req, resp);
            }
            return ann != null
                    ? HttpRequestResponse.httpRequestResponse(req, HttpResponse.httpResponse(), ann)
                    : HttpRequestResponse.httpRequestResponse(req, HttpResponse.httpResponse());
        } catch (IOException e) {
            return null;
        }
    }

    /** Extracts just the caption string from a wire-format payload. */
    static String extractCaption(byte[] payload) {
        try {
            DataInputStream dis = new DataInputStream(new ByteArrayInputStream(payload));
            int reqLen = dis.readInt();
            dis.skipBytes(reqLen);
            int urlLen = dis.readInt();
            dis.skipBytes(urlLen);
            int capLen = dis.readInt();
            byte[] capBytes = new byte[capLen];
            dis.readFully(capBytes);
            return new String(capBytes, StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "";
        }
    }
}
