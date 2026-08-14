package yentra.liveshare;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.io.*;
import java.net.*;
import java.util.function.BiConsumer;

public class ShareClient {
    private final MontoyaApi api;
    private final String host;
    private final int port;
    private final BiConsumer<HttpRequestResponse, String> onReceive;
    private final Runnable onConnectionChange;
    private Socket socket;
    private DataInputStream in;
    private OutputStream out;
    private volatile boolean connected;
    private Thread readThread;

    public ShareClient(MontoyaApi api, String host, int port,
                       BiConsumer<HttpRequestResponse, String> onReceive,
                       Runnable onConnectionChange) {
        this.api = api;
        this.host = host;
        this.port = port;
        this.onReceive = onReceive;
        this.onConnectionChange = onConnectionChange;
    }

    private static final int CONNECT_TIMEOUT_MS = 10000;

    public synchronized void connect() throws IOException {
        if (connected) return;
        IOException lastFailure = null;
        InetAddress[] addresses = InetAddress.getAllByName(host);
        Socket connectedSocket = null;
        for (InetAddress address : addresses) {
            Socket candidate = new Socket();
            try {
                candidate.setTcpNoDelay(true);
                candidate.connect(new InetSocketAddress(address, port), CONNECT_TIMEOUT_MS);
                connectedSocket = candidate;
                lastFailure = null;
                break;
            } catch (IOException e) {
                lastFailure = e;
                try { candidate.close(); } catch (IOException ignored) {}
            }
        }
        if (connectedSocket == null) {
            String detail = lastFailure != null && lastFailure.getMessage() != null
                    ? lastFailure.getMessage() : "no address was reachable";
            throw new IOException("Could not connect to " + host + ":" + port
                    + " (tried " + addresses.length + " address"
                    + (addresses.length == 1 ? "" : "es") + "): " + detail);
        }
        socket = connectedSocket;
        in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
        out = socket.getOutputStream();
        connected = true;
        readThread = new Thread(this::readLoop, "liveshare-client-read");
        readThread.setDaemon(true);
        readThread.start();
        api.logging().logToOutput("[yentra] Live Share connected to " + host + ":" + port);
        if (onConnectionChange != null) onConnectionChange.run();
    }

    public synchronized void disconnect() {
        if (!connected) return;
        connected = false;
        try { if (socket != null) socket.close(); } catch (IOException ignored) {}
        if (readThread != null) readThread.interrupt();
        api.logging().logToOutput("[yentra] Live Share disconnected");
        if (onConnectionChange != null) onConnectionChange.run();
    }

    public boolean isConnected() { return connected; }

    public void share(HttpRequestResponse rr, String caption) {
        if (!connected) return;
        byte[] msg = ShareServer.encodeMessage(rr, caption);
        if (msg == null) return;
        try {
            synchronized (out) {
                DataOutputStream dos = new DataOutputStream(out);
                dos.writeInt(msg.length);
                dos.write(msg);
                dos.flush();
            }
        } catch (IOException e) {
            api.logging().logToError("[yentra] share send failed: " + e);
            disconnect();
        }
    }

    private void readLoop() {
        try {
            while (connected && !socket.isClosed()) {
                int msgLen = in.readInt();
                byte[] payload = new byte[msgLen];
                in.readFully(payload);
                HttpRequestResponse rr = ShareServer.decodeMessage(payload);
                if (rr == null) continue;
                String caption = ShareServer.extractCaption(payload);
                if (onReceive != null) {
                    onReceive.accept(rr, caption);
                }
            }
        } catch (EOFException | SocketException ignored) {
        } catch (IOException e) {
            if (connected) {
                api.logging().logToError("[yentra] client receive: " + e);
            }
        } finally {
            disconnect();
        }
    }
}
