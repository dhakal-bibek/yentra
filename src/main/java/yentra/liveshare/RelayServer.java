package yentra.liveshare;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiConsumer;

/**
 * Lightweight HTTP relay server that stores recent messages per room.
 * Both sides poll this server — no direct connection needed between peers.
 * Can be embedded or run standalone via main().
 */
public class RelayServer {
    private final int port;
    private HttpServer server;
    private final Map<String, List<RelayMessage>> rooms = new ConcurrentHashMap<>();
    private final AtomicLong nextId = new AtomicLong(1);
    private final int maxMessagesPerRoom;
    private BiConsumer<RelayMessage, String> onReceive;

    public RelayServer(int port) {
        this(port, 200);
    }

    public RelayServer(int port, int maxMessagesPerRoom) {
        this.port = port;
        this.maxMessagesPerRoom = maxMessagesPerRoom;
    }

    public void setOnReceive(BiConsumer<RelayMessage, String> onReceive) {
        this.onReceive = onReceive;
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/api/messages", this::handleMessages);
        server.createContext("/api/health", this::handleHealth);
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
    }

    public void stop() {
        if (server != null) server.stop(1);
    }

    public int getPort() { return port; }

    public boolean isRunning() { return server != null; }

    private void handleMessages(HttpExchange ex) throws IOException {
        try {
            String method = ex.getRequestMethod();
            if ("POST".equalsIgnoreCase(method)) {
                handlePost(ex);
            } else if ("GET".equalsIgnoreCase(method)) {
                handleGet(ex);
            } else {
                respond(ex, 405, "Method not allowed");
            }
        } catch (Exception e) {
            respond(ex, 500, "Server error: " + e.getMessage());
        }
    }

    private void handlePost(HttpExchange ex) throws IOException {
        String body = readBody(ex);
        RelayMessage msg = RelayMessage.fromJson(body);
        if (msg == null || msg.roomId == null || msg.roomId.isEmpty()) {
            respond(ex, 400, "Bad request: roomId required");
            return;
        }
        msg.id = nextId.getAndIncrement();
        msg.timestamp = System.currentTimeMillis();

        List<RelayMessage> messages = rooms.computeIfAbsent(msg.roomId,
                k -> new CopyOnWriteArrayList<>());
        messages.add(msg);

        // Trim old messages
        while (messages.size() > maxMessagesPerRoom) {
            messages.remove(0);
        }

        // Notify local onReceive if set (for when relay is embedded)
        if (onReceive != null) {
            onReceive.accept(msg, msg.roomId);
        }

        respondJson(ex, 200, "{\"id\": " + msg.id + "}");
    }

    private void handleGet(HttpExchange ex) throws IOException {
        Map<String, String> params = parseQuery(ex.getRequestURI().getQuery());
        String roomId = params.get("roomId");
        if (roomId == null || roomId.isEmpty()) {
            respond(ex, 400, "roomId required");
            return;
        }
        long since = 0;
        String sinceStr = params.get("since");
        if (sinceStr != null) {
            try { since = Long.parseLong(sinceStr); } catch (NumberFormatException ignored) {}
        }

        List<RelayMessage> messages = rooms.getOrDefault(roomId, Collections.emptyList());
        StringBuilder json = new StringBuilder("[");
        boolean first = true;
        for (RelayMessage msg : messages) {
            if (msg.id <= since) continue;
            if (!first) json.append(',');
            json.append(msg.toJson());
            first = false;
        }
        json.append(']');
        respondJson(ex, 200, json.toString());
    }

    private void handleHealth(HttpExchange ex) throws IOException {
        respondJson(ex, 200, "{\"status\":\"ok\",\"rooms\":" + rooms.size() + "}");
    }

    // ---- helpers ----

    private void respond(HttpExchange ex, int code, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
        ex.sendResponseHeaders(code, bytes.length);
        ex.getResponseBody().write(bytes);
        ex.getResponseBody().close();
    }

    private void respondJson(HttpExchange ex, int code, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json; charset=utf-8");
        ex.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
        ex.sendResponseHeaders(code, bytes.length);
        ex.getResponseBody().write(bytes);
        ex.getResponseBody().close();
    }

    private String readBody(HttpExchange ex) throws IOException {
        try (InputStream is = ex.getRequestBody();
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[4096];
            int n;
            while ((n = is.read(buf)) >= 0) bos.write(buf, 0, n);
            return bos.toString(StandardCharsets.UTF_8);
        }
    }

    private Map<String, String> parseQuery(String query) {
        Map<String, String> result = new HashMap<>();
        if (query == null || query.isEmpty()) return result;
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if (eq >= 0) {
                result.put(pair.substring(0, eq), pair.substring(eq + 1));
            }
        }
        return result;
    }

    // ---- message model ----

    public static class RelayMessage {
        public long id;
        public String roomId;
        public String method;
        public String url;
        public String caption;
        public String requestBase64;
        public String responseBase64;
        public String notesBase64;
        public long timestamp;

        public String toJson() {
            return "{\"id\":" + id
                    + ",\"roomId\":\"" + escape(roomId)
                    + "\",\"method\":\"" + escape(method)
                    + "\",\"url\":\"" + escape(url)
                    + "\",\"caption\":\"" + escape(caption)
                    + "\",\"requestBase64\":\"" + escape(requestBase64)
                    + "\",\"responseBase64\":\"" + escape(responseBase64 != null ? responseBase64 : "")
                    + "\",\"notesBase64\":\"" + escape(notesBase64 != null ? notesBase64 : "")
                    + "\",\"timestamp\":" + timestamp
                    + "}";
        }

        public static RelayMessage fromJson(String json) {
            try {
                RelayMessage msg = new RelayMessage();
                msg.roomId = extract(json, "roomId");
                msg.method = extract(json, "method");
                msg.url = extract(json, "url");
                msg.caption = extract(json, "caption");
                msg.requestBase64 = extract(json, "requestBase64");
                msg.responseBase64 = extract(json, "responseBase64");
                msg.notesBase64 = extract(json, "notesBase64");
                return msg;
            } catch (Exception e) {
                return null;
            }
        }

        private static String extract(String json, String key) {
            String search = "\"" + key + "\":\"";
            int start = json.indexOf(search);
            if (start < 0) return "";
            start += search.length();
            StringBuilder val = new StringBuilder();
            for (int i = start; i < json.length(); i++) {
                char c = json.charAt(i);
                if (c == '\\' && i + 1 < json.length()) {
                    char next = json.charAt(i + 1);
                    if (next == '"') { val.append('"'); i++; }
                    else if (next == '\\') { val.append('\\'); i++; }
                    else { val.append(c); }
                } else if (c == '"') {
                    break;
                } else {
                    val.append(c);
                }
            }
            return val.toString();
        }

        private static String escape(String s) {
            if (s == null) return "";
            return s.replace("\\", "\\\\").replace("\"", "\\\"");
        }
    }

    // ---- standalone entry point for Docker / self-hosting ----

    public static void main(String[] args) throws IOException {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8080;
        RelayServer relay = new RelayServer(port);
        relay.start();
        System.out.println("[relay] Relay server running on http://0.0.0.0:" + port);
        System.out.println("[relay] API endpoints:");
        System.out.println("[relay]   POST /api/messages  — push a message");
        System.out.println("[relay]   GET  /api/messages?roomId=X&since=Y — poll for messages");
        System.out.println("[relay]   GET  /api/health — health check");
    }
}
