package burpdedupe.liveshare;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.HttpService;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiConsumer;

/**
 * Pull-based relay client. Both sides connect to the same HTTP relay server
 * and poll for new messages. No direct connection between peers needed.
 */
public class RelayClient {
    private final MontoyaApi api;
    private final String relayUrl;
    private final String roomId;
    private final int pollIntervalMs;
    private final BiConsumer<HttpRequestResponse, String> onReceive;
    private final Runnable onActivity;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread pollThread;
    private volatile String statusMessage;
    private volatile long lastSeenId;
    private final Set<Long> seenIds = new HashSet<>();

    private static final int DEFAULT_POLL_MS = 2000;
    private static final int MAX_RETRY_DELAY_MS = 30000;

    public RelayClient(MontoyaApi api, String relayUrl, String roomId,
                       BiConsumer<HttpRequestResponse, String> onReceive, Runnable onActivity) {
        this(api, relayUrl, roomId, DEFAULT_POLL_MS, onReceive, onActivity);
    }

    public RelayClient(MontoyaApi api, String relayUrl, String roomId, int pollIntervalMs,
                       BiConsumer<HttpRequestResponse, String> onReceive, Runnable onActivity) {
        this.api = api;
        this.relayUrl = normalizeUrl(relayUrl);
        this.roomId = roomId;
        this.pollIntervalMs = pollIntervalMs;
        this.onReceive = onReceive;
        this.onActivity = onActivity;
    }

    public String statusMessage() { return statusMessage; }
    public boolean isRunning() { return running.get(); }

    /** Connects and starts polling for messages. Returns true if the relay is reachable. */
    public boolean connect() {
        if (running.get()) return true;
        // Verify the relay is reachable
        if (!healthCheck()) {
            statusMessage = "Relay unreachable: " + relayUrl;
            return false;
        }
        running.set(true);
        pollThread = new Thread(this::pollLoop, "relay-poll-" + roomId);
        pollThread.setDaemon(true);
        pollThread.start();
        statusMessage = "Connected via relay: " + roomId;
        return true;
    }

    /** Disconnects from the relay and stops polling. */
    public void disconnect() {
        running.set(false);
        if (pollThread != null) {
            pollThread.interrupt();
            pollThread = null;
        }
        statusMessage = "Disconnected";
    }

    /** Pushes a request+response to the relay for peers to receive. */
    public boolean share(HttpRequestResponse rr, String caption) {
        try {
            HttpRequest request = rr.request();
            String requestBase64 = Base64.getEncoder().encodeToString(request.toByteArray().getBytes());
            String responseBase64 = "";
            if (rr.hasResponse() && rr.response() != null) {
                responseBase64 = Base64.getEncoder().encodeToString(rr.response().toByteArray().getBytes());
            }
            String notes = "";
            try {
                Annotations ann = rr.annotations();
                if (ann != null && ann.hasNotes() && ann.notes() != null) {
                    notes = ann.notes();
                }
            } catch (RuntimeException ignored) {}
            String notesBase64 = notes.isEmpty() ? "" : Base64.getEncoder().encodeToString(notes.getBytes(StandardCharsets.UTF_8));

            String json = "{\"roomId\":\"" + escape(roomId)
                    + "\",\"method\":\"" + escape(request.method() != null ? request.method() : "")
                    + "\",\"url\":\"" + escape(request.url() != null ? request.url() : "")
                    + "\",\"caption\":\"" + escape(caption != null ? caption : "")
                    + "\",\"requestBase64\":\"" + escape(requestBase64)
                    + "\",\"responseBase64\":\"" + escape(responseBase64)
                    + "\",\"notesBase64\":\"" + escape(notesBase64)
                    + "\"}";

            HttpURLConnection conn = openConnection("POST", "/api/messages");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            try (OutputStream os = conn.getOutputStream()) {
                os.write(json.getBytes(StandardCharsets.UTF_8));
            }

            int code = conn.getResponseCode();
            if (code == 200) {
                String responseBody;
                try (BufferedReader r = new BufferedReader(
                        new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    responseBody = r.readLine();
                }
                // Extract the message id from response {"id": N} and add to seenIds
                // so the poll loop skips our own push
                if (responseBody != null) {
                    String idStr = extractJson(responseBody, "id");
                    if (idStr != null) {
                        long msgId = Long.parseLong(idStr);
                        seenIds.add(msgId);
                        if (msgId > lastSeenId) lastSeenId = msgId;
                    }
                }
            }
            conn.disconnect();
            return code == 200;
        } catch (Exception e) {
            api.logging().logToError("[burp-dedupe] relay share failed: " + e.getMessage());
            return false;
        }
    }

    private void pollLoop() {
        int retryDelay = 1000;
        while (running.get() && !Thread.currentThread().isInterrupted()) {
            try {
                pollOnce();
                retryDelay = 1000; // reset on success
                Thread.sleep(pollIntervalMs);
            } catch (InterruptedException e) {
                break;
            } catch (Exception e) {
                api.logging().logToError("[burp-dedupe] relay poll error: " + e.getMessage());
                try {
                    if (running.get()) {
                        Thread.sleep(Math.min(retryDelay, MAX_RETRY_DELAY_MS));
                        retryDelay = Math.min(retryDelay * 2, MAX_RETRY_DELAY_MS);
                    }
                } catch (InterruptedException ie) { break; }
            }
        }
    }

    private void pollOnce() throws IOException {
        String query = "/api/messages?roomId=" + urlEncode(roomId)
                + "&since=" + lastSeenId;
        HttpURLConnection conn = openConnection("GET", query);
        int code = conn.getResponseCode();
        if (code != 200) {
            conn.disconnect();
            return;
        }

        String body;
        try (BufferedReader r = new BufferedReader(
                new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) sb.append(line);
            body = sb.toString();
        }
        conn.disconnect();

        parseAndProcessMessages(body);
        onActivity.run();
    }

    private void parseAndProcessMessages(String json) {
        // Manual JSON array parsing — no external deps
        if (json == null || json.length() < 2) return;
        json = json.trim();
        if (!json.startsWith("[") || !json.endsWith("]")) return;

        // Find each {...} object in the array
        int idx = 1;
        while (idx < json.length() - 1) {
            if (json.charAt(idx) == '{') {
                int end = findMatchingBrace(json, idx);
                if (end < 0) break;
                String obj = json.substring(idx, end + 1);
                processMessage(obj);
                idx = end + 1;
            } else {
                idx++;
            }
        }
    }

    private int findMatchingBrace(String json, int start) {
        int depth = 0;
        boolean inString = false;
        for (int i = start; i < json.length(); i++) {
            char c = json.charAt(i);
            if (inString) {
                if (c == '\\') i++;
                else if (c == '"') inString = false;
            } else {
                if (c == '"') inString = true;
                else if (c == '{') depth++;
                else if (c == '}') { depth--; if (depth == 0) return i; }
            }
        }
        return -1;
    }

    private void processMessage(String obj) {
        try {
            long msgId = 0;
            String idStr = extractJson(obj, "id");
            if (idStr != null) msgId = Long.parseLong(idStr);
            if (msgId > lastSeenId) lastSeenId = msgId;
            // Skip already-seen messages (includes our own pushes)
            if (!seenIds.add(msgId)) return;

            String reqB64 = extractJson(obj, "requestBase64");
            String respB64 = extractJson(obj, "responseBase64");
            String notesB64 = extractJson(obj, "notesBase64");
            String url = extractJson(obj, "url");
            String caption = extractJson(obj, "caption");
            if (reqB64 == null || reqB64.isEmpty()) return;

            byte[] raw = Base64.getDecoder().decode(reqB64);
            HttpRequest request = HttpRequest.httpRequest(ByteArray.byteArray(raw));
            if (url != null && !url.isEmpty()) {
                HttpService svc = ShareServer.httpServiceFromUrl(url);
                if (svc != null) request = HttpRequest.httpRequest(svc, ByteArray.byteArray(raw));
            }

            HttpResponse response = null;
            if (respB64 != null && !respB64.isEmpty()) {
                byte[] respRaw = Base64.getDecoder().decode(respB64);
                response = HttpResponse.httpResponse(ByteArray.byteArray(respRaw));
            }

            String notes = "";
            if (notesB64 != null && !notesB64.isEmpty()) {
                notes = new String(Base64.getDecoder().decode(notesB64), StandardCharsets.UTF_8);
            }
            Annotations ann = (notes != null && !notes.isEmpty())
                    ? Annotations.annotations(notes) : null;

            HttpRequestResponse rr;
            if (response != null) {
                rr = ann != null
                        ? HttpRequestResponse.httpRequestResponse(request, response, ann)
                        : HttpRequestResponse.httpRequestResponse(request, response);
            } else {
                rr = ann != null
                        ? HttpRequestResponse.httpRequestResponse(request, HttpResponse.httpResponse(), ann)
                        : HttpRequestResponse.httpRequestResponse(request, HttpResponse.httpResponse());
            }

            if (onReceive != null) onReceive.accept(rr, caption != null ? caption : "");
        } catch (Exception e) {
            api.logging().logToError("[burp-dedupe] relay message parse error: " + e.getMessage());
        }
    }

    private boolean healthCheck() {
        try {
            HttpURLConnection conn = openConnection("GET", "/api/health");
            int code = conn.getResponseCode();
            conn.disconnect();
            return code == 200;
        } catch (Exception e) {
            return false;
        }
    }

    private HttpURLConnection openConnection(String method, String path) throws IOException {
        URI uri = URI.create(relayUrl + path);
        HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
        conn.setRequestMethod(method);
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        return conn;
    }

    private static String extractJson(String json, String key) {
        String search = "\"" + key + "\"";
        int keyIdx = json.indexOf(search);
        if (keyIdx < 0) return null;
        int colon = json.indexOf(':', keyIdx + search.length());
        if (colon < 0) return null;
        int start = colon + 1;
        while (start < json.length() && json.charAt(start) == ' ') start++;
        if (start >= json.length()) return null;
        if (json.charAt(start) == '"') {
            // string value
            StringBuilder val = new StringBuilder();
            for (int i = start + 1; i < json.length(); i++) {
                char c = json.charAt(i);
                if (c == '\\' && i + 1 < json.length()) {
                    val.append(json.charAt(i + 1));
                    i++;
                } else if (c == '"') {
                    break;
                } else {
                    val.append(c);
                }
            }
            return val.toString();
        } else {
            // number or other
            StringBuilder val = new StringBuilder();
            for (int i = start; i < json.length(); i++) {
                char c = json.charAt(i);
                if (c == ',' || c == '}' || Character.isWhitespace(c)) break;
                val.append(c);
            }
            return val.toString().trim();
        }
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String urlEncode(String s) {
        try { return URLEncoder.encode(s, StandardCharsets.UTF_8.name()); }
        catch (UnsupportedEncodingException e) { return s; }
    }

    private static String normalizeUrl(String url) {
        if (url == null || url.isEmpty()) return "http://localhost:8080";
        String u = url.trim();
        if (!u.startsWith("http://") && !u.startsWith("https://")) {
            u = "http://" + u;
        }
        return u.endsWith("/") ? u.substring(0, u.length() - 1) : u;
    }
}
