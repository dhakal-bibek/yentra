package yentra.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;
import yentra.core.JsonPretty;

import java.awt.Component;
import java.nio.charset.StandardCharsets;

/**
 * A read-only <b>Body Only</b> response-editor tab: it shows just the response body with the common
 * JSON anti-hijacking guards (XSSI prefixes like {@code )]}'}, {@code for(;;);}) stripped, served as
 * {@code application/json} so Burp's Pretty view formats it — no bundled JSON library needed.
 *
 * <p>A Montoya port of <b>rikeshbaniya</b>'s "Body Only (Pretty JSON)" Burp extension
 * (https://github.com/rikeshbaniya) — see the README Acknowledgements.
 */
public final class BodyOnlyResponseEditor implements ExtensionProvidedHttpResponseEditor {

    /** Factory Burp calls to create one "Body Only" editor per message viewer. */
    public static final class Provider implements HttpResponseEditorProvider {
        private final MontoyaApi api;

        public Provider(MontoyaApi api) {
            this.api = api;
        }

        @Override
        public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext ctx) {
            return new BodyOnlyResponseEditor(api);
        }
    }

    private final MontoyaApi api;
    private final HttpResponseEditor inner;   // read-only; renders the synthetic application/json response
    private HttpRequestResponse current;

    private BodyOnlyResponseEditor(MontoyaApi api) {
        this.api = api;
        this.inner = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
    }

    @Override public String caption() { return "Body Only"; }

    @Override public Component uiComponent() { return inner.uiComponent(); }

    @Override public boolean isModified() { return false; }              // read-only view

    @Override public Selection selectedData() { return inner.selection().orElse(null); }

    /** Show the tab only when there's a non-empty response body to strip down. */
    @Override
    public boolean isEnabledFor(HttpRequestResponse rr) {
        try {
            return rr != null && rr.response() != null && rr.response().body().length() > 0;
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** We never edit the message, so hand Burp back the original response untouched. */
    @Override
    public HttpResponse getResponse() {
        return current != null && current.response() != null ? current.response() : HttpResponse.httpResponse();
    }

    @Override
    public void setRequestResponse(HttpRequestResponse rr) {
        this.current = rr;
        HttpResponse resp = rr == null ? null : rr.response();
        if (resp == null) {
            inner.setResponse(HttpResponse.httpResponse());
            return;
        }
        try {
            String body = JsonPretty.prettyBody(resp.bodyToString());   // strip XSSI guards + pretty-print JSON
            String contentType = JsonPretty.looksLikeJson(body) ? "application/json" : "text/plain; charset=utf-8";
            int len = body.getBytes(StandardCharsets.UTF_8).length;
            // Synthetic response with no original headers: the body is already pretty-printed, and
            // application/json lets Burp's Pretty view colourise it too.
            inner.setResponse(HttpResponse.httpResponse(
                    "HTTP/1.1 200 OK\r\nContent-Type: " + contentType + "\r\nContent-Length: " + len
                            + "\r\n\r\n" + body));
        } catch (RuntimeException e) {
            api.logging().logToError("[yentra] Body Only render failed: " + e);
            inner.setResponse(resp);   // fall back to the raw response rather than a blank tab
        }
    }

}
