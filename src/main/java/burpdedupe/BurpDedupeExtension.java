package burpdedupe;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.hotkey.HotKeyContext;
import burp.api.montoya.ui.hotkey.HotKeyHandler;
import burpdedupe.core.DedupeEngine;
import burpdedupe.core.SignatureConfig;
import burpdedupe.liveshare.LiveShareTab;
import burpdedupe.proxy.DedupeProxyHandler;
import burpdedupe.proxy.HistoryStamper;
import burpdedupe.proxy.PortHighlightHandler;
import burpdedupe.proxy.UniqueFeed;
import burpdedupe.ui.BodyOnlyResponseEditor;
import burpdedupe.ui.DedupeContextMenu;
import burpdedupe.ui.DedupeTab;
import burpdedupe.ui.UniqueRequestsViewer;

import java.util.function.BiConsumer;

import javax.swing.SwingUtilities;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

public class BurpDedupeExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("DedupeAI");

        DedupeEngine engine = new DedupeEngine(api, SignatureConfig.forPreset(SignatureConfig.Preset.DEFAULT));
        AtomicBoolean enabled = new AtomicBoolean(true);
        AtomicBoolean colorize = new AtomicBoolean(true);
        AtomicBoolean preserveNotes = new AtomicBoolean(true);

        // In-memory live feed: the proxy handler publishes every UNIQUE straight to the "Dedupe Live"
        // tab, so the tab no longer depends on re-reading [DEDUPE] notes back out of Proxy history.
        UniqueFeed liveFeed = new UniqueFeed();

        DedupeProxyHandler proxyHandler = new DedupeProxyHandler(api, engine, enabled, colorize, preserveNotes, liveFeed);
        api.proxy().registerResponseHandler(proxyHandler);

        // Port-based highlighting + header injection (attacker/victim tagging by listener port).
        api.proxy().registerRequestHandler(new PortHighlightHandler(api));
        PortHighlightHandler.PORT_RULES.forEach((port, rule) ->
                api.logging().logToOutput("[burp-dedupe] port " + port + " -> unique="
                        + rule.uniqueColor().displayName() + " dupe=" + rule.dupeColor().displayName()
                        + " " + rule.headers()));

        HistoryStamper stamper = new HistoryStamper(api, engine, colorize, preserveNotes);

        SwingUtilities.invokeLater(() -> {
            DedupeTab tab = new DedupeTab(api, engine, enabled, colorize, preserveNotes, stamper);
            api.userInterface().registerSuiteTab("Dedupe", tab.component());

            // Live unique history as its own always-on Burp tab (no pop-up needed; Ctrl+9 still works).
            api.userInterface().registerSuiteTab("Dedupe Live", DedupeTab.liveUniqueComponent(api, liveFeed));

            // Live Share: host a server or connect to a friend to share requests in real time.
            LiveShareTab shareTab = new LiveShareTab(api, liveFeed);
            api.userInterface().registerSuiteTab("Dedupe Share", shareTab.component());
            UniqueRequestsViewer.setShareHandler((rr, caption) -> shareTab.shareImmediately(rr, caption));

            // Tear down server/client connections on extension unload.
            api.extension().registerUnloadingHandler(() -> {
                UniqueRequestsViewer.setShareHandler(null);
                UniqueRequestsViewer.setAutoShare(false);
            });

            DedupeContextMenu contextMenu = new DedupeContextMenu(api, engine, stamper, tab::currentOverrides);
            api.userInterface().registerContextMenuItemsProvider(contextMenu);

            // "Body Only" response tab — strips headers + JSON XSSI guards and pretty-renders the body
            // (a Montoya port of rikeshbaniya's "Body Only (Pretty JSON)"; see README Acknowledgements).
            api.userInterface().registerHttpResponseEditorProvider(new BodyOnlyResponseEditor.Provider(api));

            // Ctrl+9 (in Proxy HTTP history or the Site map): if rows are selected (e.g. Ctrl+A),
            // open the unique requests from that selection; with nothing selected, fall back to the
            // LIVE window that auto-collects every [DEDUPE] UNIQUE row.
            HotKeyHandler launchLiveUnique = event -> {
                List<HttpRequestResponse> selected = event.selectedRequestResponses();
                if (selected != null && !selected.isEmpty()) {
                    contextMenu.showUniqueRequests(selected);
                } else {
                    contextMenu.openLiveUnique();
                }
            };
            Registration hkHistory = api.userInterface()
                    .registerHotKeyHandler(HotKeyContext.PROXY_HTTP_HISTORY, "Ctrl+9", launchLiveUnique);
            Registration hkSiteMap = api.userInterface()
                    .registerHotKeyHandler(HotKeyContext.SITE_MAP_CONTENTS_TABLE, "Ctrl+9", launchLiveUnique);

            // Burp doesn't release hotkeys automatically on unload, so a reload otherwise warns
            // "Unable to register hotkey 'Ctrl+9' as already assigned". Deregister them ourselves.
            api.extension().registerUnloadingHandler(() -> {
                safeDeregister(hkHistory);
                safeDeregister(hkSiteMap);
            });

            if (tab.isAutoStampEnabled()) {
                tab.startHistoryStamp();
            }
        });

        api.extension().registerUnloadingHandler(() ->
                api.logging().logToOutput("[burp-dedupe] unloaded"));

        api.logging().logToOutput("[burp-dedupe] loaded. Default preset: " + engine.config().preset);
        api.logging().logToOutput("[burp-dedupe] BUILD: live-push feed enabled — Dedupe Live receives UNIQUEs "
                + "directly from the proxy handler (history poll is back-fill only).");
    }

    /** Best-effort deregistration — ignores a null/already-gone registration so unload never throws. */
    private static void safeDeregister(Registration r) {
        try {
            if (r != null && r.isRegistered()) r.deregister();
        } catch (RuntimeException ignored) {
            // best-effort cleanup during unload
        }
    }
}
