package yentra;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.hotkey.HotKeyContext;
import burp.api.montoya.ui.hotkey.HotKeyHandler;
import yentra.core.YentraEngine;
import yentra.core.SignatureConfig;
import yentra.liveshare.LiveShareTab;
import yentra.proxy.YentraProxyHandler;
import yentra.proxy.HistoryStamper;
import yentra.proxy.PortHighlightHandler;
import yentra.proxy.UniqueFeed;
import yentra.ui.BodyOnlyResponseEditor;
import yentra.ui.YentraContextMenu;
import yentra.ui.YentraTab;
import yentra.ui.UniqueRequestsViewer;

import java.util.function.BiConsumer;

import javax.swing.SwingUtilities;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

public class YentraExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Yentra");

        YentraEngine engine = new YentraEngine(api, SignatureConfig.forPreset(SignatureConfig.Preset.DEFAULT));
        AtomicBoolean enabled = new AtomicBoolean(true);
        AtomicBoolean colorize = new AtomicBoolean(true);
        AtomicBoolean preserveNotes = new AtomicBoolean(true);

        // In-memory live feed: the proxy handler publishes every UNIQUE straight to the "Yentra Live"
        // tab, so the tab no longer depends on re-reading [YENTRA] notes back out of Proxy history.
        UniqueFeed liveFeed = new UniqueFeed();

        YentraProxyHandler proxyHandler = new YentraProxyHandler(api, engine, enabled, colorize, preserveNotes, liveFeed);
        api.proxy().registerResponseHandler(proxyHandler);

        // Port-based highlighting + header injection (attacker/victim tagging by listener port).
        api.proxy().registerRequestHandler(new PortHighlightHandler(api));
        PortHighlightHandler.PORT_RULES.forEach((port, rule) ->
                api.logging().logToOutput("[yentra] port " + port + " -> unique="
                        + rule.uniqueColor().displayName() + " dupe=" + rule.dupeColor().displayName()
                        + " " + rule.headers()));

        HistoryStamper stamper = new HistoryStamper(api, engine, colorize, preserveNotes);

        SwingUtilities.invokeLater(() -> {
            YentraTab tab = new YentraTab(api, engine, enabled, colorize, preserveNotes, stamper);
            api.userInterface().registerSuiteTab("Yentra", tab.component());

            // Live unique history as its own always-on Burp tab (no pop-up needed; Ctrl+9 still works).
            api.userInterface().registerSuiteTab("Yentra Live", YentraTab.liveUniqueComponent(api, liveFeed));

            // Live Share: host a server or connect to a friend to share requests in real time.
            LiveShareTab shareTab = new LiveShareTab(api, liveFeed);
            api.userInterface().registerSuiteTab("Yentra Share", shareTab.component());
            UniqueRequestsViewer.setShareHandler((rr, caption) -> shareTab.shareImmediately(rr, caption));

            // Tear down server/client connections on extension unload.
            api.extension().registerUnloadingHandler(() -> {
                UniqueRequestsViewer.setShareHandler(null);
                UniqueRequestsViewer.setAutoShare(false);
            });

            YentraContextMenu contextMenu = new YentraContextMenu(api, engine, stamper, tab::currentOverrides);
            api.userInterface().registerContextMenuItemsProvider(contextMenu);

            // "Body Only" response tab — strips headers + JSON XSSI guards and pretty-renders the body
            // (a Montoya port of rikeshbaniya's "Body Only (Pretty JSON)"; see README Acknowledgements).
            api.userInterface().registerHttpResponseEditorProvider(new BodyOnlyResponseEditor.Provider(api));

            // Ctrl+9 (in Proxy HTTP history or the Site map): if rows are selected (e.g. Ctrl+A),
            // open the unique requests from that selection; with nothing selected, fall back to the
            // LIVE window that auto-collects every [YENTRA] UNIQUE row.
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
                api.logging().logToOutput("[yentra] unloaded"));

        api.logging().logToOutput("[yentra] loaded. Default preset: " + engine.config().preset);
        api.logging().logToOutput("[yentra] BUILD: live-push feed enabled — Yentra Live receives UNIQUEs "
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
