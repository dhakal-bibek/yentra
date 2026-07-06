package burpdedupe.liveshare;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;

/**
 * Minimal UPnP IGD port mapper — discovers the router's WAN IP Connection service
 * via SSDP and adds/removes a TCP port mapping. Pure JDK, no external libraries.
 */
public class UpnpPortMapper {
    private String controlUrl;
    private String serviceType;
    private final int port;

    private static final int SSDP_TIMEOUT_MS = 3000;
    private static final String SSDP_ADDR = "239.255.255.250";
    private static final int SSDP_PORT = 1900;

    public UpnpPortMapper(int port) {
        this.port = port;
    }

    /** True if the UPnP gateway was discovered and a mapping was added. */
    public boolean addMapping() {
        try {
            discover();
            if (controlUrl == null) return false;
            String localIp = localIp();
            if (localIp == null) return false;
            return soapAction(
                    "AddPortMapping",
                    "<u:AddPortMapping xmlns:u=\"" + serviceType + "\">"
                    + "<NewRemoteHost></NewRemoteHost>"
                    + "<NewExternalPort>" + port + "</NewExternalPort>"
                    + "<NewProtocol>TCP</NewProtocol>"
                    + "<NewInternalPort>" + port + "</NewInternalPort>"
                    + "<NewInternalClient>" + localIp + "</NewInternalClient>"
                    + "<NewEnabled>1</NewEnabled>"
                    + "<NewPortMappingDescription>burp-dedupe</NewPortMappingDescription>"
                    + "<NewLeaseDuration>0</NewLeaseDuration>"
                    + "</u:AddPortMapping>"
            );
        } catch (Exception e) {
            return false;
        }
    }

    /** Removes the port mapping. */
    public boolean removeMapping() {
        if (controlUrl == null) return false;
        try {
            return soapAction(
                    "DeletePortMapping",
                    "<u:DeletePortMapping xmlns:u=\"" + serviceType + "\">"
                    + "<NewRemoteHost></NewRemoteHost>"
                    + "<NewExternalPort>" + port + "</NewExternalPort>"
                    + "<NewProtocol>TCP</NewProtocol>"
                    + "</u:DeletePortMapping>"
            );
        } catch (Exception e) {
            return false;
        }
    }

    /** Fetches the public (external) IP from the router. */
    public String publicIp() {
        if (controlUrl == null) return null;
        try {
            String xml = soapRequest(
                    "GetExternalIPAddress",
                    "<u:GetExternalIPAddress xmlns:u=\"" + serviceType + "\"/>"
            );
            if (xml == null) return null;
            String tag = "<NewExternalIPAddress>";
            int s = xml.indexOf(tag);
            if (s < 0) return null;
            s += tag.length();
            int e = xml.indexOf("</NewExternalIPAddress>", s);
            return e > s ? xml.substring(s, e).trim() : null;
        } catch (Exception e) {
            return null;
        }
    }

    // ── SSDP discovery ─────────────────────────────────────────────────────

    private void discover() throws IOException {
        String searchMsg = "M-SEARCH * HTTP/1.1\r\n"
                + "HOST: " + SSDP_ADDR + ":" + SSDP_PORT + "\r\n"
                + "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
                + "MAN: \"ssdp:discover\"\r\n"
                + "MX: 3\r\n\r\n";

        byte[] searchBytes = searchMsg.getBytes(StandardCharsets.UTF_8);
        DatagramSocket sock = new DatagramSocket();
        sock.setSoTimeout(SSDP_TIMEOUT_MS);
        sock.send(new DatagramPacket(searchBytes, searchBytes.length,
                InetAddress.getByName(SSDP_ADDR), SSDP_PORT));

        long deadline = System.currentTimeMillis() + SSDP_TIMEOUT_MS;
        byte[] buf = new byte[4096];

        while (System.currentTimeMillis() < deadline) {
            DatagramPacket pkt = new DatagramPacket(buf, buf.length);
            try {
                sock.receive(pkt);
            } catch (SocketTimeoutException e) {
                break;
            }
            String resp = new String(pkt.getData(), 0, pkt.getLength(), StandardCharsets.UTF_8);
            String loc = extractHeader(resp, "LOCATION");
            if (loc != null) {
                String st = extractHeader(resp, "ST");
                if (st != null && st.contains("InternetGatewayDevice")) {
                    if (parseDeviceDescription(loc)) break;
                }
            }
        }
        sock.close();
    }

    /** Fetches the device description XML and finds the WAN IP Connection control URL. */
    private boolean parseDeviceDescription(String locationUrl) throws IOException {
        URL url = new URL(locationUrl);
        String base = url.getProtocol() + "://" + url.getHost() + ":" + url.getPort();
        String xml = fetchUrl(locationUrl);
        if (xml == null) return false;

        // Find the WANIPConnection service in the XML
        // Look for service with WANIPConnection in the serviceType
        String searchSvc = "WANIPConnection";
        int svcIdx = xml.indexOf(searchSvc);
        if (svcIdx < 0) {
            // Try WANPPPConnection
            searchSvc = "WANPPPConnection";
            svcIdx = xml.indexOf(searchSvc);
        }
        if (svcIdx < 0) return false;

        // Find the controlURL near the matched service
        String ctrlTag = "<controlURL>";
        int ctrlStart = xml.lastIndexOf(ctrlTag, svcIdx);
        if (ctrlStart < 0) return false;
        ctrlStart += ctrlTag.length();
        int ctrlEnd = xml.indexOf("</controlURL>", ctrlStart);
        if (ctrlEnd < 0) return false;
        String ctrl = xml.substring(ctrlStart, ctrlEnd).trim();
        if (ctrl.startsWith("/")) {
            controlUrl = base + ctrl;
        } else {
            controlUrl = base + "/" + ctrl;
        }

        // Get the service type (used in SOAP)
        String svcTag = "<serviceType>";
        int svcStart = xml.lastIndexOf(svcTag, svcIdx);
        if (svcStart >= 0) {
            svcStart += svcTag.length();
            int svcEnd = xml.indexOf("</serviceType>", svcStart);
            if (svcEnd > svcStart) {
                serviceType = xml.substring(svcStart, svcEnd).trim();
            }
        }
        return controlUrl != null;
    }

    // ── SOAP ────────────────────────────────────────────────────────────────

    private boolean soapAction(String action, String body) {
        String xml = soapRequest(action, body);
        return xml != null && !xml.contains("error");
    }

    private String soapRequest(String action, String body) {
        try {
            URL url = new URL(controlUrl);
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "text/xml; charset=utf-8");
            con.setRequestProperty("SOAPAction", "\"" + serviceType + "#" + action + "\"");
            con.setDoOutput(true);
            con.setConnectTimeout(5000);
            con.setReadTimeout(5000);

            String soap = "<?xml version=\"1.0\"?>"
                    + "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
                    + "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
                    + "<s:Body>" + body + "</s:Body></s:Envelope>";

            try (OutputStream os = con.getOutputStream()) {
                os.write(soap.getBytes(StandardCharsets.UTF_8));
            }

            int code = con.getResponseCode();
            if (code < 200 || code >= 300) return null;

            try (InputStream is = con.getInputStream()) {
                return new String(is.readAllBytes(), StandardCharsets.UTF_8);
            }
        } catch (IOException e) {
            return null;
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static String extractHeader(String resp, String name) {
        int idx = resp.indexOf(name + ":");
        if (idx < 0) {
            idx = resp.indexOf(name.toLowerCase() + ":");
        }
        if (idx < 0) return null;
        int valStart = idx + name.length() + 1;
        int valEnd = resp.indexOf('\r', valStart);
        if (valEnd < 0) valEnd = resp.indexOf('\n', valStart);
        return valEnd > valStart ? resp.substring(valStart, valEnd).trim() : null;
    }

    private static String fetchUrl(String urlStr) {
        try {
            URL url = new URL(urlStr);
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setConnectTimeout(5000);
            con.setReadTimeout(5000);
            try (InputStream is = con.getInputStream()) {
                return new String(is.readAllBytes(), StandardCharsets.UTF_8);
            }
        } catch (IOException e) {
            return null;
        }
    }

    /** The local IP on the network interface that routes to the internet. */
    private static String localIp() {
        try {
            try (DatagramSocket s = new DatagramSocket()) {
                s.connect(InetAddress.getByName("8.8.8.8"), 80);
                return s.getLocalAddress().getHostAddress();
            }
        } catch (IOException e) {
            return null;
        }
    }
}
