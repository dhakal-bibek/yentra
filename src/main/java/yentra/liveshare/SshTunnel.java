package yentra.liveshare;

import java.io.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Manages an SSH tunnel via serveo.net so friends across the internet can
 * connect without port forwarding or UPnP. Spawns a local {@code ssh} process
 * and parses its output to extract the public address.
 */
public class SshTunnel {
    private final int localPort;
    private Process process;
    private volatile String publicAddress;
    private volatile String errorMessage;
    private final StringBuilder outputLog = new StringBuilder();
    private final CountDownLatch ready = new CountDownLatch(1);

    private static final String SERVER = "serveo.net";
    private static final int CONNECT_TIMEOUT_SEC = 20;

    public SshTunnel(int localPort) {
        this.localPort = localPort;
    }

    /** Starts the SSH tunnel in a background thread. Returns immediately. */
    public void start() {
        new Thread(this::run, "liveshare-ssh").start();
    }

    /** The public address (e.g. {@code serveo.net:12345}), or null if not yet available. */
    public String publicAddress() { return publicAddress; }

    /** Error message if the tunnel failed, null otherwise. */
    public String errorMessage() { return errorMessage; }

    /** Blocks up to {@code timeout} seconds for the tunnel to be ready; returns true if ready. */
    public boolean await(int timeout) {
        try { return ready.await(timeout, TimeUnit.SECONDS); }
        catch (InterruptedException e) { return false; }
    }

    /** Tears down the tunnel. */
    public void stop() {
        if (process != null && process.isAlive()) {
            process.destroy();
            try { process.waitFor(3, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
            if (process.isAlive()) process.destroyForcibly();
        }
    }

    public boolean isRunning() {
        return process != null && process.isAlive() && publicAddress != null;
    }

    private void run() {
        try {
            // Check ssh is available
            if (!checkSshAvailable()) return;

            ProcessBuilder pb = new ProcessBuilder(
                    "ssh",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "ServerAliveInterval=30",
                    "-o", "ConnectTimeout=10",
                    "-R", "0:localhost:" + localPort,
                    "-N",
                    SERVER
            );
            pb.redirectErrorStream(true);
            process = pb.start();

            // Read output, looking for the forwarding address
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                long deadline = System.currentTimeMillis()
                        + TimeUnit.SECONDS.toMillis(CONNECT_TIMEOUT_SEC);
                while ((line = r.readLine()) != null
                        && System.currentTimeMillis() < deadline) {
                    outputLog.append(line).append('\n');
                    // serveo prints:  Forwarding TCP traffic from serveo.net:PORT
                    if (line.contains("Forwarding") && line.contains("serveo.net")) {
                        int colon = line.lastIndexOf(':');
                        if (colon > 0) {
                            String portStr = line.substring(colon + 1).trim();
                            if (portStr.matches("\\d+")) {
                                publicAddress = SERVER + ":" + portStr;
                                ready.countDown();
                                return;
                            }
                        }
                        // Fallback: use the whole host:port from the line
                        int from = line.indexOf("from ");
                        if (from >= 0) {
                            String addr = line.substring(from + 5).trim();
                            publicAddress = addr;
                            ready.countDown();
                            return;
                        }
                    }
                    // serveo prints the port on its own line too
                    if (line.startsWith("serveo.net:")) {
                        publicAddress = line.trim();
                        ready.countDown();
                        return;
                    }
                }
            }

            // If we get here, the tunnel didn't report a forwarding address
            if (process.isAlive()) {
                errorMessage = "Tunnel established but no address reported";
            } else {
                int exit = process.exitValue();
                // Collect any remaining output
                try (BufferedReader r = new BufferedReader(
                        new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = r.readLine()) != null) outputLog.append(line).append('\n');
                } catch (IOException ignored) {}
                String detail = outputLog.length() > 0
                        ? outputLog.toString().trim().replace('\n', ' ').replaceAll("\\s+", " ")
                        : "no output";
                errorMessage = "SSH exited with code " + exit + ": " + detail;
            }
        } catch (IOException e) {
            errorMessage = "SSH failed: " + e.getMessage();
        } catch (InterruptedException e) {
            errorMessage = "SSH interrupted";
        }
        ready.countDown();
    }

    private boolean checkSshAvailable() throws IOException, InterruptedException {
        Process which = new ProcessBuilder("ssh", "-V")
                .redirectErrorStream(true).start();
        boolean exited = which.waitFor(3, TimeUnit.SECONDS);
        if (!exited || which.exitValue() != 0) {
            errorMessage = "ssh not found — install OpenSSH";
            ready.countDown();
            return false;
        }
        return true;
    }
}
