# Yentra

Burp Suite extension + port-based highlighter: dedupes proxy history into a live unique-request feed and color-codes attacker/victim traffic by listener port (PwnFox-style). Features **Live Share** — the first-ever real-time peer-to-peer request sharing inside Burp Suite — plus Magic Cookie, Match & Replace, Caido-style filter palette, inline Repeater, AI bridge, and .http export for Claude Code.

---

## 🌐 Live Share — Real-Time Peer Collaboration

> **Industry-first:** No other Burp extension lets two testers share captured HTTP requests live, directly inside Burp. Host a server, connect to a friend, and every unique request you capture appears instantly on their screen — color-coded, deduplicated, and ready to test.

| Mode | How it works | Best for |
|---|---|---|
| **Direct TCP** | Host a server on any port; peers connect directly via host:port | Same network, VPN |
| **SSH Tunnel** | Auto-tunnels through serveo.net for a public address | Behind NAT, no port forwarding |
| **HTTP Relay** | Self-host the relay with Docker (`relay-server/`); peers join by room ID | Both peers behind NAT/firewall |
| **UPnP** | Automatic router port mapping | Home/office networks with UPnP-enabled routers |

![Live Share — server on port 9999 with client connected, sharing requests in real time](assets/live-share-connected.png)

![Received shared requests — double-click any entry to open in Repeater](assets/live-share-received.png)

**What makes it unique:**
- Requests arrive **already deduplicated** — only `[YENTRA] UNIQUE` entries are shared
- **Auto-share mode:** every new unique is forwarded to all connected peers in real time
- **Re-issue received → Proxy history:** replay received requests through your local proxy listener to add role tags (attacker/victim)
- **Room-based relay** with random 8-char IDs — drop-in, no registration
- **Magenta highlights** distinguish shared requests in your Yentra Live feed

---

## Table of Contents

1. [Installation](#installation)
2. [🌐 Live Share — Peer Collaboration](#-live-share--real-time-peer-collaboration)
3. [Architecture Overview](#architecture-overview)
4. [Yentra Config Tab](#yentra-config-tab)
   - [Behavior & Signature Fields](#behavior--signature-fields)
   - [Presets](#presets)
   - [Stats & Header Overrides](#stats--header-overrides)
   - [History Stamping](#history-stamping)
5. [Yentra Live Tab](#yentra-live-tab)
   - [Toolbar Actions](#toolbar-actions)
   - [Inline Repeater](#inline-repeater)
   - [Response Info Bar](#response-info-bar)
   - [History Navigation](#history-navigation)
6. [Bambda-Style Filter](#bambda-style-filter)
   - [Prefix Tokens](#prefix-tokens)
   - [Filter Chips](#filter-chips)
   - [Command Palette](#command-palette)
   - [Status Operators](#status-operators)
7. [IDOR / BOLA Tools](#idor--bola-tools)
   - [Magic Cookie](#magic-cookie)
   - [Match & Replace](#match--replace)
8. [Right-Click Actions](#right-click-actions)
9. [Remove from Scope](#remove-from-scope)
9. [Yentra Share (Live Share)](#yentra-share-live-share)
10. [AI Bridge (Live Export)](#ai-bridge-live-export)
11. [Attacker / Victim Port Highlighting](#attacker--victim-port-highlighting)
12. [Body Only (Pretty JSON) Editor](#body-only-pretty-json-editor)
13. [Keyboard Shortcuts](#keyboard-shortcuts)
14. [Build](#build)
15. [Acknowledgements](#acknowledgements)

---

## Installation

1. Burp → **Extensions** → **Installed** → **Add**
2. Extension type: **Java**
3. Select `yentra-0.1.0-SNAPSHOT.jar`
4. Three tabs appear: **Yentra**, **Yentra Live**, **Yentra Share**

---

## Architecture Overview

Yentra is built around a request pipeline that flows from capture to distribution:

```
Proxy Traffic → YentraEngine → [YENTRA] Stamp → Yentra Live Feed → 🌐 Live Share → Peers
                                         ↓                           ↓
                                    HTTP History               AI Bridge (.http)
```

**Core components:**

| Component | Role |
|---|---|
| **YentraEngine** | Thread-safe deduplication engine — computes 128-bit SHA-256 signatures from configurable request parts; `ConcurrentHashMap<Signature, AtomicInteger>` seen-set |
| **YentraProxyHandler** | Intercepts every proxy response, classifies it (unique/dupe/skip/overflow), stamps Notes, highlights rows, pushes uniques to the live feed |
| **Yentra Live Feed** | In-memory push feed — every `UNIQUE` is streamed directly to the **Yentra Live** tab without re-reading from history |
| **🌐 Live Share** | Real-time peer-to-peer TCP/SSH/Relay server — auto-forwards `UNIQUE` requests to connected peers, re-issues received traffic through local proxy |
| **AI Bridge** | Filesystem mirror to `~/.yentra/<project>/` — every unique exported as a `curl`-ready case file for Claude Code |
| **PortHighlighter** | Injects `X-AI-Use: attacker|victim` by listener port and colors rows per-port, per-verdict |

**Verdict system:**

| Verdict | Notes Stamp | Meaning |
|---|---|---|
| `UNIQUE` | `[YENTRA] UNIQUE` | First occurrence of this signature |
| `DUPE` | `[YENTRA] DUPE xN` | Seen N times before |
| `SKIP` | `[YENTRA] SKIP` | Out of scope, static asset, or disabled |
| `OVRF` | `[YENTRA] OVRF` | Exceeded 200k tracked signature cap |

**Cross-identity dedup:** When traffic arrives through role-tagged ports (attacker/victim), Cookie, Authorization, and role headers are stripped before computing the signature — so identical requests from different identities share one count (first = UNIQUE, second = DUPE x2).

**Body digest safety net:** When body parameters are enabled, the raw body content hash (first 4 KB) is always folded into the signature, preventing false DUPEs when Montoya cannot parse the body into parameters.

---

## Yentra Config Tab

The main configuration panel — `"Yentra"` suite tab.

### Behavior & Signature Fields

| Control | Description |
|---|---|
| **Stamp Notes column** | Writes `[YENTRA]` verdicts into the Notes column of HTTP history |
| **Highlight rows** | Tints rows by verdict and listener port |
| **Preserve existing notes** | Keeps manual notes when stamping (prepends the verdict after a `\|`) |
| **Preset dropdown** | Choose from 11 presets or build your own |
| **Max tracked signatures** | Hard cap (default 200,000; range 1,000–5,000,000); beyond this, `OVRF` is returned |
| **Auto-stamp existing history** | Retroactively stamps all proxy history on extension load |
| **Stamp existing history** | One-shot retroactive stamp (background thread, cancellable) |
| **Apply** | Commits config and resets the seen-set |
| **Reset stats** | Zeros all counters without changing config |
| **Live unique window** | Opens a pop-up live feed of `[YENTRA] UNIQUE` entries |

**Signature fields:** Method · Scheme · Host · Port · Path · Normalize numeric/UUID/hex path segments · Query param names · Query param values · Body param names · Body param values · Response status code · Response Content-Type

**Filters:** In-scope only · Skip static assets (`.css`, `.js`, `.png`, `.gif`, `.svg`, `.woff`, `.ttf`, `.eot`, `.otf`, `.ico`, `.webp`, `.map`, `.mp4`, `.mp3`) · Include custom headers (comma-separated)

### Presets

| Preset | Signature Components |
|---|---|
| **Default** | method + host + path + sorted query & body param names + status |
| **Request smuggling** | method + host + path only |
| **IDOR / Auth** | method + host + path (numeric/UUID normalized) + sorted param names |
| **XSS** | method + host + path + sorted query & body param names |
| **SQLi** | method + host + path + sorted param names |
| **SSRF** | method + host + path + query param names |
| **Open redirect** | host + path + query param names (method-insensitive) |
| **SSTI** | method + host + path + sorted param names |
| **Path traversal** | method + host + normalized path + query param names |
| **Strict** | full method + scheme + host + port + path + all param names & values + status + Content-Type |
| **Custom** | whatever you tick |

### Stats & Header Overrides

**Live stats** (refreshed every second): Total seen · Unique · Duplicates · Skipped · Tracked signatures (shown as `N / cap`)

**Header overrides** — inject custom headers into requests sent to Organizer:

- Paste raw header lines (`Name: value`), one per line; `#` comments and blank lines ignored
- Choose **Replace if present, add if missing** or **Replace only**
- Reserved headers (`Host`, `Content-Length`, `Transfer-Encoding`) are rejected
- Applied via right-click → **Yentra → Send unique to Organizer**

### History Stamping

- **Stamp existing history** walks all proxy history entries and applies verdicts in-place (background thread, shows progress)
- **Auto-stamp** does this automatically on every extension load — handy for saved projects
- **Revert** strips `[YENTRA]` notes and/or clears highlights when those options are toggled off
- Seen-set is reset before stamping for consistent counts

---

## Yentra Live Tab

An always-on, auto-refreshing feed of **only** the `[YENTRA] UNIQUE` requests. Opens as a Burp suite tab (`"Yentra Live"`) on load. Also accessible via **Ctrl+9** (in HTTP history / Site Map, with nothing selected) or the **Live unique window** button.

**How it works:**

- **Push path:** Every `UNIQUE` from the proxy handler is pushed directly into the live feed via an in-memory `UniqueFeed`
- **Poll path:** Background timer (every 1.5s) incrementally scans proxy history for entries stamped `[YENTRA] UNIQUE` that haven't been collected yet; full rescan every ~60s catches late "Stamp history" marks
- Both paths cross-dedupe by request identity so the same request never appears twice

### Toolbar Actions

| Button | Description |
|---|---|
| **Send to Repeater** | Sends selected rows to new Repeater tabs named by method + path |
| **Share** | Shares the selected request with connected Live Share peers |
| **Save for AI** | Exports selected rows to a `.http` file with case manifests for AI consumption |
| **Magic Cookie** | Reissue selected requests with swapped auth headers — ideal for same-request / different-identity IDOR/BOLA |
| **Match & Replace** | Swap IDs/tokens in path or body and reissue — watch for unexpected `200` responses |
| **Clear** | Empties the table (already-seen IDs won't reappear in live mode) |
| **Live export → file** | Mirrors the feed to `~/.yentra/<project>/` for AI bridge |
| **Filter bar** | Bambda-style prefix tokens, plain text, and filter chips |

### Inline Repeater

A full Repeater-style interface embedded below the table:

- **Request (left)** — editable Montoya HTTP request editor
- **Response (right)** — read-only response viewer with prominent status bar
- **Send ▶** button fires via Burp's HTTP client; lands in **Logger**, not Proxy history
- **Keyboard shortcuts:** `Cmd+Space` / `Ctrl+Space` (primary), `Ctrl+Enter` (fallback)
- **Reset** restores the request to its original state from the table

### Response Info Bar

Shown above the response editor with status-code-colored text:

| Status Range | Color | Example |
|---|---|---|
| 2xx | Green | `HTTP 200 OK  \|  1.2 KB  \|  156 ms` |
| 3xx | Indigo | `HTTP 302 Found  \|  0 bytes  \|  89 ms` |
| 4xx | Amber | `HTTP 404 Not Found  \|  234 bytes  \|  45 ms` |
| 5xx | Red | `HTTP 500 Internal Server Error  \|  567 bytes  \|  1203 ms` |

### History Navigation

- **◀ ▶** buttons navigate through sent request history (append-style)
- Keyboard: **Alt+Left** / **Alt+Right**
- History prunes forward entries when a new request is sent after navigating back (browser-style)

---

## Bambda-Style Filter

A Caido-inspired filter system with prefix tokens, chips, and a command palette.

### Prefix Tokens

Type `prefix:value` tokens (case-insensitive) into the search bar. Multiple tokens combine with AND logic. Plain text becomes substring search across all columns + request body + response body.

| Prefix | Matches | Example |
|---|---|---|
| `m:` | HTTP method | `m:GET`, `m:POST` |
| `s:` | Response status code | `s:200`, `s:404` |
| `h:` | Host substring | `h:api.example` |
| `url:` | URL path substring | `url:/api/v1/` |
| `body:` | Response body content | `body:token` |
| `req:` | Request body content | `req:user_id` |
| `hdr:` | Request header name + value | `hdr:Authorization` |
| `mime:` | Response MIME type | `mime:JSON` |
| `len:` | Response body length | `len:1024` |
| `notes:` | Notes column | `notes:UNIQUE` |
| `u:` | Only UNIQUE rows | `u:` |
| `d:` | Only DUPE rows | `d:` |
| `skip:` | Only SKIP rows | `skip:` |
| `r:` / `regex:` | Regex across all columns + body | `r:\d{3}` |

### Filter Chips

Toggle buttons in the filter bar:

| Chip | Color (Active) | Function |
|---|---|---|
| `.* regex` | Purple | Treat search as case-insensitive regex |
| `In-scope` | Green | Show only requests in Target scope |
| `Shared` | Amber | Show only requests from Live Share peers |

### Command Palette

Click the search bar (or press Down arrow when focused) to open the filter command palette. Four categorized groups with 18 options, each showing a prefix badge, label, and description. Navigate with arrow keys, select with Enter or click.

**Groups:** HTTP · Request · Yentra · Advanced

### Status Operators

Type standalone comparison operators for status-based filtering:

| Operator | Example | Matches |
|---|---|---|
| `>N` | `>399` | Status > 399 |
| `>=N` | `>=400` | Status ≥ 400 |
| `<N` | `<300` | Status < 300 |
| `<=N` | `<=200` | Status ≤ 200 |

---

## IDOR / BOLA Tools

### Magic Cookie

Reissues selected requests with a user-supplied auth set swapped in.

1. Select requests in Yentra Live
2. Click **Magic Cookie**
3. Paste auth headers — one `Name: value` per line (`#` comments ignored)
4. The auth set is remembered across sessions
5. Results stream into a new window — each response lands as it arrives

Strips the request's existing Cookie and Authorization (plus any header you list), then adds only your supplied credentials. Method, path, body, and other headers are unchanged. The dialog stays open after sending so you can swap values and send again.

### Match & Replace

Swaps an ID or token in the path/query, body, or both — then reissues.

1. Select requests → **Match & Replace**
2. Enter **Match** text and **Replace** text
3. Choose **Path/query**, **Body**, or both
4. Optionally tick **regex**
5. Click **Replace & send**

Only requests containing the match are sent (others skipped). The dialog stays open — change values, select new rows, send again. Settings are remembered across sessions.

---

## Right-Click Actions

Available in HTTP history, Site Map table, and Site Map tree via the **Yentra** submenu:

| Action | Description |
|---|---|
| **Live unique window** | Opens the auto-collecting live view (same as Ctrl+9 with no selection) |
| **Show only unique requests from selection — Ctrl+9** | Deduplicates selection by signature, opens in results window |
| **Send unique to Organizer** | Deduplicates selection, applies header overrides, sends uniques to Burp Organizer with batch label |
| **Remove host from scope** | Excludes selected request's host(s) from Target scope |
| **Remove path from scope** | Excludes selected request's path prefix(es) from Target scope |

Also available as a right-click popup on the Yentra Live table: **Send to Repeater**, **Share**, **Remove host from scope**, **Remove path from scope**.

---

## Remove from Scope

**What gets excluded:**

- **Remove host from scope** → `scheme://host:port/` (default ports 80/443 stripped) — prefix-matches all paths on that host
- **Remove path from scope** → `scheme://host:port/path` (query stripped, trailing slashes trimmed) — prefix-matches that path and sub-paths

A confirmation dialog shows exactly what will be excluded. Multi-selection deduplicates unique hosts/paths.

---

## Yentra Share (Live Share)

> **⚡ The only Burp extension with real-time peer-to-peer HTTP request sharing.**
> Two testers, two Burp instances, one shared feed. No exports, no copy-paste, no waiting.

### How It Works

1. **Tester A** starts a server on the **Yentra Share** tab (port 9999)
2. **Tester B** connects to Tester A's address
3. Tester A browses the target — every `[YENTRA] UNIQUE` request appears **instantly** in Tester B's **Yentra Live** feed, color-coded magenta
4. Tester B can replay received requests through their own proxy listener to add role tags (attacker/victim)
5. Both testers see identical, deduplicated feeds in real time

### Four Connection Modes — Always Reachable

| Mode | Setup | Best For |
|---|---|---|
| **Direct TCP** | Open a port, share the IP — zero config | Same LAN / VPN |
| **SSH Tunnel** | Tick one checkbox — auto-tunnels through `serveo.net` | Behind NAT, no port forwarding needed |
| **HTTP Relay** | `docker compose up -d` in `relay-server/`, share the room ID | Both peers fully firewalled |
| **UPnP IGD** | Automatic — tries to map a port on your router | Home/office networks |

### Sharing Features

| Feature | Description |
|---|---|
| **Manual Share** | Click **Share** on any selected request to send it to all connected peers |
| **Auto-Share** | Every new `[YENTRA] UNIQUE` is automatically forwarded — toggle on/off |
| **Re-issue to Proxy** | Replay received requests through a local Burp proxy listener (default 8080) so they appear in your HTTP history with role tags |
| **Magenta Highlighting** | Shared requests are visually distinct in Yentra Live |
| **Double-click → Repeater** | Any received request opens in a Burp Repeater tab with one double-click |
| **500-entry log** | Scrollable list of all received requests with method + URL preview |

### Self-Hosting the Relay

```bash
cd relay-server
docker compose up -d
```

The relay is a lightweight Java HTTP server. Two peers connect to it with the same room ID and messages are brokered in real time. No database, no auth, no accounts — just room-based pub/sub. Works behind any NAT or firewall.

### Use Cases

- **Pair testing:** One tester browses as attacker, the other as victim — both see identical traffic
- **Training / mentoring:** Senior tester shares live traffic with a junior in real time
- **Distributed testing:** Two testers on different networks testing the same target simultaneously
- **Demo / presentation:** Share your Burp session live without screen sharing

---

## AI Bridge (Live Export)

Burp's MCP server cannot see custom extension windows, so Yentra uses the **filesystem** as the AI bridge:

```
~/.yentra/<burp-project-name>/
  live-unique.http   ← every unique request, as it arrives
  selection.http     ← current table selection
```

The folder is named after the current Burp project. Each entry is a `####`-delimited request+response block prefixed with a **case manifest** — five fields the AI reads before touching payloads:

1. **Source request** — method + URL
2. **Identity role** — `attacker` / `victim` (from `X-AI-Use` header or `[attacker]/[victim]` tag)
3. **Why it's unique** — the Yentra verdict and signature rationale
4. **Replay command** — a ready-to-run `curl` (auth + body included; body omitted if > 4 KB)
5. **Expected safe failure** — the IDOR/BOLA oracle: replayed under a different identity this should be denied (401/403/404); a 200 with another identity's data is the finding

**Workflow:** Open Yentra Live → it fills with `[YENTRA] UNIQUE` requests and mirrors them → in Claude Code: *"read `~/.yentra/<project>/live-unique.http`"*. The toggle is on by default in live mode. Tick **Responses: body only, pretty JSON** when saving for AI to get clean JSON without headers.

---

## Attacker / Victim Port Highlighting

For multi-account IDOR/BOLA testing where each account browses through its own proxy listener port.

**Default port rules** (edit `PORT_RULES` in `PortHighlightHandler.java` and rebuild):

| Listener Port | Role | Unique Color | Duplicate Color | Injected Headers |
|---|---|---|---|---|
| **8082** | attacker | Green | Yellow | `X-AI-Use: attacker` |
| **8083** | victim | Red | Gray | `X-AI-Use: victim` |
| any other | — | Yellow | Gray | — |

Row colors are per-port and per-verdict, applied after classification. The **Highlight rows** toggle must be on. Port rules are logged to extension output on load.

---

## Body Only (Pretty JSON) Editor

A read-only response-viewer tab available everywhere a response is shown:

- Shows only the body (no headers)
- Strips JSON XSSI guards (`)]}'`, `for(;;);`, `while(1);`)
- Pretty-prints JSON with zero-dependency re-indenter
- Opt-in when you **Save for AI**: tick **Responses: body only, pretty JSON**

---

## Keyboard Shortcuts

| Shortcut | Context | Action |
|---|---|---|
| `Cmd+Space` / `Ctrl+Space` | Inline Repeater | Send request |
| `Ctrl+Enter` | Inline Repeater | Send request (fallback) |
| `Alt+Left` | Inline Repeater | Navigate history back |
| `Alt+Right` | Inline Repeater | Navigate history forward |
| `Ctrl+9` | HTTP history / Site Map | Open live unique window (snapshot if rows selected) |
| `Down` | Filter field (focused) | Open command palette |
| `Up/Down/Enter/Esc` | Command palette | Navigate / select / dismiss |

---

## Build

Requires JDK 21+.

```bash
./gradlew build
```

Output: `build/libs/yentra-0.1.0-SNAPSHOT.jar`

---

## Acknowledgements

- Yentra builds on **[burp-dedupe](https://github.com/sw33tLie/burp-dedupe)** by **sw33tLie** — the original deduplication engine. MIT-licensed.
- The per-request **case manifest** in the AI export was suggested by **[Timur Yessenov (@Timur_Yessenov)](https://x.com/Timur_Yessenov)**.
- The **Body Only (Pretty JSON)** response tab was inspired by **[rikeshbaniya](https://github.com/rikeshbaniya)**'s Burp extension.