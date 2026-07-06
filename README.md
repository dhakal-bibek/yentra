# DedupeAI

Burp Suite extension (Montoya API) that turns noisy HTTP history into a **deduplicated, AI-ready** attack surface. It stamps every new proxy entry **UNIQUE** or **DUPE**, streams the unique ones into a live feed, color-codes attacker/victim traffic by listener port — a **port-based highlighter** (PwnFox-style, but keyed on the proxy listener port) built for **Android/iOS** multi-account testing — and hands the deduped set straight to **Claude Code / AI** through a file bridge, with **IDOR/BOLA** tooling built in.

![DedupeAI — the Dedupe Live feed with attacker (green) / victim (red) tagging and an inline Repeater](assets/dedupe-live.png)

---

## Table of Contents

- [Installation](#install-in-burp)
- [Quick Start](#usage)
- [Dedupe Engine](#dedupe-engine)
- [Presets](#presets)
- [Dedupe Config Tab](#dedupe-config-tab)
- [Dedupe Live Tab](#dedupe-live-tab)
- [Dedupe Share Tab (Live Share)](#dedupe-share-tab-live-share)
- [Right-Click Actions (HTTP history / Site map)](#right-click-actions-http-history--site-map)
- [Right-Click Popup (Dedupe Live / Unique Requests table)](#right-click-popup-dedupe-live--unique-requests-table)
- [Remove from Scope](#remove-from-scope)
- [IDOR / BOLA Tools](#idor--bola-tools)
  - [Magic Cookie](#magic-cookie)
  - [Match & Replace](#match--replace)
- [Inline Repeater](#inline-repeater)
- [Live Export (AI Bridge)](#live-export-ai-bridge)
- [Case Manifest](#case-manifest-per-request)
- [Body Only (Pretty JSON) Editor](#body-only-pretty-json-editor)
- [Attacker / Victim Port Highlighting](#attacker--victim-port-highlighting)
- [Header Overrides](#header-overrides)
- [Notes / Edge Cases](#notes--edge-cases)
- [Build](#build)
- [Acknowledgements](#acknowledgements)

---

## Install in Burp

1. Burp → **Extensions** → **Installed** → **Add**
2. Extension type: **Java**
3. Select `build/libs/burp-dedupe-0.1.0-SNAPSHOT.jar`
4. Three new tabs appear: **Dedupe**, **Dedupe Live**, and **Dedupe Share**.

---

## Usage

1. Open the **Dedupe** tab.
2. Pick a preset (e.g. **Request smuggling** if you only care about path uniqueness).
3. Hit **Apply** — this also resets the seen-set so verdicts stay consistent.
4. Browse / replay traffic. New entries get stamped.
5. In **HTTP history**, click the **Notes** column header to sort. All `[DEDUPE] UNIQUE` rows cluster. Multi-select → send to your scanner / extension.

---

## Dedupe Engine

Every response that lands in HTTP history is classified by a `ProxyResponseHandler`:

- A **signature** is computed from configurable parts of the request/response (method, host, path, param names, values, etc.).
- Signatures are SHA-256-derived 128-bit keys stored in a `ConcurrentHashMap<Signature, AtomicInteger>` — fast, thread-safe, memory-light.
- The verdict is stamped into the Notes column as `[DEDUPE] UNIQUE` or `[DEDUPE] DUPE x3`.
- A **body digest** safety net: when body param names/values are included in the signature, the raw body's content hash (first 4096 bytes) is always folded in. This prevents two POSTs with different JSON bodies (e.g. `{"id":1}` → `{"id":2}`) from colliding into a false DUPE.
- **Cross-identity dedupe**: when traffic arrives through role-tagged ports (attacker/victim), Cookie, Authorization, and role headers are stripped before computing the signature, so the same request from two identities shares one count (first = UNIQUE, second = DUPE).

**Verdicts:**
| Verdict | Meaning |
|---|---|
| `[DEDUPE] UNIQUE` | First time seeing this signature |
| `[DEDUPE] DUPE xN` | Seen N times before |
| `[DEDUPE] SKIP` | Out of scope, static asset, or dedupe disabled |
| `[DEDUPE] OVRF` | Seen-set cap exceeded (default 200k signatures) |

---

## Presets

| Preset | What it considers unique |
|---|---|
| Default | method + host + path + sorted param names + status |
| Request smuggling | method + host + path only (params ignored) |
| IDOR / Auth | method + host + path (numeric IDs normalized) + sorted param names |
| XSS | method + host + path + sorted query+body param names |
| SQLi | method + host + path + sorted param names |
| SSRF | method + host + path + query param names |
| Open redirect | host + path + query param names (method-insensitive) |
| SSTI | method + host + path + param names |
| Path traversal | method + host + normalized path + query param names |
| Strict | full URL + all params + values + status + content-type |
| Custom | whatever you tick |

![The Dedupe config tab — pick a Preset (or tick individual signature fields), set filters and the memory cap, paste header overrides, and watch live stats](assets/dedupe-config.png)

---

## Dedupe Config Tab

The main configuration panel (Burp suite tab: **"Dedupe"**) with two panes:

**Left pane — Behavior & Signature:**
- **Stamp Notes column** — writes `[DEDUPE]` verdicts into the Notes column.
- **Highlight rows** — tints rows by verdict and listener port.
- **Preserve existing notes** — keeps your manual notes when stamping (prepends the verdict).
- **Preset dropdown** — choose from 10 presets or build your own with individual checkboxes.
- **Signature fields** — 12 checkboxes: Method, Scheme, Host, Port, Path, Normalize numeric/UUID path segments, Query param names, Query param values, Body param names, Body param values, Response status code, Response Content-Type.
- **Filters** — "In-scope only" (skip out-of-scope), "Skip static assets" (skip .css, .js, images, fonts, etc.), "Include headers" (comma-separated extra header names to fold into the signature).
- **Max tracked signatures** — hard cap (default 200k); beyond this new signatures get `OVRF` to prevent OOM.
- **Auto-stamp existing history** — retroactively stamp all proxy history when the extension loads.
- **Stamp existing history** button — one-shot retroactive stamp of all history (background thread, cancellable).
- **Apply (resets seen-set)** — applies config changes and clears the seen-set for clean verdicts.
- **Reset stats** — zeros all counters.
- **Live unique window** — opens a pop-up live feed of `[DEDUPE] UNIQUE` entries.

**Right pane — Stats & Overrides:**
- **Live stats** — Total seen, Unique, Duplicates, Skipped, Tracked signatures (refreshes every second).
- **Header overrides** — paste raw header lines (e.g. `Cookie: a=1; b=2`) to inject into requests sent to Organizer. Choose *Replace if present, add if missing* or *Replace only*. Reserved headers (Host, Content-Length, Transfer-Encoding) are rejected.
- **Quick guide** — inline help text.

---

## Dedupe Live Tab

An always-on, auto-refreshing feed of **only** the `[DEDUPE] UNIQUE` requests. No selection needed — it's there the moment the extension loads as a Burp suite tab (**"Dedupe Live"**). You can also open it as a pop-up window via **Ctrl+9** in HTTP history / Site Map (with nothing selected) or via the **Live unique window** button on the Dedupe tab.

![DEDUPE verdicts and attacker/victim port tags in Burp's HTTP history](assets/history-verdicts.png)

**How it works:**
- **Push path** — every `UNIQUE` classified by the proxy handler is pushed directly into the live feed.
- **Poll path** — a background timer (every 1.5s) incrementally scans `api.proxy().history()` for entries stamped `[DEDUPE] UNIQUE` that haven't been collected yet. Full rescan every ~60s to catch late "Stamp existing history" marks.
- Both paths cross-dedupe by request identity (method + URL + body hash + status) so the same request never appears twice.

**Toolbar:**
- **Send to Repeater** — sends selected rows to new Repeater tabs named by method + path.
- **Share** — shares the selected request with connected peers (see [Live Share](#dedupe-share-tab-live-share)).
- **In-scope only** — filters the table to only requests in Target scope.
- **Shared only** — shows only requests received from peers.
- **Save request(s) for AI** — exports selected rows to a `.http` file with case manifests.
- **Magic Cookie** — reissue with swapped auth headers (see [Magic Cookie](#magic-cookie)).
- **Match & Replace** — swap IDs and reissue for IDOR/BOLA (see [Match & Replace](#match--replace)).
- **Clear** — empties the table (already-seen IDs won't reappear).
- **Live export → file** — mirrors the live feed to `~/.burp-dedupe/<project>/live-unique.http` and `selection.http`.
- **Filter** — substring or regex search across all columns and full request/response body.

**Editor pane (below table):** Split request/response viewers with an **inline Repeater** — select a row to load it, edit the request on the left, **Send** (Ctrl+Space), see the response on the right with status/length/timing. Reissued requests land in Logger, not Proxy history.

---

## Dedupe Share Tab (Live Share)

Real-time request sharing with peers — host a server or connect to a friend to share captured requests live.

![Multi-account IDOR/BOLA in DedupeAI — attacker vs victim traffic](assets/idor-bola.png)

**Host a server:**
- Enter a port (default 9999) and click **Start Server**.
- **UPnP IGD** port mapping is attempted automatically for NAT traversal (optional toggle).
- **SSH tunnel via serveo.net** — bypass firewalls by tunneling through a public SSH service (optional toggle).

**Connect to a friend:**
- Enter the host and port, click **Connect**.
- Supports direct TCP and **relay** mode (Drop-style HTTP relay for when both peers are behind NAT/firewalls).

**Relay server:**
- A standalone relay you can self-host. Build and run with Docker:
  ```bash
  cd relay-server && docker compose up -d
  ```
- The relay is a simple HTTP server that brokers room-based message exchange — two peers join the same room ID and requests flow through it.

**Share bar:**
- **Share this request** — sends the currently selected request to all connected peers.
- **Auto-share new uniques** — every new `UNIQUE` is automatically forwarded to peers.
- **Re-issue received → Proxy history** — reissues requests received from peers through a specified proxy listener port so they appear in your history with the correct role tagging.

**Received shared requests:** A list of all received requests — double-click to open in Repeater.

---

## Right-Click Actions (HTTP history / Site map)

Select rows, right-click → **Dedupe**:

### Show only unique requests from selection — Ctrl+9
Opens a separate window styled like Burp's HTTP history: columns for `# / Host / Method / URL / Status / Length / MIME / Notes`, rows tinted by their Burp highlight color, the Notes column showing the `[DEDUPE] …` verdict + `[attacker]/[victim] port N` tag, and read-only request/response viewers beneath. Burp's API can't filter its own history table, so the deduplicated set is shown here instead. (Out-of-scope/static `SKIP` rows and known duplicates are excluded.)

This is a **snapshot** of the current selection. For an auto-updating view, use the **Dedupe Live** tab.

### Send unique to Organizer
Ships only the unique requests (dupes filtered) to Burp Organizer, optionally applying header overrides, tagged with a batch label in the Notes column (`Dedupe @ 2026-07-05 16:44:00`). If the selection has no `[DEDUPE]` stamps yet, a full history stamp pass runs first so you can see verdicts on the rows you just acted on.

From Organizer, right-click → **Extensions → …** to feed them to any extension (HTTP Request Smuggler, Turbo Intruder, etc.).

### Live unique window
Opens the auto-collecting live view — same as the **Dedupe Live** tab but as a pop-up window.

### Remove host from scope
Excludes the selected request's host from Burp's Target scope. A confirmation dialog shows the URL(s) to exclude. For example, selecting `https://api.example.com/v1/users/123` → excludes `https://api.example.com/`. When multiple rows are selected across different hosts, each unique host is excluded.

### Remove path from scope
Excludes the selected request's full path prefix from Burp's Target scope. For example, selecting `https://api.example.com/v1/users/123?page=1` → excludes `https://api.example.com/v1/users/123` (query string stripped). When multiple rows are selected, unique path prefixes are deduplicated. This is like Burp's built-in "Remove from scope" but you can select any request from history and exclude its host or path with a single click — no need to manually type URL patterns in the Target scope settings.

---

## Right-Click Popup (Dedupe Live / Unique Requests table)

Right-click any row in the **Dedupe Live** tab or **Unique Requests** window:

- **Send to Repeater** — sends selected rows to new Repeater tabs.
- **Share** — shares the selected request with connected Live Share peers.
- **Remove host from scope** — excludes the selected request's host from Target scope (with confirmation dialog).
- **Remove path from scope** — excludes the selected request's path prefix from Target scope (with confirmation dialog).

All scope removal actions show a confirmation dialog listing the URLs to be excluded and log the result to the extension output.

---

## Remove from Scope

Available in two places:
1. **HTTP history / Site Map** — right-click → **Dedupe → Remove host from scope** or **Remove path from scope**
2. **Dedupe Live / Unique Requests table** — right-click popup with the same options

**What gets excluded:**
- **Remove host from scope** → constructs `scheme://host:port/` (strip default ports 80/443), which prefix-matches all paths on that host in Burp's scope engine.
- **Remove path from scope** → constructs `scheme://host:port/path` (query stripped, trailing slashes removed), which prefix-matches that path and everything under it.

Both work on multi-selections — unique hosts/paths across selected rows are deduplicated before exclusion. A confirmation dialog shows exactly what will be excluded before acting.

---

## IDOR / BOLA Tools

### Magic Cookie

Reissues selected request(s) with a user-supplied auth set swapped in. Strips the request's existing `Cookie` and `Authorization` (plus any header you list) and sends with **only** the credentials you provide — method, path, body and every other header unchanged.

**Usage:**
1. Select one or more requests in the Dedupe Live table (or unique-requests window).
2. Click **Magic Cookie** in the toolbar.
3. Paste auth headers — one `Name: value` per line. Lines starting with `#` are comments.
4. The auth set is remembered across windows and restarts (Montoya preferences).
5. Click **Send**. Results open in their own streaming window — each response lands as it returns so you can compare status codes live.

Ideal for same-request / different-identity IDOR/BOLA checks (e.g. replay an attacker's request with the victim's session and watch for a `200`). The results window has all the same toolbar actions (Send to Repeater, Save for AI, Magic Cookie, Match & Replace, filter, inline repeater).

The Magic Cookie dialog is **non-modal** — it stays open after sending so you can change auth headers, select new rows, and send again without reopening.

### Match & Replace

Reissues selected request(s) with a find/replace applied to the **path/query**, the **body**, or **both** (literal, or tick **regex**). Built for IDOR/BOLA: swap an object id (e.g. `1001` → `1002`) and watch the results for a `200` where another identity's value should be denied.

**Usage:**
1. Select one or more requests in the Dedupe Live table.
2. Click **Match & Replace** in the toolbar.
3. Enter the value to **match** and what to **replace** it with.
4. Choose **Path/query**, **Body**, or both. Tick **regex** for regex-based replacements.
5. Click **Replace & send**.

**Key behaviors:**
- **Only requests that actually contain the match are reissued** — the rest are skipped, so you hit only the endpoints carrying that ID.
- Method, headers, and untouched parts go out as-is (`Content-Length` is refreshed automatically).
- The match/replace/scope/regex settings are remembered across windows and restarts (Montoya preferences).
- Results open in their own streaming window — each response lands as it returns.

The Match & Replace dialog is **non-modal** — it stays open after sending so you can:
- Change match/replace values for a different ID and send again.
- Select different rows from the table while the dialog is open.
- Send multiple batches without reopening the dialog. Close with Cancel or the window X.

---

## Inline Repeater

A full Repeater-style interface built into the bottom half of every Dedupe Live / Unique Requests window — no need to switch to Burp's Repeater tab.

- **Request (left)** — editable Montoya HTTP request editor.
- **Response (right)** — read-only response viewer with a prominent **status bar** showing the HTTP status code, response size (bytes/KB/MB), and timing in ms — same format as Burp Repeater.
- **Send ▶** — sends the edited request via Burp's HTTP client. Shortcuts: **Cmd+Space** / **Ctrl+Space** (primary) and **Ctrl+Enter** (fallback).
- **◀ ▶ Back/Forward** — full request/response history navigation. Every sent request is recorded; click ◀ to go back to a previous request+response pair, ▶ to go forward. Keyboard: **Alt+Left** / **Alt+Right**. History is pruned when you send after navigating back (append-style, like a browser).
- **Cancel** — stops waiting for a response.
- **Target display** — shows the host:port you're sending to.

Reissued requests land in **Logger**, not Proxy history. Uses Burp's HTTP client.

---

## Live Export (AI Bridge)

Burp's MCP server can't see a custom extension window, so to hand your deduped requests to an AI we use the **filesystem** as the shared channel. With the **Live export → file** toggle on (default in the live window):

```
~/.burp-dedupe/<burp-project-name>/
  live-unique.http   ← every unique request it collects, as it arrives
  selection.http     ← just the rows you currently have selected
```

The folder is named after the **current Burp project** (`api.project().name()`), so each engagement gets its own. Each entry is the request **and** its response in a `####`-delimited block, prefixed with a [case manifest](#case-manifest-per-request); the file opens with a one-line protocol telling the AI to read the manifest and explain the risk before touching payloads.

**Workflow:** open the **Dedupe Live** tab → it fills with `[DEDUPE] UNIQUE` requests and mirrors them automatically → in **Claude Code**: *"read `~/.burp-dedupe/<project>/live-unique.http`"* for the full deduped set, or `selection.http` for just what you've highlighted. The folder path is logged to the extension's **Output** on open and shown in the **status bar** after each write.

![The AI bridge on disk — ~/.burp-dedupe/<project>/ holds live-unique.http and selection.http](assets/ai-export.png)

---

## Case Manifest (per request)

So the AI gets a **case file, not a bucket of HTTP noise**, every exported request is prefixed with a `#`-commented manifest — un-skippable, it rides in front of every block:

1. **Source request** — method + URL.
2. **Identity role** — `attacker` / `victim`, from the `X-AI-Use` header or the `[attacker]/[victim] port N` tag.
3. **Why it's unique** — the dedupe verdict and what the signature keyed on.
4. **Replay command** — a ready-to-run `curl` (auth + body included).
5. **Expected safe failure** — the IDOR/BOLA oracle: replayed under a *different* identity it should be denied (`401/403/404`); a `200` returning the other identity's data is the finding.

```
# --- CASE MANIFEST (read before touching payloads) ------------------------
# 1. Source request : POST https://api.example.com/v1/tracking/batch/events
# 2. Identity role  : victim  (X-AI-Use: victim, proxy listener port 8083)
# 3. Why unique     : [DEDUPE] UNIQUE — first request with this signature.
# 4. Replay command : curl -isSk -X POST 'https://api.example.com/v1/tracking' -H 'Cookie: ...' --data-raw '...'
# 5. Expected safe  : original response 200; replayed under a DIFFERENT identity this should be DENIED —
#                     expect 401/403/404. A 200 returning the other identity's data is the finding.
# --------------------------------------------------------------------------
===== REQUEST =====
POST /v1/tracking/batch/events HTTP/2
...
```

*Manifest format suggested by [Timur Yessenov (@Timur_Yessenov)](https://x.com/Timur_Yessenov) — thanks!*

---

## Body Only (Pretty JSON) Editor

A read-only response-viewer tab (**"Body Only"**) available in Proxy, Repeater, and everywhere else a response is shown. It:

- Strips HTTP headers — shows only the body.
- Strips JSON XSSI guards (`)]}'`, `for(;;);`, `while(1);`).
- Pretty-prints JSON with a zero-dependency re-indenter.
- Also available as an opt-in when you **Save request(s) for AI** — tick **Responses: body only, pretty JSON** in the save dialog.

---

## Attacker / Victim Port Highlighting

For multi-account IDOR/BOLA testing where each account browses through its own proxy listener port.

- Registers a `ProxyRequestHandler` that injects identifying headers (`X-AI-Use`, `X-Role`) into traffic by the **listener port** it arrived on.
- Row colors are per **port** and per **verdict** (unique vs duplicate). Default port rules (edit `PORT_RULES` in `PortHighlightHandler.java` and rebuild):

| Listener port | Unique color | Duplicate color | Injected header |
|---|---|---|---|
| **8082** (attacker) | green | yellow | `X-AI-Use: attacker` |
| **8083** (victim) | red | gray | `X-AI-Use: victim` |
| any other port | yellow | gray | — |

Because color is verdict-aware, it's applied after classification — so the "Highlight rows" toggle must be on for colors to show.

Port rule config is logged to the extension output on load:
```
[burp-dedupe] port 8082 -> unique=GREEN dupe=YELLOW {X-AI-Use=attacker}
[burp-dedupe] port 8083 -> unique=RED dupe=GRAY {X-AI-Use=victim}
```

---

## Header Overrides

In the Dedupe tab's **Header overrides** section:

- Paste raw header lines (e.g. `Cookie: a=1; b=2`, `Authorization: Bearer …`), one per line. Blank lines and `#` comments are ignored.
- Pick **Replace if present, add if missing** or **Replace only (don't add new headers)**.
- Tick **Apply header overrides when sending to Organizer** and hit **Apply**.
- Reserved headers (`Host`, `Content-Length`, `Transfer-Encoding`) are rejected with a warning logged.
- Overrides are applied when you right-click → **Dedupe → Send unique to Organizer** — each request is modified in-flight before hitting Organizer.

---

## Notes / Edge Cases

- **Existing history can be retro-stamped.** Use the **"Stamp existing history"** button in the Dedupe tab to walk `api.proxy().history()` and apply verdicts in-place. Or tick **"Auto-stamp existing history when extension loads"** to do it automatically on every load (handy when reopening saved projects). The job runs on a background thread and can be cancelled. The seen-set is reset before the pass so counts stay consistent.
- **Changing the config resets the seen-set** so you don't get mixed verdicts under different signature rules.
- **Static assets** (`.css`, `.js`, images, fonts, etc.) are skipped by default to keep the seen-set small.
- **Memory cap**: at *Max tracked signatures* (default 200k) new keys stop being added and the verdict becomes `OVRF` — prevents OOM on huge engagements.
- **Out-of-scope**: enable "In-scope only" to skip everything not in target scope.
- **Path normalization** (numeric IDs → `{n}`, UUIDs → `{uuid}`, long hex → `{hex}`) is opt-in per preset; turn it on for IDOR / path traversal.
- **Body digest safety net**: when body params are included, a hash of the raw body content is always folded into the signature — ensuring different JSON/XML bodies never produce false DUPEs even if Montoya can't parse them into parameters.
- **Non-modal dialogs**: both Magic Cookie and Match & Replace dialogs are non-modal — they stay open after sending so you can change values, select new rows, and send again without reopening.

---

## Build

Requires JDK 21+.

```bash
./gradlew build
```

Output: `build/libs/burp-dedupe-0.1.0-SNAPSHOT.jar`

---

## Acknowledgements

- DedupeAI builds on **[burp-dedupe](https://github.com/sw33tLie/burp-dedupe)** by **sw33tLie** — the original dedupe + unique-requests core. It's MIT-licensed and that licence is retained in [`LICENSE`](LICENSE).
- The per-request **[case manifest](#case-manifest-per-request)** in the AI export was suggested by **[Timur Yessenov (@Timur_Yessenov)](https://x.com/Timur_Yessenov)**.
- The **Body Only (Pretty JSON)** response tab was inspired by **[rikeshbaniya](https://github.com/rikeshbaniya)**'s Burp extension.