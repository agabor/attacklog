# Attack Log — WordPress Plugin System Plan

| | |
|---|---|
| **Plugin name** | Attack Log |
| **Slug / text domain** | `attack-log` |
| **Table prefix** | `{$wpdb->prefix}attacklog_` |
| **Minimum requirements** | WordPress 6.0+, PHP 7.4+, MySQL 5.7+ / MariaDB 10.3+ |
| **Coding standard** | WordPress.org coding standards, met strictly (section 13) |
| **Multisite** | Not tested or supported, but not blocked (see 4.3) |
| **Document date** | 2026-10-08 |

---

## 1. Purpose

Attack Log detects and records five kinds of suspicious traffic:

1. **Cloudflare Bypass** — the site sits behind the Cloudflare proxy, yet a request reaches the origin server without the headers Cloudflare always adds. This usually means someone found the origin IP and is talking to it directly, skipping the WAF.
2. **Probing** — requests that end in a 404 and whose path matches well-known scanner patterns (`.env`, `backup.sql`, `.git/config`, …).
3. **Direct PHP Access** — requests for `.php` files inside `wp-includes` or the uploads folder. No legitimate visitor requests these; they are typically attempts to reach a planted webshell, trigger a full-path-disclosure error, or hit a vulnerable bundled library.
4. **XML-RPC** — every request to `xmlrpc.php`. Treated as suspicious by default, because the endpoint is mostly used for password brute force (`system.multicall`), pingback abuse and reconnaissance. Legitimate clients are allowed through the whitelist.
5. **Suspicious User Agent** — requests whose User-Agent is missing, malformed, or belongs to an HTTP library or a known scanner (`curl`, `python-requests`, `Go-http-client`, `sqlmap`, …).

Every logged request records the **client IP** and **User-Agent**. A general **whitelist** (by IP or by User-Agent) suppresses logging for trusted sources, for all categories or for selected ones.

The admin screen shows whether the site is behind Cloudflare and lists the logged requests in a clean, modern interface.

---

## 2. Functional requirements

| ID | Requirement |
|---|---|
| FR-1 | Set the Cloudflare state **once, automatically**: on activation, inspect the current HTTP request for `CF-Ray`, `CF-IPCountry` and `CF-Visitor`; if **all three** are present, turn Cloudflare bypass detection on. If activation had no HTTP request (WP-CLI), do the same on the first visit to the Attack Log page. Never change it automatically afterwards. |
| FR-2 | If Cloudflare bypass detection is on, log every front-end request that is missing **any** of the three headers, with error type *Cloudflare Bypass*. |
| FR-3 | Log every request that returns **404** and whose path matches a probing pattern, with error type *Probing*. Applies whether or not the site is behind Cloudflare. |
| FR-4 | Admin page shows the Cloudflare status and the request log. |
| FR-5 | Simple, modern design consistent with (but cleaner than) core WP admin. |
| FR-6 | The admin page has a **switch** to turn Cloudflare bypass detection on or off. Above it, a note says whether the **current request** seems to have come through Cloudflare. |
| FR-7 | **Auto-clean:** keep only the last X days of log entries (setting, default **30**), removed daily via WP-Cron. |
| FR-8 | **Manual clearing:** clear one error type, or clear the whole log. Full cleanup on uninstall. |
| FR-9 | Log every request for a `.php` file under `/wp-includes/` or the uploads directory, with error type *Direct PHP Access*, regardless of status code. |
| FR-10 | Requests from **logged-in users** (any role) are **never logged**. No setting. |
| FR-11 | Log the **client IP** and **User-Agent** with every logged request. Client IP = `CF-Connecting-IP` if present, otherwise `REMOTE_ADDR`. |
| FR-12 | Log **every** request to `xmlrpc.php` with error type *XML-RPC*, regardless of method or status code. |
| FR-13 | Log every request with a suspicious User-Agent (missing, malformed, HTTP library, scanner) with error type *Suspicious User Agent*. |
| FR-14 | **Whitelist** by IP or by User-Agent, always **exact match**. Each entry applies to all categories or to selected ones. Whitelisted requests are not logged. |
| FR-15 | The request log is **split into tabs**: an **All** tab plus one tab per error type. Each tab shows its name and request count. |
| FR-16 | **Multisite is not supported, but not forbidden.** No multisite-specific features and no checks that block it; everything is stored per site so per-site activation is expected to work. |


---

## 3. Architecture overview

```
                    ┌──────────────────────────────────────┐
 HTTP request ───▶  │  WordPress bootstrap                 │
                    │                                      │
                    │  plugins_loaded                      │
                    │   └─ Request_Context::capture()      │  CF headers, method, path,
                    │                                      │  client IP, remote addr, UA
                    │  xmlrpc_call / xmlrpc_login_error    │
                    │  (XML-RPC only)                      │  collect XML-RPC details
                    │                                      │
                    │  status_header (filter)              │  remember final status code
                    │                                      │
                    │  shutdown                            │
                    │   └─ Classifier::evaluate()          │  rules → whitelist → Logger
                    └──────────────────┬───────────────────┘
                                       │
                             ┌─────────▼─────────┐
                             │  Repository (DB)  │
                             └─────────┬─────────┘
                                       │
                             ┌─────────▼─────────┐
                             │  Admin page (UI)  │
                             └───────────────────┘
```

**Why classify on `shutdown`?** The final status code is only known once WordPress has finished routing, and XML-RPC details are only complete after the method has run. Using `shutdown` also means the DB write happens after output has been generated, so it has no effect on the visitor's page time (after `fastcgi_finish_request()` where available).

`xmlrpc.php` is a real file, but it loads `wp-load.php`, so plugins load and `shutdown` fires as usual.

---

## 4. Cloudflare detection

### 4.1 Header access in PHP

| Header | `$_SERVER` key |
|---|---|
| `CF-Ray` | `HTTP_CF_RAY` |
| `CF-IPCountry` | `HTTP_CF_IPCOUNTRY` |
| `CF-Visitor` | `HTTP_CF_VISITOR` |
| `CF-Connecting-IP` | `HTTP_CF_CONNECTING_IP` |

### 4.2 State model

Option `attacklog_cf_status`:

```php
[
    'enabled' => true,                  // Cloudflare bypass detection on/off — the only value the classifier reads
    'state'   => 'set',                 // 'unknown' until set for the first time
    'set_by'  => 'activation',          // 'activation' | 'first_admin_visit' | 'user'
    'set_at'  => '2026-10-08 06:43:12', // UTC
    'user_id' => null,                  // admin who flipped the switch, when set_by = 'user'
]
```

The helper used everywhere:

```php
function attacklog_request_has_cf_headers(): bool {
    return ! empty( $_SERVER['HTTP_CF_RAY'] )
        && ! empty( $_SERVER['HTTP_CF_IPCOUNTRY'] )
        && ! empty( $_SERVER['HTTP_CF_VISITOR'] );
}
```

### 4.3 Automatic setting — exactly once

| Moment | Condition | Action |
|---|---|---|
| Activation (`register_activation_hook`) | Activation runs inside an HTTP request | `enabled = attacklog_request_has_cf_headers()`, `set_by = activation` |
| Activation | No HTTP request (WP-CLI, `wp plugin activate`) | `state = unknown`, `enabled = false` |
| First Attack Log page view (`load-{page_hook}`) | `state == unknown` only | `enabled = attacklog_request_has_cf_headers()`, `set_by = first_admin_visit` |

After that, the plugin **never** changes `enabled` on its own — not on later page views, not on reactivation (activation keeps an existing `set` state, so deactivate/activate cycles don't overwrite the admin's choice). Only the switch (4.4) changes it.

While `state == unknown`, bypass detection is off; the other four categories work regardless.

**Multisite:** not tested or supported, but not blocked. The design stays multisite-safe without adding multisite features:

- Everything is per site: tables use `$wpdb->prefix` (e.g. `wp_2_attacklog_*`), state and settings are regular options. The plugin never uses `$wpdb->base_prefix` or network options.
- **Per-site activation** behaves exactly like a single-site install.
- **Network activation:** the activation hook only runs for the main site. On every other site the schema check on `plugins_loaded` (8) creates the missing tables on its first request, and the Cloudflare state stays `unknown` until that site's Attack Log page is first opened (rows above). There is no network admin page; each site has its own.
- **Uninstall** loops over all sites when `is_multisite()` is true (10), so no tables are left behind.
- The readme states: "Multisite: not tested or supported. Per-site activation is expected to work; network activation is not recommended."

### 4.4 Admin switch and live note

The Cloudflare card on the Log tab (9.2) has two parts:

**1. Live note (top)** — computed fresh on every page view from the admin's *current* request, never stored, never changes the switch:

| Current request | Note |
|---|---|
| All three CF headers present | ✓ "This request came through Cloudflare" + Ray ID and country |
| Some CF headers present | ⚠ "This request has only some Cloudflare headers (missing: CF-Visitor)" — unusual; possibly another proxy or forged headers |
| No CF headers | ○ "This request did not come through Cloudflare" |

**2. Switch (below the note)** — *Cloudflare bypass detection* on/off, with a line saying who set it last: "Set automatically at activation", "Set automatically on first visit", or "Turned on by {display name}, 8 Oct 2026".

**Hint when note and switch disagree** (shown between them, informational only):

| Switch | Current request | Hint |
|---|---|---|
| On | No CF headers | "You reached the site without Cloudflare. That's expected if you use a VPN, a hosts-file entry or a staging domain. Otherwise Cloudflare proxying (orange cloud) may be switched off — and every visitor would be logged as a bypass." |
| Off | All CF headers | "This site seems to be behind Cloudflare. Turn on bypass detection?" |

**Confirmation on change:**

- Turning **on** while the current request has no CF headers: confirm dialog — if the site is not really behind Cloudflare, every front-end request will be logged as *Cloudflare Bypass*.
- Turning **off**: confirm dialog — direct-to-origin requests will no longer be logged.

The change is saved via AJAX (nonce + `manage_options`), sets `set_by = user`, `user_id`, `set_at`, and takes effect from the next request.

### 4.5 Header spoofing (known limitation)

This version does **not** verify that requests carrying CF headers really come from Cloudflare's IP ranges. An attacker hitting the origin directly can forge every CF header, including `CF-Connecting-IP`. Consequences:

- A direct-to-origin request that forges all three CF headers is not logged as *Cloudflare Bypass*.
- Such a request is treated as Cloudflare-trusted, so its forged `CF-Connecting-IP` is used for whitelist matching (7.3).

The readme recommends the real fix at the infrastructure level: let the origin firewall accept HTTP(S) only from Cloudflare's IP ranges, or use Cloudflare Authenticated Origin Pulls. Verifying `REMOTE_ADDR` against Cloudflare's published ranges inside the plugin is a candidate for a later version.

---

## 5. Request context: IP and User-Agent

### 5.1 Client IP

```
client_ip   = valid( HTTP_CF_CONNECTING_IP ) ?: REMOTE_ADDR
remote_addr = REMOTE_ADDR                       (always stored as well)
```

- Values are validated with `filter_var( …, FILTER_VALIDATE_IP )`; an invalid header is ignored and `REMOTE_ADDR` is used.
- Stored as binary (`inet_pton`, `VARBINARY(16)`) so IPv4 and IPv6 share one column and whitelist comparison is a plain byte compare; shown with `inet_ntop`.
- Filter `attacklog_client_ip` lets sites behind another proxy (e.g. a load balancer with `X-Forwarded-For`) supply their own resolution.

**Why `remote_addr` is stored as well:** `CF-Connecting-IP` is only trustworthy when the request really came through Cloudflare. On a direct-to-origin request an attacker can set it to anything — including an address on the whitelist. Keeping `REMOTE_ADDR` means the log always shows the real connecting address, and it is what the whitelist uses when Cloudflare can't be trusted (see 7.3).

The request is considered **Cloudflare-trusted** when Cloudflare bypass detection is on (4.2) and all three CF headers are present. The headers are not verified against Cloudflare's IP ranges in this version (4.5).

### 5.2 User-Agent

- Read from `HTTP_USER_AGENT`, trimmed, control characters stripped, truncated to 512 characters.
- Missing or empty → stored as `NULL` (displayed as *— missing —*).
- Deduplicated into the `user_agents` table (6.4), the same way paths are deduplicated into `request_types`.

---

## 6. Request classification

### 6.1 Requests that are never logged

To avoid false positives:

- `wp_doing_cron()` / `DOING_CRON`
- `WP_CLI` defined
- Loopback requests: `REMOTE_ADDR` is `127.0.0.1`, `::1` or equals `SERVER_ADDR` (WP-Cron spawning, Site Health checks and some page-cache warmers call the site directly).
- **Logged-in users, any role — always, no setting** (FR-10). Checked on `shutdown`: `is_user_logged_in()`, or a valid logged-in cookie (`wp_validate_auth_cookie( '', 'logged_in' )`). The cookie check covers REST requests where WordPress resets the current user because no nonce was sent. Requests that authenticated through XML-RPC or an Application Password also count as logged in at that point, so successful XML-RPC client calls are not logged; failed logins are.
  - Trade-off: requests made with a stolen account are not logged either. Detecting compromised accounts is outside this plugin's scope.
- Configurable path ignore-list (filter `attacklog_ignored_paths`), e.g. health-check endpoints used by the hosting provider.
- Requests matching a whitelist entry for the category in question (section 7).

### 6.2 Cloudflare Bypass rule

```
IF   attacklog_cf_status.enabled == true
AND  any of CF-Ray / CF-IPCountry / CF-Visitor missing
THEN match "Cloudflare Bypass"
```

Logged regardless of the status code — a 200 served directly from the origin is exactly the case we want to see.

### 6.3 Probing rule

```
IF   final status code == 404
AND  normalised path matches any probing pattern
THEN match "Probing"
```

**Path normalisation:** take `REQUEST_URI`, strip the query string, URL-decode once, lowercase, collapse repeated `/`, strip the site's subdirectory prefix, truncate to 2048 chars.

**Default pattern list** (stored as regex fragments, extendable through filter `attacklog_probe_patterns` and a settings textarea):

| Category | Examples |
|---|---|
| Environment / secrets | `\.env(\..*)?$`, `\.aws/credentials`, `\.npmrc`, `\.htpasswd`, `config\.json$`, `secrets?\.(ya?ml\|json)$` |
| VCS / IDE | `\.git/`, `\.svn/`, `\.hg/`, `\.DS_Store$`, `\.vscode/`, `\.idea/` |
| Backups / dumps | `\.(sql\|sql\.gz\|bak\|old\|orig\|backup\|swp\|zip\|tar\|tar\.gz\|7z\|rar)$`, `backup`, `dump`, `db\.sql` |
| WP config copies | `wp-config\.(php[~_.-].*\|txt\|bak\|old\|save)$` |
| Debug / info | `phpinfo\.php$`, `info\.php$`, `debug\.log$`, `error_log$`, `server-status` |
| Admin tools / shells | `phpmyadmin`, `adminer\.php$`, `shell\.php$`, `c99\.php$`, `r57\.php$`, `xmlrpc\.php\.bak` |
| Other stacks | `/vendor/phpunit/`, `/cgi-bin/`, `\.asp(x)?$`, `/actuator/`, `/console/`, `/solr/` |

Patterns are compiled into a single combined regex once per request.

### 6.4 Direct PHP Access rule

```
IF   normalised path matches a protected-directory PHP pattern
THEN match "Direct PHP Access"
```

**Default patterns** (extendable through filter `attacklog_direct_php_paths`):

| Directory | Pattern |
|---|---|
| Core includes | `^/wp-includes/.*\.(php\d?\|phtml\|phar)$` |
| Uploads | `^{uploads_path}/.*\.(php\d?\|phtml\|phar)$` |

- `{uploads_path}` is derived from `wp_upload_dir()['baseurl']` at runtime, so relocated upload folders are covered.
- Extensions cover `.php`, `.php5`, `.php7`, `.phtml` and `.phar`, because webshells often use alternative extensions to slip past naive `*.php` blocks.
- **Not tied to the status code.** In practice these requests are almost always 404s (see 6.8), but the rule logs whatever code is returned.

### 6.5 XML-RPC rule

```
IF   defined( 'XMLRPC_REQUEST' ) OR normalised path == '/xmlrpc.php'
THEN match "XML-RPC"
```

Every request matches — `GET`, `POST`, any status code — except calls that log in successfully (logged-in rule, 6.1). Other legitimate clients are kept out of the log with the whitelist.

**Details collected** (stored in the `detail` column of the request's XML-RPC error-type row, 8.3, so the log shows *what* the request tried to do):

| Data | Source |
|---|---|
| Top-level method name | Bounded read (first 8 KB) of the raw body, regex on `<methodName>` |
| Number of inner calls in `system.multicall` | Counter on the `xmlrpc_call` action, which fires for each method executed |
| Failed logins | Counter on the `xmlrpc_login_error` filter |

Example `detail` values:

- `GET (recon)`
- `system.listMethods`
- `system.multicall ×250 · 250 failed logins`
- `pingback.ping`

### 6.6 Suspicious User Agent rule

```
IF   User-Agent matches any suspicious-UA rule
THEN match "Suspicious User Agent", detail = matched rule label
```

Logged regardless of path and status code.

**Default rules** (extendable through filter `attacklog_suspicious_ua_patterns` and a settings textarea):

| Label | Matches |
|---|---|
| `missing` | Header absent or empty |
| `malformed` | Shorter than 10 characters; only `Mozilla/5.0` with nothing after; non-printable characters; placeholders such as `-`, `null`, `undefined`, `test` |
| `http-library` | `curl/`, `Wget/`, `python-requests`, `Python-urllib`, `python-httpx`, `aiohttp`, `Go-http-client`, `okhttp`, `Java/`, `Apache-HttpClient`, `libwww-perl`, `PHP/`, `GuzzleHttp`, `node-fetch`, `axios/`, `undici`, `Ruby`, `PycURL`, `Scrapy`, `HeadlessChrome` |
| `scanner` | `sqlmap`, `nikto`, `nmap`, `masscan`, `zgrab`, `nuclei`, `wpscan`, `dirbuster`, `gobuster`, `ffuf`, `feroxbuster`, `acunetix`, `nessus`, `openvas`, `whatweb`, `wfuzz`, `burp`, `hydra`, `CensysInspect` |
| `outdated` | Browsers no real visitor uses any more: `MSIE [2-8]\.`, `Windows NT 5\.`, `Firefox/[1-3]\.` |

Matching is case-insensitive; the first matching label is recorded in `detail` together with the matched token (e.g. `http-library: python-requests/2.32.3`).

**Expected false positives**, which the admin handles with the whitelist (the UI says so next to the category):

- Uptime monitors and SEO tools that use a library UA.
- A real server cron job such as `wget -q -O - https://example.com/wp-cron.php`. Its request often comes in through Cloudflare with the server's public IP, so the loopback exclusion doesn't catch it.
- Integrations calling the REST API with `GuzzleHttp`, `python-requests`, etc.

WordPress's own outgoing requests (`WordPress/6.x; https://…`) and well-known search engine bots do not match any rule.

### 6.7 Combining rules

The five categories fall into two groups:

| Group | Categories | Describes |
|---|---|---|
| **Target** | Direct PHP Access, XML-RPC, Probing | *What* was requested |
| **Origin** | Cloudflare Bypass, Suspicious User Agent | *How* and *by what* it was sent |

Rules:

1. **Within the Target group, at most one category matches**, by precedence: Direct PHP Access → XML-RPC → Probing. A generic probe pattern (e.g. `shell\.php$`) must not double-count `/wp-includes/shell.php`.
2. **Origin categories are independent** of each other and of the Target group.
3. **The whitelist is applied per category** after matching. A category the matching entry covers is dropped; the others are still logged.
4. **One record per HTTP request.** If at least one category remains, exactly one row is written to `requests`, plus one row per remaining category in the pivot table `request_errors` (8.3). If no category remains, nothing is written.

Example: `curl https://ORIGIN_IP/.env` from a non-whitelisted IP → one `requests` row, with three `request_errors` rows (Probing, Cloudflare Bypass, Suspicious User Agent).

### 6.8 Coverage limitation (documented in the readme)

Attack Log only sees requests that reach PHP. With the default WordPress `.htaccess` / nginx `try_files` rules, requests for **non-existent** files (`/.env`, `/backup.sql`, `/wp-includes/fonts/x.php`) are routed to `index.php` and therefore are seen. Requests for files that **exist** on disk, or that the web server blocks itself (e.g. nginx `deny` for dotfiles), never reach WordPress and are not logged. Requests served from a full-page cache (Cloudflare APO, Varnish, a static-cache plugin) also never reach PHP, so Suspicious User Agent hits on cached pages are invisible.

This matters most for Direct PHP Access: if a webshell **does** exist at the requested path, the web server executes it directly and Attack Log never sees the hit. The defence for that case is blocking PHP execution in `wp-includes` and uploads at the web server or Cloudflare level; the readme includes example rules for Apache and nginx.

Likewise, if XML-RPC is blocked at the web server or Cloudflare, those requests never reach the plugin — which is the desired outcome.

---

## 7. Whitelist

### 7.1 Entry model

Stored in option `attacklog_whitelist` (not autoloaded) as an array of entries; cached in the object cache / a static variable per request.

| Field | Values | Notes |
|---|---|---|
| `id` | random 12-char string | Stable key for edit/delete |
| `type` | `ip` \| `ua` | |
| `value` | `203.0.113.7`, `2001:db8::1`, `Mozilla/5.0 (compatible; MyMonitor/1.0)` … | Always matched exactly (7.2) |
| `categories` | `all` or a list of error type IDs | Default `all` |
| `note` | free text | E.g. "Uptime monitor", "Office" |
| `created_at`, `created_by` | UTC datetime, user ID | Audit trail |

### 7.2 Matching

**Exact match only** — no ranges, wildcards, substrings or regex.

- IP entries: the request IP (7.3) must equal the entry. Both are compared in binary (`inet_pton`) form, so `2001:db8::1` and `2001:0db8:0:0:0:0:0:1` are the same address. IPv4-mapped IPv6 (`::ffff:1.2.3.4`) is normalised to IPv4 first.
- UA entries: the sanitised User-Agent (5.2) must equal the entry character for character, case-sensitive. Entries are sanitised the same way when saved, so a value copied from the log always matches.
- A missing User-Agent can't be whitelisted.
- An entry only suppresses the categories it lists. Example: whitelisting a monitor's exact UA for *Suspicious User Agent* only — its requests still show up if they ever probe for `/.env`.

### 7.3 Which IP the whitelist checks

| Request | IP used for IP-whitelist matching |
|---|---|
| Cloudflare-trusted (5.1) | `client_ip` (= `CF-Connecting-IP`) |
| Bypass detection off, or Cloudflare not trusted for this request | `remote_addr` |

Without this, an attacker connecting straight to the origin could send `CF-Connecting-IP: <a whitelisted address>` and hide every request. The displayed client IP still follows FR-11; only whitelist matching is protected.

Limitation: an attacker who also forges all three CF headers is treated as Cloudflare-trusted, because source IPs are not verified in this version (4.5).

### 7.4 Whitelist UI helpers

- "**Add my current IP**" button pre-fills the admin's own address (resolved per 7.3).
- Whitelist entries are **not retroactive**: existing rows stay; the form offers "Also delete existing matching rows" as an explicit checkbox.

---

## 8. Database design

All tables use `InnoDB`, `utf8mb4`, and are created with `dbDelta()`. Schema version is stored in option `attacklog_db_version` and checked on `plugins_loaded`: if missing or older, tables are created or upgraded. This also covers sites that never ran the activation hook (network activation, 4.3).

### 8.1 `wp_attacklog_request_types`

One row per unique (method, path) combination.

| Column | Type | Notes |
|---|---|---|
| `id` | `BIGINT UNSIGNED AUTO_INCREMENT` | PK |
| `http_method` | `VARCHAR(10) NOT NULL` | `GET`, `POST`, `HEAD`, … |
| `request_path` | `VARCHAR(2048) NOT NULL` | Normalised path (see 6.3) |
| `path_hash` | `CHAR(40) NOT NULL` | *Added.* `sha1(method . ' ' . path)`; long VARCHARs can't be uniquely indexed |
| `first_seen` | `DATETIME NOT NULL` | UTC |
| `last_seen` | `DATETIME NOT NULL` | UTC |
| `hit_count` | `INT UNSIGNED NOT NULL DEFAULT 1` | *Added.* Cheap counter for the UI |

Indexes: `UNIQUE KEY uq_hash (path_hash)`, `KEY idx_last_seen (last_seen)`.

Upsert:

```sql
INSERT INTO {prefix}attacklog_request_types
    (http_method, request_path, path_hash, first_seen, last_seen, hit_count)
VALUES (%s, %s, %s, UTC_TIMESTAMP(), UTC_TIMESTAMP(), 1)
ON DUPLICATE KEY UPDATE
    id        = LAST_INSERT_ID(id),
    last_seen = UTC_TIMESTAMP(),
    hit_count = hit_count + 1;
```

`LAST_INSERT_ID(id)` returns the existing row's ID on duplicate, so one query gives us the foreign key. `hit_count` is incremented once per logged HTTP request.

### 8.2 `wp_attacklog_error_types`

Lookup table, seeded on activation.

| Column | Type | Notes |
|---|---|---|
| `id` | `TINYINT UNSIGNED` | PK (fixed values) |
| `name` | `VARCHAR(50) NOT NULL` | `UNIQUE` |

Seed data:

| id | name |
|---|---|
| 1 | Cloudflare Bypass |
| 2 | Probing |
| 3 | Direct PHP Access |
| 4 | XML-RPC |
| 5 | Suspicious User Agent |

PHP constants mirror these IDs (`Error_Type::CF_BYPASS = 1`, `PROBING = 2`, `DIRECT_PHP = 3`, `XMLRPC = 4`, `SUSPICIOUS_UA = 5`). Seeding uses `INSERT IGNORE`, so the schema upgrade routine adds new rows to existing installs.

### 8.3 `wp_attacklog_requests` and `wp_attacklog_request_errors`

A request can match several error types (6.7), but it is stored **once**. Its error types live in a pivot table.

#### `wp_attacklog_requests`

One row per logged HTTP request.

| Column | Type | Notes |
|---|---|---|
| `id` | `BIGINT UNSIGNED AUTO_INCREMENT` | *Added.* PK |
| `request_type_id` | `BIGINT UNSIGNED NOT NULL` | → `request_types.id` |
| `return_code` | `SMALLINT UNSIGNED NOT NULL` | Final HTTP status |
| `cf_ray` | `VARCHAR(64) NULL` | `NULL` when header missing |
| `cf_ipcountry` | `CHAR(2) NULL` | ISO country, `XX`/`T1` possible |
| `cf_visitor` | `VARCHAR(64) NULL` | Raw JSON, e.g. `{"scheme":"https"}` |
| `client_ip` | `VARBINARY(16) NULL` | `CF-Connecting-IP` if present, else `REMOTE_ADDR` (FR-11) |
| `remote_addr` | `VARBINARY(16) NULL` | *Added.* Actual connecting address (5.1) |
| `user_agent_id` | `BIGINT UNSIGNED NULL` | → `user_agents.id`; `NULL` = UA missing |
| `created_at` | `DATETIME NOT NULL` | *Added.* UTC; needed for sorting, filtering, auto-clean |

Indexes: `KEY idx_created (created_at)`, `KEY idx_req (request_type_id)`, `KEY idx_ip (client_ip, created_at)`, `KEY idx_ua (user_agent_id)`.

The spec's `Error Type` column on Requests moves to the pivot table below.

#### `wp_attacklog_request_errors` (pivot)

One row per (request, error type). A request has 1–3 rows here (at most one Target type plus up to two Origin types, 6.7).

| Column | Type | Notes |
|---|---|---|
| `request_id` | `BIGINT UNSIGNED NOT NULL` | → `requests.id` |
| `error_type_id` | `TINYINT UNSIGNED NOT NULL` | → `error_types.id` |
| `detail` | `VARCHAR(255) NULL` | What this type matched: XML-RPC method/counters (6.5), UA rule label and token (6.6). Per type, because one request can have both. |
| `created_at` | `DATETIME NOT NULL` | Copy of `requests.created_at`. Denormalised so a type tab can filter, sort and page by time from one index without joining first. |

Keys: `PRIMARY KEY (request_id, error_type_id)` — also prevents duplicates and serves "which types does this request have?"; `KEY idx_type_time (error_type_id, created_at, request_id)` — serves type tabs, their counts and clear-by-type.

**Why a pivot table** rather than one row per error type in `requests` or a bitmask column:

- Each request and its IP, UA and CF headers are stored once, and the All tab is a plain query on `requests`.
- Type tabs and their counts are index lookups on `idx_type_time`; a bitmask (`error_mask & 4`) can't use an index.
- Each type keeps its own `detail`.
- Adding a sixth error type later needs no schema change.

Write path, in one transaction: insert the `requests` row, then a single multi-row `INSERT` into `request_errors`.

### 8.4 `wp_attacklog_user_agents` (new)

One row per unique User-Agent string, mirroring `request_types`. Scanners send the same UA thousands of times, so this keeps the log table small.

| Column | Type | Notes |
|---|---|---|
| `id` | `BIGINT UNSIGNED AUTO_INCREMENT` | PK |
| `user_agent` | `VARCHAR(512) NOT NULL` | Sanitised, truncated (5.2) |
| `ua_hash` | `CHAR(40) NOT NULL` | `sha1(user_agent)`, `UNIQUE` |
| `first_seen` | `DATETIME NOT NULL` | UTC |
| `last_seen` | `DATETIME NOT NULL` | UTC |

Same `ON DUPLICATE KEY UPDATE id = LAST_INSERT_ID(id)` upsert as 8.1.

Foreign keys are **not** declared at the DB level (`dbDelta` doesn't handle them well and many hosts use MyISAM defaults); integrity is maintained in the repository layer, and auto-clean / clearing delete children before orphaned parents.

### 8.5 Entity relationships

```
attacklog_request_types 1 ──* attacklog_requests *── 1 attacklog_user_agents   (user_agent_id nullable)
                                     1
                                     │
                                     * 
                              attacklog_request_errors  (pivot, 1–3 rows per request)
                                     *
                                     │
                                     1
                              attacklog_error_types
```

### 8.6 Privacy (GDPR)

IP addresses and User-Agents are personal data. Logging them for security is generally covered by *legitimate interest* (GDPR Art. 6(1)(f); Recital 49 names network and information security explicitly), but the site owner must disclose it. The plugin:

- Adds suggested text to the site's privacy policy via `wp_add_privacy_policy_content()` (what is logged, why, how long).
- Keeps data only for the auto-clean period (default 30 days).
- Never sends IPs or UAs anywhere off the site.

This is a design note, not legal advice; the site owner should confirm their own obligations.

### 8.7 Auto-clean and manual clearing

All three operations share one repository routine, `Repository::delete_requests( $where )`, followed by the same cleanup.

| Operation | Trigger | What is deleted |
|---|---|---|
| **Auto-clean** | Daily WP-Cron event `attacklog_purge` | `requests` older than X days (`created_at < UTC_TIMESTAMP() - INTERVAL {keep_days} DAY`) and their `request_errors` rows |
| **Clear by type** | "Clear {type}" button on a type tab | `request_errors` rows of that type; then `requests` left with no error type |
| **Clear all** | "Clear all" button | Everything — `DELETE` from `request_errors`, `requests`, `request_types` and `user_agents`, in batches (13: avoids the schema-change warning `TRUNCATE` would add) |

**Clear by type keeps shared requests.** A request flagged as Probing *and* Suspicious UA loses only its Probing row; it stays in the Suspicious UA tab and in All. Requests whose only type was the cleared one are deleted.

For auto-clean and clear by type, in batches of 5,000 (`… LIMIT 5000`, looped) so a large log doesn't hit time or lock limits:

1. Delete the matching `request_errors` rows (auto-clean: by `created_at`; clear by type: by `error_type_id`, both via `idx_type_time` or the PK).
2. Delete `requests` that now have no `request_errors` row (`LEFT JOIN … WHERE e.request_id IS NULL`). For auto-clean this is the same set as step 1's requests.
3. Delete orphaned `request_types` (`LEFT JOIN … WHERE r.id IS NULL`).
4. Delete orphaned `user_agents` the same way.
5. Recompute `hit_count` of the surviving `request_types` that lost requests (`COUNT(*)` on `requests`), so counts match what is still in the log. `first_seen` / `last_seen` stay as lifetime values.
6. Invalidate the cached tab counts and stats (60-second transient).

**Keep last X days:** setting `keep_days`, integer 1–365, default **30**. There is no "keep forever" option; auto-clean always runs. The cron runs daily at a randomised time; changing the setting also runs one clean-up immediately.

Clearing never touches the whitelist, settings or Cloudflare state.

### 8.8 Options

| Option | Content |
|---|---|
| `attacklog_cf_status` | Bypass detection switch, state, who/when set it (4.2) |
| `attacklog_settings` | Keep-days (auto-clean), extra patterns, ignored paths |
| `attacklog_whitelist` | Whitelist entries (7.1), not autoloaded |
| `attacklog_db_version` | Schema version |

---

## 9. Admin interface

### 9.1 Placement

Top-level menu item **Attack Log** (dashicon `dashicons-shield-alt`), capability `manage_options`. Three tabs: **Log**, **Whitelist** and **Settings**.

### 9.2 Log tab layout

```
┌────────────────────────────────────────────────────────────────────────────────┐
│  Attack Log        [Log] [Whitelist] [Settings]                                 │
├──────────────────────────┬─────────────────────────────────────────────────────┤
│ ✓ This request came      │ Last 24 hours                          1,204 events │
│   through Cloudflare     │ Cloudflare Bypass     █▌                   12    ▲  │
│                          │ Probing               ██████              347    ▼  │
│ Bypass detection [ON ●]  │ Direct PHP Access     █                    41    ▲  │
│ Set at activation        │ XML-RPC               ██████████          602    ▲  │
│                          │ Suspicious UA         ███▌                202    ─  │
├──────────────────────────┴─────────────────────────────────────────────────────┤
│        ┌───────────────────┐                                                   │
│  All   │ Cloudflare Bypass │ Probing  Direct PHP  XML-RPC  Suspicious UA       │
│  998   │       12          │   347        41        602        202            │
│ ───────┘                   └──────────────────────────────────────────────────  │
│                                                          Range: All (30 d) ▾   │
├────────────────────────────────────────────────────────────────────────────────┤
│ Time      Method Path               Code IP             Also flagged          │
│ 06:41:12  GET    /.env               404 185.220.101.4  Probing  Suspicious UA│
│           python-requests/2.32.3                                               │
│ 06:40:55  POST   /xmlrpc.php         200 203.0.113.9    XML-RPC  Suspicious UA│
│           curl/8.5.0                                                           │
│ …                                                                              │
├────────────────────────────────────────────────────────────────────────────────┤
│ ‹ 1 2 3 › · 12 requests                          [Clear Cloudflare Bypass]     │
│ Auto-clean: entries older than 30 days are removed daily · Change    [Clear all]│
└────────────────────────────────────────────────────────────────────────────────┘
```

**Error-type tabs** (FR-15):

- Tabs in a fixed order: **All**, Cloudflare Bypass, Probing, Direct PHP Access, XML-RPC, Suspicious User Agent. Each tab shows its **name** and **request count**.
  - Type tabs count the requests that have that error type (`request_errors` rows of that type).
  - **All** counts rows in `requests`, so a request flagged as both Probing and Suspicious UA counts once. That's why All can be lower than the sum of the type tabs; a tooltip on the count explains this.
- The counts follow the active date range, so a tab's number always equals the total in its table. With no filter they show everything currently in the log (i.e. within the auto-clean window).
- Default tab: **All**; afterwards the last opened tab is remembered per user (user meta).
- The active tab is part of the URL (`&type=all`, `&type=probing`, …), so links into a tab work and the browser back button behaves.
- When Cloudflare bypass detection is off, the Cloudflare Bypass tab stays visible (old entries remain readable) but is greyed with a "detection off" label.
- Empty tabs show their count as 0 and an empty-state message explaining what the category catches.

**Rows inside a tab:**

- **All tab:** one row per request, with a **Types** column holding one badge per error type it was logged as.
- **Type tabs:** one row per request that has that type, with an **"Also flagged"** column showing the request's other error types, e.g. a probe that also had a suspicious UA. Clicking a badge opens the same request in that type's tab.
- Second line: on a type tab, that type's `detail` if present; on the All tab, the first available `detail`; otherwise the User-Agent.

**Clearing** (FR-8), at the bottom of the log:

- **Clear {type}** — shown on type tabs; removes that error type from every request (8.7). Confirmation dialog states the numbers: "Remove Probing from 347 requests? 120 of them also have other types and stay in those tabs; the other 227 are deleted. This can't be undone."
- On the **All** tab only **Clear all** is shown.
- **Clear all** — deletes the whole log, all types. Confirmation requires typing `CLEAR` (it wipes everything, including entries in other tabs).
- Both ignore the current date range — they always clear the whole type / whole log, and the dialog says so.
- Next to the buttons: "Auto-clean: entries older than {X} days are removed daily", with a link to the setting.

**Cloudflare card:**

| Part | Content |
|---|---|
| Live note | Whether the current request came through Cloudflare (green ✓ / amber ⚠ / grey ○), see 4.4 |
| Hint | Shown only when the note and the switch disagree (4.4) |
| Switch | *Cloudflare bypass detection* on/off; green when on, grey when off |
| Footer line | Who set it and when |

When the switch is off, the *Cloudflare Bypass* row in the 24h panel and its tab are greyed out with "detection off".

**Table features:** server-side pagination (50 rows per page), sort by time / code, date range (default: whole log). The date range stays set when switching tabs. There is no search.

**IP column:** shows `client_ip`. When `remote_addr` differs (5.1), it is shown in smaller text below, so a forged or proxied `CF-Connecting-IP` is visible at a glance. Long paths and User-Agents are truncated with the full value in a `title` tooltip; rows are not clickable.

### 9.3 Whitelist tab

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ [+ Add entry]  [Add my current IP]                                           │
├──────┬──────────────────────────────────────────┬───────────────┬────────────┤
│ Type │ Value (exact)                            │ Applies to    │ Note       │
├──────┼──────────────────────────────────────────┼───────────────┼────────────┤
│ IP   │ 203.0.113.7                              │ All           │ Office  ✎ 🗑│
│ UA   │ Mozilla/5.0 (compatible; MyMonitor/1.0)  │ Suspicious UA │ Monitor ✎ 🗑│
│ IP   │ 198.51.100.24                            │ XML-RPC       │ Editor  ✎ 🗑│
└──────┴──────────────────────────────────────────┴───────────────┴────────────┘
```

The add/edit form: type (IP / User-Agent), value (exact), category checkboxes (*All* by default), note, and the optional "Also delete existing matching rows" checkbox. IPs are validated with `inet_pton`; duplicates are rejected.

### 9.4 Settings tab

- Auto-clean: keep last X days (number, 1–365, default 30; required, no "keep forever")
- Extra probing patterns (textarea, one regex per line, validated on save)
- Extra suspicious User-Agent patterns (textarea, one regex per line, validated on save)
- Ignored paths (textarea)

### 9.5 Design system

"Simple modern" without a heavy framework:

- Plain CSS file scoped under `.attacklog-wrap`; no Bootstrap/Tailwind.
- CSS custom properties for colours, radius (`8px`), spacing scale (4/8/12/16/24).
- Cards: white background, 1px `#e5e7eb` border, subtle shadow, generous padding.
- Typography: system font stack (inherits WP admin), tabular numbers for counts, times and IPs.
- Badges: pill-shaped, colour-coded — Cloudflare Bypass = red/rose, Probing = amber, Direct PHP = violet, XML-RPC = blue, Suspicious UA = slate; status codes 2xx green, 4xx amber, 5xx red.
- Monospace for paths, IPs, User-Agents and Ray IDs; long values truncated with ellipsis + full value in `title`.
- Respects WP admin colour scheme for primary buttons; dark-mode friendly via `prefers-color-scheme`.
- Responsive: status and 24h cards stack on narrow screens; table scrolls horizontally.
- Vanilla JS only (tabs, date range, whitelist form, clear dialogs, Cloudflare switch); data via admin-ajax / REST endpoint.

---

## 10. Code structure

```
attack-log/
├── attack-log.php                 Plugin header, constants, autoloader, bootstrap
├── uninstall.php                  Drop tables, delete options, clear cron; on multisite,
│                                  repeat for every site (`get_sites()` + `switch_to_blog()`)
├── readme.txt
├── includes/
│   ├── class-plugin.php           Wires hooks, holds service instances
│   ├── class-activator.php        Create tables, seed, CF detection, schedule cron
│   ├── class-deactivator.php      Unschedule cron (data is kept)
│   ├── class-schema.php           dbDelta definitions, version upgrades
│   ├── class-cf-detector.php      Header checks, trust decision, one-time auto-set, live note
│   ├── class-ip-resolver.php      client_ip / remote_addr, validation, binary conversion
│   ├── class-request-context.php  Immutable snapshot: method, path, headers, IPs, UA
│   ├── class-classifier.php       Applies rules (6.1–6.7), precedence, whitelist
│   ├── rules/
│   │   ├── class-cf-bypass-rule.php
│   │   ├── class-probe-rule.php           Default list + filters + compiled regex
│   │   ├── class-direct-php-rule.php      wp-includes / uploads PHP patterns
│   │   ├── class-xmlrpc-rule.php          Detection + xmlrpc_call / login listeners
│   │   └── class-suspicious-ua-rule.php   UA rule sets and labels
│   ├── class-whitelist.php        Entry storage, validation, exact IP and UA matching
│   ├── class-privacy.php          Privacy policy text
│   ├── class-repository.php       All SQL (upserts, queries, purge, stats)
│   ├── class-logger.php           shutdown handler: classify → repository
│   └── class-cron.php             Daily auto-clean
├── admin/
│   ├── class-admin-page.php       Menu, tabs, rendering
│   ├── class-log-controller.php   AJAX/REST: list per type, tab counts, stats, clear by type / all, CF switch
│   ├── class-whitelist-controller.php  AJAX/REST: list, add, edit, delete
│   ├── class-settings.php         Settings API registration + sanitisation
│   └── views/
│       ├── log.php
│       ├── whitelist.php
│       └── settings.php
├── assets/
│   ├── css/admin.css
│   └── js/admin.js
└── languages/
    └── attack-log.pot
```

Namespace: `AttackLog\`. PSR-4-style autoloader without Composer (keeps the plugin dependency-free).

---

## 11. Hooks

| Hook | Purpose |
|---|---|
| `register_activation_hook` | Schema, seed, one-time CF auto-set (keeps an existing state), cron |
| `register_deactivation_hook` | Unschedule cron |
| `plugins_loaded` | Schema upgrade check; build `Request_Context` |
| `xmlrpc_call` (action) | Count XML-RPC method calls |
| `xmlrpc_login_error` (filter) | Count failed XML-RPC logins |
| `status_header` (filter) | Capture final status code (fallback: `http_response_code()`) |
| `shutdown` | Classify and log |
| `admin_menu` | Register page |
| `admin_enqueue_scripts` | Load CSS/JS only on plugin page |
| `admin_init` | `wp_add_privacy_policy_content()` |
| `load-{attack_log_page_hook}` | One-time CF auto-set if state is `unknown`; build the live note |
| `wp_ajax_attacklog_*` | Log listing, stats, clear by type / all, CF switch, whitelist CRUD |
| `attacklog_purge` | Daily auto-clean cron event |

---

## 12. Security

- Every admin action: `current_user_can( 'manage_options' )` + nonce check.
- All SQL via `$wpdb->prepare()`; table names from constants only.
- Header values — including User-Agent and `CF-Connecting-IP` — are attacker-controlled: sanitised, length-capped to column size, and **escaped on output** (`esc_html`, `esc_attr`). User-Agents are a common XSS and log-injection vector, so the log viewer must never render them unescaped.
- `CF-Connecting-IP` is never trusted for decisions unless the request is Cloudflare-trusted (5.1, 7.3).
- `CF-Visitor` stored as raw string, never `json_decode`-and-trusted for logic.
- XML-RPC body inspection reads at most 8 KB and only extracts `<methodName>` with a simple regex — no XML parser (avoids XXE and billion-laughs issues).
- Paths stored as received (normalised) and only ever rendered escaped; never turned into links to the live site.
- User-supplied regex patterns validated on save; invalid ones rejected with a notice. Whitelist entries validated (IP via `inet_pton`, UA sanitised as in 5.2).
- Logging must never fatally error the site: the shutdown handler is wrapped in `try/catch (\Throwable)` and fails silently (with `error_log` when `WP_DEBUG`).

---

## 13. Coding standards

The plugin must **strictly** meet the WordPress.org coding standards. A build that doesn't pass is not releasable.

- **PHP:** [WordPress Coding Standards](https://developer.wordpress.org/coding-standards/wordpress-coding-standards/php/) via PHP_CodeSniffer with the `WordPress` ruleset (Core, Docs and Extra) plus `PHPCompatibilityWP` for PHP 7.4+. Target: **zero errors and zero warnings** (see the rule for unavoidable warnings below).
- **No suppressions:** warnings and errors are fixed, never silenced — no `phpcs:ignore`, `phpcs:disable` or similar comments, and no sniffs excluded or downgraded in the ruleset.
- **Unavoidable warnings — leave them and report them.** Always try to fix a warning first. If a warning can only be removed by suppressing it, leave it in place and point it out (file, line, sniff, and why it can't be fixed) in the hand-over summary, so the project owner can check it manually. Known cases:
  - `WordPress.DB.DirectDatabaseQuery.DirectQuery` on queries against the plugin's own tables;
  - `WordPress.DB.DirectDatabaseQuery.SchemaChange` on `DROP TABLE` in `uninstall.php` (use `DELETE`, not `TRUNCATE`, for "Clear all" so it doesn't add more).
  - `WordPress.DB.DirectDatabaseQuery.NoCaching` is **not** in this list: fix it by wrapping reads in the object cache (`wp_cache_get` / `wp_cache_set`) and invalidating on writes.
- **JavaScript and CSS:** WordPress JavaScript and CSS coding standards (`@wordpress/eslint-plugin`, `@wordpress/stylelint-config`), zero errors.
- **Inline documentation:** every file, class, method, function and hook documented to the WordPress PHP documentation standard.
- **Plugin handbook rules that the standards enforce, applied throughout:**
  - every function, class, option, transient, hook, table and AJAX action prefixed (`attacklog_` / `AttackLog\`);
  - input sanitised early, output escaped late, with the correct `esc_*` function for the context;
  - nonces and capability checks on every state-changing action;
  - all user-facing strings translatable with the `attack-log` text domain;
  - scripts and styles enqueued, never printed inline;
  - `$wpdb->prepare()` for every query with variables;
  - GPLv2-or-later licence, no calls to external services, `readme.txt` in WordPress.org format.

---

## 14. Milestones

| # | Deliverable | Contents |
|---|---|---|
| M1 | Core | Schema, activator, CF detection, IP/UA capture, classifier (all five types), logger, default patterns |
| M2 | Admin MVP | Cloudflare card, All + error-type tabs with counts, per-type table with "also flagged" badges (pivot queries), pagination, clear by type / clear all |
| M3 | Whitelist | Whitelist storage and matching, Whitelist tab |
| M4 | Polish | 24h stats, date range, design pass |
| M5 | Hardening | Settings tab, auto-clean cron, privacy text, uninstall |
| M6 | Release | WPCS run: zero errors, remaining warnings only the unavoidable ones (13); i18n `.pot`, readme |