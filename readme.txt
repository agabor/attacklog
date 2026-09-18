=== Attack Log ===
Contributors: gaborangyal
Tags: cloudflare, security, logging, monitoring, ip
Requires at least: 5.0
Tested up to: 7.1
Requires PHP: 7.0
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Refreshes Cloudflare's published IP ranges daily via cron and logs suspicious requests, providing an admin Tools page to review Cloudflare indicators and forbidden-request logs.

== Description ==

Attack Log fetches Cloudflare's official published IP ranges (both IPv4 and IPv6) and stores them, refreshing them daily via a scheduled cron event. It does not block any requests. Instead, it monitors incoming requests and logs ones that appear suspicious, so you can review them from the WordPress admin area.

A request is logged when any of the following are true:

* The HTTP response status code is 401, 403, 404, or 500.
* The User-Agent header matches a list of known non-browser clients (such as curl, Wget, various HTTP client libraries, and common scanning tools).
* A Cloudflare indicator that was present on a previous admin page visit (such as the visitor's IP being within Cloudflare's range, the X-Forwarded-For header containing a Cloudflare IP, or a specific Cloudflare HTTP header being present) is missing on the current request, or a Cloudflare indicator appears that was not present before.

Each log entry records the timestamp, IP address, HTTP method, request URI, User-Agent, HTTP status code, any forwarded/Cloudflare-related headers present on the request, and the specific flags that caused the entry to be logged.

= Features =

* Automatically fetches and stores Cloudflare's current IPv4 and IPv6 ranges on activation and daily via cron.
* Logs requests with suspicious HTTP status codes, suspicious User-Agent strings, or missing/unexpected Cloudflare indicators.
* Admin Tools page (Tools > Attack Log) displaying:
  * Current Cloudflare indicators for the request loading the admin page (IP address, X-Forwarded-For header, whether the IP is within Cloudflare's range, whether X-Forwarded-For contains a Cloudflare IP, and which Cloudflare-specific headers are present).
  * Baseline Cloudflare indicators, saved automatically each time the admin page is viewed, used as the reference point for detecting missing or unexpected indicators on other requests.
  * A summary table of logged requests grouped by User-Agent with request counts.
  * A detailed table of individual logged requests, including timestamp, IP, method, URI, User-Agent, status, headers, and flags.
* Ability to clear all logs from the admin page.

= Important Notes =

* This plugin does not block, restrict, or otherwise interfere with any requests. It is a monitoring and logging tool only.
* Logging occurs on the `shutdown` hook, after the response has already been generated.
* Requests made via WP-CLI or WordPress's cron system (`DOING_CRON`) are never logged.
* Visiting the Attack Log admin page updates the "baseline" Cloudflare indicators used for comparison against other requests. Because of this, the baseline reflects whatever indicators were present the last time an administrator viewed the page.
* If Cloudflare's IP ranges cannot be fetched, or have not been fetched yet for an IP family (IPv4 or IPv6), IP-range membership checks for that family will be treated as matching (fail open), since this plugin does not use IP-range membership to block anything.

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/attacklog` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress.
3. Go to Tools > Attack Log to review Cloudflare indicators and the request log.

== Frequently Asked Questions ==

= Does this plugin block any requests? =

No. This plugin only logs requests that meet certain suspicious criteria (unusual HTTP status codes, suspicious User-Agent strings, or missing/unexpected Cloudflare indicators). It does not deny or restrict access to your site in any way.

= Where do the Cloudflare IP ranges come from? =

The plugin fetches them directly from `https://www.cloudflare.com/ips-v4/` and `https://www.cloudflare.com/ips-v6/`, and refreshes them daily via a scheduled cron event named `alw_daily_ip_refresh`.

= What are "baseline indicators" on the admin page? =

Each time an administrator loads the Attack Log admin page, the plugin records which Cloudflare-related indicators (IP range membership, X-Forwarded-For range membership, and presence of specific Cloudflare headers) were present on that admin request. Subsequent requests are compared against this baseline, and any indicator that was present in the baseline but missing on a later request (or vice versa) is flagged and logged.

= Will this affect WP-CLI or cron jobs? =

No. Requests made via WP-CLI or WordPress's cron system (`DOING_CRON`) are explicitly excluded from logging.

== Screenshots ==

1. Admin Tools page showing current and baseline Cloudflare indicators, User-Agent request counts, and the suspicious request log.

== Changelog ==

= 1.0.0 =
* Initial release.

== Upgrade Notice ==

= 1.0.0 =
Initial release.