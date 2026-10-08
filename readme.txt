=== Attack Log ===
Contributors: gaborangyal
Tags: security, cloudflare, log, 404, xmlrpc
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Logs suspicious requests: Cloudflare bypasses, probing for secret files, direct PHP access, XML-RPC calls and scanner user agents.

== Description ==

Attack Log shows you who is poking at your site and how. It records suspicious requests in your own database and lists them in a simple admin screen, one tab per type.

**Attack Log is a log, not a firewall.** It does not block, rate-limit or challenge anything. It tells you what is happening so you can decide what to do — for example, add a firewall rule at your host or in Cloudflare.

= What it logs =

* **Cloudflare Bypass** — your site is behind Cloudflare, but a request reached your server without the headers Cloudflare always adds (`CF-Ray`, `CF-IPCountry`, `CF-Visitor`). This usually means someone found your server's real IP address and is skipping Cloudflare and its firewall.
* **Probing** — requests that end in a 404 and look for files scanners hunt for: `.env`, `backup.sql`, `.git/config`, `wp-config.php.bak`, `phpinfo.php` and similar.
* **Direct PHP Access** — requests for `.php` files inside `wp-includes` or your uploads folder. Visitors never need these; they are typically attempts to reach a planted backdoor.
* **XML-RPC** — every request to `xmlrpc.php` (except calls that log in successfully). The endpoint is mostly used for password guessing; the log shows the method called and the number of failed logins.
* **Suspicious User Agent** — requests with a missing or malformed User-Agent, or one from an HTTP library or a known scanner (`curl`, `python-requests`, `Go-http-client`, `sqlmap`, `nikto` and others).

One request can match several types — for example a probe for `.env` sent with `curl`. It is stored once and appears in each matching tab, and in the **All** tab.

For each logged request Attack Log stores the time, method, path, status code, client IP address, User-Agent, and the Cloudflare headers if present.

= Features =

* Tabs for All and each error type, with request counts.
* Filter by date range.
* Cloudflare card: shows whether your current request came through Cloudflare, and a switch to turn bypass detection on or off.
* Whitelist by exact IP address or exact User-Agent, for all types or selected ones — for example your uptime monitor or office IP. Each log row has buttons to whitelist its IP or User-Agent in one click.
* Clear one type, or clear the whole log.
* Automatic clean-up: keeps the last 30 days by default (configurable, 1–365 days).
* Requests from logged-in users are never logged.

= What Attack Log cannot see =

Please read this before relying on the log.

* **Only requests that reach WordPress are logged.** Requests for files that exist on disk, requests your web server blocks itself, and pages served from a full-page cache (for example Cloudflare APO, Varnish or a static cache plugin) never reach WordPress, so they are not in the log.
* **An existing backdoor is invisible.** If a malicious PHP file actually exists in `wp-includes` or uploads, your web server runs it directly and Attack Log never sees the request. Blocking PHP execution in those folders at the web server is the real protection; see the FAQ.
* **Forged Cloudflare headers are not detected.** Attack Log checks whether the Cloudflare headers are present, not whether the request really came from Cloudflare's network. An attacker who sends fake headers directly to your server is not logged as a bypass. To close that gap, let your server accept web traffic only from Cloudflare's IP ranges, or use Cloudflare's Authenticated Origin Pulls.
* **Logged-in users are never logged**, including requests made with a stolen account.
* **Some legitimate tools will show up** as Suspicious User Agent or XML-RPC — uptime monitors, server cron jobs that call `wp-cron.php` with `wget` or `curl`, integrations using HTTP libraries, desktop blogging apps. Add them to the whitelist.

= Privacy =

Attack Log stores IP addresses and User-Agents of the requests it logs. These are personal data under the GDPR.

* Everything stays in your own WordPress database. The plugin sends nothing to any external service.
* Entries are deleted automatically after the configured period (default 30 days).
* Attack Log adds suggested text to your privacy policy page (Settings → Privacy) describing what it logs and why.

You are responsible for mentioning the logging in your privacy policy. This is not legal advice.

== Installation ==

1. Install Attack Log from Plugins → Add New, or upload the `attacklog` folder to `/wp-content/plugins/`.
2. Activate the plugin **from your browser**, the way you normally visit your site. On activation Attack Log checks whether your request came through Cloudflare and turns bypass detection on or off accordingly.
3. Open **Attack Log** in the admin menu. Check the Cloudflare card: if the switch doesn't match your setup, change it.
4. Optionally, add your uptime monitor, office IP or other trusted tools to the whitelist.

If you activate the plugin with WP-CLI, the Cloudflare check runs the first time you open the Attack Log page instead.

== Frequently Asked Questions ==

= Does Attack Log block attacks? =

No. It only logs them. Use the log to decide what to block at your web server, your host's firewall or in Cloudflare.

= My site isn't behind Cloudflare. Is the plugin still useful? =

Yes. Probing, Direct PHP Access, XML-RPC and Suspicious User Agent logging work on any site. Only Cloudflare Bypass detection needs Cloudflare; turn it off on the Cloudflare card.

= The Cloudflare switch was set wrong. Why? =

The setting is made once, automatically, from the request that activated the plugin (or your first visit to the Attack Log page). If that request reached your server directly — through a VPN, a hosts-file entry or a staging domain — the plugin concluded you are not behind Cloudflare. Use the switch to correct it. Attack Log never changes it again on its own.

= Every visitor is logged as a Cloudflare Bypass. What's wrong? =

Most likely bypass detection is on but your site is not (or no longer) proxied through Cloudflare — for example the orange cloud is switched off in your Cloudflare DNS settings. Turn the switch off, or fix the Cloudflare setting.

= Why is my uptime monitor in the log? =

Many monitors and tools use HTTP library User-Agents such as `curl` or `python-requests`. Click **+ IP** or **+ UA** on its row in the log, choose which types the entry applies to, and save. Whitelist entries match exactly.

= Does it slow down my site? =

Requests that don't match any rule cost a few string checks and no database query. Logged requests are written after the page has been generated.

= Does it work on multisite? =

Multisite is not tested or supported. Activating it on individual sites is expected to work; network activation is not recommended.

= What happens when I uninstall the plugin? =

All Attack Log tables and settings are deleted. Deactivating keeps your data.

== Changelog ==

= 1.0.0 =
* Initial release.

== Upgrade Notice ==

= 1.0.0 =
Initial release.