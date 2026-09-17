=== Attack Log ===
Contributors: gaborangyal
Tags: cloudflare, security, firewall, ip restriction, access control
Requires at least: 5.0
Tested up to: 6.7
Requires PHP: 7.0
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Restricts site access to Cloudflare IP ranges, refreshes those ranges daily via cron, and provides an admin Tools page to view ranges and forbidden-request logs.

== Description ==

**WARNING: Only use this plugin if you really know what you are doing.** This plugin restricts access to your WordPress site to Cloudflare's published IP ranges only. If misconfigured, or if your site is not properly configured behind Cloudflare, this plugin **can lock you and all other visitors out of your site**, including the WordPress admin area. Use at your own risk. Always test with Test Mode enabled first, and ensure you have another way to access your server (such as SSH or FTP) to disable the plugin if something goes wrong.

Attack Log compares each visitor's IP address against Cloudflare's official published IP ranges (both IPv4 and IPv6). If a request does not originate from one of these ranges, it is logged and, unless Test Mode is enabled, blocked with a 403 Forbidden response.

**This plugin requires the "Remove visitor IP headers" Managed Transform to be enabled in your Cloudflare dashboard.** Without this setting, visitors could potentially spoof headers to bypass this restriction, or the plugin may not correctly identify the true visitor IP. This plugin relies solely on `REMOTE_ADDR` and does not read `X-Forwarded-For` or `CF-Connecting-IP` headers for access decisions, precisely because those headers can be spoofed unless Cloudflare is configured to strip them from incoming requests before they reach your origin server.

To enable this setting:

1. Log in to your Cloudflare dashboard.
2. Select your domain.
3. Navigate to Rules > Managed Transforms.
4. Enable "Remove visitor IP headers".

= Features =

* Automatically fetches and stores Cloudflare's current IPv4 and IPv6 ranges.
* Daily cron job to keep IP ranges up to date.
* Test Mode to log would-be blocked requests without actually blocking them, so you can verify correct behavior before enforcing restrictions.
* Safeguard preventing Test Mode from being disabled if your current IP is not within Cloudflare's IP range, reducing the risk of accidental lockout.
* Admin Tools page displaying current IP ranges, last update time, your current IP and whether it is recognized as a Cloudflare IP, and a log of forbidden requests.
* Ability to clear logs from the admin page.

= Important Notes =

* This plugin blocks requests very early, on the `init` hook, before most of WordPress has loaded.
* Requests from WP-CLI and WordPress Cron (`DOING_CRON`) are never blocked, to avoid breaking scheduled tasks and command-line operations.
* If Cloudflare's IP ranges cannot be fetched, the plugin will fail open (allow all requests) for that IP family (IPv4 or IPv6) rather than blocking everyone, but this should not be relied upon as a safety mechanism.
* Test Mode is enabled by default on activation to help prevent accidental lockouts. Review the logs before disabling Test Mode.

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/attacklog` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress.
3. In your Cloudflare dashboard, enable the "Remove visitor IP headers" Managed Transform under Rules > Managed Transforms.
4. Go to Tools > Attack Log to review the fetched IP ranges and confirm your current IP is recognized as a Cloudflare IP.
5. Leave Test Mode enabled and monitor the logs for a period of time before disabling Test Mode to enforce blocking.

== Frequently Asked Questions ==

= What happens if I get locked out? =

If you are locked out, you will need another way to access your server, such as SFTP, SSH, or your hosting control panel's file manager, to rename or delete the plugin folder, which will deactivate it.

= Why does the plugin only check REMOTE_ADDR and not X-Forwarded-For or CF-Connecting-IP? =

Headers such as `X-Forwarded-For` and `CF-Connecting-IP` can be spoofed by visitors unless your server or CDN strips them from incoming requests. This plugin relies on `REMOTE_ADDR`, which is the actual TCP connection IP address seen by your web server. For this to correctly reflect the visitor's real IP when behind Cloudflare, you must enable Cloudflare's "Remove visitor IP headers" Managed Transform, which ensures Cloudflare properly sets `REMOTE_ADDR` at the connection level and strips potentially spoofed headers.

= Does this replace a firewall? =

No. This plugin is a supplementary access control layer at the application level and should not be considered a replacement for a properly configured firewall or other server-level security measures.

= Will this affect WP-CLI or cron jobs? =

No. Requests made via WP-CLI or WordPress's cron system (`DOING_CRON`) are explicitly excluded from IP filtering.

== Screenshots ==

1. Admin Tools page showing Test Mode toggle, current IP status, IP ranges, and forbidden request logs.

== Changelog ==

= 1.0.0 =
* Initial release.

== Upgrade Notice ==

= 1.0.0 =
Initial release. Please read the plugin description carefully before activating, and ensure the "Remove visitor IP headers" Managed Transform is enabled in Cloudflare.