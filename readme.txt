=== RH Hardening ===
Contributors: robinherbeck
Tags: security, hardening, firewall, integrity, vulnerabilities
Requires at least: 6.5
Tested up to: 7.0
Requires PHP: 8.1
Stable tag: 0.8.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Security baseline for WordPress: a request shield that runs before WordPress, file integrity checks against wordpress.org, a vulnerability radar and an audit log.

== Description ==

RH Hardening applies the security baseline that every production WordPress site should have. Each measure is a toggle and on by default, so a fresh install is hardened out of the box.

= Layers =

* **Shield** - a small mu-plugin that inspects requests before WordPress builds its REST API. This is the only place where a flaw like wp2shell (CVE-2026-63030) can be stopped, because that one bypassed the permission check inside the request.
* **Prevention** - toggles that remove attack surface: REST gatekeeper, application passwords, PHP execution in uploads, session hardening, file editor.
* **Watch** - compares WordPress core and plugins against the official checksums from wordpress.org, guards the places WordPress loads unasked (mu-plugins, drop-ins, wp-config.php) and looks for executable files in the uploads folder.
* **Radar** - checks daily whether a vulnerability is known for any installed plugin, theme or core. Reports only, never installs anything.
* **Log and notification** - an audit log with truncated origin (no personal data), critical findings by mail, everything else in a weekly digest.

= Measures =

* Block user enumeration over the REST API (/wp/v2/users) and over ?author=N and /author/<slug>/
* Disable RSS/Atom feeds (returns 404), for sites without a blog
* Set security headers: X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-Frame-Options, HSTS (HTTPS only), and remove X-Powered-By
* Remove WordPress head clutter: generator tag, WLW manifest, RSD link, shortlink, feed links and the emoji script
* Disable XML-RPC

The hook order is chosen deliberately: ?author= is blocked in parse_request (before WordPress' canonical redirect would leak the login name), feeds in template_redirect.

Part of the rh-blueprint collection. Settings live under RH Blueprint > Sicherheit.

== Changelog ==

= 0.8.1 =
* Internal: shared building blocks from core 2.6.0. The update check no longer loads on regular front-end requests.

= 0.8.0 =
* Content-Security-Policy with a guided rollout: the policy first runs in observe mode, the browser reports what it would have blocked, and the module builds a rule suggestion from what was collected. Only then is it worth switching to enforce.
* Collection is opt-in, switches itself off after three days and only then exposes a reporting endpoint. Nothing personal is stored: no query parameters, no referrer, no visitor origin, and reports are grouped per rule and source instead of logged one by one.
* Both reporting mechanisms are supported. report-uri is formally deprecated but is still the only one Firefox implements for CSP, so it is sent alongside report-to and Reporting-Endpoints.

= 0.7.0 =
* Hardened the module itself: the upload probe now uses a random name, is always cleaned up and is never reported by its own scan.
* Shield: invalid rule patterns are detected and logged instead of silently not matching; values above 8 KB skip the pattern match; queue writes are throttled to one per minute, so a scanner cannot amplify database load.
* Vulnerability index is now processed as text instead of a decoded array: peak memory dropped from 24.8 MB to 2.0 MB, which keeps the radar working on hosts with a 64 MB limit.
* All calls to functions that hosts commonly disable (glob, file_put_contents, hash_file, inet_pton) are guarded; the affected check is skipped and reported instead of causing a fatal error.
* Error logging across the module: shield not deployable, feed unreachable, mail not sent, scan aborted.
* The overview now states what the environment prevents: disabled WP-Cron, disabled functions, low memory limit.

= 0.6.0 =
* Security tab split into Overview, Protection, Monitoring and Log.
* Fixed false positives after a WordPress update: the core checksum cache key now carries version and locale.

= 0.5.0 =
* Vulnerability radar: daily comparison against a curated feed, local matching, reports only.
* Detects plugins that disappeared from the wordpress.org directory.

= 0.4.0 =
* Request shield as an mu-plugin, running before WordPress boots.

= 0.3.0 =
* File integrity: core and plugins against wordpress.org checksums, guarded locations, uploads scan.

= 0.2.0 =
* Audit log, mail notification, REST gatekeeper, access hardening, docroot hygiene check.

= 0.1.0 =
* Initial release: user enumeration block, feed disable, security headers, head cleanup, XML-RPC off, all as toggles.
