=== RH Hardening ===
Contributors: robinherbeck
Tags: security, hardening, headers, user enumeration, xmlrpc
Requires at least: 6.5
Tested up to: 7.0
Requires PHP: 8.1
Stable tag: 0.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Standard security hardening for WordPress: block user enumeration, disable feeds, set security headers, remove head clutter and XML-RPC.

== Description ==

RH Hardening applies the security baseline that every production WordPress site should have. Each measure is a toggle and on by default, so a fresh install is hardened out of the box.

= Measures =

* Block user enumeration over the REST API (/wp/v2/users) and over ?author=N and /author/<slug>/
* Disable RSS/Atom feeds (returns 404), for sites without a blog
* Set security headers: X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-Frame-Options, HSTS (HTTPS only), and remove X-Powered-By
* Remove WordPress head clutter: generator tag, WLW manifest, RSD link, shortlink, feed links and the emoji script
* Disable XML-RPC

The hook order is chosen deliberately: ?author= is blocked in parse_request (before WordPress' canonical redirect would leak the login name), feeds in template_redirect.

Part of the rh-blueprint collection. Settings live under RH Blueprint > Sicherheit.

== Changelog ==

= 0.1.0 =
* Initial release: user enumeration block, feed disable, security headers, head cleanup, XML-RPC off, all as toggles.
