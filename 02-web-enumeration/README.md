# Lab 02: Web Enumeration of DVWA with Nikto and Gobuster

The second lab in the series. [Lab 01](../01-nmap-dvwa-recon/) found one open port running Apache 2.4.25. This lab looks at what that web server exposes: known misconfigurations with Nikto, and hidden directories and files with Gobuster.

| | |
| --- | --- |
| **Date** | 2026-11-17 |
| **Target** | DVWA (`vulnerables/web-dvwa`), `http://dvwa` (172.18.0.2) |
| **Attacker** | Kali Linux (`kalilinux/kali-rolling`) in Docker |
| **Tools** | Nikto, Gobuster, wordlist `dirb/common.txt` |
| **Type** | Enumeration only. No login, no exploitation. |

## Summary

Nikto sent 7,793 requests in 6 seconds and reported 14 items. Gobuster tested 13,839 paths and returned 27 result lines (24 unique paths). Together they show a web server that lists directory contents, serves files that should not be public, and sends none of the modern security headers. Several DVWA pages (`setup.php`, `instructions.php`, `about.php`) load without logging in. Apache's own configuration files and `server-status` are correctly blocked.

## Scope and authorization

- **In scope:** the `dvwa` container on my private Docker network.
- **Out of scope:** every other host and any network I do not own.
- **Authorization:** I built and own the target. Do not run these tools against systems you do not own or have written permission to test. Both tools are loud and will appear in any server's logs.

## Methodology

All commands ran from inside the Kali container. Output was written to files and the whole session was recorded with `script`.

```bash
mkdir -p /root/lab02 && cd /root/lab02
script -a session.log        # record the session

nikto -h http://dvwa -o nikto.txt -Format txt

gobuster dir -u http://dvwa \
  -w /usr/share/dirb/wordlists/common.txt \
  -x php,txt -t 20 -o gobuster.txt

exit                         # stop recording
```

- **Nikto** checks a web server against a database of known issues: outdated software, dangerous files, missing headers, and default content.
- **Gobuster** (`dir` mode) requests every word in a wordlist as a path and records the ones that exist. `-x php,txt` also tries each word with those extensions, and `-t 20` limits it to 20 threads so the emulated container is not overloaded. With 4,613 words and three variants each, that is 13,839 requests.
- Gobuster lists some paths twice (`index.php`, `phpinfo.php`, `robots.txt`) because the wordlist contains both the bare word and the full filename.

Raw output: [`evidence/01-nikto.txt`](evidence/01-nikto.txt) and [`evidence/02-gobuster.txt`](evidence/02-gobuster.txt).

## Findings

Risk ratings are my own judgment for a production-style system. "Reported" means a tool flagged it and I did not open the page by hand.

| # | Finding | Evidence | Source | Risk |
| --- | --- | --- | --- | --- |
| 1 | Directory listing and possible exposed configuration in `/config/` | Nikto: directory indexing, "configuration information may be available remotely"; Gobuster: 301 | Both | High (reported) |
| 2 | Directory listing in `/docs/` | Nikto: directory indexing (CWE-548); Gobuster: 301 | Both | Low to medium |
| 3 | `php.ini` served over HTTP | Gobuster: 200, 148 bytes | Gobuster | Medium |
| 4 | Setup page reachable without logging in | `setup.php`: 200, 4,070 bytes (in DVWA this page holds the database create and reset function; not tested) | Gobuster | Medium to high |
| 5 | Other pages reachable without logging in | `instructions.php` 200, `about.php` 200 | Gobuster | Low |
| 6 | `.gitignore` exposed | Nikto: "possible to grasp the directory structure" | Nikto | Low |
| 7 | Apache default file left in place | `/icons/README` | Nikto | Low |
| 8 | Missing security headers | No HSTS, Referrer-Policy, X-Content-Type-Options, Permissions-Policy, or Content-Security-Policy; X-Frame-Options is deprecated | Nikto | Medium |
| 9 | Outdated Apache confirmed | Nikto: Apache 2.4.25 "appears to be outdated" (matches Lab 01) | Nikto | Medium to high |
| 10 | Unexplored `/external/` directory | Gobuster: 301 | Gobuster | To investigate |
| 11 | `phpinfo.php` exists but needs a login | Gobuster: 302 to `login.php` | Gobuster | Low (info leak if reached after login) |
| 12 | Hidden Apache files and `server-status` blocked | `.htaccess`, `.htpasswd`, `.hta`, `server-status`: 403 | Gobuster | Good practice |
| 13 | Authentication enforced on key pages | `index.php`, `logout.php`, `security.php`, `phpinfo.php`: 302 to `login.php` | Gobuster | Good practice |

## Analysis

- **Directory listing and `/config/` are the headline issue.** In a typical DVWA install this directory holds the application's database settings. Nikto's warning is a strong lead, but I did not open the directory, so the finding stays "reported" until verified.
- **Findings 3 and 4 show a pattern:** files that belong to the application's setup (`php.ini`, `setup.php`) sit inside the public web root. Setup and installer pages should be removed or locked down once the app is running.
- **Nikto and Gobuster agree where they overlap** (`/config/`, `/docs/`, `login.php`, the outdated Apache), which raises my confidence in those results. Items only one tool found need a manual check.
- **Nikto is noisy and prone to false positives.** It checks for many things that do not apply to a given app. Treat each line as a lead.
- **Speed is itself a finding for defenders.** 7,793 requests in 6 seconds from one address is easy to spot in access logs and easy to rate-limit.

## Remediation

| Finding | Fix |
| --- | --- |
| Directory listing (1, 2) | Turn off indexing with `Options -Indexes`. |
| `/config/` exposure (1) | Deny web access to the directory entirely and keep secrets outside the web root. |
| `php.ini`, `.gitignore`, `/icons/README` (3, 6, 7) | Remove them from the web root, or deny access to those file types. |
| Setup and info pages (4, 5, 11) | Remove `setup.php` after installation, or restrict it by IP or authentication. Remove or protect `phpinfo.php` and `instructions.php`. |
| Missing headers (8) | Add the headers shown below. |
| Outdated Apache (9) | Move to a supported OS and a current Apache 2.4.x. |

```apache
# Turn off directory listing everywhere
<Directory /var/www/html>
    Options -Indexes
</Directory>

# Block the config directory and sensitive file types
<Directory /var/www/html/config>
    Require all denied
</Directory>
<FilesMatch "^(\.git.*|php\.ini)$">
    Require all denied
</FilesMatch>

# Security headers (mod_headers). HSTS only once the site serves HTTPS.
Header always set X-Content-Type-Options "nosniff"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "geolocation=(), camera=(), microphone=()"
Header always set Content-Security-Policy "default-src 'self'; frame-ancestors 'self'"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
```

Paths and header values are examples. Test any policy before deploying it, because a strict Content-Security-Policy can break a working site.

## Challenges and lessons learned

- Nikto finished in 6 seconds, much faster than I expected. The container is local, so there was no network delay.
- Recording the session with `script` plus saving each tool's output with `-o` gave me clean evidence files. The `script` log contains terminal control characters, so I used the `-o` files for the write-up.
- Duplicated Gobuster lines looked like an error at first. They come from the wordlist containing both a word and its full filename.
- A 302 redirect to the login page is a useful signal: the page exists and is protected.

## Limitations

- No authenticated testing. Everything behind the login was out of reach.
- Findings marked "reported" were not opened or verified by hand.
- The evidence files are transcribed from terminal captures. The Nikto header block (target, port, start time) was not captured.
- One wordlist (`common.txt`). A larger list could find more.

## Next steps

- Open `/config/`, `/docs/`, `/external/`, and `/.gitignore` with `curl` and record what they actually contain.
- Check the web server's access log to see what these scans look like from the defender's side.
- Log in and test DVWA's SQL injection page with `sqlmap`, comparing the security levels (Lab 03).
- Repeat the enumeration against a VM on my Proxmox homelab.
