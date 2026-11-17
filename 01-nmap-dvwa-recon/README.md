# Lab 01: Network Reconnaissance of DVWA with Nmap

A reconnaissance exercise against a deliberately vulnerable web application, run entirely inside an isolated Docker lab on my own machine.

| | |
| --- | --- |
| **Date** | 2026-11-16 |
| **Target** | DVWA (`vulnerables/web-dvwa`), container `dvwa`, 172.18.0.2 |
| **Attacker** | Kali Linux (`kalilinux/kali-rolling`), container `kali` |
| **Tools** | Nmap 7.991, searchsploit (exploitdb), curl |
| **Type** | Discovery and enumeration only. No exploitation. |

## Summary

An Nmap scan of the DVWA container found one open TCP port, 80/tcp, running Apache httpd 2.4.25 (Debian) with no HTTPS. The other 65,534 TCP ports were closed. The Apache version is old, the session cookie lacks the HttpOnly flag, and the server banner reveals its version. The target is a good candidate for deeper web testing.

## Scope and authorization

- **In scope:** one container named `dvwa` on a private Docker network.
- **Out of scope:** every other host, the Mac itself, and any network I do not own.
- **Authorization:** I built and own the target and the lab network. Nothing in this repository should be run against systems you do not own or have written permission to test.

## Lab environment

Both machines run as containers on a MacBook Pro (Apple Silicon) under Docker Desktop. A user-defined bridge network named `lab` lets them resolve each other by name.

```
 MacBook Pro (Docker Desktop)
 ┌──────────────────────────────────────────────┐
 │  network: lab (bridge)                       │
 │                                              │
 │  ┌──────────────┐        ┌────────────────┐  │
 │  │ kali         │ nmap   │ dvwa           │  │
 │  │ kali-rolling │ ─────▶ │ 172.18.0.2:80  │  │
 │  └──────────────┘        └───────┬────────┘  │
 └──────────────────────────────────┼───────────┘
                                    │ published to 127.0.0.1:8080 only
                                    ▼
                              browser on the Mac
```

### Setup commands

```bash
docker network create lab

docker run -d --name dvwa --network lab --platform linux/amd64 \
  -p 127.0.0.1:8080:80 vulnerables/web-dvwa

docker run -it --name kali kalilinux/kali-rolling
# inside Kali:
apt update && apt install -y kali-tools-top10 exploitdb
```

Notes:

- `127.0.0.1:` keeps the intentionally vulnerable app reachable only from the Mac.
- `--platform linux/amd64` is required on Apple Silicon. The image runs under emulation, so it is slower.
- If the Kali container was started before the network existed, attach it with `docker network connect lab kali`.

## Methodology

Five steps, moving from broad to specific. All commands ran from inside the Kali container.

### 1. Host discovery

Confirm the target is reachable without touching its ports.

```bash
nmap -sn dvwa
```

Result: host up, 172.18.0.2, reverse DNS `dvwa.lab`. See [`evidence/01-host-discovery.txt`](evidence/01-host-discovery.txt).

### 2. Full TCP port scan

Check all 65,535 ports so nothing hides on an unusual port.

```bash
nmap -p- dvwa
```

Result: one open port, 80/tcp. 65,534 closed. Finished in 0.53 seconds. See [`evidence/02-full-port-scan.txt`](evidence/02-full-port-scan.txt).

### 3. Service and version detection

Probe the open port, run Nmap's default scripts, and save the results in every output format.

```bash
nmap -sV -sC -p 80 -oA dvwa-scan dvwa
```

Result: Apache httpd 2.4.25 (Debian), redirect to `login.php`, one `robots.txt` entry, `PHPSESSID` cookie without the HttpOnly flag. See [`evidence/03-service-scan.nmap`](evidence/03-service-scan.nmap).

### 4. Exploit matching

Search the local Exploit-DB copy for the detected version.

```bash
searchsploit apache 2.4.25
```

Result: 16 loose matches, of which two apply to Apache httpd in this version range. See [`evidence/04-searchsploit.txt`](evidence/04-searchsploit.txt).

### 5. Manual check

Read the file that Nmap's script flagged.

```bash
curl -s http://dvwa/robots.txt
```

Result: `User-agent: *` and `Disallow: /`. It blocks crawlers but reveals no paths.

## Findings

Risk ratings are my own judgment for a production-style system. They are not CVSS scores.

| # | Finding | Evidence | Risk |
| --- | --- | --- | --- |
| 1 | Outdated web server | Apache httpd 2.4.25 (Debian) on 80/tcp | Medium to high (patch level unconfirmed) |
| 2 | No encrypted web traffic | Only 80/tcp open, no 443/tcp | Medium |
| 3 | Session cookie missing HttpOnly flag | Nmap `http-cookie-flags`: `PHPSESSID` | Low to medium |
| 4 | Server version disclosed | `Server: Apache/2.4.25 (Debian)` header | Low |
| 5 | Possible matching public exploits | searchsploit: EDB 42745 (OPTIONS memory leak), EDB 46676 (`apache2ctl graceful` local privilege escalation) | Needs verification |
| 6 | `robots.txt` blocks everything | `Disallow: /`, no paths revealed | Informational |
| 7 | Database not exposed | No MySQL port open on the network | Good practice |

The other searchsploit results were loose matches for different products (Tomcat, mod_ssl, CXF, OpenMeetings, Xerces-C, Shoutbox) or far older Apache versions, so I excluded them.

## Analysis

A version number is a lead, not proof. Debian often backports security fixes without changing the version string, so Apache 2.4.25 may or may not be vulnerable to the matched exploits. I did not test them. Confirming would need authenticated patch-level checks or a vulnerability scanner.

The small attack surface (one port) is a strength. Keeping the database unreachable from the network is the right design.

## Remediation

| Finding | Why it matters | Fix |
| --- | --- | --- |
| Outdated Apache | 2.4.25 shipped with Debian 9, which is end of life and no longer receives security updates | Move to a supported OS and a current Apache 2.4.x. Apply updates on a schedule. |
| No HTTPS | Logins and session cookies cross the network in clear text | Add a TLS certificate, listen on 443, redirect port 80 to HTTPS, and enable HSTS. |
| No HttpOnly flag | Injected JavaScript can read the session cookie | Set the PHP session cookie flags (below). |
| Version in banner | Helps an attacker choose targeted exploits | Set `ServerTokens Prod` and `ServerSignature Off`. |
| `robots.txt` | Reveals nothing here, but listing sensitive paths in it would advertise them | Protect sensitive paths with authentication, not with `robots.txt`. |

Example configuration:

```apache
# Apache: hide version details
ServerTokens Prod
ServerSignature Off

# Apache: redirect HTTP to HTTPS
<VirtualHost *:80>
    Redirect permanent / https://example.com/
</VirtualHost>

# Apache: HSTS (inside the HTTPS virtual host, with mod_headers enabled)
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
```

```ini
; php.ini: harden the session cookie
session.cookie_httponly = 1
session.cookie_secure = 1
session.cookie_samesite = "Lax"
```

## Challenges

- Nmap failed with `Operation not permitted` inside Docker, because its binary carries file capabilities the container does not grant. Removing them with `setcap -r /usr/lib/nmap/nmap` fixed it, and the scans still ran as root.
- The DVWA image is built for x86, so it ran under emulation on Apple Silicon and needed `--platform linux/amd64`.
- searchsploit matched loosely on the version string, so I filtered the results by product and version range by hand.

## Lessons learned

- Scan broad first (`-p-`), then go deep on the ports that are open.
- Save scan output with `-oA` so the results can be reused as evidence and fed to other tools.
- A banner version needs verification before it becomes a finding.

## Limitations

- One scan from one vantage point, against a container with a single exposed service.
- No authenticated checks, no web application testing, and no exploitation.
- The OS detection flag (`-O`) was not used.

## Next steps

- Enumerate the web application with `nikto` and `gobuster`.
- Test SQL injection with `sqlmap` at each DVWA security level and compare the results.
- Run a vulnerability scan (such as OpenVAS) to confirm which matched exploits apply.
- Repeat this exercise against a VM on my Proxmox homelab.
