# Lab 03: SQL Injection with sqlmap Across DVWA's Security Levels

The third lab in the series. [Lab 01](../01-nmap-dvwa-recon/) and [Lab 02](../02-web-enumeration/) scanned DVWA from the outside. This lab tests one specific vulnerability — SQL injection — against the same tool, at each of DVWA's four built-in security levels (Low, Medium, High, Impossible), to see how the same automated attack performs as the application's own code gets more careful.

| | |
| --- | --- |
| **Date** | 2026-11-17 |
| **Target** | DVWA SQL Injection page, `http://dvwa/vulnerabilities/sqli/` |
| **Attacker** | Kali Linux (`kalilinux/kali-rolling`) in Docker |
| **Tool** | sqlmap 1.10.10 |
| **Type** | Authenticated testing with a valid session cookie. No data was modified. |

## Summary

At **Low** and **Medium**, sqlmap found four working injection techniques and dumped the full `users` table: 5 accounts with usernames, real names, and password hashes. Two of the five accounts share the same hash, which decodes to the word "password" — a sign of weak, reused credentials on top of the injection flaw itself.

At **High**, the same URL and parameters were not injectable, even at sqlmap's maximum test depth (`--level=5 --risk=3`, several hundred payload variations). At **Impossible**, the request was redirected before any injection test could run at all.

DVWA's own levels are a teaching tool, not a real audit scale, but the pattern holds a real lesson: escaping user input (High) and using parameterized queries with strict validation (Impossible) both defeated the same automated tool that walked straight through Low and Medium.

## Scope and authorization

- **In scope:** the `dvwa` container's SQL Injection page on my private Docker network, using my own authenticated session.
- **Out of scope:** every other host and any network I do not own.
- **Authorization:** I built and own the target. Do not run sqlmap, or any injection tool, against an application you do not own or have written permission to test — it sends a large number of requests and can alter data on a real system.

## Methodology

I logged into DVWA in a browser, copied the session cookie, and ran sqlmap from the Kali container against DVWA's `id` parameter at each security level in turn, recording the whole session with `script`.

```bash
mkdir -p /root/lab03 && cd /root/lab03
script -a session.log

# repeated once per security level, with the matching cookie
sqlmap -u "http://dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=<value>; security=<level>" \
  --batch --dbs

exit
```

- `--batch` answers sqlmap's prompts automatically so the scan runs unattended.
- `--dbs` asks sqlmap to enumerate database names, which also forces it to find and confirm an injection point first.
- After a positive result, I followed up with `--tables` and `--dump` on the `dvwa` database to pull the actual data.
- The security level is changed from DVWA's own **DVWA Security** page in the browser, then a fresh `PHPSESSID` and `security` cookie value is copied from DevTools for the next sqlmap run.

Raw output: [`evidence/01-low.txt`](evidence/01-low.txt), [`evidence/02-medium.txt`](evidence/02-medium.txt), [`evidence/03-high.txt`](evidence/03-high.txt), [`evidence/04-impossible.txt`](evidence/04-impossible.txt).

## Findings

| Level | Injectable? | Techniques found | Data recovered |
| --- | --- | --- | --- |
| Low | Yes | Boolean-based blind, error-based, time-based blind, UNION query | Full `users` table: 5 accounts, usernames, real names, password hashes |
| Medium | Yes | Same four techniques, same payloads | Identical dump to Low |
| High | No | None, even at `--level=5 --risk=3` (several hundred payload variations tested) | None |
| Impossible | No | None (request redirected before testing) | None |

| # | Finding | Evidence | Risk |
| --- | --- | --- | --- |
| 1 | Full SQL injection at Low and Medium | 4 confirmed techniques, full table dump | Critical |
| 2 | Weak, reused password hashes | `admin` and `smithy` share the hash for "password" | High (made worse by finding 1) |
| 3 | A naive re-run gave a false positive at High | sqlmap reused a cached injection point from an earlier run against the same URL | Testing-process risk, not an application flaw |
| 4 | High blocks this attack class at maximum test depth | 0 findings at `--level=5 --risk=3` | N/A (this is the good outcome) |
| 5 | Impossible rejects the request before injection testing starts | 302 redirect to the plain page on the first request | N/A (this is the good outcome) |

## Analysis

- **Low and Medium are functionally the same vulnerability.** DVWA's Medium level strips quote characters from the input, but the UNION-based payload sqlmap used does not need a quote, so it walked straight through. A filter that blocks one character is not the same as fixing the underlying query.
- **The password hashes point to a second, independent weakness.** `5f4dcc3b5aa765d61d8327deb882cf99` is the MD5 hash of the literal word "password", used by two different accounts (`admin` and `smithy`). Even without the injection flaw, a hash this weak would fall to an offline dictionary attack in seconds. SQL injection and weak password hashing compound each other here: the injection exposes the hashes, and the hashes are trivial to crack.
- **A scanner's cache can lie to you.** My first attempt at High reused sqlmap's session cache from the Low/Medium runs against the same URL and reported the target as injectable — a false positive caused by my own tooling, not by DVWA. The giveaway was the log line `resuming ... from stored session`. Re-running with `--flush-session` forced a genuine retest, which returned a different (and correct) result. This is a methodology lesson as much as a technical one: always confirm a scanner actually re-tested, rather than replayed a cached result, especially when testing the same target twice with different settings.
- **High's defense is input escaping, not parameterization.** Based on DVWA's own published source for this level, the `id` value is passed through MySQL's "real escape string" function before the query runs. That neutralizes the quote-based payloads sqlmap tried, which is why raising `--level` and `--risk` (more payload variations, not smarter ones) still found nothing. This is a real improvement over Low/Medium, but it is not the same guarantee as a parameterized query: escaping has to be applied correctly everywhere user input touches a query, and it is easy to miss a spot in a larger application. A single missed escape call anywhere in the codebase can reopen the exact same hole.
- **Impossible's defense starts even earlier.** The request was redirected before sqlmap could test anything, which suggests the `id` value is validated as a clean integer (and rejected otherwise) before a query is built at all, on top of using parameterized queries. That is a stronger pattern than escaping: the untrusted input never reaches the SQL layer in an unvalidated form.

## Remediation

| Finding | Fix |
| --- | --- |
| SQL injection (Low, Medium) | Use parameterized queries (prepared statements) everywhere user input reaches SQL, never string concatenation. Validate that `id` is an integer before using it. |
| Weak password hashes | Use a slow, salted hashing algorithm (bcrypt, scrypt, or Argon2), never bare MD5 or SHA1. Enforce a minimum password strength and prevent hash reuse across accounts. |
| Escaping as the only defense (High) | Treat escaping as a second layer, not the primary defense. Move to parameterized queries so no individual call site can be missed. |
| General | Run an automated SQL injection scan as part of release testing, not just manual review, so a regression is caught before it ships. |

Example of the fix, in concept (PHP with PDO):

```php
// Vulnerable (Low/Medium): string concatenation
$query = "SELECT * FROM users WHERE user_id = '$id';";

// Fixed: parameterized query, input never touches the SQL string directly
$stmt = $pdo->prepare('SELECT * FROM users WHERE user_id = :id');
$stmt->execute(['id' => $id]);
```

```php
// Hashing: never store a bare MD5/SHA1 hash
$hash = password_hash($password, PASSWORD_BCRYPT);
password_verify($password, $hash); // to check a login
```

## Challenges and lessons learned

- **The false positive at High was the most important lesson of this lab.** sqlmap caches injection points per target URL, so running it again against the same URL with a different cookie can silently reuse a stale result instead of testing fresh. `--flush-session` forces a clean test, and I now use it by default whenever I re-test the same URL under different conditions.
- **Changing DVWA's security level mid-session changes the server-side code, not just a setting on the page** — each level is a genuinely different PHP implementation of the same form. That is what made this comparison meaningful: I was testing four different pieces of code, not one piece of code with a toggle.
- **A clean "not injectable" result still needs maximum effort before it counts.** The default `--level 1 --risk 1` scan is fast but shallow. Running it again at `--level 5 --risk 3` against High took about four minutes and tried several hundred payloads before I trusted the negative result.
- **`script -a session.log` captured the full terminal, including the long real-time progress output**, which made it easy to go back and find the exact moment an injection point was confirmed or a prompt was answered.

## Limitations

- This tested one parameter (`id`) on one page. DVWA has a separate Blind SQL Injection page and other vulnerable pages that were not tested here.
- I did not attempt to escalate from database access to the underlying server (for example, via `--os-shell`).
- The High-level finding is specific to the `id`/`Submit` GET parameters on this URL with sqlmap's standard technique set. It does not rule out every possible injection vector on that page.
- DVWA's security levels are an intentionally simplified teaching model. They demonstrate real defensive patterns (escaping, parameterization, validation) but should not be read as a general vulnerability-severity scale for production code.

## Next steps

- Test DVWA's **SQL Injection (Blind)** page the same way, since it uses a different code path.
- Try to crack the recovered password hashes with `hashcat` or `john`, to show the second half of this finding end to end.
- Review the actual High and Impossible PHP source in the DVWA repository and quote the specific defense used, rather than inferring it from behavior alone.
- Repeat this comparison against a real (not intentionally vulnerable) web application on my Proxmox homelab, where the baseline is unknown going in.
