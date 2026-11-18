# Lab 04: Cracking DVWA's Password Hashes with hashcat

The fourth lab in the series. [Lab 03](../03-sqli-sqlmap/) used SQL injection to dump DVWA's `users` table, including five password hashes. This lab answers the question that dump leaves open: how much do those hashes actually protect the underlying passwords?

| | |
| --- | --- |
| **Date** | 2026-11-17 |
| **Input** | 5 password hashes recovered in Lab 03 (4 unique, 2 accounts share one hash) |
| **Attacker** | Kali Linux (`kalilinux/kali-rolling`) in Docker, CPU only |
| **Tool** | hashcat 7.1.2, rockyou.txt wordlist (14,344,385 entries) |
| **Type** | Offline dictionary attack. No requests were sent to DVWA in this lab. |

## Summary

All 5 hashes cracked in 20 seconds, using only a CPU and a public wordlist. Every password was found within the first 8,192 words tried — 0.06% of the list. The hashes are unsalted MD5, which has no computational cost built in, and every password was short, common, and already present in a 2009 leak.

| User | Password |
| --- | --- |
| admin | `password` |
| smithy | `password` |
| gordonb | `abc123` |
| 1337 | `charley` |
| pablo | `letmein` |

## Scope and authorization

- **In scope:** the 5 password hashes recovered from my own lab's database in Lab 03.
- **Authorization:** these are my own lab's data, extracted from an application I own. Cracking hashes you do not have explicit authorization to attack is illegal in most jurisdictions, offline attack or not — authorization applies to the data, not just to sending network requests.

## Methodology

```bash
mkdir -p /root/lab04 && cd /root/lab04
script -a session.log

# Extract just the hash column from the sqlmap dump, skipping the header row
cut -d, -f4 /root/.local/share/sqlmap/output/dvwa/dump/dvwa/users.csv \
  | tail -n +2 | awk '{print $1}' > hashes.txt

apt install -y wordlists hashcat
gunzip -k /usr/share/wordlists/rockyou.txt.gz

hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt --force
hashcat -m 0 hashes.txt --show
```

- The hash file was built with a `cut`/`awk` pipeline straight from the CSV sqlmap produced, rather than retyped from a screenshot. Lab 03's notes on one of these hashes turned out to have a transcription error, which is exactly the kind of mistake this avoids.
- `-m 0` tells hashcat the hash type: raw, unsalted MD5.
- `-a 0` is a straight dictionary attack — try every word in the wordlist, unmodified.
- **rockyou.txt** is a list of roughly 14.3 million real passwords from a 2009 breach of the social app RockYou. It ships with Kali and is the standard first wordlist for this kind of exercise, because it reflects what people actually choose.
- `--show` prints the cracked hash:password pairs from hashcat's own cache, without rerunning the attack.

Raw output: [`evidence/01-hashes.txt`](evidence/01-hashes.txt) and [`evidence/02-hashcat.txt`](evidence/02-hashcat.txt).

## Findings

| # | Finding | Evidence | Risk |
| --- | --- | --- | --- |
| 1 | All 5 hashes cracked | 4/4 unique digests recovered, 100% | Critical |
| 2 | Cracked in 20 seconds on CPU alone | `Time.Started` to `Stopped`: 20 seconds; no GPU used | Critical |
| 3 | Every password found in the first 0.06% of the wordlist | `Progress: 8192/14344385 (0.06%)` | Critical |
| 4 | Two accounts share the same password | `admin` and `smithy` both hash to `5f4dcc3b5aa765d61d8327deb882cf99` (`password`) | High |
| 5 | Hashing algorithm is unsalted MD5 | hashcat reports `Hash.Mode: 0 (MD5)` and `1 unique salts` (i.e., no salt) | Critical (root cause of 1-3) |

## Analysis

- **The root cause is the hashing algorithm, not the passwords.** MD5 was designed to be fast, which is exactly the wrong property for password storage — it lets an attacker try millions of guesses per second. hashcat reports 134.4 kH/s on an ordinary CPU in this container; a modern GPU would push that figure far higher. A slow, purpose-built algorithm (see Remediation) would have made this attack take vastly longer, even with the exact same weak passwords.
- **No salt means identical passwords produce identical hashes.** That's why `admin` and `smithy`'s hashes are literally the same string — cracking one password cracks both accounts for free. A unique salt per user would have required cracking each hash independently.
- **The passwords themselves are also weak** — each one is a short, common word, which is why rockyou.txt found all of them in a fraction of a second. But this is the secondary problem. Even these same weak passwords, hashed with a modern algorithm, would have resisted an attack at this speed and cost.
- **This connects directly to Lab 03.** SQL injection was the delivery mechanism; weak hashing is what made the payload valuable once delivered. A defender who fixes the injection flaw but leaves MD5 in place is still one future bug away from this exact outcome repeating.

## Remediation

| Finding | Fix |
| --- | --- |
| Unsalted MD5 (3, 5) | Use a password-hashing function designed to be slow: bcrypt, scrypt, or Argon2. These build in both a per-user salt and a tunable work factor. |
| Fast cracking, even on weak hardware (2) | A proper password hashing algorithm raises the cost of each guess by orders of magnitude, directly countering this. |
| Shared passwords across accounts (4) | Enforce unique passwords where feasible, and alert on identical hashes found during a credential audit. |
| Weak user-chosen passwords | Enforce a minimum length and check new passwords against a breach list (such as the "Have I Been Pwned" Pwned Passwords API) at signup and password change. |

Example fix, in concept (PHP):

```php
// Vulnerable: fast, unsalted MD5
$hash = md5($password);

// Fixed: bcrypt via PHP's built-in password hashing API
// (automatically salts, and the "cost" factor tunes how slow it is)
$hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
$ok = password_verify($password, $hash);
```

## Challenges and lessons learned

- **Transcription errors are a real risk when evidence comes from screenshots.** My own notes from Lab 03 had a typo in one hash, caught only because I rebuilt the hash file from the actual CSV with a shell command instead of retyping it. Whenever possible, generate evidence files with a command, not by hand.
- **`--force` was only needed because this is a Docker container** without the usual hardware monitoring hashcat expects; it is not a sign that anything was being bypassed unsafely in this case.
- **`--show` is a convenient way to re-print results** after the fact without rerunning the whole attack, useful when writing up a scan you already ran.

## Limitations

- Tested one wordlist (rockyou.txt) and one simple attack mode (straight dictionary). Rule-based attacks (trying capitalization, number substitutions, appended digits) or a brute-force mask attack were not attempted, and were not needed here.
- This is a CPU-only result. A GPU would crack the same hashes faster still, which matters when estimating cost for a stronger hash (bcrypt/Argon2) that is deliberately slow even on a GPU.
- The scope here is limited to the hashes already recovered via SQL injection in Lab 03. I did not attempt to crack anything outside that dataset.

## Next steps

- Re-run this same wordlist against a bcrypt or Argon2 hash of the same five passwords, and time the difference, to show numerically why the hashing algorithm matters as much as the password strength.
- Try a rule-based attack (hashcat's `best64.rule`) against a password that doesn't crack from the plain wordlist alone.
- Check the recovered passwords against each other and against common patterns to look for a reused "base" password across the dataset.
- Repeat the full chain (recon → enumeration → injection → cracking) against a VM on my Proxmox homelab, where the starting weaknesses are unknown going in.
