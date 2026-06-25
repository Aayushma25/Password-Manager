# VaultGen

An all-in-one **local** password manager built with Python + Flask.
No cloud sync. No accounts. No telemetry. Everything lives on your machine.

---

## Features

| Feature | Details |
|---|---|
| **Password Generator** | Cryptographically secure via `secrets` module; controls for length, character classes, ambiguous-char exclusion |
| **Passphrase Generator** | EFF Large Wordlist; 4–8 words; entropy displayed in bits |
| **Strength Checker** | zxcvbn (Dropbox); score 0–4, crack-time estimates, specific weaknesses |
| **Breach Checker** | HaveIBeenPwned v3 via k-anonymity — password never leaves your machine |
| **Encrypted Vault** | Fernet (AES-128-CBC + HMAC-SHA256); master password → PBKDF2 key derivation |
| **Export** | Encrypted JSON backup (passwords stay encrypted without your master password + salt) |


