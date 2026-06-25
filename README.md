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

---

## Quick Start

### 1. Prerequisites

- Python 3.10 or higher
- pip

### 2. Clone / Download

```bash
git clone https://github.com/yourorg/vaultgen.git
cd vaultgen
```

### 3. Create a virtual environment (recommended)

```bash
python -m venv .venv

# macOS / Linux
source .venv/bin/activate

# Windows (PowerShell)
.venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. (Optional) Configure environment

```bash
cp .env.example .env
# Edit .env if you want a different port or data directory
```

### 6. Run VaultGen

```bash
python app.py
```

Open your browser at **http://127.0.0.1:5000**

---
## First Launch

1. You will be taken to the **Create Vault** screen.
2. Choose a strong master password (≥ 8 characters; longer is better).
3. This password is **never stored** — only a hash of its derived key is kept for unlock verification.
4. If you forget your master password, your vault data cannot be recovered.


---

## File Layout

```
vaultgen/
├── app.py                  # Flask application + all backend logic
├── requirements.txt
├── .env.example
├── README.md
├── data/                   # Created automatically on first run
│   ├── vault.db            # Encrypted SQLite database
│   └── vault.salt          # 256-bit random salt (keep this file!)
├── static/
│   ├── css/style.css
│   └── js/app.js
└── templates/
    ├── index.html
    ├── setup.html
    └── unlock.html
```

> ⚠️ **Back up both `vault.db` AND `vault.salt`** together.
> The salt is required to derive the correct encryption key from your master password.
> Without it, encrypted entries cannot be decrypted even with the correct master password.

---


## Security Architecture

### Why `secrets` instead of `random`?
Python's `random` module uses a Mersenne Twister PRNG whose state can be reconstructed after observing ~624 outputs — entirely unsuitable for security-sensitive values. `secrets` wraps `os.urandom()` (backed by the OS CSPRNG / `/dev/urandom`), providing cryptographically uniform randomness.

### Why PBKDF2-HMAC-SHA256 with 100,000 iterations?
Password-based key derivation must be deliberately slow to resist brute-force attacks. PBKDF2 (NIST SP 800-132) applies the PRF repeatedly, making each guess expensive. 100,000 iterations is a conservative minimum; increase `iterations` in `app.py` if your hardware allows.

### Why Fernet instead of raw AES?
Fernet is a high-level authenticated encryption scheme (AES-128-CBC + HMAC-SHA256). It handles IV generation, PKCS7 padding, and MAC verification automatically — removing common implementation pitfalls like IV reuse and padding oracle vulnerabilities.

### Why k-anonymity for HIBP?
Sending the full password hash to a third-party API would expose the hash to potential interception or logging. With k-anonymity, only the first 5 hex characters of the SHA-1 hash are transmitted. The API returns ~500 matching suffixes; comparison is done locally. The full hash — let alone the password — is never sent over the network.

### Master password storage
The master password itself is never persisted. On first setup, the application:
1. Loads (or generates) a 256-bit random salt from `data/vault.salt`
2. Derives a 32-byte key via PBKDF2-HMAC-SHA256(master_password, salt, 100_000)
3. Stores `SHA-256(derived_key)` in the database for unlock verification

This means an attacker with only the database cannot verify guesses without also having the salt file.

---

## Updating the PBKDF2 Iteration Count

Open `app.py` and find the `derive_key` function. Increase `iterations`:

```python
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=600_000,   # OWASP 2023 recommendation
    ...
)
```

After changing this, you must **reset your vault** (delete `data/vault.db` and `data/vault.salt`) because existing entries were encrypted with a key derived at the old iteration count.

---

## Dependencies

| Package | Purpose |
|---|---|
| Flask | Web framework |
| cryptography | Fernet encryption, PBKDF2 key derivation |
| zxcvbn | Realistic password strength estimation |
| requests | HIBP Pwned Passwords API calls |
| python-dotenv | Optional `.env` config loading |

All dependencies are free and open source. No paid services required.

---

