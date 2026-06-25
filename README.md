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
