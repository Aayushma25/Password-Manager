
"""
VaultGen — All-in-One Local Password Manager
=============================================
Security decisions documented inline throughout.
"""




import os
import json
import math
import sqlite3
import hashlib
import secrets
import string
import base64
import datetime
import requests

# Load .env if present (optional — app works without it)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from flask import Flask, render_template, request, jsonify, session, redirect, url_for

# cryptography.fernet: AES-128 in CBC mode with HMAC-SHA256 authentication.
# Chosen over raw AES because Fernet handles IV generation, padding, and MAC
# automatically — reducing the risk of implementation errors.
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# zxcvbn is Dropbox's realistic password strength estimator.
# Falls back to our bundled estimator if not installed.
try:
    from zxcvbn import zxcvbn as _zxcvbn_lib
    ZXCVBN_SOURCE = "zxcvbn"
except ImportError:
    _zxcvbn_lib = None
    ZXCVBN_SOURCE = "bundled"
    from vaultgen_strength import estimate_strength as _bundled_strength

app = Flask(__name__)
# Secret key for Flask session (generated fresh each run; sessions are
# server-side only and contain no sensitive vault data)
app.secret_key = secrets.token_hex(32)

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "vault.db")
SALT_PATH = os.path.join(os.path.dirname(__file__), "data", "vault.salt")

# ---------------------------------------------------------------------------
# EFF Large Wordlist (abbreviated — 200 words for passphrase generation)
# Full list: https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
# ---------------------------------------------------------------------------
EFF_WORDLIST = [
    "aardvark","ability","absence","abstract","academy","account","achieve","acquire",
    "actress","adapter","address","admiral","advance","advised","aerobic","affluent",
    "against","ageless","agency","ailment","airport","alarm","almanac","already",
    "altered","ambush","amplify","ancient","android","animals","antenna","anxiety",
    "apparel","approve","archery","arrange","article","ascend","aspirin","assorted",
    "atelier","athlete","attuned","audible","author","avocado","awesome","awkward",
    "backlog","balance","bandana","bargain","barrier","battery","bedrock","believe",
    "beneath","bicycle","blossom","bookend","bracket","bravery","brimstone","broaden",
    "cabinet","calcium","capable","captain","careful","cashflow","catalog","ceiling",
    "chamber","circuit","classic","climate","cluster","coastal","compile","conduct",
    "console","context","control","courage","crevice","crystal","culture","current",
    "dagger","daytime","decimal","defense","deliver","diamond","digital","dolphin",
    "doorway","droplet","durable","dynamic","earlier","eclipse","economy","educate",
    "effects","elastic","elegant","element","empower","enforce","enhance","episode",
    "erosion","essence","exactly","examine","example","explain","explore","extreme",
    "factory","failure","fantasy","fashion","feature","finance","firewall","fitness",
    "flywheel","forward","fragile","freedom","furnace","future","galaxy","gateway",
    "glacier","goblin","granite","gravity","greater","grocery","guardian","helpful",
    "history","holistic","horizon","housing","hydrate","ignite","imagine","improve",
    "insight","install","instant","intense","interim","invoke","island","journey",
    "justice","kingdom","lantern","lattice","launder","library","license","linkage",
    "logical","longevity","loyalty","machine","marble","measure","message","mineral",
    "miracle","mission","mixture","mobility","modern","monitor","mountain","mystery",
    "natural","network","neutral","notable","nucleus","nourish","observe","olympic",
    "outcome","outline","outside","overall","overlap","package","pathway","pattern",
    "payment","pendant","persist","picture","pioneer","polygon","portable","premium",
    "primary","process","program","project","protect","provide","publish","purpose",
    "quality","quantum","quarter","quickly","radiant","ranking","reactor","receive",
    "recover","refresh","release","renewal","replace","respect","restore","revenue",
    "revival","rhythm","rocket","sandbox","scanner","science","section","segment",
    "service","shelter","silicon","society","solvent","spatial","sphere","stellar",
    "storage","stretch","subject","success","surface","sustain","symbol","system",
    "tablet","tactics","textile","thermal","through","toolkit","topical","torsion",
    "tracker","traffic","transit","trigger","trusted","turbine","uncover","upgrade",
    "utility","venture","vibrant","victory","vintage","voltage","wisdom","witness",
]


# ===========================================================================
# DATABASE SETUP
# ===========================================================================

def get_db():
    """Return a sqlite3 connection. Creates schema on first call."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vault (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            app_name     TEXT    NOT NULL,
            username     TEXT,
            password_enc TEXT    NOT NULL,
            date_saved   TEXT    NOT NULL,
            strength     INTEGER,
            breach_count INTEGER,
            notes        TEXT
        )
    """)
    conn.commit()
    return conn


def vault_initialized():
    """Return True if a master-password hash has been stored."""
    if not os.path.exists(DB_PATH):
        return False
    db = get_db()
    row = db.execute("SELECT value FROM meta WHERE key='master_hash'").fetchone()
    db.close()
    return row is not None


# ===========================================================================
# KEY DERIVATION & ENCRYPTION
# ===========================================================================

def load_or_create_salt():
    """
    Salt is stored separately from the DB so that even if the DB is copied
    without the salt file, brute-forcing the master password is harder.
    """
    if os.path.exists(SALT_PATH):
        with open(SALT_PATH, "rb") as f:
            return f.read()
    salt = secrets.token_bytes(32)   # 256-bit salt
    os.makedirs(os.path.dirname(SALT_PATH), exist_ok=True)
    with open(SALT_PATH, "wb") as f:
        f.write(salt)
    return salt


def derive_key(master_password: str) -> bytes:
    """
    Derive a 32-byte key from the master password using PBKDF2-HMAC-SHA256.

    Why PBKDF2?
    - Intentionally slow (100,000 iterations) to resist brute-force attacks.
    - NIST SP 800-132 and OWASP recommend ≥ 600,000 iterations for new systems;
      100k is a reasonable minimum for local use on modest hardware.
    - The salt ensures the same password produces a different key on every
      installation, defeating rainbow-table attacks.
    """
    salt = load_or_create_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))


def get_fernet(master_password: str) -> Fernet:
    """Return a Fernet instance keyed to this master password."""
    return Fernet(derive_key(master_password))


def hash_master(master_password: str) -> str:
    """
    Store a SHA-256 hash of the *derived key* (not the raw password) for
    verification. We never store the master password itself.
    """
    key = derive_key(master_password)
    return hashlib.sha256(key).hexdigest()


# ===========================================================================
# PASSWORD GENERATOR
# ===========================================================================

def calculate_entropy(password: str, charset_size: int) -> float:
    """
    Entropy (bits) = log2(charset_size ^ length) = length * log2(charset_size).
    This is a theoretical maximum; zxcvbn gives a more realistic estimate.
    """
    if charset_size <= 1:
        return 0.0
    return len(password) * math.log2(charset_size)


def generate_password(length: int, use_upper: bool, use_lower: bool,
                       use_digits: bool, use_symbols: bool,
                       exclude_ambiguous: bool) -> dict:
    """
    Generate a cryptographically secure password.

    Why secrets.choice instead of random.choice?
    - random uses a Mersenne Twister PRNG, which is NOT cryptographically
      secure — its state can be reconstructed from ~624 outputs.
    - secrets uses os.urandom() (hardware entropy / /dev/urandom), which
      is suitable for generating tokens, keys, and passwords.
    """
    AMBIGUOUS = set("0Ol1I|`")

    charset = ""
    if use_upper:
        pool = string.ascii_uppercase
        if exclude_ambiguous:
            pool = "".join(c for c in pool if c not in AMBIGUOUS)
        charset += pool
    if use_lower:
        pool = string.ascii_lowercase
        if exclude_ambiguous:
            pool = "".join(c for c in pool if c not in AMBIGUOUS)
        charset += pool
    if use_digits:
        pool = string.digits
        if exclude_ambiguous:
            pool = "".join(c for c in pool if c not in AMBIGUOUS)
        charset += pool
    if use_symbols:
        pool = string.punctuation
        if exclude_ambiguous:
            pool = "".join(c for c in pool if c not in AMBIGUOUS)
        charset += pool

    if not charset:
        charset = string.ascii_letters + string.digits  # safe fallback

    # Guarantee at least one character from each requested class
    guaranteed = []
    if use_upper:
        pool = "".join(c for c in string.ascii_uppercase
                       if not exclude_ambiguous or c not in AMBIGUOUS)
        if pool:
            guaranteed.append(secrets.choice(pool))
    if use_lower:
        pool = "".join(c for c in string.ascii_lowercase
                       if not exclude_ambiguous or c not in AMBIGUOUS)
        if pool:
            guaranteed.append(secrets.choice(pool))
    if use_digits:
        pool = "".join(c for c in string.digits
                       if not exclude_ambiguous or c not in AMBIGUOUS)
        if pool:
            guaranteed.append(secrets.choice(pool))
    if use_symbols:
        pool = "".join(c for c in string.punctuation
                       if not exclude_ambiguous or c not in AMBIGUOUS)
        if pool:
            guaranteed.append(secrets.choice(pool))

    remaining = length - len(guaranteed)
    if remaining < 0:
        remaining = 0

    # secrets.choice on each position independently; no shuffling bias
    password_chars = guaranteed + [secrets.choice(charset) for _ in range(remaining)]

    # Fisher-Yates shuffle via secrets for unbiased ordering
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    password = "".join(password_chars)
    entropy = calculate_entropy(password, len(set(charset)))

    return {"password": password, "entropy": round(entropy, 1)}


def generate_passphrase(word_count: int) -> dict:
    """
    Generate a passphrase from the EFF large wordlist.
    Each word is chosen with secrets.choice so selection is
    cryptographically uniform. Entropy ≈ word_count * log2(len(wordlist)).
    """
    words = [secrets.choice(EFF_WORDLIST) for _ in range(word_count)]
    passphrase = "-".join(words)
    entropy = word_count * math.log2(len(EFF_WORDLIST))
    return {"password": passphrase, "entropy": round(entropy, 1)}


# ===========================================================================
# HIBP BREACH CHECK
# ===========================================================================

def check_breach(password: str) -> dict:
    """
    Check HaveIBeenPwned Pwned Passwords API using k-anonymity.

    Why k-anonymity (prefix method)?
    - We hash the password with SHA-1 locally.
    - Only the first 5 hex characters are sent to the API.
    - The API returns all hashes matching that prefix (~500 entries).
    - We compare the remainder locally — the full hash NEVER leaves this machine.
    - This gives us breach data without exposing the actual password or even
      its full hash to a third party.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true"},
            timeout=5,
        )
        resp.raise_for_status()
    except requests.RequestException as e:
        return {"error": str(e), "pwned": False, "count": 0}

    for line in resp.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix.strip() == suffix:
            return {"pwned": True, "count": int(count.strip())}

    return {"pwned": False, "count": 0}


# ===========================================================================
# ROUTES — AUTH
# ===========================================================================

@app.route("/")
def index():
    if not vault_initialized():
        return redirect(url_for("setup"))
    if not session.get("unlocked"):
        return redirect(url_for("unlock"))
    return render_template("index.html")


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if vault_initialized():
        return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        pw = request.form.get("master_password", "")
        confirm = request.form.get("confirm_password", "")
        if len(pw) < 8:
            error = "Master password must be at least 8 characters."
        elif pw != confirm:
            error = "Passwords do not match."
        else:
            os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
            db = get_db()
            db.execute("INSERT INTO meta (key, value) VALUES ('master_hash', ?)",
                       (hash_master(pw),))
            db.commit()
            db.close()
            session["unlocked"] = True
            session["master_password"] = pw
            return redirect(url_for("index"))
    return render_template("setup.html", error=error)


@app.route("/unlock", methods=["GET", "POST"])
def unlock():
    if not vault_initialized():
        return redirect(url_for("setup"))
    error = None
    if request.method == "POST":
        pw = request.form.get("master_password", "")
        db = get_db()
        row = db.execute("SELECT value FROM meta WHERE key='master_hash'").fetchone()
        db.close()
        if row and hash_master(pw) == row["value"]:
            session["unlocked"] = True
            session["master_password"] = pw
            return redirect(url_for("index"))
        error = "Incorrect master password."
    return render_template("unlock.html", error=error)


@app.route("/lock")
def lock():
    session.clear()
    return redirect(url_for("unlock"))



# ===========================================================================
# ROUTES — PASSWORD GENERATOR
# ===========================================================================

@app.route("/api/generate", methods=["POST"])
def api_generate():
    if not session.get("unlocked"):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(force=True)
    mode = data.get("mode", "password")

    if mode == "passphrase":
        word_count = max(4, min(8, int(data.get("word_count", 5))))
        result = generate_passphrase(word_count)
    else:
        length = max(8, min(128, int(data.get("length", 16))))
        result = generate_password(
            length=length,
            use_upper=data.get("use_upper", True),
            use_lower=data.get("use_lower", True),
            use_digits=data.get("use_digits", True),
            use_symbols=data.get("use_symbols", True),
            exclude_ambiguous=data.get("exclude_ambiguous", False),
        )
    return jsonify(result)


# ===========================================================================
# ROUTES — STRENGTH CHECKER
# ===========================================================================

@app.route("/api/strength", methods=["POST"])
def api_strength():
    if not session.get("unlocked"):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(force=True)
    password = data.get("password", "")

    if ZXCVBN_SOURCE == "zxcvbn":
        result = _zxcvbn_lib(password)
        labels = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
        ct = result.get("crack_times_display", {})
        fb = result.get("feedback", {})
        warnings = []
        if fb.get("warning"):
            warnings.append(fb["warning"])
        warnings += fb.get("suggestions", [])
        charset_size = 0
        if any(c in string.ascii_lowercase for c in password): charset_size += 26
        if any(c in string.ascii_uppercase for c in password): charset_size += 26
        if any(c in string.digits           for c in password): charset_size += 10
        if any(c in string.punctuation      for c in password): charset_size += 32
        entropy = round(len(password) * math.log2(max(charset_size, 2)), 1) if password else 0
        return jsonify({
            "score":              result["score"],
            "label":              labels[result["score"]],
            "entropy":            entropy,
            "crack_time_offline": ct.get("offline_fast_hashing_1e10_per_second", "N/A"),
            "crack_time_online":  ct.get("online_throttling_100_per_hour", "N/A"),
            "warnings":           warnings,
            "guesses_log10":      round(result.get("guesses_log10", 0), 1),
        })
    else:
        # Bundled fallback estimator
        r = _bundled_strength(password)
        labels = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
        return jsonify({
            "score":              r["score"],
            "label":              labels[r["score"]],
            "entropy":            r["entropy"],
            "crack_time_offline": r["crack_time_offline"],
            "crack_time_online":  r["crack_time_online"],
            "warnings":           r["warnings"],
            "guesses_log10":      r["guesses_log10"],
        })


# ===========================================================================
# ROUTES — BREACH CHECKER
# ===========================================================================

@app.route("/api/breach", methods=["POST"])
def api_breach():
    if not session.get("unlocked"):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(force=True)
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "No password provided"}), 400

    return jsonify(check_breach(password))


# ===========================================================================
# ROUTES — VAULT CRUD
# ===========================================================================

@app.route("/api/vault/save", methods=["POST"])
def api_vault_save():
    if not session.get("unlocked"):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(force=True)
    master_pw = session.get("master_password", "")
    f = get_fernet(master_pw)

    # Encrypt the password before storage
    encrypted = f.encrypt(data["password"].encode("utf-8")).decode("utf-8")

    db = get_db()
    db.execute("""
        INSERT INTO vault (app_name, username, password_enc, date_saved,
                           strength, breach_count, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get("app_name", ""),
        data.get("username", ""),
        encrypted,
        datetime.datetime.now().isoformat(timespec="seconds"),
        data.get("strength", None),
        data.get("breach_count", None),
        data.get("notes", ""),
    ))
    db.commit()
    db.close()
    return jsonify({"success": True})


@app.route("/api/vault/list", methods=["GET"])
def api_vault_list():
    if not session.get("unlocked"):
        return jsonify({"error": "Unauthorized"}), 401

    db = get_db()
    rows = db.execute(
        "SELECT id, app_name, username, date_saved, strength, breach_count, notes "
        "FROM vault ORDER BY date_saved DESC"
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/vault/get/<int:entry_id>", methods=["GET"])
def api_vault_get(entry_id):
    if not session.get("unlocked"):
        return jsonify({"error": "Unauthorized"}), 401

    master_pw = session.get("master_password", "")
    f = get_fernet(master_pw)

    db = get_db()
    row = db.execute("SELECT * FROM vault WHERE id=?", (entry_id,)).fetchone()
    db.close()

    if not row:
        return jsonify({"error": "Not found"}), 404

    try:
        decrypted = f.decrypt(row["password_enc"].encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return jsonify({"error": "Decryption failed — wrong master password?"}), 500

    result = dict(row)
    result["password"] = decrypted
    del result["password_enc"]
    return jsonify(result)


@app.route("/api/vault/delete/<int:entry_id>", methods=["DELETE"])
def api_vault_delete(entry_id):
    if not session.get("unlocked"):
        return jsonify({"error": "Unauthorized"}), 401

    db = get_db()
    db.execute("DELETE FROM vault WHERE id=?", (entry_id,))
    db.commit()
    db.close()
    return jsonify({"success": True})


@app.route("/api/vault/update/<int:entry_id>", methods=["PUT"])
def api_vault_update(entry_id):
    if not session.get("unlocked"):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(force=True)
    master_pw = session.get("master_password", "")
    f = get_fernet(master_pw)
    encrypted = f.encrypt(data["password"].encode("utf-8")).decode("utf-8")

    db = get_db()
    db.execute("""
        UPDATE vault SET app_name=?, username=?, password_enc=?, notes=?
        WHERE id=?
    """, (data.get("app_name", ""), data.get("username", ""),
          encrypted, data.get("notes", ""), entry_id))
    db.commit()
    db.close()
    return jsonify({"success": True})


@app.route("/api/vault/export", methods=["GET"])
def api_vault_export():
    """
    Export vault as JSON. Passwords remain encrypted — this is a safe backup
    because without the master password (and the salt file), the encrypted
    blobs cannot be decrypted.
    """
    if not session.get("unlocked"):
        return jsonify({"error": "Unauthorized"}), 401

    db = get_db()
    rows = db.execute("SELECT * FROM vault").fetchall()
    db.close()

    export_data = {
        "vaultgen_export": True,
        "exported_at": datetime.datetime.now().isoformat(),
        "entries": [dict(r) for r in rows],
    }
    return jsonify(export_data)


# ===========================================================================
# ENTRY POINT
# ===========================================================================

if __name__ == "__main__":
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    host  = os.environ.get("VAULTGEN_HOST", "127.0.0.1")
    port  = int(os.environ.get("VAULTGEN_PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    print(f"\n  VaultGen is running at http://{host}:{port}\n")
    app.run(debug=debug, host=host, port=port)


