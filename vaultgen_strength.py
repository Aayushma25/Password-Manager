

import re
import math
import string

# Top-200 most common passwords (NIST / RockYou sample)
COMMON_PASSWORDS = {
    "password","123456","12345678","qwerty","abc123","monkey","1234567",
    "letmein","trustno1","dragon","baseball","iloveyou","master","sunshine",
    "ashley","bailey","passw0rd","shadow","123123","654321","superman",
    "qazwsx","michael","football","password1","password123","admin","welcome",
    "login","hello","whatever","qwerty123","iloveyou1","princess","1q2w3e4r",
    "passw0rd1","test","password2","1234","12345","123456789","1234567890",
    "0987654321","qwertyuiop","asdfghjkl","zxcvbnm","pass","qwerty1",
    "password12","pass123","secret","changeme","love","sunshine1","flowers",
    "jordan","harley","ranger","shadow1","hockey","access","batman",
    "starwars","cheese","butter","jessica","andrew","thomas","matthew",
}

# Common keyboard walk sequences
KEYBOARD_WALKS = [
    "qwerty","qwert","werty","asdfg","sdfgh","dfghj","zxcvb","xcvbn",
    "12345","23456","34567","45678","56789","67890","09876","98765",
    "qazwsx","wsxedc","edcrfv","rfvtgb","tgbyhn","yhnujm",
]

SEQUENTIAL_DIGITS = "01234567890"
SEQUENTIAL_ALPHA  = "abcdefghijklmnopqrstuvwxyz"


def _has_repeat_chars(pw: str, run: int = 3) -> bool:
    """Return True if any character repeats ≥ `run` times consecutively."""
    count = 1
    for i in range(1, len(pw)):
        if pw[i].lower() == pw[i-1].lower():
            count += 1
            if count >= run:
                return True
        else:
            count = 1
    return False


def _has_keyboard_walk(pw: str, length: int = 4) -> bool:
    pwl = pw.lower()
    for walk in KEYBOARD_WALKS:
        for i in range(len(walk) - length + 1):
            if walk[i:i+length] in pwl:
                return True
    return False


def _has_sequential(pw: str, length: int = 3) -> bool:
    pwl = pw.lower()
    for seq in (SEQUENTIAL_DIGITS, SEQUENTIAL_ALPHA):
        for i in range(len(seq) - length + 1):
            if seq[i:i+length] in pwl:
                return True
    return False


def _charset_size(pw: str) -> int:
    size = 0
    if any(c in string.ascii_lowercase for c in pw): size += 26
    if any(c in string.ascii_uppercase for c in pw): size += 26
    if any(c in string.digits           for c in pw): size += 10
    if any(c in string.punctuation      for c in pw): size += 32
    return max(size, 2)


def _crack_time_label(seconds: float) -> str:
    """Human-readable time from seconds."""
    if seconds < 1:           return "less than a second"
    if seconds < 60:          return f"{int(seconds)} seconds"
    if seconds < 3600:        return f"{int(seconds/60)} minutes"
    if seconds < 86400:       return f"{int(seconds/3600)} hours"
    if seconds < 2592000:     return f"{int(seconds/86400)} days"
    if seconds < 31536000:    return f"{int(seconds/2592000)} months"
    years = seconds / 31536000
    if years < 1_000:         return f"{int(years)} years"
    if years < 1_000_000:     return f"{years/1_000:.1f}k years"
    if years < 1_000_000_000: return f"{years/1_000_000:.1f}M years"
    return "centuries"


def estimate_strength(password: str) -> dict:
    """
    Return a dict compatible with the zxcvbn output shape used by app.py:
      score (0–4), label, entropy, crack_time_offline,
      crack_time_online, warnings, guesses_log10
    """
    pw = password

    warnings = []
    penalties = 0

    # --- Common password check ---
    if pw.lower() in COMMON_PASSWORDS:
        warnings.append("This is one of the most commonly used passwords.")
        penalties += 3

    # --- Length checks ---
    if len(pw) < 8:
        warnings.append("Password is too short (minimum 8 characters recommended).")
        penalties += 2
    elif len(pw) < 12:
        warnings.append("Consider using a longer password (12+ characters).")
        penalties += 1

    # --- Repeated characters ---
    if _has_repeat_chars(pw, 3):
        warnings.append("Avoid repeating characters (e.g. 'aaa', '111').")
        penalties += 1

    # --- Keyboard walk ---
    if _has_keyboard_walk(pw, 4):
        warnings.append("Keyboard pattern detected (e.g. 'qwerty', 'asdf').")
        penalties += 1

    # --- Sequential ---
    if _has_sequential(pw, 3):
        warnings.append("Sequential characters detected (e.g. '123', 'abc').")
        penalties += 1

    # --- All same character class ---
    if pw.isdigit():
        warnings.append("Password contains only digits.")
        penalties += 1
    elif pw.isalpha():
        warnings.append("Password contains only letters — add digits or symbols.")
        penalties += 1

    # --- Raw entropy ---
    charset = _charset_size(pw)
    entropy = len(pw) * math.log2(charset)

    # Effective guesses: 2^entropy, penalised
    raw_guesses = 2 ** entropy
    for _ in range(penalties):
        raw_guesses /= 100
    guesses = max(1, raw_guesses)
    guesses_log10 = math.log10(guesses)

    # --- Score (0–4) ---
    # Thresholds based on log10(guesses): <3 / <6 / <8 / <10 / >=10
    if guesses_log10 < 3:      score = 0
    elif guesses_log10 < 6:    score = 1
    elif guesses_log10 < 8:    score = 2
    elif guesses_log10 < 10:   score = 3
    else:                      score = 4

    # Crack time at 1e10 guesses/sec (offline fast, e.g. bcrypt cracker)
    offline_secs = guesses / 1e10
    # Crack time at 100 guesses/hour (online throttled)
    online_secs  = guesses / (100 / 3600)

    return {
        "score":             score,
        "entropy":           round(entropy, 1),
        "crack_time_offline": _crack_time_label(offline_secs),
        "crack_time_online":  _crack_time_label(online_secs),
        "warnings":          warnings,
        "guesses_log10":     round(guesses_log10, 1),
    }

