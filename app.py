





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
