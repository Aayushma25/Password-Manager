

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

