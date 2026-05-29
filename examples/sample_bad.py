"""A deliberately flawed module used to demonstrate CodeQual findings.

Run:  codequal file examples/sample_bad.py
"""
import hashlib

# Hardcoded credentials (heuristic + AI should both flag these).
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
DB_PASSWORD = "sup3rs3cr3t-password"


def cache_user(user, store=[]):  # mutable default argument
    store.append(user)
    return store


def find(item, items):
    if item == None:  # should use 'is None'
        return -1
    for i in range(len(items)):
        if items[i] == item:
            return i
    return -1


def run_user_code(expr):
    # Dynamic code execution from untrusted input.
    return eval(expr)


def checksum(data):
    # Weak hash algorithm.
    return hashlib.md5(data).hexdigest()


def load(path):
    try:
        with open(path) as handle:
            return handle.read()
    except:  # bare except swallows everything
        pass
