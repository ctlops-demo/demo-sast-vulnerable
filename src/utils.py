"""
INTENTIONALLY VULNERABLE — Python utilities for SAST scanner demo.

Every function contains security vulnerabilities that Opengrep/CodeQL should flag.
DO NOT use this code in production.
"""

import os
import pickle
import subprocess
import sqlite3
import hashlib
import tempfile
import yaml
import xml.etree.ElementTree as ET
from flask import request, render_template_string


# ─── SQL Injection (Python) ────────────────────────────────────
def get_user(user_id):
    """VULN: f-string SQL injection"""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()


def search_users(name):
    """VULN: format-string SQL injection"""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name LIKE '%{}%'".format(name)
    cursor.execute(query)
    return cursor.fetchall()


# ─── Command Injection (Python) ────────────────────────────────
def run_diagnostic(hostname):
    """VULN: shell=True with user input"""
    result = subprocess.run(
        f"nslookup {hostname}",
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def compress_file(filename):
    """VULN: os.system with user-controlled input"""
    os.system(f"tar -czf archive.tar.gz {filename}")


# ─── Insecure Deserialization ──────────────────────────────────
def load_session(data):
    """VULN: pickle.loads on untrusted data — arbitrary code execution"""
    return pickle.loads(data)


def load_config(yaml_content):
    """VULN: yaml.load without SafeLoader — allows arbitrary Python object creation"""
    return yaml.load(yaml_content)


# ─── Path Traversal (Python) ──────────────────────────────────
def read_document(filename):
    """VULN: user-controlled path with no sanitization"""
    filepath = os.path.join("/var/documents", filename)
    with open(filepath, "r") as f:
        return f.read()


def serve_template(template_name):
    """VULN: path traversal in template loading"""
    with open(f"templates/{template_name}") as f:
        return f.read()


# ─── Server-Side Template Injection ───────────────────────────
def render_greeting(name):
    """VULN: SSTI — user input rendered as Jinja2 template"""
    template = f"Hello {name}! Welcome to our site."
    return render_template_string(template)


# ─── XML External Entity (XXE) ────────────────────────────────
def parse_xml_config(xml_string):
    """VULN: XML parsing without disabling external entities"""
    tree = ET.fromstring(xml_string)
    return tree


# ─── Weak Cryptography ────────────────────────────────────────
def hash_password(password):
    """VULN: SHA1 is not suitable for password hashing"""
    return hashlib.sha1(password.encode()).hexdigest()


def generate_token():
    """VULN: predictable random — should use secrets.token_hex()"""
    import random
    return "".join(random.choices("abcdefghijklmnop0123456789", k=32))


# ─── Hardcoded Credentials ────────────────────────────────────
DATABASE_PASSWORD = "admin123!"
API_KEY = "sk-proj-demo-not-real-aBcDeFgHiJkLmNoPqRsTuVwXyZ"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def get_db_connection():
    """VULN: hardcoded credentials in source"""
    return sqlite3.connect(
        "postgresql://admin:SuperSecret123!@prod-db.example.com:5432/main"
    )


# ─── Insecure Temporary File ──────────────────────────────────
def write_temp_data(data):
    """VULN: predictable temp file path — race condition"""
    path = "/tmp/app_data.txt"
    with open(path, "w") as f:
        f.write(data)
    return path


# ─── SSRF (Python) ────────────────────────────────────────────
def fetch_url(url):
    """VULN: user-controlled URL without allowlist"""
    import urllib.request
    return urllib.request.urlopen(url).read()
