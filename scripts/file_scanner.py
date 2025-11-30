import hashlib
import json
import os


DB_PATH = os.path.join(os.path.dirname(__file__), "malware_db.json")

def load_malware_db():
    """Load malware signatures from JSON file."""
    if not os.path.exists(DB_PATH):
        return {}
    try:
        with open(DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def calculate_sha256(file_path):
    """Calculate SHA-256 hash of any file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def scan_file(file_path):
    """
    Scan a file by comparing its SHA-256 hash with known malware signatures.
    Returns (is_malware: bool, message: str).
    """
    file_hash = calculate_sha256(file_path)
    malware_db = load_malware_db()

    if file_hash in malware_db:
        return True, malware_db[file_hash]  
    else:
        return False, "Unknown File (Not in database)"
