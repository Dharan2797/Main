# config.py

"""Configuration for the Flask File Manager application."""

import os

# Absolute path on the server where uploaded files will be stored.
UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "/home/admin/Documents/Softwares")

# Fallback to local 'uploads' directory if UPLOAD_FOLDER is not writable or we are on Windows
is_writable = True
try:
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    # Test writing a dummy file to ensure it's writable
    test_file = os.path.join(UPLOAD_FOLDER, '.write_test')
    with open(test_file, 'w') as f:
        f.write('test')
    os.remove(test_file)
except Exception:
    is_writable = False

if os.name == 'nt' or not is_writable:
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
    if not os.path.isdir(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Set to None → no global Flask-level file size limit.
# Individual folders are governed by the quota system in app.py.
# NOTE: Also set  client_max_body_size 0;  in nginx if used in production.
MAX_CONTENT_LENGTH = None

# ── Allowed extensions ────────────────────────────────────────────────────────
# To allow EVERY file type with no restriction, set ALLOWED_EXTENSIONS = None.
ALLOWED_EXTENSIONS = None

def allowed_file(filename):
    """Return True if the file extension is permitted.

    If ALLOWED_EXTENSIONS is None/empty, every file is accepted.
    Files with no extension are always accepted.
    """
    allowed = ALLOWED_EXTENSIONS
    if not allowed:
        return True
    if "." not in filename:
        return True
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in allowed
