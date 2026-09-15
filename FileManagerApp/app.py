from markupsafe import Markup
# app.py  –  FileVault Advanced File Manager
"""
Features:
  - Folder navigation & creation
  - File / folder upload (single + whole-folder with progress)
  - Rename, Move, Copy  (file & folder)
  - Download folder as ZIP
  - Per-folder storage quotas (assign / extend / shrink)
  - Global recursive search
  - File preview (image, PDF, text, video, audio)
  - Shareable links (token-based, optional expiry & password)
  - Activity / Audit log
  - Recycle bin  (soft-delete → restore / purge)
  - Sort by name / size / date  (handled client-side via JS)
"""

import os, sys, json, shutil, secrets, hashlib, zipfile, tempfile, time, threading
from datetime import datetime, timedelta
# pyrefly: ignore [missing-import]
from werkzeug.security import generate_password_hash, check_password_hash as _check_password_hash
# pyrefly: ignore [missing-import]
from flask import (Flask, request, render_template, redirect, url_for,
                   send_from_directory, send_file, flash, jsonify, abort,
                   Response, session, g, after_this_request)
# pyrefly: ignore [missing-import]
from flask_login import (LoginManager, UserMixin,
                         login_user, logout_user, login_required, current_user)
from config import UPLOAD_FOLDER, MAX_CONTENT_LENGTH, allowed_file

# ─── App ──────────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config['UPLOAD_FOLDER']         = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH']    = MAX_CONTENT_LENGTH   # Set a ceiling in config.py for production
app.config['TEMPLATES_AUTO_RELOAD'] = os.environ.get('FLASK_ENV') == 'development'
# Cached once at startup – avoids repeated os.path.abspath(app.config[...]) calls in every route.
_BASE_UPLOAD_DIR = os.path.abspath(UPLOAD_FOLDER)

# ── Session / cookie security ─────────────────────────────────────────────────
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# Set FLASK_HTTPS=1 in the environment when serving over HTTPS
app.config['SESSION_COOKIE_SECURE']   = os.environ.get('FLASK_HTTPS', '0') == '1'

# ── Stable secret key ─────────────────────────────────────────────────────────
# Uses SECRET_KEY env var if set, otherwise reads/generates a persistent key
# stored in a local file.  Never use os.urandom() directly – it changes every
# restart and would break share-link tokens (and session cookies).
_SECRET_KEY_FILE = os.path.join(os.path.dirname(__file__), '.secret_key')

def _load_or_create_secret_key():
    """Return a stable secret key: env var → persisted file → generate+save."""
    env_key = os.environ.get('SECRET_KEY', '').strip()
    if env_key:
        return env_key
    if os.path.exists(_SECRET_KEY_FILE):
        with open(_SECRET_KEY_FILE, 'rb') as f:
            key = f.read().strip()
            if key:
                return key
    key = secrets.token_hex(32)
    with open(_SECRET_KEY_FILE, 'w') as f:
        f.write(key)
    return key

app.secret_key = _load_or_create_secret_key()
from datetime import timedelta
# Extended to 8 hours – the frontend idle timer (base.html) is responsible
# for the actual inactivity logout; the cookie must never expire mid-upload.
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

# ── Public base URL (for share links) ─────────────────────────────────────────
# Set  APP_BASE_URL=https://your-domain.com  in the environment so that
# share links generated on any server automatically use the correct host.
# If not set, links fall back to the current request's host (local use).
_APP_BASE_URL = os.environ.get('APP_BASE_URL', '').rstrip('/')

BASE_DIR      = os.path.dirname(__file__)
DATA_DIR      = os.environ.get("DATA_DIR", BASE_DIR)
if not os.path.exists(DATA_DIR):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
    except Exception:
        pass

QUOTA_FILE    = os.path.join(DATA_DIR, 'folder_quotas.json')
SHARE_FILE    = os.path.join(DATA_DIR, 'share_links.json')
ACTIVITY_FILE = os.path.join(DATA_DIR, 'activity.log')
TRASH_DIR     = os.path.join(UPLOAD_FOLDER, '.trash')
USERS_FILE    = os.path.join(DATA_DIR, 'users.json')
ACL_FILE      = os.path.join(DATA_DIR, 'folder_acl.json')
VERSIONS_DIR  = os.path.join(UPLOAD_FOLDER, '.versions')
FAVORITES_FILE       = os.path.join(DATA_DIR, 'favorites.json')
INTERNAL_SHARES_FILE = os.path.join(DATA_DIR, 'internal_shares.json')
COMMENTS_FILE        = os.path.join(DATA_DIR, 'comments.json')
VAULT_FILE           = os.path.join(DATA_DIR, 'shares_vault.json')
RULES_FILE           = os.path.join(DATA_DIR, 'upload_rules.json')
CHUNKS_TMP_DIR       = os.path.join(tempfile.gettempdir(), 'filevault_chunks')
os.makedirs(CHUNKS_TMP_DIR, exist_ok=True)


# ─── Flask-Login ──────────────────────────────────────────────────────────────
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ── User store (file-backed, role-aware) ──────────────────────────────────────
# load_json / save_json are defined in HELPERS below; we call them lazily here.
def load_users():    return _g_load('_users', lambda: load_json(USERS_FILE))
def save_users(u):   save_json(USERS_FILE, u);  _g_invalidate('_users')
def load_acl():      return _g_load('_acl',   lambda: load_json(ACL_FILE))
def save_acl(a):     save_json(ACL_FILE, a);    _g_invalidate('_acl')
def load_rules():
    r = _g_load('_rules', lambda: load_json(RULES_FILE))
    dirty = False
    for k, default_val in [
        ('max_file_size_mb', None),
        ('max_folder_size_mb', None),
        ('blocked_extensions', []),
        ('blocked_mimetypes', []),
        ('folder_rules', {}),
        ('session_timeout_minutes', 5),   # Admin-configurable idle auto-logout (minutes)
    ]:
        if k not in r:
            r[k] = default_val
            dirty = True
    if dirty:
        save_json(RULES_FILE, r)
    return r
def save_rules(r):
    save_json(RULES_FILE, r)
    _g_invalidate('_rules')

def _rule_val(folder_rule, global_rules, key, default=None):
    """Return folder-specific rule value falling back to global rules.
    Uses a single dict lookup per key instead of the double r.get() pattern."""
    v = folder_rule.get(key)
    return v if v is not None else global_rules.get(key, default)

def get_rules_for_path(folder_path):
    rules = load_rules()
    if not folder_path:
        return rules
    folder_path = folder_path.replace('\\', '/').strip('/')
    folder_rules = rules.get('folder_rules', {})
    parts = folder_path.split('/')
    for i in range(len(parts), 0, -1):
        parent_path = '/'.join(parts[:i])
        if parent_path in folder_rules:
            r = folder_rules[parent_path]
            return {
                'max_file_size_mb':   _rule_val(r, rules, 'max_file_size_mb'),
                'max_folder_size_mb': _rule_val(r, rules, 'max_folder_size_mb'),
                'blocked_extensions': _rule_val(r, rules, 'blocked_extensions', []),
                'blocked_mimetypes':  _rule_val(r, rules, 'blocked_mimetypes',  []),
            }
    return rules

def validate_upload_rules(file, filename, folder_path, folder_total_size=None):
    rules = get_rules_for_path(folder_path)
    
    # 1. Blocked extensions – set for O(1) lookup
    if "." in filename:
        ext = filename.rsplit(".", 1)[1].lower()
        blocked_exts = {e.strip().lower() for e in rules.get('blocked_extensions', []) if e.strip()}
        if ext in blocked_exts:
            return False, f'File format ".{ext}" is blocked by administrator'

    # 2. Blocked mimetypes / file types – set for O(1) lookup
    content_type = file.content_type
    if content_type:
        blocked_types = {t.strip().lower() for t in rules.get('blocked_mimetypes', []) if t.strip()}
        if any(bt in content_type.lower() for bt in blocked_types):
            return False, f'File type "{content_type}" is blocked by administrator'

    # 3. Max file size
    # Use 'total_size' sent by the JS chunked uploader (actual file size).
    # Fall back to content_length only when total_size is absent (non-chunked).
    max_file_size_mb = rules.get('max_file_size_mb')
    raw_total_size = request.form.get('total_size')
    if raw_total_size:
        try:
            file_size_bytes = int(raw_total_size)
        except (ValueError, TypeError):
            file_size_bytes = request.content_length or 0
    else:
        file_size_bytes = request.content_length or 0
    if max_file_size_mb:
        try:
            max_bytes = float(max_file_size_mb) * 1024 * 1024
            if file_size_bytes > max_bytes:
                return False, 'Your file size exceeds the limit set by the administrator. Please contact the administrator.'
        except (ValueError, TypeError):
            pass

    # 4. Max folder size (for folder uploads)
    if folder_total_size:
        max_folder_size_mb = rules.get('max_folder_size_mb')
        if max_folder_size_mb:
            try:
                max_f_bytes = float(max_folder_size_mb) * 1024 * 1024
                if float(folder_total_size) > max_f_bytes:
                    return False, 'your file size is larger then the admin allow please contact the administrator..'
            except (ValueError, TypeError):
                pass

    return True, None
def hash_pw(pw: str) -> str:
    """Hash a password with PBKDF2-HMAC-SHA256 via Werkzeug.
    Returns a string like 'pbkdf2:sha256:260000$...' safe to store.
    """
    return generate_password_hash(pw)

def verify_pw(pw: str, stored_hash: str) -> bool:
    """Verify *pw* against *stored_hash*.
    Supports both new Werkzeug PBKDF2 hashes and legacy plain SHA-256 hex
    strings so existing accounts continue to work after the upgrade.
    """
    if not stored_hash:
        return False
    if ':' in stored_hash:          # Werkzeug format: 'pbkdf2:sha256:...'
        try:
            return _check_password_hash(stored_hash, pw)
        except Exception:
            return False
    # Legacy format: bare SHA-256 hex string
    return stored_hash == hashlib.sha256(pw.encode()).hexdigest()

class User(UserMixin):
    def __init__(self, uid, role='viewer'):
        self.id   = uid
        self.role = role

    @property
    def is_admin(self):  return self.role == 'admin'
    @property
    def is_editor(self): return self.role in ('admin', 'editor')

@login_manager.user_loader
def load_user(uid):
    u = load_json(USERS_FILE).get(uid)
    if u and u.get('active', True):
        return User(uid, u.get('role', 'viewer'))
    return None


# ═══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def is_safe_path(path, base_dir):
    return os.path.normcase(os.path.abspath(path)).startswith(
        os.path.normcase(os.path.abspath(base_dir)))

def trigger_temp_cleanup():
    """Clean up old temp zip files from CHUNKS_TMP_DIR in a daemon thread.
    Deletes files older than 4 hours.
    """
    def _do():
        try:
            if not os.path.exists(CHUNKS_TMP_DIR):
                return
            now = time.time()
            for filename in os.listdir(CHUNKS_TMP_DIR):
                file_path = os.path.join(CHUNKS_TMP_DIR, filename)
                if os.path.isfile(file_path):
                    # Check modification time
                    mtime = os.path.getmtime(file_path)
                    # 4 hours = 14400 seconds
                    if now - mtime > 14400:
                        os.unlink(file_path)
        except Exception:
            pass
    threading.Thread(target=_do, daemon=True).start()


def resolve_path(sub=''):
    """Resolve a sub-path relative to the upload root, or return None if unsafe."""
    target = os.path.abspath(os.path.join(_BASE_UPLOAD_DIR, sub)) if sub else _BASE_UPLOAD_DIR
    return target if is_safe_path(target, _BASE_UPLOAD_DIR) else None

def quota_key(sub): return sub.strip('/\\').replace('\\', '/') if sub else 'root'

def load_json(path):
    """Load a JSON file, returning {} on missing file or parse error."""
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}

def save_json(path, data):
    """Atomically write JSON: write to a .tmp file then os.replace() to avoid
    mid-write corruption if the process crashes during the write."""
    tmp = path + '.tmp'
    try:
        with open(tmp, 'w') as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
    except OSError as e:
        # Log disk-full / permission errors rather than silently swallowing them
        try:
            app.logger.error('save_json failed for %s: %s', path, e)
        except Exception:
            pass

# ── Per-request g-cache helpers ────────────────────────────────────────────────
# Many routes call load_users / load_acl / load_internal_shares / load_favorites
# multiple times in a single request.  Storing the result on flask.g eliminates
# redundant disk reads within the same HTTP request context.
def _g_load(attr, loader):
    """Return a value cached on flask.g; falls back to a fresh load when outside
    a request context (startup, CLI, background threads)."""
    try:
        if not hasattr(g, attr):
            setattr(g, attr, loader())
        return getattr(g, attr)
    except RuntimeError:          # No active request context
        return loader()

def _g_invalidate(attr):
    """Evict a cached entry from flask.g after a write so the next read is fresh."""
    try:
        if hasattr(g, attr):
            delattr(g, attr)
    except RuntimeError:
        pass

def load_quotas():  return load_json(QUOTA_FILE)
def save_quotas(q): save_json(QUOTA_FILE, q)
# g-cached: load_shares / load_vault are called by 10+ share routes per request.
# Caching on flask.g eliminates 2+ redundant disk reads per request.
def load_shares():  return _g_load('_shares', lambda: load_json(SHARE_FILE))
def save_shares(s): save_json(SHARE_FILE, s); _g_invalidate('_shares')
def load_favorites():        return _g_load('_favs',    lambda: load_json(FAVORITES_FILE))
def save_favorites(f):       save_json(FAVORITES_FILE, f); _g_invalidate('_favs')
def load_internal_shares():  return _g_load('_ishares', lambda: load_json(INTERNAL_SHARES_FILE))
def save_internal_shares(s): save_json(INTERNAL_SHARES_FILE, s); _g_invalidate('_ishares')
def load_comments():   return load_json(COMMENTS_FILE)
def save_comments(c):  save_json(COMMENTS_FILE, c)
def load_vault():   return _g_load('_vault',  lambda: load_json(VAULT_FILE))
def save_vault(v):  save_json(VAULT_FILE, v);  _g_invalidate('_vault')


# ── Folder-size cache (TTL = 5 s, eliminates repeated full-tree walks) ─────────
# The index page calls get_folder_size() once per sub-folder plus once for the
# current folder – O(N) calls on every page load.  Caching the result for a
# short window cuts CPU usage dramatically on large file stores.
_size_cache: dict = {}              # {abs_path: (total_bytes, expiry_monotonic)}
_size_cache_lock  = threading.Lock()
_SIZE_CACHE_TTL   = 5               # seconds

def get_folder_size(path: str) -> int:
    """Return total bytes under *path*, using a short-lived TTL cache.
    Thread-safe: cache lookup / write is guarded by _size_cache_lock;
    the expensive os.walk() runs outside the lock so other threads
    are not blocked during the traversal.
    """
    now = time.monotonic()
    with _size_cache_lock:
        entry = _size_cache.get(path)
        if entry and now < entry[1]:
            return entry[0]
    # Walk outside the lock – one extra walk per TTL window is acceptable
    total = 0
    try:
        for dp, _, fnames in os.walk(path):
            for f in fnames:
                try:
                    total += os.path.getsize(os.path.join(dp, f))
                except OSError:
                    pass
    except OSError:
        pass
    with _size_cache_lock:
        _size_cache[path] = (total, now + _SIZE_CACHE_TTL)
    return total

def invalidate_size_cache(path: str) -> None:
    """Evict *path* and any parent / child entries from the size cache so the
    next call triggers a fresh os.walk().
    Called after every mutation: upload, delete, move, copy, restore.
    """
    norm = os.path.abspath(path)
    with _size_cache_lock:
        to_delete = [
            k for k in _size_cache
            if k == norm
            or norm.startswith(k + os.sep)
            or k.startswith(norm + os.sep)
        ]
        for k in to_delete:
            _size_cache.pop(k, None)


def check_quota(sub, incoming_bytes):
    quotas = load_quotas()
    key    = quota_key(sub)
    if key not in quotas: return True, 0, None, None
    limit  = quotas[key]['quota_bytes']
    used   = get_folder_size(resolve_path(sub) or '')
    if used + incoming_bytes > limit:
        return False, used, limit, round(used / limit * 100, 1)
    return True, used, limit, round(used / limit * 100, 1)

# ── Activity log ──────────────────────────────────────────────────────────────
_log_lock = threading.Lock()   # Serialise log appends so concurrent requests
                               # never interleave partial JSON lines.

def log_activity(action, path, extra=''):
    user = 'system'
    try:
        user = current_user.id
    except Exception:
        pass
    line = json.dumps({
        'ts':     datetime.now().isoformat(timespec='seconds'),
        'user':   user,
        'action': action,
        'path':   path,
        'extra':  extra,
    }, ensure_ascii=True)
    try:
        with _log_lock:
            with open(ACTIVITY_FILE, 'a', encoding='utf-8') as f:
                f.write(line + '\n')
    except Exception:
        # Never let a log write failure crash the calling route
        # (e.g. PermissionError on Linux if the file is not writable)
        pass


def _tail_log(filepath, n):
    """Return the last *n* parsed JSON-line entries from an append-only log.
    Reads backward in 8 KB chunks so only the tail is loaded – never the full file.
    """
    if not os.path.exists(filepath):
        return []
    try:
        with open(filepath, 'rb') as f:
            f.seek(0, 2)
            size = f.tell()
            if size == 0:
                return []
            chunk_size = min(8192, size)
            buf   = b''
            pos   = size
            # Keep reading backward until we have at least n+1 newlines
            while pos > 0:
                pos = max(0, pos - chunk_size)
                f.seek(pos)
                buf = f.read(min(chunk_size, size - pos)) + buf
                if buf.count(b'\n') >= n + 1:
                    break
            raw_lines = buf.split(b'\n')
            if pos > 0:               # Drop the potentially partial leading line
                raw_lines = raw_lines[1:]
            result = []
            for line in raw_lines:
                line = line.strip()
                if line:
                    try:
                        result.append(json.loads(line))
                    except Exception:
                        pass
            return result[-n:]
    except Exception:
        return []

# ── Trash helpers ─────────────────────────────────────────────────────────────
def trash_dir():
    os.makedirs(TRASH_DIR, exist_ok=True)
    return TRASH_DIR

def trash_meta_path():
    return os.path.join(trash_dir(), '.meta.json')

def load_trash_meta():  return load_json(trash_meta_path())
def save_trash_meta(m): save_json(trash_meta_path(), m)

def sync_trash_meta():
    """Scan the .trash directory and ensure all files have an entry in .meta.json.
    If any untracked files are found, reconstruct their metadata.
    """
    td = trash_dir()
    meta = load_trash_meta()
    changed = False
    try:
        filenames = os.listdir(td)
    except Exception:
        return
    for fname in filenames:
        if fname == '.meta.json':
            continue
        if fname not in meta:
            ts = str(int(time.time()))
            original_name = fname
            if '__' in fname:
                parts = fname.split('__', 1)
                if parts[0].isdigit():
                    ts = parts[0]
                    original_name = parts[1]
            base = os.path.abspath(app.config['UPLOAD_FOLDER'])
            meta[fname] = {
                'original': os.path.join(base, original_name),
                'deleted_at': ts,
                'name': original_name,
                'is_dir': os.path.isdir(os.path.join(td, fname))
            }
            changed = True
    if changed:
        save_trash_meta(meta)

_TRASH_CLEANUP_INTERVAL  = 3600   # seconds – run at most once per hour
_TRASH_CLEANUP_STAMP     = os.path.join(DATA_DIR, '.trash_cleanup_ts')
_last_trash_cleanup_ts: float = 0.0   # in-process guard (zero disk I/O per request)

def cleanup_expired_trash():
    """Permanently delete trash items older than 30 days.
    Throttled by two layers:
      1. Module-level float (no disk I/O) – fastest, guards within a process.
      2. On-disk timestamp file – coordinates across separate processes / restarts.
    Runs at most once per _TRASH_CLEANUP_INTERVAL seconds.
    """
    global _last_trash_cleanup_ts
    try:
        now = time.time()
        # ── Fast in-process guard (no disk I/O) ───────────────────────────────
        if now - _last_trash_cleanup_ts < _TRASH_CLEANUP_INTERVAL:
            return
        # ── Cross-process guard via on-disk stamp ─────────────────────────────
        if os.path.exists(_TRASH_CLEANUP_STAMP):
            try:
                with open(_TRASH_CLEANUP_STAMP) as _f:
                    last_run = float(_f.read().strip())
                if now - last_run < _TRASH_CLEANUP_INTERVAL:
                    _last_trash_cleanup_ts = last_run   # sync in-process guard
                    return
            except Exception:
                pass   # Corrupt stamp → fall through and run anyway
        # Write the stamp before running so concurrent requests skip too
        with open(_TRASH_CLEANUP_STAMP, 'w') as _f:
            _f.write(str(now))
        _last_trash_cleanup_ts = now
        # ── Actual cleanup ────────────────────────────────────────────────────
        sync_trash_meta()
        meta = load_trash_meta()
        td = trash_dir()
        changed = False
        for trash_name, info in list(meta.items()):
            deleted_at = info.get('deleted_at')
            if deleted_at:
                try:
                    deleted_time = float(deleted_at)
                    # 30 days = 2 592 000 seconds
                    if now - deleted_time > 2592000:
                        src = os.path.join(td, trash_name)
                        if os.path.isdir(src):
                            shutil.rmtree(src)
                        elif os.path.exists(src):
                            os.remove(src)
                        del meta[trash_name]
                        changed = True
                        log_activity('trash_auto_purge', info.get('name', ''), '30-day policy')
                except Exception:
                    pass
        if changed:
            save_trash_meta(meta)
    except Exception:
        pass


# ── Default admin seed ────────────────────────────────────────────────────────
_DEFAULT_ADMIN_PW = 'admin123'

def _init_default_admin():
    """Create an admin account on first run if users.json doesn't exist yet.
    Prints a prominent warning — the default password MUST be changed.
    """
    if not os.path.exists(USERS_FILE):
        save_json(USERS_FILE, {'admin': {
            'password_hash': hash_pw(_DEFAULT_ADMIN_PW),
            'role':          'admin',
            'created_at':    datetime.now().isoformat(timespec='seconds'),
            'active':        True,
        }})
        print('\n' + '!' * 60, flush=True)
        print('  FileVault: First-run admin account created.', flush=True)
        print(f'  Username : admin', flush=True)
        print(f'  Password : {_DEFAULT_ADMIN_PW}', flush=True)
        print('  *** CHANGE THIS PASSWORD IMMEDIATELY AFTER LOGIN ***', flush=True)
        print('!' * 60 + '\n', flush=True)

_init_default_admin()

# ── Login brute-force protection ──────────────────────────────────────────────
# Simple in-process rate-limiter: max 10 failed attempts per username within a
# 15-minute window.  Resets automatically once the window expires.
# Note: this is per-process; use a shared store (Redis) in multi-worker prod.
_login_attempts: dict = {}     # {username: {'count': int, 'first_fail': float}}
_LOGIN_MAX_ATTEMPTS    = 10
_LOGIN_LOCKOUT_SECONDS = 900   # 15 minutes

def _is_login_locked(username: str) -> bool:
    now = time.time()
    e   = _login_attempts.get(username)
    if not e:
        return False
    if now - e['first_fail'] > _LOGIN_LOCKOUT_SECONDS:
        _login_attempts.pop(username, None)
        return False
    return e['count'] >= _LOGIN_MAX_ATTEMPTS

def _record_failed_login(username: str):
    now = time.time()
    e   = _login_attempts.get(username)
    if not e or now - e['first_fail'] > _LOGIN_LOCKOUT_SECONDS:
        _login_attempts[username] = {'count': 1, 'first_fail': now}
    else:
        e['count'] += 1

def _clear_login_attempts(username: str):
    _login_attempts.pop(username, None)


# ── CSRF Protection ───────────────────────────────────────────────────────────
def _get_csrf_token() -> str:
    """Return (lazily creating) a per-session CSRF token."""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

@app.before_request
def _csrf_protect():
    """Verify CSRF token on every state-changing request.
    Exemptions:
      - Non-mutating HTTP methods (GET, HEAD, OPTIONS)
      - Public share routes (authenticated by URL token, not session)
      - The /login endpoint (no session exists to piggyback yet)
    The token may be supplied as a hidden form field OR an X-CSRF-Token
    header (used by AJAX calls via the fetch() patcher in base.html).
    """
    if request.method not in ('POST', 'PUT', 'DELETE', 'PATCH') or app.config.get('TESTING'):
        return
    if request.path.startswith('/share/') or request.path.startswith('/share/upload/'):
        return          # Public share routes use token-based auth
    if request.endpoint == 'login':
        return
    submitted = (request.form.get('csrf_token')
                 or request.headers.get('X-CSRF-Token', ''))
    if not submitted or submitted != session.get('_csrf_token', ''):
        abort(403)

@app.template_global()
def csrf_token() -> str:
    """Jinja2 template global – renders the CSRF token for hidden form fields."""
    return _get_csrf_token()

# ── ACL / permission helpers ──────────────────────────────────────────────────
def check_internal_access(item_path, user, required_permission='viewer'):
    """Check if the user has internal share access to the path.
    required_permission can be 'viewer' or 'editor'.
    """
    if not hasattr(user, 'id'):
        return False
    if user.role == 'admin':
        return True

    shares = load_internal_shares()
    norm_path = item_path.replace('\\', '/').strip('/')
    parts = norm_path.split('/') if norm_path else []

    for depth in range(len(parts), -1, -1):
        key = '/'.join(parts[:depth]) if depth > 0 else 'root'
        if key in shares:
            for share in shares[key]:
                if share.get('user') == user.id:
                    perm = share.get('permission', 'viewer')
                    if required_permission == 'viewer':
                        return True
                    if required_permission == 'editor' and perm == 'editor':
                        return True
    return False

def check_folder_access(folder_path, user=None):
    """Return True if the user (default: current_user) can access folder_path."""
    try:
        u = user or current_user
    except Exception:
        return False
    if not hasattr(u, 'role') or u.role == 'admin':
        return True                         # Admins bypass all ACL

    # Check internal shares first, as it allows explicit delegation
    if check_internal_access(folder_path, u, 'viewer'):
        return True

    acl   = load_acl()
    parts = folder_path.replace('\\', '/').strip('/').split('/') \
            if folder_path and folder_path not in ('', '.') else []
    # Walk from most-specific to root; first matching entry wins
    for depth in range(len(parts), -1, -1):
        key = '/'.join(parts[:depth]) if depth > 0 else 'root'
        if key in acl:
            e = acl[key]
            return (u.id in e.get('allowed_users', [])) or \
                   (u.role in e.get('allowed_roles', []))
    return True   # No ACL set → accessible to everyone

def can_write(folder_path=''):
    """True if current user may upload / delete / rename in this folder."""
    try:
        u = current_user
    except Exception:
        return False
    if u.role == 'admin':
        return True
    if check_internal_access(folder_path, u, 'editor'):
        return True
    return check_folder_access(folder_path, u) and u.is_editor

def require_editor(folder_path=''):
    """Abort 403 unless current user can write to this folder."""
    if not can_write(folder_path):
        abort(403)

# ═══════════════════════════════════════════════════════════════════════════════
#  JINJA2 FILTERS
# ═══════════════════════════════════════════════════════════════════════════════

# ── Module-level constants for Jinja2 filters ────────────────────────────────
# Defined once at import time instead of being rebuilt on every template call.
_SIZE_UNITS = ('B', 'KB', 'MB', 'GB', 'TB', 'PB')
_FILEICON_MAP = {
    'pdf':'📕','doc':'📝','docx':'📝','xls':'📊','xlsx':'📊','ppt':'📊','pptx':'📊',
    'txt':'📄','csv':'📄','json':'📄','xml':'📄','md':'📄',
    'zip':'🗜','rar':'🗜','7z':'🗜','tar':'🗜','gz':'🗜',
    'mp4':'🎬','mkv':'🎬','avi':'🎬','mov':'🎬','mp3':'🎵','wav':'🎵','flac':'🎵',
    'png':'🖼','jpg':'🖼','jpeg':'🖼','gif':'🖼','svg':'🖼','webp':'🖼',
    'exe':'⚙️','msi':'⚙️','dmg':'⚙️','deb':'⚙️','rpm':'⚙️',
    'py':'🐍','js':'🟨','ts':'🟦','html':'🌐','css':'🎨','sql':'🗃','iso':'💿','sh':'🖥',
}
_PREVIEWABLE_EXT = frozenset({
    'png','jpg','jpeg','gif','svg','webp','bmp',
    'mp4','webm','mov','mp3','wav','ogg','flac',
    'pdf','txt','md','csv','json','xml','py','js','html','css','log',
})

# ── File-icon style maps – defined once at module level, not rebuilt per template call ──
_FILEICON_COLORS = {
    'word': '#2b579a',       # Blue
    'excel': '#107c41',      # Green
    'powerpoint': '#d83b01', # Orange-Red
    'onenote': '#80397b',    # Purple
    'pdf': '#ea4335',        # Red
    'archive': '#fbbc05',    # Yellow/Amber
    'image': '#4285f4',      # Photo Blue
    'video': '#ff5722',      # Orange-red
    'audio': '#00bcd4',      # Cyan
    'code': '#607d8b',       # Slate Gray
    'executable': '#455a64', # Blue Grey
    'database': '#009688',   # Teal
    'default': '#9aa0a6',    # Light Gray
}
_FILEICON_EXT_MAP = {
    'doc': ('word', 'W'),      'docx': ('word', 'W'),
    'xls': ('excel', 'X'),     'xlsx': ('excel', 'X'),
    'ppt': ('powerpoint', 'P'),'pptx': ('powerpoint', 'P'),
    'one': ('onenote', 'N'),   'pdf':  ('pdf', 'PDF'),
    'zip': ('archive', 'ZIP'), 'rar':  ('archive', 'RAR'), '7z': ('archive', '7Z'),
    'tar': ('archive', 'TAR'), 'gz':   ('archive', 'GZ'),
    'png': ('image', 'IMG'),   'jpg':  ('image', 'IMG'),  'jpeg': ('image', 'IMG'),
    'gif': ('image', 'IMG'),   'svg':  ('image', 'SVG'),  'webp': ('image', 'IMG'),
    'mp4': ('video', 'VID'),   'mkv':  ('video', 'VID'),  'avi':  ('video', 'VID'), 'mov': ('video', 'VID'),
    'mp3': ('audio', 'AUD'),   'wav':  ('audio', 'AUD'),  'flac': ('audio', 'AUD'),
    'py':  ('code', 'PY'),     'js':   ('code', 'JS'),    'ts':   ('code', 'TS'),
    'html':('code', 'HTML'),   'css':  ('code', 'CSS'),   'sql':  ('code', 'SQL'),
    'msi': ('executable', 'MSI'), 'exe': ('executable', 'EXE'), 'dll': ('executable', 'DLL'),
    'iso': ('database', 'ISO'),
}
# ── Extension sets for utilization() category breakdown – frozenset = O(1) lookup ──
_IMG_EXTS = frozenset({'.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.bmp'})
_VID_EXTS = frozenset({'.mp4', '.webm', '.mov', '.avi', '.mkv'})
_DOC_EXTS = frozenset({'.pdf', '.txt', '.md', '.csv', '.json', '.xml', '.doc', '.docx', '.xls', '.xlsx'})

@app.template_filter('filesizeformat')
def filesizeformat(value):
    try: value = int(value)
    except: return '0 B'
    for u in _SIZE_UNITS:
        if value < 1024: return f"{value:.1f} {u}" if u != 'B' else f"{value} B"
        value /= 1024
    return f"{value:.1f} EB"

@app.template_filter('datetimeformat')
def datetimeformat(value):
    try: return datetime.fromtimestamp(float(value)).strftime('%d %b %Y, %I:%M %p')
    except: return '—'

@app.template_filter('fileicon')
def fileicon(filename, size='1.2em'):
    """Return an inline SVG icon for the given filename, styled by file type.
    Uses module-level _FILEICON_COLORS / _FILEICON_EXT_MAP to avoid rebuilding
    dicts on every template call.
    """
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    cat, label = _FILEICON_EXT_MAP.get(ext, ('default', ext.upper()[:4]))
    color = _FILEICON_COLORS[cat]
    if cat == 'archive':
        svg = f'<svg class="file-icon-svg" viewBox="0 0 24 24" width="{size}" height="{size}" style="vertical-align: middle; fill: {color}; display: inline-block;"><path d="M20 6h-8l-2-2H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2zm-6 10h-4v-2h4v2zm0-3h-4v-2h4v2zm0-3h-4V8h4v2z"/></svg>'
    else:
        font_size = "7px" if len(label) > 1 else "10px"
        y_pos     = "16.5" if len(label) > 1 else "17"
        svg = (f'<svg class="file-icon-svg" viewBox="0 0 24 24" width="{size}" height="{size}"'
               f' style="vertical-align: middle; display: inline-block;">'
               f'<path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6z"'
               f' fill="{color}"/>'
               f'<path d="M14 2v6h6L14 2z" fill="#ffffff" opacity="0.3"/>'
               f'<text x="11" y="{y_pos}" fill="#ffffff"'
               f' font-family="-apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif"'
               f' font-weight="bold" font-size="{font_size}" text-anchor="middle">{label}</text></svg>')
    return Markup(svg)

@app.template_filter('previewable')
def previewable(filename):
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    return ext in _PREVIEWABLE_EXT

@app.template_filter('is_app_file')
def is_app_file(filename):
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    return ext in ('exe', 'msi', 'dll', 'lnk')



# ═══════════════════════════════════════════════════════════════════════════════
#  INDEX / FOLDER VIEW
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/', methods=['GET'])
@login_required
def index():
    cleanup_expired_trash()
    folder   = request.args.get('folder', '')
    safe_sub = os.path.normpath(folder) if folder else ''
    curr_abs = resolve_path(safe_sub)
    if not curr_abs:
        flash('Invalid folder path.', 'error')
        return redirect(url_for('index'))

    quotas = load_quotas()
    favs   = load_favorites().get(current_user.id, [])
    folder_names = []
    file_names   = []

    # os.scandir gives DirEntry objects with cached is_dir/is_file – 2-4x faster
    # than os.listdir + per-item os.path.isdir/isfile calls on large directories.
    try:
        with os.scandir(curr_abs) as it:
            for entry in it:
                if entry.name == '.trash' and not safe_sub:
                    continue  # Hide .trash at root level
                if entry.is_dir(follow_symlinks=False):
                    folder_names.append(entry.name)
                elif entry.is_file(follow_symlinks=False):
                    file_names.append(entry.name)
    except OSError:
        pass

    folders_meta = []
    for name in sorted(folder_names):
        sub_path = (safe_sub + '/' + name).strip('/') if safe_sub and safe_sub != '.' else name
        key   = quota_key(sub_path)
        q     = quotas.get(key)
        used  = get_folder_size(os.path.join(curr_abs, name))
        folders_meta.append({
            'name': name, 'sub_path': sub_path, 'used': used,
            'quota_bytes': q['quota_bytes'] if q else None,
            'has_quota':   q is not None,
            'starred':     sub_path.replace('\\', '/').strip('/') in favs,
        })

    file_meta = []
    for f in sorted(file_names):
        fp = os.path.join(curr_abs, f)
        dl = (safe_sub + '/' + f).strip('/') if safe_sub and safe_sub != '.' else f
        file_meta.append({
            'name': f, 'size': os.path.getsize(fp),
            'mtime': os.path.getmtime(fp), 'folder': safe_sub or '',
            'starred': dl.replace('\\', '/').strip('/') in favs,
        })

    # Quota for current folder
    ckey  = quota_key(safe_sub)
    cq    = quotas.get(ckey)
    cused = get_folder_size(curr_abs)
    quota_info = None
    if cq:
        lim = cq['quota_bytes']
        quota_info = {'limit': lim, 'used': cused,
                      'free': max(0, lim - cused),
                      'pct':  round(min(cused / lim * 100, 100), 1)}

    # Active share links for files in this folder
    shares = load_shares()
    shared_names = {v.get('rel_path', '').split('/')[-1]
                    for v in shares.values()
                    if v.get('rel_path') and v.get('rel_path', '').rsplit('/', 1)[0] == (safe_sub or '').replace('\\', '/')}

    return render_template('index.html',
        folders=folders_meta, files=file_meta,
        current_folder=safe_sub, current_user=current_user,
        quota_info=quota_info, curr_used=cused,
        shared_names=shared_names)

# ═══════════════════════════════════════════════════════════════════════════════
#  UPLOAD
# ═══════════════════════════════════════════════════════════════════════════════

def _assemble_chunks(file, chunk_index, total_chunks, chunk_offset, total_size, upload_id):
    """Write a chunk to a temp file and assemble when all chunks arrive.

    Returns (is_complete, assembled_tmp_path):
      - is_complete=False  → more chunks pending, assembled_tmp_path is None.
      - is_complete=True   → all chunks received, assembled_tmp_path is the
                             finished temp file that the caller must move/copy
                             to the final destination and then delete.
    """
    chunk_dir = os.path.join(CHUNKS_TMP_DIR, upload_id)
    os.makedirs(chunk_dir, exist_ok=True)

    # Write this chunk at the correct byte offset
    chunk_path = os.path.join(chunk_dir, f'chunk_{chunk_index:06d}')
    with open(chunk_path, 'wb') as cf:
        file.save(cf)

    # Count received chunks with a generator – avoids building an intermediate list
    received = sum(1 for f in os.listdir(chunk_dir) if f.startswith('chunk_'))

    if received < total_chunks:
        return False, None  # Still waiting for more chunks

    # All chunks present – assemble into a single temp file
    fd, assembled = tempfile.mkstemp(dir=CHUNKS_TMP_DIR, prefix='assembled_')
    try:
        with os.fdopen(fd, 'wb') as out:
            for i in range(total_chunks):
                part = os.path.join(chunk_dir, f'chunk_{i:06d}')
                with open(part, 'rb') as pf:
                    shutil.copyfileobj(pf, out)
    except Exception:
        os.unlink(assembled)
        shutil.rmtree(chunk_dir, ignore_errors=True)
        raise

    shutil.rmtree(chunk_dir, ignore_errors=True)
    return True, assembled


@app.route('/upload', methods=['POST'])
@login_required
def upload():
    target_sub = request.form.get('folder', '')
    safe_sub   = os.path.normpath(target_sub) if target_sub else ''
    require_editor(safe_sub)
    rel_path   = request.form.get('rel_path', '').strip()

    if rel_path and '/' in rel_path:
        rel_dir  = '/'.join(rel_path.split('/')[:-1])
        base_sub = (safe_sub + '/' + rel_dir).strip('/') if safe_sub else rel_dir
    else:
        base_sub = safe_sub

    dest_dir = resolve_path(base_sub)
    if not dest_dir:
        return _ajax_or_redirect({'status':'error','msg':'Invalid folder'}, safe_sub, 400)

    if 'file' not in request.files:
        return _ajax_or_redirect({'status':'error','msg':'No file'}, safe_sub, 400)

    file = request.files['file']
    if not file or file.filename == '':
        return _ajax_or_redirect({'status':'error','msg':'No file selected'}, safe_sub, 400)

    filename = rel_path.split('/')[-1] if rel_path else file.filename
    if not allowed_file(filename):
        return _ajax_or_redirect({'status':'error','msg':'File type not allowed'}, safe_sub, 400)

    # ── Chunked upload fields ───────────────────────────────────────────────
    try:
        chunk_index  = int(request.form.get('chunk_index', 0))
        total_chunks = int(request.form.get('total_chunks', 1))
        total_size   = int(request.form.get('total_size', 0))
    except (ValueError, TypeError):
        chunk_index, total_chunks, total_size = 0, 1, 0

    # ── Admin Upload Rules Validation (only on first chunk to avoid re-check) ──
    if chunk_index == 0:
        folder_total_size = request.form.get('folder_total_size')
        ok, err_msg = validate_upload_rules(file, filename, safe_sub, folder_total_size)
        if not ok:
            return _ajax_or_redirect({'status':'error','msg':err_msg}, safe_sub, 400)

        ok, used, lim, pct = check_quota(safe_sub, total_size or (request.content_length or 0))
        if not ok:
            msg = f'Quota exceeded: {filesizeformat(used)} of {filesizeformat(lim)} used.'
            return _ajax_or_redirect({'status':'error','msg':msg}, safe_sub, 400)

    if total_chunks <= 1:
        # ── Non-chunked / single-chunk upload – save directly ───────────────
        os.makedirs(dest_dir, exist_ok=True)
        dest_file = os.path.join(dest_dir, filename)
        _save_version(base_sub, filename, dest_file)
        file.save(dest_file)
        invalidate_size_cache(dest_dir)
        log_activity('upload', f"{base_sub}/{filename}".lstrip('/'))
        return _ajax_or_redirect({'status':'success','msg':f'"{filename}" uploaded.'}, safe_sub)

    # ── Multi-chunk upload: accumulate then assemble ─────────────────────────
    # Build a stable upload ID from user + destination + filename
    uid = hashlib.sha1(
        f"{current_user.id}:{base_sub}:{filename}".encode()
    ).hexdigest()

    try:
        is_complete, assembled_path = _assemble_chunks(
            file, chunk_index, total_chunks,
            int(request.form.get('chunk_offset', 0)),
            total_size, uid
        )
    except Exception as e:
        return _ajax_or_redirect({'status':'error','msg':f'Chunk assembly error: {e}'}, safe_sub, 500)

    if not is_complete:
        # Acknowledge chunk but keep going
        return jsonify({'status': 'chunk_success', 'chunk': chunk_index}), 200

    # All chunks assembled – move to final destination
    os.makedirs(dest_dir, exist_ok=True)
    dest_file = os.path.join(dest_dir, filename)
    try:
        _save_version(base_sub, filename, dest_file)
        shutil.move(assembled_path, dest_file)
    except Exception as e:
        try:
            os.unlink(assembled_path)
        except OSError:
            pass
        return _ajax_or_redirect({'status':'error','msg':f'Failed to save file: {e}'}, safe_sub, 500)

    invalidate_size_cache(dest_dir)
    log_activity('upload', f"{base_sub}/{filename}".lstrip('/'))
    return _ajax_or_redirect({'status':'success','msg':f'"{filename}" uploaded.'}, safe_sub)

@app.route('/upload_folder', methods=['POST'])
@login_required
def upload_folder_stub():
    dest = request.form.get('dest_folder', '')
    return redirect(url_for('index', folder=dest))

def _ajax_or_redirect(payload, sub, code=200):
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify(payload), code
    if payload.get('status') == 'success':
        flash(payload['msg'], 'success')
    else:
        flash(payload['msg'], 'error')
    return redirect(url_for('index', folder=sub or ''))

# ── File Versioning helper ────────────────────────────────────────────────────────
_MAX_VERSIONS = 10   # Maximum historical versions kept per file (oldest pruned first)

def _save_version(folder_sub, filename, abs_path):
    """Copy the current file into .versions/<rel_path>/ before it is overwritten.
    After saving, prunes versions beyond _MAX_VERSIONS (oldest removed first)
    to prevent unbounded disk consumption.
    """
    if not os.path.isfile(abs_path):
        return    # Nothing to version – it's a fresh upload
    rel = (folder_sub + '/' + filename).strip('/')
    ver_dir = os.path.join(VERSIONS_DIR, os.path.dirname(rel))
    os.makedirs(ver_dir, exist_ok=True)
    ts = str(int(time.time()))
    shutil.copy2(abs_path, os.path.join(ver_dir, f"{ts}__{filename}"))

    # ── Prune old versions ────────────────────────────────────────────────────
    try:
        suffix = f'__{filename}'
        ver_files = sorted(
            [vf for vf in os.listdir(ver_dir) if vf.endswith(suffix)],
            key=lambda vf: vf.split('__', 1)[0]   # ascending by timestamp prefix
        )
        for old_vf in ver_files[:-_MAX_VERSIONS]:
            try:
                os.remove(os.path.join(ver_dir, old_vf))
            except OSError:
                pass
    except OSError:
        pass

# ═══════════════════════════════════════════════════════════════════════════════
#  DOWNLOAD  /  PREVIEW
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/download/<path:filename>')
@login_required
def download(filename):
    base  = os.path.abspath(app.config['UPLOAD_FOLDER'])
    parts = filename.replace('\\', '/').split('/')
    directory = os.path.join(base, *parts[:-1]) if len(parts) > 1 else base
    fname     = parts[-1]
    if not is_safe_path(directory, base): abort(403)
    log_activity('download', filename)
    return send_from_directory(directory, fname, as_attachment=True)


# ═══════════════════════════════════════════════════════════════════════════════
#  UTILIZATION & ANALYTICS
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/utilization')
@login_required
def utilization():
    users_dict = load_users()
    total_users = len(users_dict)
    
    upload_folder = app.config['UPLOAD_FOLDER']
    total_folders = 0
    total_files = 0
    
    categories = {
        'Images': 0,
        'Videos': 0,
        'Documents': 0,
        'Others': 0
    }
    
    # Use module-level frozensets for O(1) category lookups
    for root, dirs, files in os.walk(upload_folder):
        # skip internal folders
        if '.trash' in root or '.versions' in root:
            continue

        total_folders += len(dirs)
        total_files += len(files)

        for file in files:
            filepath = os.path.join(root, file)
            if not os.path.islink(filepath):
                try:
                    size = os.path.getsize(filepath)
                    ext = os.path.splitext(file)[1].lower()
                    if ext in _IMG_EXTS:
                        categories['Images'] += size
                    elif ext in _VID_EXTS:
                        categories['Videos'] += size
                    elif ext in _DOC_EXTS:
                        categories['Documents'] += size
                    else:
                        categories['Others'] += size
                except Exception:
                    pass

    ok, used, lim, pct = check_quota('', 0)
    limit_bytes = lim if lim else 0
    
    # ── Activity Time-Series Aggregation ──
    activity_by_date = {}
    if os.path.exists(ACTIVITY_FILE):
        try:
            with open(ACTIVITY_FILE, 'r', encoding='utf-8') as f:
                for line in f:          # Stream line-by-line – avoids loading entire log into RAM
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        act = json.loads(line)
                        date_str = act.get('ts', '')[:10]
                        if date_str:
                            if date_str not in activity_by_date:
                                activity_by_date[date_str] = {'upload': 0, 'download': 0, 'other': 0}
                            action = act.get('action', '')
                            if action == 'upload':
                                activity_by_date[date_str]['upload'] += 1
                            elif action == 'download':
                                activity_by_date[date_str]['download'] += 1
                            else:
                                activity_by_date[date_str]['other'] += 1
                    except Exception:
                        pass
        except Exception:
            pass

    # Sort dates and take the last 7 days of activity
    sorted_dates = sorted(activity_by_date.keys())[-7:]
    chart_data = {
        'labels': sorted_dates,
        'uploads': [activity_by_date[d]['upload'] for d in sorted_dates],
        'downloads': [activity_by_date[d]['download'] for d in sorted_dates],
        'others': [activity_by_date[d]['other'] for d in sorted_dates]
    }
            
    return render_template('utilization.html', 
                           total_users=total_users, 
                           total_folders=total_folders, 
                           total_files=total_files,
                           used_bytes=used,
                           limit_bytes=limit_bytes,
                           pct=pct,
                           categories=categories,
                           chart_data=chart_data)


def _ico_to_png(ico_path, png_path):
    """Convert an .ico file to .png using Pillow so Linux browsers render it correctly.
    Returns True on success, False if Pillow is unavailable or conversion fails.
    """
    try:
        from PIL import Image
        with Image.open(ico_path) as img:
            # Pick the largest available size in the .ico container
            sizes = getattr(img, 'ico', None)
            if sizes:
                best = max(getattr(img, 'info', {}).get('sizes', [(32, 32)]))
                img.size = best
            img.save(png_path, 'PNG')
        return True
    except Exception:
        return False


def _extract_win32_icon(abs_path, icon_path):
    """Extract Windows-specific icon and save as PNG."""
    try:
        import ctypes
        from ctypes import wintypes
        from PIL import Image

        class SHFILEINFOW(ctypes.Structure):
            _fields_ = [
                ('hIcon', wintypes.HICON),
                ('iIcon', ctypes.c_int),
                ('dwAttributes', wintypes.DWORD),
                ('szDisplayName', wintypes.WCHAR * 260),
                ('szTypeName', wintypes.WCHAR * 80),
            ]

        shfi = SHFILEINFOW()
        res = ctypes.windll.shell32.SHGetFileInfoW(
            abs_path, 0, ctypes.byref(shfi), ctypes.sizeof(shfi), 0x000000100
        )
        if not res or not shfi.hIcon:
            return False

        hIcon = shfi.hIcon
        hdc_screen = ctypes.windll.user32.GetDC(0)
        hdc_mem = ctypes.windll.gdi32.CreateCompatibleDC(hdc_screen)
        hbmp = ctypes.windll.gdi32.CreateCompatibleBitmap(hdc_screen, 32, 32)
        ctypes.windll.gdi32.SelectObject(hdc_mem, hbmp)

        ctypes.windll.user32.DrawIconEx(hdc_mem, 0, 0, hIcon, 32, 32, 0, 0, 0x0003)

        class BITMAPINFOHEADER(ctypes.Structure):
            _fields_ = [
                ('biSize', wintypes.DWORD),
                ('biWidth', ctypes.c_long),
                ('biHeight', ctypes.c_long),
                ('biPlanes', wintypes.WORD),
                ('biBitCount', wintypes.WORD),
                ('biCompression', wintypes.DWORD),
                ('biSizeImage', wintypes.DWORD),
                ('biXPelsPerMeter', ctypes.c_long),
                ('biYPelsPerMeter', ctypes.c_long),
                ('biClrUsed', wintypes.DWORD),
                ('biClrImportant', wintypes.DWORD),
            ]

        bmi = BITMAPINFOHEADER()
        bmi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
        bmi.biWidth = 32
        bmi.biHeight = -32
        bmi.biPlanes = 1
        bmi.biBitCount = 32
        bmi.biCompression = 0

        buffer = ctypes.create_string_buffer(32 * 32 * 4)
        ctypes.windll.gdi32.GetDIBits(hdc_mem, hbmp, 0, 32, buffer, ctypes.byref(bmi), 0)

        ctypes.windll.gdi32.DeleteObject(hbmp)
        ctypes.windll.gdi32.DeleteDC(hdc_mem)
        ctypes.windll.user32.ReleaseDC(0, hdc_screen)
        ctypes.windll.user32.DestroyIcon(hIcon)

        img = Image.frombytes('RGBA', (32, 32), buffer.raw, 'raw', 'BGRA')
        img.save(icon_path, 'PNG')
        return True
    except Exception:
        return False


@app.route('/app_icon/<path:filename>')
@login_required
def get_app_icon(filename):
    """Extract and serve the icon embedded in an executable, installer, or library file.

    Strategy:
      Windows → Windows Shell API (SHGetFileInfoW) gives 100% accurate icons
                for ALL file types (exe, msi, dll, lnk ...).
      Linux   → icoextract (PE parser) for .exe and .dll; graceful 404 for
                msi/lnk (browser falls back to fileicon filter).
    """
    safe_sub = os.path.normpath(filename)
    if safe_sub.startswith('..') or os.path.isabs(safe_sub):
        abort(403)

    abs_path = resolve_path(safe_sub)
    if not abs_path or not os.path.exists(abs_path):
        abort(404)

    ext = abs_path.lower().rsplit('.', 1)[-1] if '.' in abs_path else ''
    if ext not in ('exe', 'msi', 'dll', 'lnk'):
        abort(404)

    # ── Icon cache directory ────────────────────────────────────────────────
    ICONS_DIR = os.path.join(DATA_DIR, '.icons')
    os.makedirs(ICONS_DIR, exist_ok=True)

    mtime     = os.path.getmtime(abs_path)
    hash_str  = hashlib.md5(f"{abs_path}_{mtime}".encode('utf-8')).hexdigest()
    png_path  = os.path.join(ICONS_DIR, f"{hash_str}.png")
    ico_path  = os.path.join(ICONS_DIR, f"{hash_str}.ico")

    # ── Serve from cache if already extracted ───────────────────────────────
    if os.path.exists(png_path):
        return send_file(png_path, mimetype='image/png')
    if os.path.exists(ico_path):
        return send_file(ico_path, mimetype='image/x-icon')

    # ── Windows: use Shell API (works for ALL file types) ──────────────────
    if sys.platform == 'win32':
        if _extract_win32_icon(abs_path, png_path) and os.path.exists(png_path):
            return send_file(png_path, mimetype='image/png')
        # Shell API failed -> fall through to icoextract below

    # ── Linux / fallback: icoextract handles PE binaries (exe + dll) ───────
    if ext in ('exe', 'dll'):
        try:
            from icoextract import IconExtractor
            extractor = IconExtractor(abs_path)
            try:
                extractor.export_icon(ico_path)
            finally:
                if hasattr(extractor, '_pe') and hasattr(extractor._pe, 'close'):
                    try: extractor._pe.close()
                    except Exception: pass

            if os.path.exists(ico_path):
                # Convert .ico -> .png so all Linux browsers render correctly.
                # (Some browsers on Linux have issues with multi-size .ico files.)
                if _ico_to_png(ico_path, png_path):
                    try: os.remove(ico_path)   # keep only the png
                    except OSError: pass
                    return send_file(png_path, mimetype='image/png')
                return send_file(ico_path, mimetype='image/x-icon')
        except Exception:
            pass

    # Nothing worked (msi/lnk on Linux, or exe with no icon resource)
    abort(404)


@app.route('/preview/<path:filename>')
@login_required
def preview(filename):
    """Stream file inline (not as attachment) for in-browser preview."""
    base  = os.path.abspath(app.config['UPLOAD_FOLDER'])
    parts = filename.replace('\\', '/').split('/')
    directory = os.path.join(base, *parts[:-1]) if len(parts) > 1 else base
    fname     = parts[-1]
    if not is_safe_path(directory, base): abort(403)
    return send_from_directory(directory, fname, as_attachment=False)

@app.route('/download_zip/<path:folder_path>')
@login_required
def download_zip(folder_path):
    """Stream an entire folder as a ZIP file.
    The ZIP is built to a named temp file first, then served with send_file.
    Cleanup is deferred to a background thread (4 hours delay) and general
    cleanup deletes files older than 4 hours, to support large/slow downloads.
    """
    trigger_temp_cleanup()
    target = resolve_path(folder_path)
    if not target or not os.path.isdir(target): abort(404)
    folder_name = os.path.basename(target)

    # Ensure the temp directory always exists (may be cleared after restart)
    os.makedirs(CHUNKS_TMP_DIR, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(suffix='.zip', dir=CHUNKS_TMP_DIR)
    try:
        with os.fdopen(fd, 'wb') as tmp:
            with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_STORED, allowZip64=True) as zf:
                for dirpath, _, filenames in os.walk(target):
                    for fname in filenames:
                        full = os.path.join(dirpath, fname)
                        arc  = os.path.relpath(full, target)
                        try:
                            zf.write(full, arc)
                        except OSError:
                            pass   # skip files that can't be read
    except Exception as e:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        app.logger.error('download_zip build failed: %s', e)
        abort(500)

    def _deferred_remove(path, delay=14400):
        """Delete *path* after *delay* seconds in a daemon thread.
        Using a delay (instead of @after_this_request) avoids the race where
        Gunicorn deletes the file before the WSGI iterator has finished sending
        its bytes to the client.
        """
        def _do():
            time.sleep(delay)
            try:
                os.unlink(path)
            except OSError:
                pass
        t = threading.Thread(target=_do, daemon=True)
        t.start()

    _deferred_remove(tmp_path)
    log_activity('zip_download', folder_path)
    return send_file(tmp_path,
                     mimetype='application/zip',
                     as_attachment=True,
                     download_name=f'{folder_name}.zip',
                     conditional=False)


# ═══════════════════════════════════════════════════════════════════════════════
#  BATCH DOWNLOAD (multiple files/folders → single ZIP)
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/batch_download', methods=['POST'])
@login_required
def batch_download():
    """Stream a ZIP containing multiple user-selected files and/or folders.
    Accepts both form POST (legacy) and XMLHttpRequest (AJAX) calls.
    """
    trigger_temp_cleanup()
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    paths_raw = request.form.get('paths', '')
    paths     = [p.strip() for p in paths_raw.split(',') if p.strip()]
    if not paths:
        if is_ajax:
            return jsonify({'status': 'error', 'msg': 'No files selected.'}), 400
        flash('No files selected.', 'error')
        return redirect(url_for('index'))

    base = os.path.abspath(app.config['UPLOAD_FOLDER'])
    valid_files   = []   # list of (arcname, abs_path) for individual files
    valid_folders = []   # list of (folder_name, abs_folder_path) for directories

    for rel in paths:
        # Normalise separators: always use the OS separator for os.path.join
        rel_norm = rel.replace('\\', '/').strip('/')
        abs_p = os.path.abspath(os.path.join(base, *rel_norm.split('/')))
        if not is_safe_path(abs_p, base):
            app.logger.warning('batch_download: unsafe path skipped: %s', rel)
            continue
        if os.path.isfile(abs_p):
            valid_files.append((os.path.basename(abs_p), abs_p))
        elif os.path.isdir(abs_p):
            valid_folders.append((os.path.basename(abs_p), abs_p))
        else:
            app.logger.warning('batch_download: path not found: %s -> %s', rel, abs_p)

    if not valid_files and not valid_folders:
        app.logger.warning('batch_download: no valid items from paths: %s', paths_raw)
        if is_ajax:
            return jsonify({'status': 'error', 'msg': 'No valid files or folders found.'}), 400
        flash('No valid files or folders found.', 'error')
        return redirect(url_for('index'))

    # Ensure the temp directory always exists (may be cleared after restart)
    os.makedirs(CHUNKS_TMP_DIR, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(suffix='.zip', dir=CHUNKS_TMP_DIR)
    try:
        with os.fdopen(fd, 'wb') as tmp:
            with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_STORED, allowZip64=True) as zf:
                # Add individual files
                for arcname, abs_p in valid_files:
                    try:
                        zf.write(abs_p, arcname)
                    except OSError:
                        pass   # skip unreadable files
                # Add folder contents (preserving sub-structure under folder name)
                for folder_name, abs_folder in valid_folders:
                    for dirpath, _, filenames in os.walk(abs_folder):
                        for fname in filenames:
                            full = os.path.join(dirpath, fname)
                            # Arc path: folder_name/relative/path/file
                            rel_to_parent = os.path.relpath(full, os.path.dirname(abs_folder))
                            try:
                                zf.write(full, rel_to_parent)
                            except OSError:
                                pass
    except Exception as e:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        app.logger.error('batch_download build failed: %s', e)
        if is_ajax:
            return jsonify({'status': 'error', 'msg': f'ZIP build failed: {e}'}), 500
        abort(500)

    def _deferred_remove(path, delay=14400):
        """Delete the temp ZIP after streaming completes (deferred cleanup)."""
        def _do():
            time.sleep(delay)
            try:
                os.unlink(path)
            except OSError:
                pass
        threading.Thread(target=_do, daemon=True).start()

    _deferred_remove(tmp_path)
    total = len(valid_files) + len(valid_folders)
    log_activity('batch_download', f'{total} items')
    return send_file(tmp_path,
                     mimetype='application/zip',
                     as_attachment=True,
                     download_name='FileVault_batch.zip',
                     conditional=False)

@app.route('/batch_delete', methods=['POST'])
@login_required
def batch_delete():
    """Move multiple selected files/folders to Trash in a single request to avoid race conditions."""
    paths_raw = request.form.get('paths', '')
    paths     = [p.strip() for p in paths_raw.split(',') if p.strip()]
    if not paths:
        return jsonify({'status': 'error', 'msg': 'No items selected.'}), 400

    base = os.path.abspath(app.config['UPLOAD_FOLDER'])
    td = trash_dir()
    ts = str(int(time.time()))
    meta = load_trash_meta()
    
    deleted_count = 0
    errors = []

    for rel in paths:
        rel_norm = rel.replace('\\', '/').strip('/')
        abs_p = os.path.abspath(os.path.join(base, *rel_norm.split('/')))
        if not is_safe_path(abs_p, base):
            errors.append(f"Unsafe path skipped: {rel}")
            continue

        folder_sub = '/'.join(rel_norm.split('/')[:-1])
        try:
            require_editor(folder_sub)
        except Exception:
            errors.append(f"Permission denied for: {rel}")
            continue

        if not os.path.exists(abs_p):
            errors.append(f"Not found: {rel}")
            continue

        fname = os.path.basename(abs_p)
        trash_name = f"{ts}__{fname}"
        
        # Ensure unique name in trash directory
        suffix = 1
        while os.path.exists(os.path.join(td, trash_name)):
            trash_name = f"{ts}_{suffix}__{fname}"
            suffix += 1

        try:
            shutil.move(abs_p, os.path.join(td, trash_name))
            invalidate_size_cache(os.path.dirname(abs_p))
            
            is_dir = os.path.isdir(os.path.join(td, trash_name))
            meta[trash_name] = {
                'original': abs_p,
                'deleted_at': ts,
                'name': fname,
                'is_dir': is_dir
            }
            deleted_count += 1
            log_activity('delete', rel)
        except Exception as e:
            errors.append(f"Failed to delete {rel}: {e}")

    save_trash_meta(meta)

    if deleted_count > 0:
        flash(f'Moved {deleted_count} item(s) to Trash.', 'success')
    if errors:
        for err in errors:
            flash(err, 'error')

    return jsonify({'status': 'success', 'deleted': deleted_count, 'errors': errors})

# ═══════════════════════════════════════════════════════════════════════════════
#  DELETE  (→ Trash)
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/delete/<path:filename>', methods=['POST'])
@login_required
def delete(filename):
    base  = os.path.abspath(app.config['UPLOAD_FOLDER'])
    parts = filename.replace('\\', '/').split('/')
    fpath = os.path.join(base, *parts)
    if not is_safe_path(fpath, base): abort(403)

    folder_sub = '/'.join(parts[:-1])
    require_editor(folder_sub)
    fname      = parts[-1]
    td         = trash_dir()
    ts         = str(int(time.time()))
    trash_name = f"{ts}__{fname}"

    try:
        shutil.move(fpath, os.path.join(td, trash_name))
        invalidate_size_cache(os.path.dirname(fpath))
        meta = load_trash_meta()
        meta[trash_name] = {'original': fpath, 'deleted_at': ts, 'name': fname}
        save_trash_meta(meta)
        log_activity('delete', filename)
        flash(f'"{fname}" moved to Trash.', 'success')
    except PermissionError as pe:
        log_activity('delete_error_permission', filename, str(pe))
        flash(f'Permission Denied: The web server user does not have write access to the trash folder. Please adjust permissions on your server (e.g., run "sudo chown -R www-data:www-data /home/admin/Documents/Softwares/.trash")', 'error')
    except Exception as e:
        flash(f'Error: {e}', 'error')
    return redirect(url_for('index', folder=folder_sub))

@app.route('/delete_folder/<path:folder_path>', methods=['POST'])
@login_required
def delete_folder(folder_path):
    require_editor(folder_path)
    target = resolve_path(folder_path)
    if not target: abort(403)
    parent = os.path.dirname(folder_path)
    fname  = os.path.basename(folder_path)
    td     = trash_dir()
    ts     = str(int(time.time()))
    trash_name = f"{ts}__{fname}"
    try:
        shutil.move(target, os.path.join(td, trash_name))
        invalidate_size_cache(os.path.dirname(target))
        meta = load_trash_meta()
        meta[trash_name] = {'original': target, 'deleted_at': ts, 'name': fname, 'is_dir': True}
        save_trash_meta(meta)

        # Remove quota entry if any
        q = load_quotas()
        k = quota_key(folder_path)
        if k in q: del q[k]; save_quotas(q)

        log_activity('delete_folder', folder_path)
        flash(f'Folder "{fname}" moved to Trash.', 'success')
    except PermissionError as pe:
        log_activity('delete_folder_error_permission', folder_path, str(pe))
        flash(f'Permission Denied: The web server user does not have write access to the trash folder. Please adjust permissions on your server.', 'error')
    except Exception as e:
        flash(f'Error: {e}', 'error')
    return redirect(url_for('index', folder=parent))

# ═══════════════════════════════════════════════════════════════════════════════
#  CREATE FOLDER
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/create_folder', methods=['POST'])
@login_required
def create_folder():
    name   = request.form.get('folder_name', '').strip()
    parent = request.form.get('parent_folder', '')
    visibility = request.form.get('visibility', 'public').strip()
    if not name:
        flash('Folder name is required.', 'error')
        return redirect(url_for('index'))
    safe   = os.path.basename(name)
    parent_safe = os.path.normpath(parent) if parent else ''
    require_editor(parent_safe)
    ppath  = resolve_path(parent_safe)
    if not ppath:
        flash('Invalid parent.', 'error')
        return redirect(url_for('index'))
    try:
        folder_rel_path = f"{parent}/{safe}".lstrip('/')
        os.makedirs(os.path.join(ppath, safe), exist_ok=False)
        log_activity('create_folder', folder_rel_path)
        flash(f'Folder "{safe}" created.', 'success')

        if visibility == 'private':
            acl = load_acl()
            acl[folder_rel_path] = {
                'allowed_users': [current_user.id],
                'allowed_roles': ['admin'],
                'updated_at': datetime.now().isoformat(timespec='seconds')
            }
            save_acl(acl)
            flash(f'Folder "{safe}" set to private.', 'success')
    except FileExistsError:
        flash('Folder already exists.', 'error')
    except Exception as e:
        flash(f'Error: {e}', 'error')
    return redirect(url_for('index', folder=parent))

# ═══════════════════════════════════════════════════════════════════════════════
#  RENAME
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/rename', methods=['POST'])
@login_required
def rename():
    old_rel  = request.form.get('old_path', '').strip()
    new_name = request.form.get('new_name', '').strip()
    is_ajax  = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    if not old_rel or not new_name:
        r = {'status':'error','msg':'Missing parameters'}
        return (jsonify(r), 400) if is_ajax else (flash(r['msg'],'error'), redirect(url_for('index')))

    # Enforce write access to the path's parent directory
    folder_sub = '/'.join(old_rel.replace('\\','/').split('/')[:-1])
    if not can_write(folder_sub):
        r = {'status':'error','msg':'Access denied'}
        return (jsonify(r), 403) if is_ajax else (flash(r['msg'],'error'), redirect(url_for('index')))

    safe_new = os.path.basename(new_name)
    old_abs  = resolve_path(old_rel)
    if not old_abs or not os.path.exists(old_abs):
        r = {'status':'error','msg':'Path not found'}
        return (jsonify(r), 404) if is_ajax else (flash(r['msg'],'error'), redirect(url_for('index')))

    new_abs = os.path.join(os.path.dirname(old_abs), safe_new)

    try:
        os.rename(old_abs, new_abs)
        log_activity('rename', old_rel, f'→ {safe_new}')
        r = {'status':'success','msg':f'Renamed to "{safe_new}"','new_name': safe_new}
        return jsonify(r) if is_ajax else (flash(r['msg'],'success'), redirect(url_for('index', folder=folder_sub)))
    except Exception as e:
        r = {'status':'error','msg':str(e)}
        return (jsonify(r), 500) if is_ajax else (flash(r['msg'],'error'), redirect(url_for('index', folder=folder_sub)))

# ═══════════════════════════════════════════════════════════════════════════════
#  MOVE / COPY
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/move', methods=['POST'])
@login_required
def move():
    src_rel  = request.form.get('src_path', '').strip()
    dest_rel = request.form.get('dest_folder', '').strip()

    # Enforce write permission on source parent and destination
    src_parent = '/'.join(src_rel.replace('\\','/').split('/')[:-1])
    require_editor(src_parent)
    require_editor(dest_rel)

    src_abs  = resolve_path(src_rel)
    dest_abs = resolve_path(dest_rel)

    if not src_abs or not os.path.exists(src_abs):
        flash('Source not found.', 'error')
        return redirect(url_for('index'))
    if not dest_abs:
        flash('Invalid destination.', 'error')
        return redirect(url_for('index'))

    os.makedirs(dest_abs, exist_ok=True)
    fname = os.path.basename(src_abs)
    try:
        shutil.move(src_abs, os.path.join(dest_abs, fname))
        invalidate_size_cache(os.path.dirname(src_abs))
        invalidate_size_cache(dest_abs)
        log_activity('move', src_rel, f'→ {dest_rel}')
        flash(f'"{fname}" moved to "{dest_rel or "Root"}".', 'success')
    except Exception as e:
        flash(f'Error moving: {e}', 'error')
    return redirect(url_for('index', folder=dest_rel))   # Bug fix: was missing return

@app.route('/copy', methods=['POST'])
@login_required
def copy():
    src_rel  = request.form.get('src_path', '').strip()
    dest_rel = request.form.get('dest_folder', '').strip()

    # Enforce read access to source, and write permission on destination
    if not check_folder_access(src_rel):
        abort(403)
    require_editor(dest_rel)

    src_abs  = resolve_path(src_rel)
    dest_abs = resolve_path(dest_rel)

    if not src_abs or not os.path.exists(src_abs):
        flash('Source not found.', 'error')
        return redirect(url_for('index'))
    if not dest_abs:
        flash('Invalid destination.', 'error')
        return redirect(url_for('index'))

    os.makedirs(dest_abs, exist_ok=True)
    fname = os.path.basename(src_abs)
    try:
        if os.path.isdir(src_abs):
            shutil.copytree(src_abs, os.path.join(dest_abs, fname))
        else:
            shutil.copy2(src_abs, os.path.join(dest_abs, fname))
        invalidate_size_cache(dest_abs)
        log_activity('copy', src_rel, f'→ {dest_rel}')
        flash(f'"{fname}" copied to "{dest_rel or "Root"}".', 'success')
    except Exception as e:
        flash(f'Error copying: {e}', 'error')

    return redirect(url_for('index', folder=dest_rel))

# ═══════════════════════════════════════════════════════════════════════════════
#  GLOBAL SEARCH
# ═══════════════════════════════════════════════════════════════════════════════

_SEARCH_MAX_RESULTS = 500   # Cap to prevent huge result sets on large file stores

@app.route('/search')
@login_required
def search():
    q = request.args.get('q', '').strip().lower()
    results = []
    if q:
        base = os.path.abspath(app.config['UPLOAD_FOLDER'])
        for dp, dirs, files in os.walk(base):
            # Skip hidden / system directories (both trash and version store)
            dirs[:] = [d for d in dirs if d not in ('.trash', '.versions')]
            for name in dirs + files:
                if q in name.lower():
                    abs_path = os.path.join(dp, name)
                    rel      = os.path.relpath(abs_path, base).replace('\\', '/')
                    is_dir   = os.path.isdir(abs_path)
                    results.append({
                        'name':   name,
                        'rel':    rel,
                        'folder': os.path.dirname(rel),
                        'is_dir': is_dir,
                        'size':   0 if is_dir else os.path.getsize(abs_path),
                        'mtime':  os.path.getmtime(abs_path),
                    })
                    if len(results) >= _SEARCH_MAX_RESULTS:
                        break
            if len(results) >= _SEARCH_MAX_RESULTS:
                break
    return render_template('search.html', query=q, results=results,
                           current_user=current_user)

# ═══════════════════════════════════════════════════════════════════════════════
#  SHARE LINKS  (file download  +  folder upload)
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/share/create', methods=['POST'])
@login_required
def share_create():
    rel_path = request.form.get('rel_path', '').strip()
    expiry_h = request.form.get('expiry_hours', '').strip()
    password = request.form.get('password', '').strip()
    shared_username = request.form.get('shared_username', '').strip()
    permissions = request.form.get('permissions', 'read').strip()

    if not rel_path:
        flash('No file specified for sharing.', 'error')
        return redirect(url_for('index'))

    token   = secrets.token_urlsafe(20)
    shares  = load_shares()
    entry   = {
        'rel_path':   rel_path,
        'created_at': datetime.now().isoformat(timespec='seconds'),
        'created_by': current_user.id,
        'expires_at': (datetime.now() + timedelta(hours=float(expiry_h))).isoformat(timespec='seconds')
                       if expiry_h else None,
        'permissions': permissions,
    }
    shares[token] = entry
    save_shares(shares)

    # Save credentials securely to the vault
    if password or shared_username:
        vault = load_vault()
        vault[token] = {
            'username': shared_username if shared_username else None,
            'password_hash': hashlib.sha256(password.encode()).hexdigest() if password else None,
        }
        save_vault(vault)

    log_activity('share_create', rel_path, f'token={token[:8]}… perm={permissions}')

    # Build the public share link.
    # Priority: APP_BASE_URL env var → current request host (fallback)
    if _APP_BASE_URL:
        link = f"{_APP_BASE_URL}{url_for('share_download', token=token)}"
    else:
        link = url_for('share_download', token=token, _external=True)

    flash(f'Share link created: {link}', 'success')
    folder_sub = '/'.join(rel_path.replace('\\','/').split('/')[:-1])
    return redirect(url_for('index', folder=folder_sub))

@app.route('/share/<token>', methods=['GET', 'POST'])
def share_download(token):
    """Public download/view page – no login required."""
    shares = load_shares()
    entry  = shares.get(token)
    if not entry:
        abort(404)

    # Expiry check
    if entry.get('expires_at'):
        if datetime.now() > datetime.fromisoformat(entry['expires_at']):
            flash('This share link has expired.', 'error')
            return render_template('share_expired.html'), 410

    # Credentials (Vault check)
    vault = load_vault()
    vault_entry = vault.get(token, {})
    shared_username = vault_entry.get('username')
    password_hash = vault_entry.get('password_hash') or entry.get('password_hash')

    if shared_username or password_hash:
        if request.method == 'POST':
            req_username = request.form.get('username', '').strip()
            req_password = request.form.get('password', '')

            username_ok = True
            password_ok = True

            if shared_username and req_username != shared_username:
                username_ok = False
            if password_hash and hashlib.sha256(req_password.encode()).hexdigest() != password_hash:
                password_ok = False

            if not username_ok or not password_ok:
                flash('Incorrect credentials.', 'error')
                return render_template('share_password.html', token=token, has_username=bool(shared_username))

            session[f'share_authed_{token}'] = True
        else:
            if not session.get(f'share_authed_{token}'):
                return render_template('share_password.html', token=token, has_username=bool(shared_username))

    # Serve the file or view the folder
    rel_path = entry['rel_path']
    base     = os.path.abspath(app.config['UPLOAD_FOLDER'])
    shared_root_abs = os.path.abspath(os.path.join(base, rel_path.replace('/', os.sep)))
    if not is_safe_path(shared_root_abs, base): abort(403)

    perms = entry.get('permissions', 'read')

    if os.path.isdir(shared_root_abs):
        # Enforce download-only behavior: immediately download entire ZIP
        if perms == 'download':
            return redirect(url_for('share_folder_zip_download', token=token))

        subpath = request.args.get('path', '').strip().replace('\\', '/')
        if subpath:
            target_abs = os.path.abspath(os.path.join(shared_root_abs, subpath.replace('/', os.sep)))
            if not is_safe_path(target_abs, shared_root_abs): abort(403)
        else:
            target_abs = shared_root_abs

        if not os.path.isdir(target_abs):
            abort(404)

        try:
            items = os.listdir(target_abs)
        except Exception:
            items = []

        files = []
        for name in sorted(items):
            if name in ('.trash', '.versions'):
                continue
            item_path = os.path.join(target_abs, name)
            is_dir = os.path.isdir(item_path)
            item_subpath = os.path.relpath(item_path, shared_root_abs).replace('\\', '/')
            files.append({
                'name': name,
                'is_dir': is_dir,
                'size': 0 if is_dir else os.path.getsize(item_path),
                'mtime': os.path.getmtime(item_path),
                'subpath': item_subpath
            })

        log_activity('share_folder_view', rel_path, f'token={token[:8]}… path={subpath}')
        return render_template('folder_share_view.html',
                               token=token,
                               folder_name=os.path.basename(shared_root_abs) or 'Shared Folder',
                               files=files,
                               rel_path=rel_path,
                               subpath=subpath,
                               permissions=perms)
    else:
        parts    = rel_path.replace('\\', '/').split('/')
        directory = os.path.join(base, *parts[:-1]) if len(parts) > 1 else base
        fname     = parts[-1]
        if perms == 'read':
            log_activity('share_preview', rel_path, f'token={token[:8]}…')
            return send_from_directory(directory, fname, as_attachment=False)
        log_activity('share_download', rel_path, f'token={token[:8]}…')
        return send_from_directory(directory, fname, as_attachment=True)


@app.route('/share/<token>/preview', methods=['GET'])
def share_file_preview(token):
    """Preview a shared file if the user has read permissions."""
    shares = load_shares()
    entry  = shares.get(token)
    if not entry:
        abort(404)
    vault = load_vault()
    vault_entry = vault.get(token, {})
    if (vault_entry.get('username') or vault_entry.get('password_hash') or entry.get('password_hash')) and not session.get(f'share_authed_{token}'):
        abort(403)

    rel_path = entry['rel_path']
    base     = os.path.abspath(app.config['UPLOAD_FOLDER'])
    target_abs = os.path.abspath(os.path.join(base, rel_path.replace('/', os.sep)))
    if not is_safe_path(target_abs, base) or os.path.isdir(target_abs):
        abort(403)

    parts    = rel_path.replace('\\', '/').split('/')
    directory = os.path.join(base, *parts[:-1]) if len(parts) > 1 else base
    fname     = parts[-1]
    return send_from_directory(directory, fname, as_attachment=False)


@app.route('/share/<token>/download/<path:subpath>', methods=['GET'])
def share_folder_file_download(token, subpath):
    """Download a file from within a shared folder."""
    shares = load_shares()
    entry  = shares.get(token)
    if not entry:
        abort(404)
    if entry.get('expires_at') and datetime.now() > datetime.fromisoformat(entry['expires_at']):
        abort(410)

    # Vault check
    vault = load_vault()
    vault_entry = vault.get(token, {})
    if (vault_entry.get('username') or vault_entry.get('password_hash') or entry.get('password_hash')) and not session.get(f'share_authed_{token}'):
        abort(403)

    perms = entry.get('permissions', 'read')
    if perms == 'read':
        abort(403)

    rel_path = entry['rel_path']
    base     = os.path.abspath(app.config['UPLOAD_FOLDER'])
    shared_root_abs = os.path.abspath(os.path.join(base, rel_path.replace('/', os.sep)))
    if not is_safe_path(shared_root_abs, base) or not os.path.isdir(shared_root_abs):
        abort(403)

    file_path = os.path.abspath(os.path.join(shared_root_abs, subpath.replace('/', os.sep)))
    if not is_safe_path(file_path, shared_root_abs):
        abort(403)

    if not os.path.isfile(file_path):
        abort(404)

    return send_file(file_path, as_attachment=True, download_name=os.path.basename(file_path))


@app.route('/share/<token>/preview/<path:subpath>', methods=['GET'])
def share_folder_file_preview(token, subpath):
    """Preview a file from within a shared folder inline (not as attachment)."""
    shares = load_shares()
    entry  = shares.get(token)
    if not entry:
        abort(404)
    if entry.get('expires_at') and datetime.now() > datetime.fromisoformat(entry['expires_at']):
        abort(410)

    # Vault check
    vault = load_vault()
    vault_entry = vault.get(token, {})
    if (vault_entry.get('username') or vault_entry.get('password_hash') or entry.get('password_hash')) and not session.get(f'share_authed_{token}'):
        abort(403)

    rel_path = entry['rel_path']
    base     = os.path.abspath(app.config['UPLOAD_FOLDER'])
    shared_root_abs = os.path.abspath(os.path.join(base, rel_path.replace('/', os.sep)))
    if not is_safe_path(shared_root_abs, base) or not os.path.isdir(shared_root_abs):
        abort(403)

    file_path = os.path.abspath(os.path.join(shared_root_abs, subpath.replace('/', os.sep)))
    if not is_safe_path(file_path, shared_root_abs):
        abort(403)

    if not os.path.isfile(file_path):
        abort(404)

    return send_file(file_path, as_attachment=False)


@app.route('/share/<token>/download_zip', methods=['GET'])
def share_folder_zip_download(token):
    """Download the entire shared folder or a subfolder as a ZIP file.
    Uses tempfile.TemporaryFile() (always disk-backed) to keep RAM flat
    regardless of archive size.
    """
    trigger_temp_cleanup()
    shares = load_shares()
    entry  = shares.get(token)
    if not entry:
        abort(404)
    if entry.get('expires_at') and datetime.now() > datetime.fromisoformat(entry['expires_at']):
        abort(410)

    # Vault check
    vault = load_vault()
    vault_entry = vault.get(token, {})
    if (vault_entry.get('username') or vault_entry.get('password_hash') or entry.get('password_hash')) and not session.get(f'share_authed_{token}'):
        abort(403)

    perms = entry.get('permissions', 'read')
    if perms == 'read':
        abort(403)

    rel_path = entry['rel_path']
    base     = os.path.abspath(app.config['UPLOAD_FOLDER'])
    shared_root_abs = os.path.abspath(os.path.join(base, rel_path.replace('/', os.sep)))
    if not is_safe_path(shared_root_abs, base) or not os.path.isdir(shared_root_abs):
        abort(403)

    subpath = request.args.get('path', '').strip().replace('\\', '/')
    if subpath:
        target_abs = os.path.abspath(os.path.join(shared_root_abs, subpath.replace('/', os.sep)))
        if not is_safe_path(target_abs, shared_root_abs): abort(403)
    else:
        target_abs = shared_root_abs

    if not os.path.isdir(target_abs):
        abort(404)

    folder_name = os.path.basename(target_abs) or 'Shared Folder'

    # Named temp file approach — Linux-safe (no anonymous TemporaryFile in generator).
    fd, tmp_path = tempfile.mkstemp(suffix='.zip', dir=CHUNKS_TMP_DIR)
    try:
        with os.fdopen(fd, 'wb') as tmp:
            with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_STORED, allowZip64=True) as zf:
                for dirpath, _, filenames in os.walk(target_abs):
                    for fname in filenames:
                        full = os.path.join(dirpath, fname)
                        arc  = os.path.relpath(full, target_abs)
                        try:
                            zf.write(full, arc)
                        except OSError:
                            pass   # skip unreadable files
    except Exception as e:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        app.logger.error('share_folder_zip_download build failed: %s', e)
        abort(500)

    def _deferred_remove(path, delay=14400):
        def _do():
            time.sleep(delay)
            try: os.unlink(path)
            except OSError: pass
        threading.Thread(target=_do, daemon=True).start()

    _deferred_remove(tmp_path)
    log_activity('share_folder_zip_download', rel_path, f'token={token[:8]}… path={subpath}')
    return send_file(tmp_path,
                     mimetype='application/zip',
                     as_attachment=True,
                     download_name=f'{folder_name}.zip',
                     conditional=False)


@app.route('/share/<token>/batch_download', methods=['POST'])
def share_folder_batch_download(token):
    """Batch-download selected files from a shared folder as a single ZIP.
    Requires the share to have a permission other than 'read'.
    """
    trigger_temp_cleanup()
    shares = load_shares()
    entry  = shares.get(token)
    if not entry:
        abort(404)
    if entry.get('expires_at') and datetime.now() > datetime.fromisoformat(entry['expires_at']):
        abort(410)

    # Vault / credentials check
    vault = load_vault()
    vault_entry = vault.get(token, {})
    if (vault_entry.get('username') or vault_entry.get('password_hash') or entry.get('password_hash')) \
            and not session.get(f'share_authed_{token}'):
        abort(403)

    perms = entry.get('permissions', 'read')
    if perms == 'read':
        abort(403)   # read-only shares cannot download files

    rel_path = entry['rel_path']
    base     = os.path.abspath(app.config['UPLOAD_FOLDER'])
    shared_root_abs = os.path.abspath(os.path.join(base, rel_path.replace('/', os.sep)))
    if not is_safe_path(shared_root_abs, base) or not os.path.isdir(shared_root_abs):
        abort(403)

    paths_raw = request.form.get('paths', '')
    paths     = [p.strip() for p in paths_raw.split(',') if p.strip()]
    if not paths:
        abort(400)

    valid = []
    for sub in paths:
        abs_p = os.path.abspath(os.path.join(shared_root_abs, sub.replace('/', os.sep)))
        if is_safe_path(abs_p, shared_root_abs) and os.path.isfile(abs_p):
            valid.append((sub, abs_p))

    if not valid:
        abort(400)

    # Named temp file approach — Linux-safe.
    fd, tmp_path = tempfile.mkstemp(suffix='.zip', dir=CHUNKS_TMP_DIR)
    try:
        with os.fdopen(fd, 'wb') as tmp:
            with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_STORED, allowZip64=True) as zf:
                for sub, abs_p in valid:
                    try:
                        zf.write(abs_p, os.path.basename(abs_p))
                    except OSError:
                        pass   # skip unreadable files
    except Exception as e:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        app.logger.error('share_folder_batch_download build failed: %s', e)
        abort(500)

    def _deferred_remove(path, delay=14400):
        def _do():
            time.sleep(delay)
            try: os.unlink(path)
            except OSError: pass
        threading.Thread(target=_do, daemon=True).start()

    _deferred_remove(tmp_path)
    log_activity('share_folder_batch_download', rel_path, f'token={token[:8]}… files={len(valid)}')
    return send_file(tmp_path,
                     mimetype='application/zip',
                     as_attachment=True,
                     download_name='shared_files.zip',
                     conditional=False)


@app.route('/share/<token>/upload', methods=['POST'])
def share_folder_upload(token):
    """Collaborative upload inside shared folder."""
    shares = load_shares()
    entry  = shares.get(token)
    if not entry: abort(404)
    if entry.get('expires_at') and datetime.now() > datetime.fromisoformat(entry['expires_at']):
        abort(410)

    vault = load_vault()
    vault_entry = vault.get(token, {})
    if (vault_entry.get('username') or vault_entry.get('password_hash') or entry.get('password_hash')) and not session.get(f'share_authed_{token}'):
        abort(403)

    perms = entry.get('permissions', 'read')
    if perms not in ('upload_read_download', 'full'):
        abort(403)

    rel_path = entry['rel_path']
    base     = os.path.abspath(app.config['UPLOAD_FOLDER'])
    shared_root_abs = os.path.abspath(os.path.join(base, rel_path.replace('/', os.sep)))
    if not is_safe_path(shared_root_abs, base) or not os.path.isdir(shared_root_abs):
        abort(403)

    subpath = request.form.get('subpath', '').strip().replace('\\', '/')
    rel_path_form = request.form.get('rel_path', '').strip()
    
    if rel_path_form and '/' in rel_path_form:
        rel_dir = '/'.join(rel_path_form.split('/')[:-1])
        dest_subpath = (subpath + '/' + rel_dir).strip('/') if subpath else rel_dir
    else:
        dest_subpath = subpath

    if dest_subpath:
        dest_abs = os.path.abspath(os.path.join(shared_root_abs, dest_subpath.replace('/', os.sep)))
        if not is_safe_path(dest_abs, shared_root_abs): abort(403)
    else:
        dest_abs = shared_root_abs

    if 'file' not in request.files:
        return jsonify({'status': 'error', 'msg': 'No file'}), 400

    file = request.files['file']
    filename = rel_path_form.split('/')[-1] if rel_path_form else file.filename
    if not filename:
        return jsonify({'status': 'error', 'msg': 'No file selected'}), 400

    if not allowed_file(filename):
        return jsonify({'status': 'error', 'msg': 'File type not allowed'}), 400

    # Check upload rules
    target_folder = (rel_path + '/' + dest_subpath).strip('/') if dest_subpath else rel_path
    folder_total_size = request.form.get('folder_total_size')
    ok, err_msg = validate_upload_rules(file, filename, target_folder, folder_total_size)
    if not ok:
        return jsonify({'status': 'error', 'msg': err_msg}), 400

    # Check quota using actual file size (total_size) not HTTP content-length
    try:
        file_total_size = int(request.form.get('total_size', 0))
    except (ValueError, TypeError):
        file_total_size = request.content_length or 0
    ok, used, lim, _ = check_quota(rel_path, file_total_size)
    if not ok:
        return jsonify({'status': 'error', 'msg': f'Quota exceeded: {filesizeformat(used)} / {filesizeformat(lim)}'}), 400

    # ── Chunked upload assembly ─────────────────────────────────────────────
    try:
        chunk_index  = int(request.form.get('chunk_index', 0))
        total_chunks = int(request.form.get('total_chunks', 1))
    except (ValueError, TypeError):
        chunk_index = 0; total_chunks = 1

    os.makedirs(dest_abs, exist_ok=True)
    dest_file_path = os.path.join(dest_abs, filename)

    if total_chunks <= 1:
        file.save(dest_file_path)
    else:
        uid = hashlib.sha1(
            f"share:{token}:{filename}:{rel_path_form}".encode()
        ).hexdigest()
        try:
            is_complete, assembled_path = _assemble_chunks(
                file, chunk_index, total_chunks,
                int(request.form.get('chunk_offset', 0)),
                file_total_size, uid
            )
        except Exception as e:
            return jsonify({'status': 'error', 'msg': f'Chunk error: {e}'}), 500
        if not is_complete:
            return jsonify({'status': 'chunk_success', 'chunk': chunk_index}), 200
        try:
            shutil.move(assembled_path, dest_file_path)
        except Exception as e:
            try: os.unlink(assembled_path)
            except OSError: pass
            return jsonify({'status': 'error', 'msg': f'Failed to save file: {e}'}), 500

    invalidate_size_cache(dest_abs)
    log_activity('share_upload', f"{rel_path}/{dest_subpath}/{filename}".replace('//', '/'), f'token={token[:8]}…')
    return jsonify({'status': 'success', 'msg': f'"{filename}" uploaded successfully.'})


@app.route('/share/<token>/create_folder', methods=['POST'])
def share_folder_create_dir(token):
    """Collaborative folder creation inside shared folder."""
    shares = load_shares()
    entry  = shares.get(token)
    if not entry or entry.get('permissions', 'read') != 'full':
        abort(403)

    vault = load_vault()
    vault_entry = vault.get(token, {})
    if (vault_entry.get('username') or vault_entry.get('password_hash') or entry.get('password_hash')) and not session.get(f'share_authed_{token}'):
        abort(403)

    rel_path = entry['rel_path']
    base     = os.path.abspath(app.config['UPLOAD_FOLDER'])
    shared_root_abs = os.path.abspath(os.path.join(base, rel_path.replace('/', os.sep)))
    if not is_safe_path(shared_root_abs, base) or not os.path.isdir(shared_root_abs):
        abort(403)

    name = request.form.get('folder_name', '').strip()
    subpath = request.form.get('subpath', '').strip().replace('\\', '/')
    if not name:
        flash('Folder name is required.', 'error')
        return redirect(url_for('share_download', token=token, path=subpath))

    safe_name = os.path.basename(name)
    if subpath:
        parent_abs = os.path.abspath(os.path.join(shared_root_abs, subpath.replace('/', os.sep)))
        if not is_safe_path(parent_abs, shared_root_abs): abort(403)
    else:
        parent_abs = shared_root_abs

    try:
        os.makedirs(os.path.join(parent_abs, safe_name), exist_ok=False)
        log_activity('share_create_folder', f"{rel_path}/{subpath}/{safe_name}".replace('//', '/'), f'token={token[:8]}…')
        flash(f'Folder "{safe_name}" created.', 'success')
    except Exception as e:
        flash(f'Error: {e}', 'error')

    return redirect(url_for('share_download', token=token, path=subpath))


@app.route('/share/<token>/delete/<path:item_subpath>', methods=['POST'])
def share_folder_delete(token, item_subpath):
    """Collaborative delete inside shared folder."""
    shares = load_shares()
    entry  = shares.get(token)
    if not entry or entry.get('permissions', 'read') != 'full':
        abort(403)

    vault = load_vault()
    vault_entry = vault.get(token, {})
    if (vault_entry.get('username') or vault_entry.get('password_hash') or entry.get('password_hash')) and not session.get(f'share_authed_{token}'):
        abort(403)

    rel_path = entry['rel_path']
    base     = os.path.abspath(app.config['UPLOAD_FOLDER'])
    shared_root_abs = os.path.abspath(os.path.join(base, rel_path.replace('/', os.sep)))
    if not is_safe_path(shared_root_abs, base) or not os.path.isdir(shared_root_abs):
        abort(403)

    target_abs = os.path.abspath(os.path.join(shared_root_abs, item_subpath.replace('/', os.sep)))
    if not is_safe_path(target_abs, shared_root_abs):
        abort(403)

    parent_sub = '/'.join(item_subpath.split('/')[:-1])
    try:
        if os.path.isdir(target_abs):
            shutil.rmtree(target_abs)
        else:
            os.remove(target_abs)
        invalidate_size_cache(shared_root_abs)
        log_activity('share_delete', f"{rel_path}/{item_subpath}", f'token={token[:8]}…')
        flash('Item deleted.', 'success')
    except Exception as e:
        flash(f'Error: {e}', 'error')

    return redirect(url_for('share_download', token=token, path=parent_sub))


@app.route('/share/<token>/rename', methods=['POST'])
def share_folder_rename(token):
    """Collaborative rename inside shared folder."""
    shares = load_shares()
    entry  = shares.get(token)
    if not entry or entry.get('permissions', 'read') != 'full':
        abort(403)

    vault = load_vault()
    vault_entry = vault.get(token, {})
    if (vault_entry.get('username') or vault_entry.get('password_hash') or entry.get('password_hash')) and not session.get(f'share_authed_{token}'):
        abort(403)

    rel_path = entry['rel_path']
    base     = os.path.abspath(app.config['UPLOAD_FOLDER'])
    shared_root_abs = os.path.abspath(os.path.join(base, rel_path.replace('/', os.sep)))
    if not is_safe_path(shared_root_abs, base) or not os.path.isdir(shared_root_abs):
        abort(403)

    old_item_sub = request.form.get('old_path', '').strip()
    new_name     = request.form.get('new_name', '').strip()
    is_ajax      = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    if not old_item_sub or not new_name:
        return jsonify({'status': 'error', 'msg': 'Missing parameters'}), 400

    old_abs = os.path.abspath(os.path.join(shared_root_abs, old_item_sub.replace('/', os.sep)))
    if not is_safe_path(old_abs, shared_root_abs) or not os.path.exists(old_abs):
        return jsonify({'status': 'error', 'msg': 'Path not found'}), 404

    safe_new = os.path.basename(new_name)
    new_abs  = os.path.join(os.path.dirname(old_abs), safe_new)

    try:
        os.rename(old_abs, new_abs)
        log_activity('share_rename', f"{rel_path}/{old_item_sub}", f'→ {safe_new}')
        return jsonify({'status': 'success', 'new_name': safe_new})
    except Exception as e:
        return jsonify({'status': 'error', 'msg': str(e)}), 500


@app.route('/share/<token>/move', methods=['POST'])
def share_folder_move(token):
    """Collaborative move/copy inside shared folder."""
    shares = load_shares()
    entry  = shares.get(token)
    if not entry or entry.get('permissions', 'read') != 'full':
        abort(403)

    vault = load_vault()
    vault_entry = vault.get(token, {})
    if (vault_entry.get('username') or vault_entry.get('password_hash') or entry.get('password_hash')) and not session.get(f'share_authed_{token}'):
        abort(403)

    rel_path = entry['rel_path']
    base     = os.path.abspath(app.config['UPLOAD_FOLDER'])
    shared_root_abs = os.path.abspath(os.path.join(base, rel_path.replace('/', os.sep)))
    if not is_safe_path(shared_root_abs, base) or not os.path.isdir(shared_root_abs):
        abort(403)

    src_sub = request.form.get('src_path', '').strip()
    dest_sub = request.form.get('dest_folder', '').strip()
    action = request.form.get('action', 'move').strip()   # 'move' or 'copy'

    src_abs = os.path.abspath(os.path.join(shared_root_abs, src_sub.replace('/', os.sep)))
    dest_abs = os.path.abspath(os.path.join(shared_root_abs, dest_sub.replace('/', os.sep)))

    if not is_safe_path(src_abs, shared_root_abs) or not os.path.exists(src_abs):
        flash('Source not found.', 'error')
        return redirect(url_for('share_download', token=token, path=os.path.dirname(src_sub)))
    if not is_safe_path(dest_abs, shared_root_abs):
        flash('Invalid destination.', 'error')
        return redirect(url_for('share_download', token=token, path=os.path.dirname(src_sub)))

    os.makedirs(dest_abs, exist_ok=True)
    fname = os.path.basename(src_abs)
    try:
        if action == 'move':
            shutil.move(src_abs, os.path.join(dest_abs, fname))
            invalidate_size_cache(shared_root_abs)
            log_activity('share_move', f"{rel_path}/{src_sub}", f'→ {dest_sub}')
            flash(f'"{fname}" moved.', 'success')
        else:
            if os.path.isdir(src_abs):
                shutil.copytree(src_abs, os.path.join(dest_abs, fname))
            else:
                shutil.copy2(src_abs, os.path.join(dest_abs, fname))
            invalidate_size_cache(dest_abs)
            log_activity('share_copy', f"{rel_path}/{src_sub}", f'→ {dest_sub}')
            flash(f'"{fname}" copied.', 'success')
    except Exception as e:
        flash(f'Error: {e}', 'error')

    return redirect(url_for('share_download', token=token, path=dest_sub))

# ── Folder Upload Share ───────────────────────────────────────────────────────

@app.route('/share/folder/create', methods=['POST'])
@login_required
def share_folder_create():
    """Admin creates a public upload link for a specific folder."""
    folder_path = request.form.get('folder_path', '').strip()
    expiry_h    = request.form.get('expiry_hours', '').strip()
    password    = request.form.get('password', '').strip()
    note        = request.form.get('note', '').strip()

    if not folder_path:
        flash('No folder specified.', 'error')
        return redirect(url_for('index'))

    target = resolve_path(folder_path)
    if not target or not os.path.isdir(target):
        flash('Folder does not exist.', 'error')
        return redirect(url_for('index'))

    token  = secrets.token_urlsafe(20)
    shares = load_shares()
    entry  = {
        'type':          'folder_upload',
        'folder_path':   folder_path,
        'note':          note,
        'created_at':    datetime.now().isoformat(timespec='seconds'),
        'created_by':    current_user.id,
        'expires_at':    (datetime.now() + timedelta(hours=float(expiry_h))).isoformat(timespec='seconds')
                         if expiry_h else None,
        'password_hash': hashlib.sha256(password.encode()).hexdigest() if password else None,
    }
    shares[token] = entry
    save_shares(shares)
    log_activity('share_folder_create', folder_path, f'token={token[:8]}…')

    if _APP_BASE_URL:
        link = f"{_APP_BASE_URL}{url_for('folder_upload_share', token=token)}"
    else:
        link = url_for('folder_upload_share', token=token, _external=True)

    flash(f'Folder upload link created: {link}', 'success')
    return redirect(url_for('index', folder=folder_path))


@app.route('/share/upload/<token>', methods=['GET', 'POST'])
def folder_upload_share(token):
    """Public upload page – no login required."""
    shares = load_shares()
    entry  = shares.get(token)
    if not entry or entry.get('type') != 'folder_upload':
        abort(404)

    # Expiry check
    if entry.get('expires_at'):
        if datetime.now() > datetime.fromisoformat(entry['expires_at']):
            return render_template('share_expired.html'), 410

    folder_path = entry.get('folder_path', '')
    folder_name = os.path.basename(folder_path) if folder_path else 'Shared Folder'
    note        = entry.get('note', '')

    # Password check
    pw_ok = True
    if entry.get('password_hash'):
        pw_ok = False
        if request.method == 'POST' and 'password' in request.form:
            pw  = request.form.get('password', '')
            hsh = hashlib.sha256(pw.encode()).hexdigest()
            pw_ok = (hsh == entry['password_hash'])
            if not pw_ok:
                flash('Incorrect password.', 'error')
                return render_template('folder_upload_share.html',
                                       token=token, folder_name=folder_name,
                                       note=note, pw_required=True, pw_ok=False)
        elif request.method == 'GET':
            return render_template('folder_upload_share.html',
                                   token=token, folder_name=folder_name,
                                   note=note, pw_required=True, pw_ok=False)

    # Handle file upload
    if request.method == 'POST' and pw_ok and 'file' in request.files:
        dest_abs = resolve_path(folder_path)
        if not dest_abs:
            return jsonify({'status': 'error', 'msg': 'Invalid folder'}), 403

        file = request.files['file']
        rel  = request.form.get('rel_path', '').strip()
        filename = rel.split('/')[-1] if rel else file.filename
        if not filename:
            return jsonify({'status': 'error', 'msg': 'No filename'}), 400

        if not allowed_file(filename):
            return jsonify({'status': 'error', 'msg': 'File type not allowed'}), 400

        # Check upload rules
        target_folder = (folder_path + '/' + '/'.join(rel.split('/')[:-1])).strip('/') if (rel and '/' in rel) else folder_path
        folder_total_size = request.form.get('folder_total_size')
        ok, err_msg = validate_upload_rules(file, filename, target_folder, folder_total_size)
        if not ok:
            return jsonify({'status': 'error', 'msg': err_msg}), 400

        # sub-folder from rel_path (folder structure upload)
        if rel and '/' in rel:
            sub = '/'.join(rel.split('/')[:-1])
            dest_abs = os.path.join(dest_abs, sub)

        try:
            file_total_size = int(request.form.get('total_size', 0))
        except (ValueError, TypeError):
            file_total_size = request.content_length or 0
        ok, used, lim, _ = check_quota(folder_path, file_total_size)
        if not ok:
            return jsonify({'status': 'error',
                            'msg': f'Quota exceeded: {filesizeformat(used)} / {filesizeformat(lim)}'}), 400

        # ── Chunked upload assembly ───────────────────────────────────────────
        try:
            chunk_index  = int(request.form.get('chunk_index', 0))
            total_chunks = int(request.form.get('total_chunks', 1))
        except (ValueError, TypeError):
            chunk_index = 0; total_chunks = 1

        os.makedirs(dest_abs, exist_ok=True)
        dest_file_path = os.path.join(dest_abs, filename)

        if total_chunks <= 1:
            file.save(dest_file_path)
        else:
            uid = hashlib.sha1(
                f"pub:{token}:{rel}:{filename}".encode()
            ).hexdigest()
            try:
                is_complete, assembled_path = _assemble_chunks(
                    file, chunk_index, total_chunks,
                    int(request.form.get('chunk_offset', 0)),
                    file_total_size, uid
                )
            except Exception as e:
                return jsonify({'status': 'error', 'msg': f'Chunk error: {e}'}), 500
            if not is_complete:
                return jsonify({'status': 'chunk_success', 'chunk': chunk_index}), 200
            try:
                shutil.move(assembled_path, dest_file_path)
            except Exception as e:
                try: os.unlink(assembled_path)
                except OSError: pass
                return jsonify({'status': 'error', 'msg': f'Failed to save file: {e}'}), 500

        invalidate_size_cache(dest_abs)
        log_activity('share_upload', f"{folder_path}/{filename}", f'token={token[:8]}…')
        return jsonify({'status': 'success', 'msg': f'"{filename}" uploaded successfully.'})

    return render_template('folder_upload_share.html',
                           token=token, folder_name=folder_name,
                           note=note, pw_required=False, pw_ok=True)


@app.route('/share/revoke', methods=['POST'])
@login_required
def share_revoke():
    token  = request.form.get('token', '').strip()
    shares = load_shares()
    if token in shares:
        path = shares[token].get('rel_path','')
        del shares[token]
        save_shares(shares)

        # Remove from vault if present
        vault = load_vault()
        if token in vault:
            del vault[token]
            save_vault(vault)

        log_activity('share_revoke', path, f'token={token[:8]}…')
        flash('Share link revoked.', 'success')
    else:
        flash('Token not found.', 'error')
    return redirect(url_for('shares_page'))

@app.route('/shares')
@login_required
def shares_page():
    shares  = load_shares()
    vault   = load_vault()
    now     = datetime.now()
    enriched = []
    for token, entry in shares.items():
        exp       = entry.get('expires_at')
        stype     = entry.get('type', 'file_download')  # 'file_download' or 'folder_upload'

        # Build the correct link based on share type
        if stype == 'folder_upload':
            if _APP_BASE_URL:
                share_link = f"{_APP_BASE_URL}{url_for('folder_upload_share', token=token)}"
            else:
                share_link = url_for('folder_upload_share', token=token, _external=True)
            display_path = entry.get('folder_path', '')
        else:
            if _APP_BASE_URL:
                share_link = f"{_APP_BASE_URL}{url_for('share_download', token=token)}"
            else:
                share_link = url_for('share_download', token=token, _external=True)
            display_path = entry.get('rel_path', '')

        vault_entry = vault.get(token, {})
        has_pw = bool(vault_entry.get('password_hash') or entry.get('password_hash'))
        shared_user = vault_entry.get('username')

        enriched.append({
            'token':        token,
            'type':         stype,
            'rel_path':     display_path,
            'note':         entry.get('note', ''),
            'created_at':   entry.get('created_at', ''),
            'created_by':   entry.get('created_by', ''),
            'expires_at':   exp,
            'expired':      (datetime.fromisoformat(exp) < now) if exp else False,
            'has_pw':       has_pw,
            'shared_user':  shared_user,
            'permissions':  entry.get('permissions', 'read'),
            'link':         share_link,
        })
    enriched.sort(key=lambda x: x['created_at'], reverse=True)
    return render_template('shares.html', shares=enriched, current_user=current_user)

# ═══════════════════════════════════════════════════════════════════════════════
#  ACTIVITY LOG
# ═══════════════════════════════════════════════════════════════════════════════

def load_all_activities():
    if not os.path.exists(ACTIVITY_FILE):
        return []
    events = []
    with open(ACTIVITY_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except Exception:
                pass
    return events

@app.route('/activity')
@login_required
def activity():
    all_events = load_all_activities()
    
    # Get unique users and actions for filters
    users = sorted(list(set(e['user'] for e in all_events if e.get('user'))))
    actions = sorted(list(set(e['action'] for e in all_events if e.get('action'))))
    
    # Filter parameters
    search_q = request.args.get('search', '').strip()
    user_q = request.args.get('user', '').strip()
    action_q = request.args.get('action', '').strip()
    start_date = request.args.get('start_date', '').strip()
    end_date = request.args.get('end_date', '').strip()
    
    filtered = []
    for e in all_events:
        if user_q and e.get('user', '').lower() != user_q.lower():
            continue
        if action_q and e.get('action', '').lower() != action_q.lower():
            continue
        if search_q:
            sq = search_q.lower()
            in_path = sq in e.get('path', '').lower()
            in_extra = sq in e.get('extra', '').lower()
            in_user = sq in e.get('user', '').lower()
            if not (in_path or in_extra or in_user):
                continue
        ts_str = e.get('ts', '')
        if ts_str:
            date_part = ts_str.split('T')[0]
            if start_date and date_part < start_date:
                continue
            if end_date and date_part > end_date:
                continue
        filtered.append(e)
        
    # Reverse so newest first
    filtered.reverse()
    
    # Limit UI display to 1000 items
    events = filtered[:1000]
    
    return render_template('activity.html', events=events, users=users, actions=actions,
                           search_q=search_q, user_q=user_q, action_q=action_q,
                           start_date=start_date, end_date=end_date, current_user=current_user)

@app.route('/activity/export')
@login_required
def activity_export():
    all_events = load_all_activities()
    
    # Filter parameters
    search_q = request.args.get('search', '').strip()
    user_q = request.args.get('user', '').strip()
    action_q = request.args.get('action', '').strip()
    start_date = request.args.get('start_date', '').strip()
    end_date = request.args.get('end_date', '').strip()
    format_type = request.args.get('format', 'csv').lower()
    
    filtered = []
    for e in all_events:
        if user_q and e.get('user', '').lower() != user_q.lower():
            continue
        if action_q and e.get('action', '').lower() != action_q.lower():
            continue
        if search_q:
            sq = search_q.lower()
            in_path = sq in e.get('path', '').lower()
            in_extra = sq in e.get('extra', '').lower()
            in_user = sq in e.get('user', '').lower()
            if not (in_path or in_extra or in_user):
                continue
        ts_str = e.get('ts', '')
        if ts_str:
            date_part = ts_str.split('T')[0]
            if start_date and date_part < start_date:
                continue
            if end_date and date_part > end_date:
                continue
        filtered.append(e)
        
    filtered.reverse()
    
    if format_type == 'json':
        return Response(
            json.dumps(filtered, indent=2),
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment; filename="activity_log.json"'}
        )
    else: # Default CSV
        import csv
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Time', 'User', 'Action', 'Path', 'Detail'])
        for e in filtered:
            writer.writerow([e.get('ts',''), e.get('user',''), e.get('action',''), e.get('path',''), e.get('extra','')])
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename="activity_log.csv"'}
        )

# ═══════════════════════════════════════════════════════════════════════════════
#  RECYCLE BIN
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/trash')
@login_required
def trash():
    cleanup_expired_trash()
    sync_trash_meta()
    meta  = load_trash_meta()
    items = []
    td    = trash_dir()
    for trash_name, info in meta.items():
        tp = os.path.join(td, trash_name)
        items.append({
            'trash_name':  trash_name,
            'name':        info.get('name', trash_name),
            'original':    info.get('original',''),
            'deleted_at':  info.get('deleted_at',''),
            'exists':      os.path.exists(tp),
            'size':        os.path.getsize(tp) if os.path.exists(tp) else 0,
        })
    items.sort(key=lambda x: x['deleted_at'], reverse=True)
    return render_template('trash.html', items=items, current_user=current_user)

@app.route('/trash/restore/<trash_name>', methods=['POST'])
@login_required
def trash_restore(trash_name):
    meta      = load_trash_meta()
    info      = meta.get(trash_name)
    if not info:
        flash('Item not found in trash.', 'error')
        return redirect(url_for('trash'))
    td        = trash_dir()
    src       = os.path.join(td, trash_name)
    dest      = info['original']
    dest_dir  = os.path.dirname(dest)
    try:
        os.makedirs(dest_dir, exist_ok=True)
        shutil.move(src, dest)
        invalidate_size_cache(dest_dir)
        del meta[trash_name]
        save_trash_meta(meta)
        log_activity('trash_restore', info.get('name',''))
        flash(f'"{info["name"]}" restored.', 'success')
    except Exception as e:
        flash(f'Error restoring: {e}', 'error')
    return redirect(url_for('trash'))

@app.route('/trash/purge/<trash_name>', methods=['POST'])
@login_required
def trash_purge(trash_name):
    meta = load_trash_meta()
    info = meta.get(trash_name)
    if not info:
        flash('Item not found in trash.', 'error')
        return redirect(url_for('trash'))
    td  = trash_dir()
    src = os.path.join(td, trash_name)
    try:
        if os.path.isdir(src):  shutil.rmtree(src)
        elif os.path.exists(src): os.remove(src)
        del meta[trash_name]
        save_trash_meta(meta)
        log_activity('trash_purge', info.get('name',''))
        flash(f'"{info["name"]}" permanently deleted.', 'success')
    except Exception as e:
        flash(f'Error: {e}', 'error')
    return redirect(url_for('trash'))

@app.route('/trash/empty', methods=['POST'])
@login_required
def trash_empty():
    meta = load_trash_meta()
    td   = trash_dir()
    count = 0
    for tname in list(meta.keys()):
        src = os.path.join(td, tname)
        try:
            if os.path.isdir(src):  shutil.rmtree(src)
            elif os.path.exists(src): os.remove(src)
            del meta[tname]
            count += 1
        except Exception:
            pass
    save_trash_meta(meta)
    log_activity('trash_empty', f'{count} items')
    flash(f'Trash emptied ({count} items removed).', 'success')
    return redirect(url_for('trash'))

# ═══════════════════════════════════════════════════════════════════════════════
#  QUOTA MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/quotas')
@login_required
def quotas_page():
    quotas  = load_quotas()
    base    = os.path.abspath(app.config['UPLOAD_FOLDER'])
    all_folders = []
    for dp, dirs, _ in os.walk(base):
        dirs[:] = [d for d in dirs if d != '.trash']
        for d in dirs:
            ap  = os.path.join(dp, d)
            rel = os.path.relpath(ap, base).replace('\\', '/')
            key = quota_key(rel)
            q   = quotas.get(key)
            used = get_folder_size(ap)
            all_folders.append({
                'name': d, 'rel': rel, 'key': key, 'used': used,
                'quota_bytes': q['quota_bytes'] if q else None,
                'note':        q.get('note','') if q else '',
                'has_quota':   q is not None,
                'pct': round(min(used/q['quota_bytes']*100,100),1) if q else 0,
            })
    rq   = quotas.get('root')
    rused = get_folder_size(base)
    root_info = {
        'name': 'Root', 'rel': '', 'key': 'root', 'used': rused,
        'quota_bytes': rq['quota_bytes'] if rq else None,
        'note':        rq.get('note','') if rq else '',
        'has_quota':   rq is not None,
        'pct': round(min(rused/rq['quota_bytes']*100,100),1) if rq else 0,
    }
    all_folders.sort(key=lambda x: x['rel'])
    return render_template('quotas.html', all_folders=all_folders,
                           root_info=root_info, current_user=current_user)

@app.route('/quota/set', methods=['POST'])
@login_required
def quota_set():
    key   = request.form.get('folder_key','').strip()
    val   = request.form.get('quota_value','0').strip()
    unit  = request.form.get('quota_unit','GB').strip()
    note  = request.form.get('note','').strip()
    try:   v = float(val); assert v > 0
    except: flash('Invalid quota value.','error'); return redirect(url_for('quotas_page'))
    mult = {'B':1,'KB':1024,'MB':1024**2,'GB':1024**3,'TB':1024**4}
    q = load_quotas()
    q[key] = {'quota_bytes': int(v * mult.get(unit,1024**3)), 'note': note,
              'updated_at': datetime.now().isoformat(timespec='seconds')}
    save_quotas(q)
    flash(f'Quota for "{key}" set to {val} {unit}.','success')
    return redirect(url_for('quotas_page'))

@app.route('/quota/remove', methods=['POST'])
@login_required
def quota_remove():
    key = request.form.get('folder_key','').strip()
    q   = load_quotas()
    if key in q: del q[key]; save_quotas(q); flash('Quota removed.','success')
    else: flash('Quota not found.','error')
    return redirect(url_for('quotas_page'))

# ═══════════════════════════════════════════════════════════════════════════════
#  AUTH
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        u = request.form.get('username', '').strip()
        p = request.form.get('password', '')

        # Brute-force lockout check
        if _is_login_locked(u):
            flash('Too many failed attempts. Please wait 15 minutes before trying again.', 'error')
            return render_template('login.html')

        users = load_users()
        rec   = users.get(u)
        if rec and rec.get('active', True) and verify_pw(p, rec.get('password_hash', '')):
            _clear_login_attempts(u)
            # ── Auto-migrate legacy SHA-256 hash to PBKDF2 on first successful login
            stored = rec.get('password_hash', '')
            if stored and ':' not in stored:   # bare hex → legacy SHA-256
                rec['password_hash'] = hash_pw(p)
                save_users(users)
            login_user(User(u, rec.get('role', 'viewer')))
            session.permanent = True  # Apply PERMANENT_SESSION_LIFETIME (8 h cookie); frontend idle timer governs actual logout
            flash(f'Welcome back, {u}!', 'success')
            return redirect(url_for('index'))
        _record_failed_login(u)
        flash('Invalid username or password.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Signed out.','success')
    return redirect(url_for('login'))


# ═══════════════════════════════════════════════════════════════════════════════
#  FILE VERSIONING
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/versions/<path:filepath>')
@login_required
def file_versions(filepath):
    """List all saved versions of a file."""
    base     = os.path.abspath(app.config['UPLOAD_FOLDER'])
    abs_file = os.path.abspath(os.path.join(base, filepath.replace('/', os.sep)))
    if not is_safe_path(abs_file, base): abort(403)

    fname   = os.path.basename(filepath)
    ver_dir = os.path.join(VERSIONS_DIR, os.path.dirname(filepath))
    versions = []
    if os.path.isdir(ver_dir):
        for vf in sorted(os.listdir(ver_dir), reverse=True):
            if not vf.endswith('__' + fname) and '__' not in vf:
                continue
            parts = vf.split('__', 1)
            if len(parts) == 2 and parts[1] == fname:
                ts = parts[0]
                vpath = os.path.join(ver_dir, vf)
                versions.append({
                    'ts':       ts,
                    'filename': vf,
                    'size':     os.path.getsize(vpath),
                    'saved_at': int(ts),
                })

    folder_sub = '/'.join(filepath.replace('\\', '/').split('/')[:-1])
    return render_template('versions.html', filepath=filepath, fname=fname,
                           versions=versions, folder_sub=folder_sub,
                           current_user=current_user)


@app.route('/version/download/<path:filepath>/<ts>')
@login_required
def version_download(filepath, ts):
    """Download a specific version of a file."""
    fname   = os.path.basename(filepath)
    ver_dir = os.path.join(VERSIONS_DIR, os.path.dirname(filepath))
    vfile   = os.path.join(ver_dir, f"{ts}__{fname}")
    if not os.path.isfile(vfile): abort(404)
    log_activity('version_download', filepath, f'ts={ts}')
    return send_file(vfile, as_attachment=True,
                     download_name=f"{fname}.v{ts}")


@app.route('/version/restore', methods=['POST'])
@login_required
def version_restore():
    """Restore a version: copy it back as the live file, saving current as version."""
    filepath = request.form.get('filepath', '').strip()
    ts       = request.form.get('ts', '').strip()
    if not filepath or not ts: abort(400)

    fname    = os.path.basename(filepath)
    ver_dir  = os.path.join(VERSIONS_DIR, os.path.dirname(filepath))
    vfile    = os.path.join(ver_dir, f"{ts}__{fname}")
    if not os.path.isfile(vfile): abort(404)

    base     = os.path.abspath(app.config['UPLOAD_FOLDER'])
    live     = os.path.join(base, filepath.replace('/', os.sep))
    if not is_safe_path(live, base): abort(403)

    folder_sub = '/'.join(filepath.replace('\\', '/').split('/')[:-1])
    require_editor(folder_sub)

    _save_version(folder_sub, fname, live)       # version the current live file
    shutil.copy2(vfile, live)
    invalidate_size_cache(os.path.dirname(live))
    log_activity('version_restore', filepath, f'ts={ts}')
    flash(f'"{fname}" restored to version from {datetime.fromtimestamp(int(ts)).strftime("%d %b %Y %H:%M")}.', 'success')
    return redirect(url_for('file_versions', filepath=filepath))


# ═══════════════════════════════════════════════════════════════════════════════
#  ADMIN PANEL  (users  +  folder ACL)
# ═══════════════════════════════════════════════════════════════════════════════

def _admin_required():
    if not current_user.is_admin: abort(403)

# ── Users ─────────────────────────────────────────────────────────────────────

@app.route('/admin/users')
@login_required
def admin_users():
    _admin_required()
    users = load_users()
    enriched = []
    for uid, rec in users.items():
        enriched.append({
            'uid':        uid,
            'role':       rec.get('role', 'viewer'),
            'active':     rec.get('active', True),
            'created_at': rec.get('created_at', ''),
        })
    enriched.sort(key=lambda x: (x['role'] != 'admin', x['uid']))
    return render_template('admin_users.html', users=enriched, current_user=current_user)


@app.route('/admin/users/add', methods=['POST'])
@login_required
def admin_user_add():
    _admin_required()
    uid  = request.form.get('uid', '').strip().lower()
    pw   = request.form.get('password', '').strip()
    role = request.form.get('role', 'viewer').strip()
    if not uid or not pw:
        flash('Username and password are required.', 'error')
        return redirect(url_for('admin_users'))
    users = load_users()
    if uid in users:
        flash(f'User "{uid}" already exists.', 'error')
        return redirect(url_for('admin_users'))
    users[uid] = {
        'password_hash': hash_pw(pw),
        'role':          role,
        'created_at':    datetime.now().isoformat(timespec='seconds'),
        'active':        True,
    }
    save_users(users)
    log_activity('admin_user_add', uid, f'role={role}')
    flash(f'User "{uid}" created as {role}.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/edit/<uid>', methods=['POST'])
@login_required
def admin_user_edit(uid):
    _admin_required()
    users = load_users()
    if uid not in users:
        flash('User not found.', 'error')
        return redirect(url_for('admin_users'))
    role   = request.form.get('role', users[uid].get('role', 'viewer'))
    active = request.form.get('active', 'true') == 'true'
    pw     = request.form.get('password', '').strip()
    users[uid]['role']   = role
    users[uid]['active'] = active
    if pw:
        users[uid]['password_hash'] = hash_pw(pw)
    save_users(users)
    log_activity('admin_user_edit', uid, f'role={role} active={active}')
    flash(f'User "{uid}" updated.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/delete/<uid>', methods=['POST'])
@login_required
def admin_user_delete(uid):
    _admin_required()
    if uid == current_user.id:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('admin_users'))
    users = load_users()
    if uid in users:
        del users[uid]
        save_users(users)
        log_activity('admin_user_delete', uid)
        flash(f'User "{uid}" deleted.', 'success')
    return redirect(url_for('admin_users'))


# ── Folder ACL ────────────────────────────────────────────────────────────────

@app.route('/admin/acl')
@login_required
def admin_acl():
    _admin_required()
    acl  = load_acl()
    base = os.path.abspath(app.config['UPLOAD_FOLDER'])
    all_folders = ['root']
    for dp, dirs, _ in os.walk(base):
        dirs[:] = [d for d in dirs if d not in ('.trash', '.versions')]
        for d in dirs:
            rel = os.path.relpath(os.path.join(dp, d), base).replace('\\', '/')
            all_folders.append(rel)
    all_folders.sort()
    users = load_users()
    return render_template('admin_acl.html', acl=acl, all_folders=all_folders,
                           users=users, current_user=current_user)


@app.route('/admin/acl/set', methods=['POST'])
@login_required
def admin_acl_set():
    _admin_required()
    folder_key    = request.form.get('folder_key', '').strip()
    allowed_users = [u.strip() for u in request.form.get('allowed_users', '').split(',') if u.strip()]
    allowed_roles = request.form.getlist('allowed_roles')
    acl = load_acl()
    if allowed_users or allowed_roles:
        acl[folder_key] = {'allowed_users': allowed_users, 'allowed_roles': allowed_roles,
                           'updated_at': datetime.now().isoformat(timespec='seconds')}
        save_acl(acl)
        flash(f'ACL for "{folder_key}" saved.', 'success')
    else:
        if folder_key in acl:
            del acl[folder_key]
            save_acl(acl)
        flash(f'ACL for "{folder_key}" removed (open to all).', 'success')
    return redirect(url_for('admin_acl'))


@app.route('/admin/acl/remove', methods=['POST'])
@login_required
def admin_acl_remove():
    _admin_required()
    folder_key = request.form.get('folder_key', '').strip()
    acl = load_acl()
    if folder_key in acl:
        del acl[folder_key]
        save_acl(acl)
        flash(f'ACL for "{folder_key}" removed.', 'success')
    return redirect(url_for('admin_acl'))


# ── Admin Upload Rules ────────────────────────────────────────────────────────

@app.route('/admin/rules', methods=['GET', 'POST'])
@login_required
def admin_rules():
    _admin_required()
    rules = load_rules()
    if request.method == 'POST':
        try:
            # Parse Max File Size (MB)
            max_file_size = request.form.get('max_file_size_mb', '').strip()
            rules['max_file_size_mb'] = float(max_file_size) if max_file_size else None
            
            # Parse Max Folder Size (MB)
            max_folder_size = request.form.get('max_folder_size_mb', '').strip()
            rules['max_folder_size_mb'] = float(max_folder_size) if max_folder_size else None
            
            # Parse Blocked Extensions
            blocked_exts = request.form.get('blocked_extensions', '').strip()
            rules['blocked_extensions'] = [e.strip().strip('.').lower() for e in blocked_exts.split(',') if e.strip()]
            
            # Parse Blocked Mimetypes
            blocked_mimes = request.form.get('blocked_mimetypes', '').strip()
            rules['blocked_mimetypes'] = [m.strip().lower() for m in blocked_mimes.split(',') if m.strip()]

            # Parse Session Idle Timeout (minutes) — admin-configurable auto-logout delay
            session_timeout = request.form.get('session_timeout_minutes', '').strip()
            if session_timeout:
                timeout_val = int(float(session_timeout))
                rules['session_timeout_minutes'] = max(1, timeout_val)  # enforce minimum 1 minute
            else:
                rules['session_timeout_minutes'] = 5  # fallback default
            
            save_rules(rules)
            flash('Upload rules updated successfully.', 'success')
        except ValueError as ex:
            flash(f'Invalid input format: {ex}', 'error')
        return redirect(url_for('admin_rules'))
        
    # Get list of folders to choose from
    base = os.path.abspath(app.config['UPLOAD_FOLDER'])
    all_folders = []
    for dp, dirs, _ in os.walk(base):
        dirs[:] = [d for d in dirs if d not in ('.trash', '.versions')]
        for d in dirs:
            rel = os.path.relpath(os.path.join(dp, d), base).replace('\\', '/')
            all_folders.append(rel)
    all_folders.sort()
        
    return render_template('admin_rules.html', rules=rules, all_folders=all_folders, current_user=current_user)

@app.route('/admin/rules/folder/set', methods=['POST'])
@login_required
def admin_rules_folder_set():
    _admin_required()
    folder_key = request.form.get('folder_key', '').strip()
    if not folder_key:
        flash('Folder path is required.', 'error')
        return redirect(url_for('admin_rules'))
    
    rules = load_rules()
    if 'folder_rules' not in rules:
        rules['folder_rules'] = {}
        
    try:
        max_file_size = request.form.get('max_file_size_mb', '').strip()
        max_folder_size = request.form.get('max_folder_size_mb', '').strip()
        blocked_exts = request.form.get('blocked_extensions', '').strip()
        blocked_mimes = request.form.get('blocked_mimetypes', '').strip()
        
        folder_rule = {
            'max_file_size_mb': float(max_file_size) if max_file_size else None,
            'max_folder_size_mb': float(max_folder_size) if max_folder_size else None,
            'blocked_extensions': [e.strip().strip('.').lower() for e in blocked_exts.split(',') if e.strip()],
            'blocked_mimetypes': [m.strip().lower() for m in blocked_mimes.split(',') if m.strip()]
        }
        rules['folder_rules'][folder_key] = folder_rule
        save_rules(rules)
        flash(f'Upload rules set for folder "{folder_key}".', 'success')
    except ValueError as ex:
        flash(f'Invalid input format: {ex}', 'error')
        
    return redirect(url_for('admin_rules'))

@app.route('/admin/rules/folder/remove', methods=['POST'])
@login_required
def admin_rules_folder_remove():
    _admin_required()
    folder_key = request.form.get('folder_key', '').strip()
    rules = load_rules()
    if 'folder_rules' in rules and folder_key in rules['folder_rules']:
        del rules['folder_rules'][folder_key]
        save_rules(rules)
        flash(f'Upload rules removed for folder "{folder_key}".', 'success')
    return redirect(url_for('admin_rules'))

@app.route('/api/upload_rules')
@login_required
def api_upload_rules():
    folder = request.args.get('folder', '').strip()
    return jsonify(get_rules_for_path(folder))


@app.route('/api/session-ping')
@login_required
def session_ping():
    """Heartbeat endpoint called by the frontend on user activity.

    - Marks the session as modified so Flask refreshes the cookie expiry,
      preventing the server-side cookie from expiring during active use.
    - Returns the admin-configured idle timeout so the frontend timer is
      always in sync with the admin setting.
    """
    session.modified = True          # Refresh the 8-hour cookie lifetime
    session.permanent = True         # Ensure it is treated as a permanent session
    rules = load_rules()
    timeout_minutes = rules.get('session_timeout_minutes', 5)
    return jsonify({'timeout_minutes': int(timeout_minutes)})

@app.route('/api/open_local', methods=['POST'])
@login_required
def api_open_local():
    filepath = request.form.get('filepath', '').strip()
    abs_path = resolve_path(filepath)
    if not abs_path or not os.path.exists(abs_path):
        return jsonify({'status': 'error', 'msg': 'File not found'}), 404
        
    import socket
    allowed_ips = {'127.0.0.1', '::1', 'localhost'}
    try:
        host_name = socket.gethostname()
        allowed_ips.update(socket.gethostbyname_ex(host_name)[2])
    except:
        pass
        
    if request.remote_addr not in allowed_ips:
         return jsonify({'status': 'error', 'msg': 'Desktop execution is only allowed when accessed on the host machine.'}), 403
         
         
    try:
        os.startfile(abs_path)
        log_activity('open_local', filepath)
        return jsonify({'status': 'success', 'msg': f'Opened {os.path.basename(filepath)}'})
    except Exception as e:
        return jsonify({'status': 'error', 'msg': f'Failed to open file: {e}'}), 500



# ═══════════════════════════════════════════════════════════════════════════════
#  FAVORITES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/favorites', methods=['GET'])
@login_required
def favorites_page():
    favs = load_favorites().get(current_user.id, [])
    base = os.path.abspath(app.config['UPLOAD_FOLDER'])
    enriched = []
    for rel in favs:
        abs_path = os.path.abspath(os.path.join(base, rel.replace('/', os.sep)))
        if is_safe_path(abs_path, base) and os.path.exists(abs_path):
            is_dir = os.path.isdir(abs_path)
            enriched.append({
                'name': os.path.basename(abs_path),
                'rel_path': rel,
                'is_dir': is_dir,
                'size': 0 if is_dir else os.path.getsize(abs_path),
                'mtime': os.path.getmtime(abs_path),
            })
    return render_template('favorites.html', items=enriched, current_user=current_user)

@app.route('/favorite/toggle', methods=['POST'])
@login_required
def favorite_toggle():
    rel_path = request.form.get('path', '').strip().replace('\\', '/').strip('/')
    if not rel_path:
        return jsonify({'status': 'error', 'msg': 'Invalid path'}), 400

    favs = load_favorites()
    user_favs = favs.get(current_user.id, [])
    if rel_path in user_favs:
        user_favs.remove(rel_path)
        starred = False
        msg = f'"{os.path.basename(rel_path)}" removed from Favorites.'
    else:
        user_favs.append(rel_path)
        starred = True
        msg = f'"{os.path.basename(rel_path)}" added to Favorites.'
    favs[current_user.id] = user_favs
    save_favorites(favs)
    log_activity('favorite_toggle', rel_path, f'starred={starred}')
    return jsonify({'status': 'success', 'starred': starred, 'msg': msg})

# ═══════════════════════════════════════════════════════════════════════════════
#  INTERNAL SHARING
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/shared-with-me', methods=['GET'])
@login_required
def shared_with_me_page():
    shares = load_internal_shares()
    base = os.path.abspath(app.config['UPLOAD_FOLDER'])
    enriched = []
    for rel_path, user_list in shares.items():
        for share in user_list:
            if share.get('user') == current_user.id:
                abs_path = os.path.abspath(os.path.join(base, rel_path.replace('/', os.sep)))
                if is_safe_path(abs_path, base) and os.path.exists(abs_path):
                    is_dir = os.path.isdir(abs_path)
                    enriched.append({
                        'name': os.path.basename(abs_path),
                        'rel_path': rel_path,
                        'is_dir': is_dir,
                        'size': 0 if is_dir else os.path.getsize(abs_path),
                        'mtime': os.path.getmtime(abs_path),
                        'shared_by': share.get('shared_by', 'system'),
                        'permission': share.get('permission', 'viewer'),
                        'shared_at': share.get('shared_at', ''),
                    })
    enriched.sort(key=lambda x: x.get('shared_at', ''), reverse=True)
    return render_template('shared_with_me.html', items=enriched, current_user=current_user)

@app.route('/share/internal/add', methods=['POST'])
@login_required
def share_internal_add():
    rel_path = request.form.get('path', '').strip().replace('\\', '/').strip('/')
    target_user = request.form.get('user', '').strip().lower()
    perm = request.form.get('permission', 'viewer').strip()

    if not rel_path or not target_user:
        return jsonify({'status': 'error', 'msg': 'Missing path or user'}), 400

    users = load_json(USERS_FILE)
    if target_user not in users:
        return jsonify({'status': 'error', 'msg': f'User "{target_user}" does not exist.'}), 404

    if target_user == current_user.id:
        return jsonify({'status': 'error', 'msg': 'You cannot share items with yourself.'}), 400

    if not current_user.is_admin and not check_internal_access(rel_path, current_user, 'editor'):
        if not can_write(rel_path):
            return jsonify({'status': 'error', 'msg': 'You do not have permission to share this item.'}), 403

    shares = load_internal_shares()
    item_shares = shares.get(rel_path, [])

    updated = False
    for share in item_shares:
        if share.get('user') == target_user:
            share['permission'] = perm
            share['shared_at'] = datetime.now().isoformat(timespec='seconds')
            share['shared_by'] = current_user.id
            updated = True
            break

    if not updated:
        item_shares.append({
            'user': target_user,
            'permission': perm,
            'shared_at': datetime.now().isoformat(timespec='seconds'),
            'shared_by': current_user.id
        })

    shares[rel_path] = item_shares
    save_internal_shares(shares)
    log_activity('share_internal', rel_path, f'to={target_user} perm={perm}')
    return jsonify({'status': 'success', 'msg': f'Item successfully shared with {target_user} as {perm}.'})

@app.route('/share/internal/remove', methods=['POST'])
@login_required
def share_internal_remove():
    rel_path = request.form.get('path', '').strip().replace('\\', '/').strip('/')
    target_user = request.form.get('user', '').strip().lower()

    if not rel_path or not target_user:
        return jsonify({'status': 'error', 'msg': 'Missing path or user'}), 400

    if not current_user.is_admin and not can_write(rel_path):
        return jsonify({'status': 'error', 'msg': 'You do not have permission to modify sharing.'}), 403

    shares = load_internal_shares()
    if rel_path in shares:
        shares[rel_path] = [s for s in shares[rel_path] if s.get('user') != target_user]
        if not shares[rel_path]:
            del shares[rel_path]
        save_internal_shares(shares)
        log_activity('share_internal_revoke', rel_path, f'user={target_user}')
        return jsonify({'status': 'success', 'msg': f'Revoked access for {target_user}.'})
    return jsonify({'status': 'error', 'msg': 'Share not found.'}), 404

# ═══════════════════════════════════════════════════════════════════════════════
#  COMMENTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/comments/<path:filepath>/add', methods=['POST'])
@login_required
def comment_add(filepath):
    rel_path = filepath.replace('\\', '/').strip('/')
    text = request.form.get('text', '').strip()
    if not text:
        return jsonify({'status': 'error', 'msg': 'Comment text cannot be empty'}), 400

    comments = load_comments()
    item_comments = comments.get(rel_path, [])

    new_comment = {
        'user': current_user.id,
        'text': text,
        'timestamp': datetime.now().isoformat(timespec='seconds')
    }
    item_comments.append(new_comment)
    comments[rel_path] = item_comments
    save_comments(comments)
    log_activity('comment_add', rel_path, f'user={current_user.id}')
    return jsonify({'status': 'success', 'comment': new_comment})

# ═══════════════════════════════════════════════════════════════════════════════
#  DETAILS / INFO DRAWER
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/details/<path:filepath>', methods=['GET'])
@login_required
def details(filepath):
    rel_path = filepath.replace('\\', '/').strip('/')
    abs_path = resolve_path(rel_path)
    if not abs_path or not os.path.exists(abs_path):
        return jsonify({'status': 'error', 'msg': 'Item not found'}), 404

    if not check_folder_access(rel_path, current_user):
        return jsonify({'status': 'error', 'msg': 'Access denied'}), 403

    is_dir = os.path.isdir(abs_path)
    size = get_folder_size(abs_path) if is_dir else os.path.getsize(abs_path)
    mtime = os.path.getmtime(abs_path)

    starred = rel_path in load_favorites().get(current_user.id, [])
    shares = load_internal_shares().get(rel_path, [])
    comments = load_comments().get(rel_path, [])

    # Read recent activity for this item.
    # Cap _tail_log at 200 (was 2000) to keep RAM and CPU flat per drawer open.
    item_activity = []
    for evt in reversed(_tail_log(ACTIVITY_FILE, 200)):
        evt_path = evt.get('path', '')
        if evt_path == rel_path or (is_dir and evt_path.startswith(rel_path + '/')):
            item_activity.append(evt)
            if len(item_activity) >= 50:
                break

    return jsonify({
        'status': 'success',
        'name': os.path.basename(abs_path),
        'rel_path': rel_path,
        'is_dir': is_dir,
        'size': size,
        'mtime': mtime,
        'starred': starred,
        'shares': shares,
        'comments': comments,
        'activity': item_activity,
        'can_edit': can_write(rel_path)
    })

# ═══════════════════════════════════════════════════════════════════════════════
#  CUSTOM ERROR HANDLERS
# ═══════════════════════════════════════════════════════════════════════════════

@app.errorhandler(403)
def err_forbidden(e):
    return render_template('error.html', code=403,
                           title='Forbidden',
                           message='You do not have permission to access this resource.'), 403

@app.errorhandler(404)
def err_not_found(e):
    return render_template('error.html', code=404,
                           title='Not Found',
                           message='The page or file you requested could not be found.'), 404

@app.errorhandler(413)
def err_too_large(e):
    return render_template('error.html', code=413,
                           title='File Too Large',
                           message='The uploaded file exceeds the maximum allowed size.'), 413

@app.errorhandler(500)
def err_server_error(e):
    return render_template('error.html', code=500,
                           title='Server Error',
                           message='An unexpected error occurred. Please try again later.'), 500

# ───────────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
