# FileVault — Complete Project Documentation
> **Last updated:** 2026-08-05 | **App:** FileVault Advanced File Manager | **Stack:** Flask + Vanilla HTML/CSS/JS

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Project Structure — Every File Explained](#2-project-structure)
3. [Configuration Guide (config.py)](#3-configuration-guide)
4. [Environment Variables](#4-environment-variables)
5. [Feature-by-Feature Breakdown](#5-feature-by-feature-breakdown)
6. [All API Routes — What, Why, When](#6-all-api-routes)
7. [Security Architecture](#7-security-architecture)
8. [Data Files — JSON Store Guide](#8-data-files)
9. [Step-by-Step Setup Guide](#9-step-by-step-setup-guide)
10. [Deployment Guide](#10-deployment-guide)
11. [User Roles & Permissions](#11-user-roles--permissions)
12. [Troubleshooting Guide](#12-troubleshooting-guide)
13. [Key Design Decisions & Why](#13-key-design-decisions--why)
14. [Documentation Auto-Watcher](#14-documentation-auto-watcher)
15. [Changelog — All Point-by-Point Changes](#15-changelog)

---

## 1. Project Overview

**FileVault** is a self-hosted, browser-based file manager built with Python Flask. It is designed to replace basic FTP/SFTP access with a modern, secure, multi-user file management interface.

### Core Philosophy
- **No cloud dependency** — all files stay on your server.
- **Zero database** — all state stored in lightweight JSON files.
- **Security-first** — CSRF protection, PBKDF2 password hashing, path traversal prevention, brute-force lockout built in from the ground up.

### What It Does
| Capability | Description |
|---|---|
| Multi-user auth | Admin, Editor, Viewer roles with login/logout |
| File CRUD | Upload (single + whole folder), download, rename, move, copy, delete |
| Soft delete | Files go to Recycle Bin; auto-purged after 30 days |
| File versioning | Up to 10 historical copies per file kept automatically |
| Share links | Token-based public links (optional expiry + password) |
| Internal shares | Share specific files/folders directly to other registered users |
| Folder quotas | Per-folder storage limits enforced on upload |
| Upload rules | Block file types, mime types, size limits globally or per-folder |
| ACL | Per-folder access control per user or role |
| Activity log | JSON-lines audit log of every action |
| Recycle bin | 30-day auto-purge trash with restore and permanent delete |
| Search | Global recursive file/folder search |
| Favorites | Per-user starred items list |
| Preview | Inline preview of images, PDFs, text, video, audio |
| Analytics | Utilization dashboard with charts |
| Executable icons | Extracts and serves `.exe`/`.dll`/`.msi` icons |

---

## 2. Project Structure

```
FileManagerApp/
├── app.py                        ← Main Flask application (3171 lines)
├── config.py                     ← Upload folder path + allowed extensions
├── requirements.txt              ← Python dependencies
├── doc_watcher.py                ← Documentation auto-regeneration watcher
├── README.md                     ← Basic setup instructions
├── users.json                    ← User accounts (auto-created on first run)
├── share_links.json              ← Active share link tokens
├── shares_vault.json             ← Hashed passwords for protected share links
├── upload_rules.json             ← Admin upload restriction rules
├── activity.log                  ← JSON-lines audit trail
├── .secret_key                   ← Auto-generated Flask secret key (gitignored)
├── .trash_cleanup_ts             ← Timestamp to throttle trash auto-cleanup
├── templates/                    ← Jinja2 HTML templates (21 files)
│   ├── base.html                 ← Common layout with CSRF fetch patcher
│   ├── index.html                ← Main file browser (largest, 54 KB)
│   ├── login.html                ← Login page
│   ├── search.html               ← Search results page
│   ├── favorites.html            ← Starred items page
│   ├── trash.html                ← Recycle bin page
│   ├── shares.html               ← Active share links management page
│   ├── shared_with_me.html       ← Items shared to current user
│   ├── activity.html             ← Audit log page with filters
│   ├── quotas.html               ← Folder quota management page
│   ├── utilization.html          ← Storage analytics dashboard
│   ├── versions.html             ← File version history page
│   ├── admin_users.html          ← User management (admin only)
│   ├── admin_acl.html            ← Folder ACL management (admin only)
│   ├── admin_rules.html          ← Upload rules management (admin only)
│   ├── folder_share_view.html    ← Public shared folder view for recipients
│   ├── folder_upload_share.html  ← Public upload link page for recipients
│   ├── share_password.html       ← Password gate for protected share links
│   ├── share_expired.html        ← Shown when a share link has expired
│   ├── share_preview.html        ← Preview within shared context
│   └── error.html                ← Generic error page (403/404/413/500)
├── static/
│   ├── css/                      ← Stylesheets
│   └── js/                       ← JavaScript files
├── uploads/                      ← Default file storage root (Windows fallback)
│   ├── .trash/                   ← Recycle bin directory
│   │   └── .meta.json            ← Trash item metadata
│   └── .versions/                ← File version history copies
├── docs/                         ← Auto-generated documentation files
│   ├── FileVault_Technical_Documentation.docx
│   ├── FileVault_SourceCode_Explanation.docx
│   ├── FileVault_Presentation.pptx
│   ├── FileVault_Reference_Sheets.xlsx
│   └── Python Web Application Deployment.docx
└── venv/                         ← Python virtual environment
```

### Key Auto-Generated Data Files

| File | Created When | Purpose |
|---|---|---|
| `users.json` | First run (if missing) | Stores hashed user credentials and roles |
| `share_links.json` | First share is created | Active share tokens and metadata |
| `shares_vault.json` | First password-protected share | Hashed share link passwords |
| `upload_rules.json` | First admin rule save | Global + per-folder upload restrictions |
| `activity.log` | First action taken | Append-only JSON-lines audit log |
| `.secret_key` | First startup | Stable 64-char hex Flask secret key |
| `.trash_cleanup_ts` | First trash cleanup run | Throttle file for once-per-hour cleanup |
| `folder_quotas.json` | First quota set | Per-folder storage quotas |
| `folder_acl.json` | First ACL rule set | Per-folder access control rules |
| `favorites.json` | First item starred | Per-user favorites list |
| `internal_shares.json` | First internal share | User-to-user share grants |
| `comments.json` | First comment added | File/folder comments |

---

## 3. Configuration Guide

### [config.py](file:///d:/VS%20Code/Softwares/FileManagerApp/config.py)

This file is the **only place** you need to edit for basic setup.

```python
# Where uploaded files are stored
UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "/home/admin/Documents/Softwares")
```

**Logic:**
1. Tries the path from `UPLOAD_FOLDER` environment variable (or the hardcoded default).
2. Tests if the path is **writable** by creating a `.write_test` file.
3. If on **Windows** (`os.name == 'nt'`) OR the path is **not writable** → falls back to `./uploads/` inside the project directory.

```python
MAX_CONTENT_LENGTH = None
```
- Set to `None` = **no global file size limit**. Individual quotas and admin rules govern sizes.
- To add a hard ceiling: set to e.g. `500 * 1024 * 1024` (500 MB).

```python
ALLOWED_EXTENSIONS = None
```
- `None` = **all file types allowed**.
- To restrict: `ALLOWED_EXTENSIONS = {'pdf', 'docx', 'xlsx', 'png', 'jpg'}`

> [!IMPORTANT]
> On Linux production servers, change `UPLOAD_FOLDER` to your actual server path, OR set the `UPLOAD_FOLDER` environment variable — do NOT edit the hardcoded path if you want portability.

---

## 4. Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `SECRET_KEY` | ⚠️ Recommended | Auto-generated | Flask session encryption key. Set this in production to prevent session invalidation on restart. |
| `APP_BASE_URL` | ⚠️ Recommended | Request host | Public URL for share links. E.g. `https://files.example.com`. Without this, share links use the local host — they won't work from the internet. |
| `UPLOAD_FOLDER` | Optional | `/home/admin/Documents/Softwares` | Where files are stored on the server. Falls back to `./uploads/` on Windows or if the path is not writable. |
| `DATA_DIR` | Optional | Project directory | Where JSON data files live. Useful if you want to separate file storage from config storage. |
| `FLASK_ENV` | Optional | — | Set to `development` to enable template auto-reload. |
| `FLASK_HTTPS` | Optional | `0` | Set to `1` when serving over HTTPS to mark cookies as `Secure`. |

### Example: Linux systemd service or `.env`

```bash
export SECRET_KEY="your-very-long-random-secret-here-at-least-32-chars"
export APP_BASE_URL="https://files.yourdomain.com"
export UPLOAD_FOLDER="/data/filevault/files"
export DATA_DIR="/data/filevault"
python app.py
```

---

## 5. Feature-by-Feature Breakdown

### 5.1 Authentication

**What:** Username/password login backed by a JSON file (`users.json`).

**Why JSON instead of a database?** Zero infrastructure requirement — the app runs anywhere Python runs, without needing PostgreSQL/MySQL.

**How it works:**
1. On first run, `_init_default_admin()` seeds `users.json` with `admin / admin123`.
2. The console prints a loud warning to change this password.
3. Passwords are hashed with **PBKDF2-HMAC-SHA256** via Werkzeug (`generate_password_hash`).
4. **Legacy SHA-256 migration**: Old plain hex SHA-256 hashes are auto-upgraded to PBKDF2 on next successful login (transparent to the user).

**Brute-force lockout:**
- Max **10 failed attempts** per username within a **15-minute window**.
- Tracked in memory (`_login_attempts` dict). Resets when the window expires.
- ⚠️ Per-process only — use Redis in a multi-worker production deployment.

---

### 5.2 File Upload

**What:** Supports single file upload and whole-folder drag-and-drop with progress tracking.

**Route:** `POST /upload`

**Flow:**
1. Check write permission (`require_editor`).
2. Check upload rules (blocked extensions, mime types, file/folder size limits).
3. Check folder quota.
4. If the file already exists → **version the existing file** first (copy to `.versions/`).
5. Save the new file.
6. Invalidate folder size cache.
7. Log the action.

**AJAX support:** Returns JSON if `X-Requested-With: XMLHttpRequest` header is present (used for drag-and-drop progress). Falls back to redirect + flash for plain form submits.

---

### 5.3 File Versioning

**What:** Every time a file is overwritten, the old copy is saved in `.versions/` with a Unix timestamp prefix.

**Where stored:** `UPLOAD_FOLDER/.versions/<relative_path>/<timestamp>__<filename>`

**Limits:** Max **10 versions per file** (oldest pruned automatically).

**Why 10?** Balance between history depth and disk space. Configurable by changing `_MAX_VERSIONS` in `app.py`.

**Routes:**
- `GET /versions/<filepath>` — list all saved versions
- `GET /version/download/<filepath>/<ts>` — download a specific version
- `POST /version/restore` — restore a version (saves current as a new version first)

---

### 5.4 Recycle Bin (Soft Delete)

**What:** Deleted files/folders go to `.trash/` instead of being permanently removed.

**Why:** Prevents accidental permanent data loss.

**How it works:**
- File is `shutil.move()`'d to `.trash/<timestamp>__<filename>`.
- Metadata saved in `.trash/.meta.json`.
- **Auto-purge:** Files older than **30 days** are permanently deleted.
- Auto-purge is **throttled** — runs at most once per hour.
- Two-layer throttle: in-process timestamp (no disk I/O) + on-disk stamp file (cross-process).

**Routes:**
- `GET /trash` — view recycle bin
- `POST /trash/restore/<trash_name>` — restore to original location
- `POST /trash/purge/<trash_name>` — permanently delete one item
- `POST /trash/empty` — permanently delete all items

---

### 5.5 Share Links (Public / External Sharing)

**What:** Generate a public URL (no login needed) to share a file or folder.

**Why token-based?** So you can revoke a link without changing the file.

**Options when creating a share:**
| Option | Description |
|---|---|
| Expiry (hours) | Link auto-expires after N hours |
| Password | Recipients must enter a username/password |
| Permissions | `read`, `download`, `upload_read_download`, `full` |

**Password storage:** Hashed with SHA-256, stored in `shares_vault.json` (separate from share metadata for cleaner revocation).

**Share link URL format:** `/share/<token>` for file/folder view; `/share/upload/<token>` for folder upload links.

**Permission levels for shared folders:**
| Level | Can Do |
|---|---|
| `read` | View files inline (preview only) |
| `download` | Download files + ZIP |
| `upload_read_download` | Upload + download |
| `full` | Upload + download + rename + move + delete + create folders |

**Routes (public, no login):**
- `GET/POST /share/<token>` — view/download shared file or folder
- `GET /share/<token>/preview` — preview file inline
- `GET /share/<token>/download/<subpath>` — download file from shared folder
- `GET /share/<token>/download_zip` — download entire shared folder as ZIP
- `POST /share/<token>/upload` — upload into shared folder
- `POST /share/<token>/create_folder` — create folder in shared space
- `POST /share/<token>/delete/<item>` — delete item in shared space
- `POST /share/<token>/rename` — rename item in shared space
- `POST /share/<token>/move` — move/copy item in shared space

**Routes (login required):**
- `POST /share/create` — create a file/folder share link
- `POST /share/folder/create` — create a folder upload share link
- `POST /share/revoke` — revoke (delete) a share link
- `GET /shares` — view all active share links

---

### 5.6 Internal (User-to-User) Sharing

**What:** Share files/folders directly with other registered users without a public link.

**Why:** More controlled than public links — recipients must have an account.

**Permission levels:** `viewer` (read-only) or `editor` (read + write).

**ACL inheritance:** When checking access, the system walks from the most-specific path up to root, using the first matching ACL entry.

**Routes:**
- `GET /shared-with-me` — items shared to the current user
- `POST /share/internal/add` — grant access to a user
- `POST /share/internal/remove` — revoke access from a user

---

### 5.7 Folder Quotas

**What:** Per-folder storage limits enforced on every upload.

**Why:** Prevent one user or folder from consuming all disk space.

**How check_quota works:**
1. Load quota for the folder key.
2. Calculate current folder size using `get_folder_size()` (cached for 5 seconds).
3. If `used + incoming > limit` → reject upload with an error message.

**Folder size cache:** A thread-safe TTL cache (`_size_cache`) with 5-second expiry eliminates repeated `os.walk()` calls. Cache is invalidated immediately after every mutation (upload, delete, move, restore).

**Routes:**
- `GET /quotas` — view all folder quotas
- `POST /quota/set` — set or update a quota
- `POST /quota/remove` — remove a quota

---

### 5.8 Upload Rules (Admin)

**What:** Global and per-folder rules that restrict what can be uploaded.

**Rules available:**
| Rule | Description |
|---|---|
| `max_file_size_mb` | Maximum size per individual file in MB |
| `max_folder_size_mb` | Maximum total folder upload size in MB |
| `blocked_extensions` | List of blocked file extensions (e.g. `exe`, `bat`) |
| `blocked_mimetypes` | List of blocked MIME type strings (e.g. `application/x-executable`) |

**Inheritance:** Per-folder rules inherit from global rules for any unset fields. The most specific ancestor folder's rules apply.

**Routes:**
- `GET/POST /admin/rules` — manage global upload rules
- `POST /admin/rules/folder/set` — set per-folder rules
- `POST /admin/rules/folder/remove` — remove per-folder rules
- `GET /api/upload_rules?folder=<path>` — get rules for a folder (used by JS on the upload UI)

---

### 5.9 Folder ACL (Access Control Lists)

**What:** Restrict which users or roles can view/access specific folders.

**How it works:**
- Stored in `folder_acl.json`.
- Each entry: `{ "allowed_users": [...], "allowed_roles": [...] }`.
- **Default (no ACL entry):** folder is accessible to everyone.
- Admins bypass all ACL checks.
- ACL is inherited — a restriction on a parent applies to children unless overridden.

**Private folders:** When creating a folder, the user can mark it "private", which automatically creates an ACL entry allowing only the creator and admins.

**Routes:**
- `GET /admin/acl` — view/manage all ACL entries (admin only)
- `POST /admin/acl/set` — create or update an ACL entry
- `POST /admin/acl/remove` — remove an ACL entry

---

### 5.10 Activity / Audit Log

**What:** Every user action is appended to `activity.log` as a JSON line.

**Format:** `{"ts": "2026-08-05T10:00:00", "user": "admin", "action": "upload", "path": "folder/file.txt", "extra": ""}`

**Why append-only JSON lines?** Simple, fast, no locking issues on append. Crash-safe — a partial write at the end is silently skipped on read.

**Reading:** `_tail_log()` reads the file **backwards** in 8 KB chunks — it never loads the full file into memory, even for very large logs.

**Features:**
- Filter by user, action, date range, or text search.
- Display capped at 1000 items in the UI.
- Export as **CSV** or **JSON**.

**Routes:**
- `GET /activity` — view and filter the audit log
- `GET /activity/export` — download filtered log as CSV or JSON

---

### 5.11 Global Search

**What:** Recursive search across all files and folders by name.

**How it works:** `os.walk()` over the upload folder, skipping `.trash` and `.versions`, matching names case-insensitively.

**Cap:** Results capped at **500 matches** to prevent hanging on huge file stores.

**Route:** `GET /search?q=<query>`

---

### 5.12 Favorites (Starred Items)

**What:** Each user can star/unstar any file or folder for quick access.

**Storage:** `favorites.json` → `{ "username": ["rel/path/to/item", ...] }`

**Per-request cache:** Favorites are cached on `flask.g` so multiple calls in one request (index page stars every item) only hit disk once.

**Routes:**
- `GET /favorites` — view starred items
- `POST /favorite/toggle` — toggle star on/off (AJAX)

---

### 5.13 File Preview

**What:** View files inline in the browser without downloading.

**Supported formats:** `png, jpg, jpeg, gif, svg, webp, bmp, mp4, webm, mov, mp3, wav, ogg, flac, pdf, txt, md, csv, json, xml, py, js, html, css, log`

**Route:** `GET /preview/<filepath>` — streams file with `as_attachment=False`

---

### 5.14 Executable Icon Extraction

**What:** Extracts and serves the embedded icon from `.exe`, `.msi`, `.dll`, `.lnk` files.

**Windows strategy:** Uses the Windows Shell API (`SHGetFileInfoW` via ctypes) — gets 100% accurate icons for all file types.

**Linux strategy:** Uses `icoextract` library (PE parser) for `.exe` and `.dll` files. Falls back to 404 for `.msi`/`.lnk` (browser uses the generic file icon).

**Caching:** Icons are cached as PNG files in `.icons/` keyed by `MD5(filepath + mtime)`. Cache is invalidated automatically when the file changes.

**Route:** `GET /app_icon/<filepath>`

---

### 5.15 Analytics (Utilization Dashboard)

**What:** Storage usage statistics and activity trend charts.

**Displays:**
- Total users, folders, files
- Storage used vs. limit
- Breakdown by category: Images, Videos, Documents, Others
- Activity chart (last 7 days of uploads, downloads, other actions)

**Route:** `GET /utilization`

---

### 5.16 ZIP Downloads

**What:** Download an entire folder or a batch of selected files as a single ZIP.

**Implementation:** Uses `tempfile.mkstemp()` to create a temporary ZIP file on disk, preventing RAM exhaustion. To download multi-gigabyte files or directories without timeouts or CPU bottlenecks, the archive is written in uncompressed **`ZIP_STORED`** mode instead of `ZIP_DEFLATED`. This enables instant zip compilation.

**Routes:**
- `GET /download_zip/<folder_path>` — download entire folder as ZIP
- `POST /batch_download` — download selected files as ZIP

---

### 5.17 Comments

**What:** Users can add text comments to any file or folder.

**Storage:** `comments.json` → `{ "rel/path": [{ "user": ..., "text": ..., "timestamp": ... }] }`

**Route:** `POST /comments/<filepath>/add`

---

### 5.18 Details Drawer

**What:** Sidebar panel showing file metadata, activity history, shares, comments, and favorite status for any selected item.

**UI Styling:** Styled with a clean, high-contrast light theme (white background, sky-blue borders, and dark gray/black text) to match the rest of the application layout for optimal readability.

**Route:** `GET /details/<filepath>` — returns JSON

**Activity capped at:** 200 log tail → max 50 matching entries shown, to keep the drawer fast.

---

## 6. All API Routes

### Auth Routes

| Method | Route | Auth | Description |
|---|---|---|---|
| GET/POST | `/login` | Public | Login page + authentication |
| GET | `/logout` | Required | Sign out current user |

### File Management Routes

| Method | Route | Auth | Description |
|---|---|---|---|
| GET | `/` | Required | Main file browser (index) |
| POST | `/upload` | Required | Upload a file |
| POST | `/upload_folder` | Required | Folder upload stub (redirect) |
| GET | `/download/<path>` | Required | Download a file as attachment |
| GET | `/preview/<path>` | Required | Preview a file inline |
| GET | `/download_zip/<path>` | Required | Download folder as ZIP |
| POST | `/batch_download` | Required | Download selected files as ZIP |
| POST | `/delete/<path>` | Required | Move file to trash |
| POST | `/delete_folder/<path>` | Required | Move folder to trash |
| POST | `/create_folder` | Required | Create a new folder |
| POST | `/rename` | Required | Rename a file or folder |
| POST | `/move` | Required | Move a file or folder |
| POST | `/copy` | Required | Copy a file or folder |
| GET | `/search` | Required | Search for files/folders |

### Versioning Routes

| Method | Route | Auth | Description |
|---|---|---|---|
| GET | `/versions/<path>` | Required | List all versions of a file |
| GET | `/version/download/<path>/<ts>` | Required | Download a specific version |
| POST | `/version/restore` | Required | Restore a version as current |

### Trash Routes

| Method | Route | Auth | Description |
|---|---|---|---|
| GET | `/trash` | Required | View recycle bin |
| POST | `/trash/restore/<name>` | Required | Restore item from trash |
| POST | `/trash/purge/<name>` | Required | Permanently delete one item |
| POST | `/trash/empty` | Required | Empty the entire trash |

### Share Routes (Public — no login)

| Method | Route | Auth | Description |
|---|---|---|---|
| GET/POST | `/share/<token>` | None | View/download shared file or folder |
| GET | `/share/<token>/preview` | None | Preview shared file |
| GET | `/share/<token>/download/<subpath>` | None | Download file from shared folder |
| GET | `/share/<token>/download_zip` | None | Download shared folder as ZIP |
| POST | `/share/<token>/upload` | None | Upload into shared folder |
| POST | `/share/<token>/create_folder` | None | Create folder in shared space |
| POST | `/share/<token>/delete/<path>` | None | Delete item in shared space |
| POST | `/share/<token>/rename` | None | Rename item in shared space |
| POST | `/share/<token>/move` | None | Move/copy item in shared space |
| GET/POST | `/share/upload/<token>` | None | Public folder upload page |

### Share Management Routes (Login Required)

| Method | Route | Auth | Description |
|---|---|---|---|
| POST | `/share/create` | Required | Create a file/folder share link |
| POST | `/share/folder/create` | Required | Create a folder upload link |
| POST | `/share/revoke` | Required | Revoke a share link |
| GET | `/shares` | Required | Manage all share links |

### Quota Routes

| Method | Route | Auth | Description |
|---|---|---|---|
| GET | `/quotas` | Required | View all folder quotas |
| POST | `/quota/set` | Required | Set or update a quota |
| POST | `/quota/remove` | Required | Remove a quota |

### Activity Routes

| Method | Route | Auth | Description |
|---|---|---|---|
| GET | `/activity` | Required | View filtered audit log |
| GET | `/activity/export` | Required | Export log as CSV or JSON |

### Analytics Route

| Method | Route | Auth | Description |
|---|---|---|---|
| GET | `/utilization` | Required | Storage analytics dashboard |

### Admin Routes

| Method | Route | Auth | Role |
|---|---|---|---|
| GET | `/admin/users` | Required | Admin only |
| POST | `/admin/users/add` | Required | Admin only |
| POST | `/admin/users/edit/<uid>` | Required | Admin only |
| POST | `/admin/users/delete/<uid>` | Required | Admin only |
| GET | `/admin/acl` | Required | Admin only |
| POST | `/admin/acl/set` | Required | Admin only |
| POST | `/admin/acl/remove` | Required | Admin only |
| GET/POST | `/admin/rules` | Required | Admin only |
| POST | `/admin/rules/folder/set` | Required | Admin only |
| POST | `/admin/rules/folder/remove` | Required | Admin only |

### Favorites & Internal Share Routes

| Method | Route | Auth | Description |
|---|---|---|---|
| GET | `/favorites` | Required | View starred items |
| POST | `/favorite/toggle` | Required | Star/unstar an item |
| GET | `/shared-with-me` | Required | Items shared to current user |
| POST | `/share/internal/add` | Required | Share item with a user |
| POST | `/share/internal/remove` | Required | Revoke internal share |

### API / Utility Routes

| Method | Route | Auth | Description |
|---|---|---|---|
| GET | `/app_icon/<path>` | Required | Serve executable file icon |
| GET | `/details/<path>` | Required | Get file/folder details as JSON |
| POST | `/comments/<path>/add` | Required | Add a comment |
| GET | `/api/upload_rules` | Required | Get upload rules for a folder |
| POST | `/api/open_local` | Required | Open file on host machine (localhost only) |

---

## 7. Security Architecture

### 7.1 CSRF Protection

**What:** All state-changing requests (POST/PUT/DELETE/PATCH) require a valid CSRF token.

**How:**
- A per-session token is generated on first access (`_get_csrf_token()`).
- Token is embedded as a hidden form field in all templates via `{{ csrf_token() }}`.
- AJAX requests send the token in the `X-CSRF-Token` header (patched globally in `base.html`).
- Exempt: GET/HEAD/OPTIONS, `/login`, and public share routes (`/share/*`).

### 7.2 Path Traversal Prevention

Every file operation calls `is_safe_path(path, base_dir)` before proceeding:

```python
def is_safe_path(path, base_dir):
    return os.path.normcase(os.path.abspath(path)).startswith(
        os.path.normcase(os.path.abspath(base_dir)))
```

This prevents URLs like `/download/../../../etc/passwd` from working.

### 7.3 Password Hashing

- **New passwords:** PBKDF2-HMAC-SHA256 via Werkzeug (`generate_password_hash`).
- **Legacy passwords:** Bare SHA-256 hex strings are supported in `verify_pw()` and **auto-migrated** to PBKDF2 on next successful login.

### 7.4 Session Cookie Security

```python
SESSION_COOKIE_HTTPONLY = True    # JS cannot read the cookie
SESSION_COOKIE_SAMESITE = 'Lax'  # Prevents CSRF from cross-site navigation
SESSION_COOKIE_SECURE = True      # Only sent over HTTPS (when FLASK_HTTPS=1)
```

### 7.5 Stable Secret Key

Flask session cookies are signed with `app.secret_key`. Using `os.urandom()` would generate a new key on every restart, invalidating all sessions and share tokens.

**Strategy:**
1. Check `SECRET_KEY` env var.
2. Read `.secret_key` file.
3. Generate a new 64-char hex key and write it to `.secret_key`.

> [!CAUTION]
> `.secret_key` must be in `.gitignore`. Committing it exposes your session signing key.

### 7.6 Brute Force Protection

- Max 10 failed login attempts per username per 15-minute window.
- In-memory only — resets on process restart.

### 7.7 Role-Based Access Control

- `admin` — full access to everything.
- `editor` — can upload, delete, rename, move, copy within allowed folders.
- `viewer` — read-only access (download, preview).

### 7.8 Share Link Password Protection

- Passwords for protected share links are stored **separately** in `shares_vault.json`.
- Hashed with SHA-256.
- Checking is done via session flag (`share_authed_<token>`) — once authenticated, the session remembers for the session lifetime.

---

## 8. Data Files

### users.json

```json
{
  "admin": {
    "password_hash": "pbkdf2:sha256:260000$...",
    "role": "admin",
    "created_at": "2026-08-01T10:00:00",
    "active": true
  }
}
```

### share_links.json

```json
{
  "<token>": {
    "rel_path": "folder/file.pdf",
    "created_at": "2026-08-01T10:00:00",
    "created_by": "admin",
    "expires_at": "2026-08-08T10:00:00",
    "permissions": "download"
  }
}
```

### shares_vault.json

```json
{
  "<token>": {
    "username": "john",
    "password_hash": "<sha256-hex>"
  }
}
```

### upload_rules.json

```json
{
  "max_file_size_mb": 100,
  "max_folder_size_mb": 500,
  "blocked_extensions": ["exe", "bat", "cmd"],
  "blocked_mimetypes": ["application/x-executable"],
  "folder_rules": {
    "public_uploads": {
      "max_file_size_mb": 10,
      "blocked_extensions": ["exe"]
    }
  }
}
```

### folder_quotas.json

```json
{
  "root": { "quota_bytes": 10737418240, "note": "10 GB root limit", "updated_at": "..." },
  "projects/alpha": { "quota_bytes": 1073741824, "note": "1 GB for alpha", "updated_at": "..." }
}
```

### folder_acl.json

```json
{
  "private-docs": {
    "allowed_users": ["alice", "bob"],
    "allowed_roles": ["admin"],
    "updated_at": "2026-08-01T10:00:00"
  }
}
```

---

## 9. Step-by-Step Setup Guide

### Prerequisites

- Python 3.9 or newer
- pip (comes with Python)
- Windows or Linux

### Step 1 — Clone / Copy the Project

Place the project in your desired directory. For example: `D:\VS Code\Softwares\FileManagerApp`

### Step 2 — Create Virtual Environment

```powershell
# Windows
python -m venv venv
venv\Scripts\activate
```

```bash
# Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 3 — Install Dependencies

```bash
pip install -r requirements.txt
```

**What gets installed:**
- `Flask==2.3.3` — web framework
- `Werkzeug==2.3.8` — WSGI utilities and password hashing
- `Flask-Login==0.6.3` — user session management
- `icoextract` — extract icons from PE binaries (Linux)
- `pefile` — PE file parser (dependency of icoextract)
- `Pillow` — image processing for icon conversion

### Step 4 — (Optional) Configure Storage Path

Either:
- Set the `UPLOAD_FOLDER` environment variable, OR
- Edit the default in `config.py` line 8.

On Windows, the app automatically falls back to the `./uploads/` folder.

### Step 5 — (Optional) Set Environment Variables

```powershell
# Windows PowerShell
$env:SECRET_KEY = "your-secret-here"
$env:APP_BASE_URL = "http://localhost:5000"
```

### Step 6 — Run the App

```bash
python app.py
```

The app starts on `http://0.0.0.0:5000`.

### Step 7 — First Login

- URL: `http://localhost:5000`
- Username: `admin`
- Password: `admin123`

> [!WARNING]
> **Change the admin password immediately.** Go to Admin → Users → Edit admin.

### Step 8 — Change Admin Password

1. Log in as admin.
2. Go to **Admin → Users**.
3. Click edit on `admin`.
4. Enter a strong new password.
5. Save.

---

## 10. Deployment Guide

### Linux Production with Gunicorn + Nginx

#### Step 1 — Install Gunicorn

Uncomment `gunicorn` in `requirements.txt` and run `pip install gunicorn`.

#### Step 2 — Create systemd Service

```ini
# /etc/systemd/system/filevault.service
[Unit]
Description=FileVault Flask App
After=network.target

[Service]
User=www-data
WorkingDirectory=/opt/filevault
Environment="SECRET_KEY=your-long-secret-here"
Environment="APP_BASE_URL=https://files.example.com"
Environment="UPLOAD_FOLDER=/data/filevault/files"
ExecStart=/opt/filevault/venv/bin/gunicorn -w 4 -b 127.0.0.1:5000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable filevault
sudo systemctl start filevault
```

#### Step 3 — Nginx Configuration

```nginx
server {
    listen 443 ssl;
    server_name files.example.com;

    client_max_body_size 0;  # No size limit (governed by Flask quotas)

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

> [!IMPORTANT]
> `client_max_body_size 0;` is required in Nginx. Without it, Nginx blocks large uploads before Flask sees them.

### Windows Production with Waitress

```powershell
pip install waitress
```

```python
# run_prod.py
from waitress import serve
from app import app
serve(app, host='0.0.0.0', port=5000)
```

---

## 11. User Roles & Permissions

| Action | Admin | Editor | Viewer |
|---|---|---|---|
| View files/folders | ✅ | ✅ | ✅ |
| Download files | ✅ | ✅ | ✅ |
| Preview files | ✅ | ✅ | ✅ |
| Search | ✅ | ✅ | ✅ |
| Upload files | ✅ | ✅ | ❌ |
| Create folders | ✅ | ✅ | ❌ |
| Rename files/folders | ✅ | ✅ | ❌ |
| Move files/folders | ✅ | ✅ | ❌ |
| Copy files/folders | ✅ | ✅ | ❌ |
| Delete (to trash) | ✅ | ✅ | ❌ |
| Restore from trash | ✅ | ✅ | ❌ |
| Create share links | ✅ | ✅ | ❌ |
| Share with users | ✅ | ✅ (own items) | ❌ |
| Manage quotas | ✅ | ❌ | ❌ |
| Manage ACL | ✅ | ❌ | ❌ |
| Manage upload rules | ✅ | ❌ | ❌ |
| Manage users | ✅ | ❌ | ❌ |
| View activity log | ✅ | ✅ | ✅ |
| Export activity log | ✅ | ✅ | ✅ |
| Empty trash | ✅ | ✅ | ❌ |
| Open local files | ✅ | ✅ | ❌ |

> [!NOTE]
> ACL restrictions can further limit Editor/Viewer access to specific folders on top of role-based permissions.

---

## 12. Troubleshooting Guide

### Problem: App won't start — `ModuleNotFoundError`

**Cause:** Virtual environment not activated or dependencies not installed.

**Fix:**
```bash
# Activate venv first
venv\Scripts\activate     # Windows
source venv/bin/activate  # Linux

pip install -r requirements.txt
python app.py
```

---

### Problem: Files uploading to wrong location / can't find uploaded files

**Cause:** `UPLOAD_FOLDER` in config.py points to a path that doesn't exist or isn't writable.

**Fix:**
1. Check `config.py` line 8 — what is the default path?
2. On Windows, the app falls back to `./uploads/` automatically. Look there.
3. Set the `UPLOAD_FOLDER` environment variable to your desired path.

```powershell
$env:UPLOAD_FOLDER = "D:\MyFiles"
python app.py
```

---

### Problem: Login sessions reset every time the app restarts

**Cause:** No stable `SECRET_KEY` set. The auto-generated key in `.secret_key` might be missing.

**Fix:**
1. Check if `.secret_key` exists in the project directory.
2. Set `SECRET_KEY` as an environment variable for production.

```bash
export SECRET_KEY="your-stable-64-char-hex-string"
```

---

### Problem: Share links point to `localhost` / wrong host

**Cause:** `APP_BASE_URL` environment variable is not set.

**Fix:**
```bash
export APP_BASE_URL="https://files.yourdomain.com"
```

---

### Problem: "Permission Denied" when deleting or moving files (Linux)

**Cause:** The web server user (`www-data`) doesn't have write access to the `.trash` folder or upload folder.

**Fix:**
```bash
sudo chown -R www-data:www-data /home/admin/Documents/Softwares
sudo chown -R www-data:www-data /home/admin/Documents/Softwares/.trash
```

---

### Problem: Large file upload fails with 413 error

**Cause:**
- Nginx's `client_max_body_size` limit (default 1 MB).
- Flask's `MAX_CONTENT_LENGTH` if set.

**Fix (Nginx):**
```nginx
client_max_body_size 0;  # No limit, governed by Flask/quotas
```

**Fix (Flask):**
In `config.py`, ensure: `MAX_CONTENT_LENGTH = None`

---

### Problem: Quota exceeded even though folder looks empty

**Cause:** The `.trash` or `.versions` subdirectories inside the quota folder count towards the size.

**Fix:** The folder size calculation (`get_folder_size`) walks all files including `.trash` and `.versions`. These hidden system folders are intentionally included. Clean trash and old versions to free space.

---

### Problem: Icon not showing for `.exe` files on Linux

**Cause:** `icoextract` library is not installed, or the `.exe` has no embedded icon resources.

**Fix:**
```bash
pip install icoextract pefile Pillow
```

Some minimal executables (e.g. compiled Python scripts) have no embedded icon — this is expected behavior and the generic file icon is shown.

---

### Problem: "Too many failed attempts" lockout

**Cause:** 10 failed login attempts within 15 minutes triggered the brute-force lockout.

**Fix:** Wait 15 minutes for the lockout window to expire. The lockout resets automatically — no server restart needed.

> [!NOTE]
> The lockout is in-memory per process. Restarting the app also clears all lockouts.

---

### Problem: Activity log is empty or not growing

**Cause:** The `activity.log` file path is wrong, or there are permission issues writing to it.

**Fix:**
```bash
# Check DATA_DIR setting (defaults to project dir)
ls -la activity.log
# Should be writable by the web server user
chown www-data:www-data activity.log
```

---

### Problem: CSRF 403 Forbidden on form submits

**Cause:** CSRF token is missing from a form, or the session expired.

**Fix:**
- All forms must include `<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">`.
- AJAX calls must include `X-CSRF-Token` header (handled automatically by the fetch patcher in `base.html`).
- If the session cookie is expired, the user just needs to log in again.

---

### Problem: `doc_watcher.py` fails with "Generator script not found"

**Cause:** The watcher script references hardcoded paths to generator scripts in the `.gemini` brain directory.

**Fix:** The generator scripts are session-specific brain artifacts. Run the watcher only when those scratch scripts exist at the paths specified in `doc_watcher.py`:

```
C:\Users\Dharan 2797\.gemini\antigravity-ide\brain\df238241-4c8f-42dd-ab59-f315d618665b\scratch\generate_docs.py
C:\Users\Dharan 2797\.gemini\antigravity-ide\brain\df238241-4c8f-42dd-ab59-f315d618665b\scratch\gen_sourcecode_doc.py
```

---

### Problem: Large file ZIP or bulk download hangs/times out

**Cause:** The application previously compressed ZIP archives on the fly using `ZIP_DEFLATED`. For very large files (e.g., several gigabytes), this operation runs CPU-bound for minutes, blocking the single-threaded development server and causing HTTP connection or client timeouts.

**Fix:**
- The ZIP compilation endpoints have been updated to use **`ZIP_STORED`** mode, which packages files instantly without CPU compression overhead.
- If the issue continues, verify that the Flask server process has been restarted to apply these changes.

---

### Problem: Folder size shown incorrectly / quota calculation wrong

**Cause:** The 5-second folder size cache may be showing stale data.

**Fix:** Wait 5 seconds and refresh. The cache is automatically invalidated after every upload, delete, move, copy, or restore operation. For debugging, look for `invalidate_size_cache()` calls in `app.py`.

---

### Problem: Multiple concurrent users, brute-force protection not working

**Cause:** `_login_attempts` is an in-memory dict — it's per-process. With multiple Gunicorn workers, each worker has its own dict.

**Fix (production):** Use a shared store like Redis for the lockout state. This is a known limitation documented in the code comments.

---

## 13. Key Design Decisions & Why

### Why JSON files instead of SQLite or PostgreSQL?

**Reason:** Maximum portability. The app runs on any machine with Python — no database installation, no migration scripts, no DBA needed. For a file manager used by a small team (< 100 users), JSON file I/O is completely adequate.

**Trade-off:** Not suitable for thousands of concurrent users. For that scale, replace `load_json`/`save_json` with a database.

---

### Why `save_json` uses an atomic write?

```python
tmp = path + '.tmp'
with open(tmp, 'w') as f:
    json.dump(data, f, indent=2)
os.replace(tmp, path)   # atomic on POSIX; near-atomic on Windows
```

**Reason:** If the process crashes mid-write, the original file is untouched. `os.replace()` is atomic on POSIX systems — the file is either fully written or not at all.

---

### Why is the trash inside the upload folder?

`TRASH_DIR = os.path.join(UPLOAD_FOLDER, '.trash')`

**Reason:** On Linux, `shutil.move()` is instantaneous when source and destination are on the same filesystem (it's just a rename). If trash were on a different partition, every delete would copy the file — slow for large files.

---

### Why is the folder size cache TTL 5 seconds?

**Reason:** The index page calls `get_folder_size()` for every subfolder on every page load. Without caching, browsing a folder with 50 subfolders would trigger 50 `os.walk()` calls per page. A 5-second TTL means at most one walk per folder per 5 seconds under heavy concurrent load, while still feeling near-real-time.

---

### Why `_tail_log()` reads backwards?

**Reason:** The activity log is append-only and can grow very large. Reading from the start to get the last N entries would load the entire file. Reading backwards in 8 KB chunks loads only the tail — constant time regardless of log size.

---

### Why are share link passwords hashed separately in `shares_vault.json`?

**Reason:** Cleaner revocation. When a share is revoked, the main `share_links.json` entry is deleted. The vault entry is also deleted. If they were mixed together, it would be easy to accidentally leave orphaned credential data.

---

### Why is `_MAX_VERSIONS = 10`?

**Reason:** Balance between history depth and disk usage. If you're overwriting a file frequently, 10 versions = 10x the file size in disk. This is configurable — change `_MAX_VERSIONS` in `app.py` to suit your storage budget.

---

## 14. Documentation Auto-Watcher

### [doc_watcher.py](file:///d:/VS%20Code/Softwares/FileManagerApp/doc_watcher.py)

**What it does:** Monitors source files for changes and automatically regenerates the `.docx`/`.xlsx`/`.pptx` documentation files in `/docs/`.

**Watched targets:**
- `app.py`
- `config.py`
- `requirements.txt`
- `templates/` directory
- `static/css/` directory

**Debounce:** 5 seconds minimum between regenerations to avoid double-triggers on rapid saves.

**Polling interval:** Every 2 seconds.

**How to run:**
```bash
# In a separate terminal, alongside the Flask app
python doc_watcher.py
```

**When to use it:** When actively developing features — it keeps your project documentation automatically up to date without manual effort.

> [!NOTE]
> The watcher depends on generator scripts that are session-specific brain artifacts. It is designed for active development sessions, not production deployment.

---

## 15. Changelog

### Point-by-Point Changes Made to FileVault

This section documents all notable changes made to the project from its initial basic state to the current advanced version.

---

#### Security Improvements

| # | Change | Where | Why |
|---|---|---|---|
| 1 | Added CSRF protection (`_csrf_protect()` before_request hook) | `app.py` L545–564 | Prevents cross-site request forgery on all state-changing routes |
| 2 | Stable secret key (`_load_or_create_secret_key()`) replacing `os.urandom()` | `app.py` L49–64 | Prevents share link token invalidation and session resets on restart |
| 3 | PBKDF2-HMAC-SHA256 password hashing via Werkzeug (replacing plain SHA-256) | `app.py` L186–205 | SHA-256 without salt/iterations is vulnerable to rainbow table attacks |
| 4 | Auto-migration of legacy SHA-256 hashes to PBKDF2 on next login | `app.py` L562–566 | Transparent upgrade path for existing accounts |
| 5 | Brute-force login protection (10 attempts / 15-min lockout) | `app.py` L508–535 | Prevents automated credential stuffing attacks |
| 6 | Session cookie flags: `HTTPONLY`, `SAMESITE=Lax`, `SECURE` (when HTTPS) | `app.py` L37–41 | Defense in depth against XSS and CSRF |
| 7 | `is_safe_path()` path traversal prevention on every file operation | `app.py` L229–231 | Prevents directory traversal attacks (`../../etc/passwd`) |
| 8 | Share link passwords stored in separate `shares_vault.json` | `app.py` L1553–1558 | Clean separation of credentials from share metadata |
| 9 | Share password uses `session[f'share_authed_{token}']` flag | `app.py` L1610 | Avoids re-authenticating on every page within a share session |

---

#### Feature Additions

| # | Feature | Routes Added | Why |
|---|---|---|---|
| 10 | Recycle Bin (soft delete) | `/trash`, `/trash/restore`, `/trash/purge`, `/trash/empty` | Prevents accidental permanent data loss |
| 11 | File Versioning (auto-save on overwrite) | `/versions/<path>`, `/version/download`, `/version/restore` | Recovery from bad overwrites |
| 12 | Share Links (public file/folder sharing) | `/share/*` (10 routes) | Share files without giving login credentials |
| 13 | Internal User-to-User Sharing | `/share/internal/add`, `/share/internal/remove`, `/shared-with-me` | Granular collaboration without public URLs |
| 14 | Folder Quotas | `/quotas`, `/quota/set`, `/quota/remove` | Control storage allocation per folder/team |
| 15 | Upload Rules (admin) | `/admin/rules`, `/admin/rules/folder/*`, `/api/upload_rules` | Block malicious or unwanted file types |
| 16 | Folder ACL | `/admin/acl`, `/admin/acl/set`, `/admin/acl/remove` | Restrict folder access by user or role |
| 17 | Multi-user authentication | `/login`, `/logout`, `/admin/users/*` | Multiple people can use the same server securely |
| 18 | Role system (admin/editor/viewer) | Throughout codebase | Least-privilege access control |
| 19 | Activity / Audit Log | `/activity`, `/activity/export` | Compliance, debugging, accountability |
| 20 | Global Recursive Search | `/search` | Find files across all folders instantly |
| 21 | Favorites / Starred Items | `/favorites`, `/favorite/toggle` | Quick access to frequently used items |
| 22 | ZIP Download (folder + batch) | `/download_zip/<path>`, `/batch_download` | Download multiple files in one click |
| 23 | Analytics Dashboard | `/utilization` | Understand storage usage at a glance |
| 24 | Executable Icon Extraction | `/app_icon/<path>` | Visual identification of `.exe`/`.msi` files |
| 25 | File Comments | `/comments/<path>/add` | Contextual notes on files/folders |
| 26 | Details Drawer API | `/details/<path>` | Rich sidebar info without page reload |
| 27 | Private folder creation (visibility=private) | `create_folder` route | Create ACL-locked folders in one step |
| 28 | Folder upload with nested structure | `/upload` (`rel_path` handling) | Drag-and-drop entire folder trees |
| 29 | Collaborative shared folder (upload/rename/delete/move) | `/share/<token>/*` | External collaborators can work within a shared folder |

---

#### Performance Improvements

| # | Change | Where | Why |
|---|---|---|---|
| 30 | Folder size TTL cache (`_size_cache`, 5 sec) | `app.py` L301–328 | Eliminates repeated `os.walk()` calls on index page load |
| 31 | Per-request `flask.g` cache for users, ACL, favorites, shares | `app.py` L265–290 | Eliminates redundant disk reads within a single HTTP request |
| 32 | Atomic JSON writes (`.tmp` + `os.replace()`) | `app.py` L250–259 | Prevents JSON corruption on crash during write |
| 33 | `_tail_log()` reads log file backwards in 8 KB chunks | `app.py` L379–414 | O(1) tail read — never loads entire log into memory |
| 34 | `invalidate_size_cache()` after every mutation | Throughout routes | Ensures index page shows accurate sizes without waiting for TTL |
| 35 | Fast ZIP downloads via ZIP_STORED (no compression) | `app.py` L1370–1465 | Large file packages zip instantly, avoiding CPU spikes and HTTP timeouts |
| 36 | Search results capped at 500 | `app.py` L1489 | Prevents browser freeze on massive file stores |
| 37 | Activity log display capped at 1000 items | `app.py` L2326 | Keeps UI responsive |
| 38 | Details drawer activity capped at 200 log tail / 50 matches | `app.py` L3119 | Keeps drawer opening fast |

---

#### Bug Fixes

| # | Fix | Where | Original Bug |
|---|---|---|---|
| 39 | Added `return` to move route | `app.py` L1447 | Missing `return` caused response-after-response Flask error |
| 40 | Trash auto-cleanup throttled with two-layer guard | `app.py` L431–482 | Without throttle, cleanup ran on every page load causing I/O spikes |
| 41 | `.trash` hidden from root folder listing | `app.py` L756 | Users could see/navigate the trash system directory |
| 42 | Quota removed when folder deleted | `app.py` L1320–1322 | Orphaned quota entries accumulated in `folder_quotas.json` |
| 43 | Share revoke also cleans vault entry | `app.py` L2208–2212 | Orphaned credential entries in `shares_vault.json` after revoke |
| 44 | Fixed large bulk downloads hanging | `app.py` L1370, L1462, L2057, L2138 | Replaced ZIP_DEFLATED with ZIP_STORED to eliminate compression timeouts |

---

#### Configuration Improvements

| # | Change | Where | Why |
|---|---|---|---|
| 44 | `UPLOAD_FOLDER` now tries env var first, falls back to `./uploads/` on Windows | `config.py` L8–26 | Zero-config startup on Windows dev machines |
| 45 | `MAX_CONTENT_LENGTH = None` (removed hard limit) | `config.py` L31 | Quotas and admin rules govern sizes instead |
| 46 | `ALLOWED_EXTENSIONS = None` (allow all types) | `config.py` L35 | Admin upload rules handle blocking instead |
| 47 | `APP_BASE_URL` env var for correct share link generation | `app.py` L70 | Share links pointed to localhost when accessed remotely |
| 48 | `DATA_DIR` env var to separate data from code | `app.py` L73 | Enables container deployments with separate data volume |
| 49 | `FLASK_HTTPS=1` env var for SECURE cookie flag | `app.py` L41 | Avoids cookie over HTTP warning in HTTPS deployments |
| 50 | `TEMPLATES_AUTO_RELOAD` only in development | `app.py` L35 | Prevents unnecessary template re-reads in production |

---

*This documentation was generated by Antigravity on 2026-08-05.*
*For the latest version of the code, see [app.py](file:///d:/VS%20Code/Softwares/FileManagerApp/app.py).*
