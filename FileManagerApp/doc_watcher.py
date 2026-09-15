"""
FileVault Documentation Auto-Watcher
=====================================
Monitors app.py, config.py, templates/, and static/ for any file changes.
Whenever a change is detected, it automatically regenerates:
  - FileVault_Technical_Documentation.docx
  - FileVault_Reference_Sheets.xlsx
  - FileVault_Presentation.pptx

Usage:
  python doc_watcher.py

Keep this running in a separate terminal alongside your Flask app.
"""

import sys
import os
import time
import subprocess
import threading
from datetime import datetime

# Fix Windows console encoding
sys.stdout.reconfigure(encoding='utf-8')

# ── Configuration ─────────────────────────────────────────────────────────────

# Root of the project to watch
WATCH_DIR = os.path.dirname(os.path.abspath(__file__))

# The doc generator scripts
DOC_SCRIPTS = [
    os.path.join(
        r"C:\Users\Dharan 2797\.gemini\antigravity-ide\brain\df238241-4c8f-42dd-ab59-f315d618665b\scratch",
        "generate_docs.py"
    ),
    os.path.join(
        r"C:\Users\Dharan 2797\.gemini\antigravity-ide\brain\df238241-4c8f-42dd-ab59-f315d618665b\scratch",
        "gen_sourcecode_doc.py"
    ),
]

# Files and folders to watch for changes
WATCH_TARGETS = [
    os.path.join(WATCH_DIR, "app.py"),
    os.path.join(WATCH_DIR, "config.py"),
    os.path.join(WATCH_DIR, "requirements.txt"),
    os.path.join(WATCH_DIR, "templates"),
    os.path.join(WATCH_DIR, "static", "css"),
]

# Minimum seconds between regenerations (debounce — avoid double-triggers)
DEBOUNCE_SECONDS = 5

# ── State ────────────────────────────────────────────────────────────────────

last_regen_time = 0
regen_lock = threading.Lock()


def log(msg, level="INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", flush=True)


def get_mtime(path):
    """Return the latest modification time for a file or directory tree."""
    try:
        if os.path.isfile(path):
            return os.path.getmtime(path)
        elif os.path.isdir(path):
            max_mtime = 0
            for root, dirs, files in os.walk(path):
                for fn in files:
                    try:
                        mt = os.path.getmtime(os.path.join(root, fn))
                        if mt > max_mtime:
                            max_mtime = mt
                    except Exception:
                        pass
            return max_mtime
    except Exception:
        return 0


def regenerate_docs(changed_file=None):
    """Run the documentation generator script."""
    global last_regen_time
    with regen_lock:
        now = time.time()
        if now - last_regen_time < DEBOUNCE_SECONDS:
            return  # Skip — too soon after last regeneration
        last_regen_time = now

    if changed_file:
        log(f"Change detected in: {os.path.basename(changed_file)}", "CHANGE")
    log("Regenerating documentation files...", "INFO")

    for script in DOC_SCRIPTS:
        try:
            result = subprocess.run(
                [sys.executable, script],
                capture_output=True,
                text=True,
                encoding='utf-8'
            )
            if result.returncode == 0:
                log(f"Documentation regenerated successfully using {os.path.basename(script)}!", "OK")
            else:
                log(f"Documentation generation failed for {os.path.basename(script)}:\n{result.stderr}", "ERROR")
        except Exception as ex:
            log(f"Failed to run generator script {script}: {ex}", "ERROR")


def watch_loop():
    """Main polling loop — checks file modification times every 2 seconds."""
    log("FileVault Documentation Auto-Watcher started.", "INFO")
    log(f"Watching: {WATCH_DIR}", "INFO")
    log("Watching targets:", "INFO")
    for t in WATCH_TARGETS:
        log(f"  - {t}", "INFO")
    log(f"Debounce interval: {DEBOUNCE_SECONDS} seconds", "INFO")
    log("Press Ctrl+C to stop.\n", "INFO")

    # Build initial snapshot of modification times
    snapshot = {t: get_mtime(t) for t in WATCH_TARGETS}

    # Trigger an initial generation on startup
    log("Running initial documentation generation...", "INFO")
    regenerate_docs()

    while True:
        time.sleep(2)  # Poll every 2 seconds
        for target in WATCH_TARGETS:
            current_mtime = get_mtime(target)
            if current_mtime > snapshot[target]:
                snapshot[target] = current_mtime
                # Run regeneration in a background thread to not block the watcher
                t = threading.Thread(
                    target=regenerate_docs,
                    args=(target,),
                    daemon=True
                )
                t.start()
                break  # One trigger per poll cycle is enough


if __name__ == "__main__":
    for script in DOC_SCRIPTS:
        if not os.path.exists(script):
            log(f"ERROR: Generator script not found at: {script}", "ERROR")
            sys.exit(1)
    try:
        watch_loop()
    except KeyboardInterrupt:
        log("\nWatcher stopped by user.", "INFO")
