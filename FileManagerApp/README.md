# File Manager Web Application

This Flask application provides file upload, listing, download, and delete functionalities. Uploaded files are stored in the dedicated folder **/opt/addvalut/Softwares/** as configured in `config.py`.

## Features
- Upload files via a modern UI.
- View a list of uploaded files.
- Download or delete files.
- Responsive design with subtle animations.

## Deployment
1. Create a virtual environment and install dependencies:
   ```bash
   python -m venv venv
   venv\Scripts\activate  # Windows
   pip install -r requirements.txt
   ```
2. Ensure the upload folder exists on the target Linux machine:
   ```bash
   sudo mkdir -p /opt/addvalut/Softwares
   sudo chown $USER:$USER /opt/addvalut/Softwares
   ```
3. Run the development server (for testing):
   ```bash
   python app.py
   ```
4. For production, use a WSGI server (e.g., gunicorn) and configure your web server to serve the app.

## Configuration
- The upload directory is defined in `config.py` as `UPLOAD_FOLDER`. Change this variable if you need a different storage location.

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | Optional | A fixed secret key for Flask sessions. If not set, one is auto-generated and stored in `.secret_key`. **Must be set (or `.secret_key` copied) when deploying to a new server** to preserve existing sessions. |
| `APP_BASE_URL` | Recommended | The public base URL of your server, e.g. `https://files.example.com`. **Required for share links to point to the correct host** when accessed from the internet or a different network. If not set, links use the current request host (fine for local use). |

### Example `.env` / systemd / shell export

```bash
export SECRET_KEY="your-long-random-secret-here"
export APP_BASE_URL="https://files.example.com"
python app.py
```

> **Note:** `.secret_key` is auto-created on first run and should be added to `.gitignore` to keep it out of version control.

---
