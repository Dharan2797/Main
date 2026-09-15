/**
 * FileVault Upload Queue Manager
 * Provides global Pause, Resume, Stop, and Cancel functionality
 * for single-file, multi-file, and folder uploads.
 */

class FileVaultUploadQueue {
  constructor(options = {}) {
    this.uploadUrl = options.uploadUrl || '/upload';
    this.destFolder = options.destFolder || '';
    this.subpath = options.subpath || '';
    this.isShared = !!options.isShared;
    this.onComplete = options.onComplete || (() => window.location.reload());

    this.queue = [];
    this.currentIndex = -1;
    this.activeXhr = null;
    this.status = 'idle'; // idle, uploading, paused, completed, canceled
    
    this.totalFiles = 0;
    this.completedFiles = 0;
    
    this.initUI();
  }

  initUI() {
    // Remove existing container if any
    const old = document.getElementById('upload-manager-panel');
    if (old) old.remove();

    this.panel = document.createElement('div');
    this.panel.id = 'upload-manager-panel';
    this.panel.className = 'upload-manager-panel hidden';

    this.panel.innerHTML = `
      <div class="ump-header">
        <div class="ump-title-area">
          <span class="ump-logo">📤</span>
          <span class="ump-title">Uploading...</span>
        </div>
        <div class="ump-controls">
          <button class="ump-btn" id="ump-btn-pause" title="Pause Queue">⏸️ Pause</button>
          <button class="ump-btn hidden" id="ump-btn-resume" title="Resume Queue">▶️ Resume</button>
          <button class="ump-btn ump-btn-danger" id="ump-btn-cancel" title="Cancel All Uploads">🛑 Cancel All</button>
          <button class="ump-btn ump-btn-close hidden" id="ump-btn-close" title="Close Panel">✕</button>
        </div>
      </div>
      <div class="ump-progress-container">
        <div class="ump-progress-bar-bg">
          <div class="ump-progress-bar" id="ump-main-progress"></div>
        </div>
        <div class="ump-stats" id="ump-main-stats">0 of 0 files (0%)</div>
      </div>
      <div class="ump-file-list" id="ump-file-list"></div>
    `;

    document.body.appendChild(this.panel);

    // Bind panel level button events
    this.panel.querySelector('#ump-btn-pause').addEventListener('click', () => this.pause());
    this.panel.querySelector('#ump-btn-resume').addEventListener('click', () => this.resume());
    this.panel.querySelector('#ump-btn-cancel').addEventListener('click', () => this.cancelAll());
    this.panel.querySelector('#ump-btn-close').addEventListener('click', () => this.hide());
  }

  show() {
    this.panel.classList.remove('hidden');
  }

  hide() {
    this.panel.classList.add('hidden');
  }

  addFiles(fileList) {
    const files = Array.from(fileList);
    if (!files.length) return;

    this.totalFiles += files.length;
    this.show();

    const fragment = document.createDocumentFragment();

    // Populate queue list
    files.forEach((file, index) => {
      const relPath = file.webkitRelativePath || file.name;
      const fileId = 'ump-file-' + (this.queue.length + index);
      
      this.queue.push({
        id: fileId,
        file: file,
        relPath: relPath,
        status: 'pending', // pending, uploading, complete, canceled, error
        progress: 0
      });

      this.renderFileRow(fragment, fileId, relPath, file.size);
    });
    
    document.getElementById('ump-file-list').appendChild(fragment);

    this.updateMainStats();

    if (this.status === 'idle') {
      this.status = 'uploading';
      this.currentIndex = 0;
      this.processNext();
    }
  }

  renderFileRow(container, id, name, size) {
    const row = document.createElement('div');
    row.id = id;
    row.className = 'ump-file-row';
    
    const displaySize = this.formatSize(size);

    row.innerHTML = `
      <div class="ump-file-info">
        <span class="ump-file-name" title="${name}">${name}</span>
        <span class="ump-file-size">${displaySize}</span>
      </div>
      <div class="ump-file-progress-area">
        <div class="ump-file-progress-bar-bg">
          <div class="ump-file-progress-bar" id="${id}-progress-bar" style="width: 0%"></div>
        </div>
        <span class="ump-file-status-badge" id="${id}-badge">Pending</span>
        <button class="ump-file-cancel-btn" title="Cancel this file">✕</button>
      </div>
    `;

    // Bind individual file cancel button
    row.querySelector('.ump-file-cancel-btn').addEventListener('click', () => {
      this.cancelFile(id);
    });

    container.appendChild(row);
  }

  formatSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  updateMainStats() {
    const pct = this.totalFiles > 0 ? Math.round((this.completedFiles / this.totalFiles) * 100) : 0;
    document.getElementById('ump-main-progress').style.width = pct + '%';
    document.getElementById('ump-main-stats').textContent = `${this.completedFiles} of ${this.totalFiles} files completed (${pct}%)`;
    
    if (this.status === 'completed') {
      document.querySelector('.ump-title').textContent = '✅ Upload Complete';
      document.getElementById('ump-btn-pause').classList.add('hidden');
      document.getElementById('ump-btn-resume').classList.add('hidden');
      document.getElementById('ump-btn-cancel').classList.add('hidden');
      document.getElementById('ump-btn-close').classList.remove('hidden');
    }
  }

  processNext() {
    if (this.status === 'paused' || this.status === 'canceled') return;

    // Find next pending file
    while (this.currentIndex < this.queue.length && this.queue[this.currentIndex].status !== 'pending') {
      this.currentIndex++;
    }

    if (this.currentIndex >= this.queue.length) {
      this.status = 'completed';
      this.updateMainStats();
      setTimeout(() => this.onComplete(), 1000);
      return;
    }

    const item = this.queue[this.currentIndex];
    this.uploadItem(item);
  }

  uploadItem(item) {
    item.status = 'uploading';
    item.uploadedBytes = item.uploadedBytes || 0;
    this.updateFileUI(item);
    this.uploadNextChunk(item);
  }

  uploadNextChunk(item) {
    if (this.status !== 'uploading' || item.status !== 'uploading') return;

    const chunkSize = 2 * 1024 * 1024; // 2MB
    const start = item.uploadedBytes;
    const end = Math.min(start + chunkSize, item.file.size);
    const chunk = item.file.slice(start, end);
    const totalChunks = Math.ceil(item.file.size / chunkSize);
    const chunkIndex = Math.floor(start / chunkSize);

    const fd = new FormData();
    fd.append('file', chunk, item.relPath);
    fd.append('filename', item.relPath.split('/').pop() || item.file.name);
    fd.append('total_size', item.file.size);
    fd.append('chunk_index', chunkIndex);
    fd.append('total_chunks', totalChunks);
    fd.append('chunk_offset', start);

    if (this.isShared) {
      fd.append('subpath', this.subpath);
    } else {
      fd.append('folder', this.destFolder);
    }
    fd.append('rel_path', item.relPath);

    this.activeXhr = new XMLHttpRequest();
    this.activeXhr.open('POST', this.uploadUrl);
    this.activeXhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
    const csrfMeta = document.querySelector('meta[name="csrf-token"]');
    if (csrfMeta) {
      this.activeXhr.setRequestHeader('X-CSRF-Token', csrfMeta.getAttribute('content'));
    }

    this.activeXhr.upload.addEventListener('progress', (e) => {
      if (e.lengthComputable) {
        const totalLoaded = start + e.loaded;
        const pct = Math.round((totalLoaded / item.file.size) * 100);
        item.progress = pct;
        const bar = document.getElementById(`${item.id}-progress-bar`);
        if (bar) bar.style.width = pct + '%';
        const badge = document.getElementById(`${item.id}-badge`);
        if (badge) badge.textContent = pct + '%';
      }
    });

    this.activeXhr.onload = () => {
      let isSuccess = false;
      try {
        const r = JSON.parse(this.activeXhr.responseText);
        isSuccess = r.status === 'success' || r.status === 'chunk_success';
      } catch {
        isSuccess = this.activeXhr.status === 200;
      }

      if (isSuccess) {
        item.uploadedBytes = end;
        if (end >= item.file.size) {
          item.status = 'complete';
          this.completedFiles++;
          this.finalizeItem(item);
        } else {
          // Upload next chunk
          this.uploadNextChunk(item);
        }
      } else {
        item.status = 'error';
        this.finalizeItem(item);
      }
    };

    this.activeXhr.onerror = () => {
      item.status = 'error';
      this.finalizeItem(item);
    };

    this.activeXhr.send(fd);
  }

  finalizeItem(item) {
    this.activeXhr = null;
    this.updateFileUI(item);
    this.updateMainStats();
    
    // Proceed to next file
    this.currentIndex++;
    this.processNext();
  }

  updateFileUI(item) {
    const row = document.getElementById(item.id);
    if (!row) return;

    const badge = document.getElementById(`${item.id}-badge`);
    const bar = document.getElementById(`${item.id}-progress-bar`);

    row.className = `ump-file-row ump-status-${item.status}`;
    
    if (item.status === 'complete') {
      badge.textContent = '✅ Done';
      bar.style.width = '100%';
    } else if (item.status === 'error') {
      badge.textContent = '❌ Failed';
    } else if (item.status === 'canceled') {
      badge.textContent = '🚫 Canceled';
      bar.style.width = '0%';
    } else if (item.status === 'paused') {
      badge.textContent = '⏸️ Paused';
    } else if (item.status === 'uploading') {
      badge.textContent = `${item.progress}%`;
    }
  }

  pause() {
    if (this.status !== 'uploading') return;
    this.status = 'paused';
    
    document.getElementById('ump-btn-pause').classList.add('hidden');
    document.getElementById('ump-btn-resume').classList.remove('hidden');
    
    // Pause: abort current active upload and mark as paused
    if (this.activeXhr) {
      this.activeXhr.abort();
      this.activeXhr = null;
      
      const item = this.queue[this.currentIndex];
      if (item) {
        item.status = 'paused';
        this.updateFileUI(item);
      }
    }
  }

  resume() {
    if (this.status !== 'paused') return;
    this.status = 'uploading';
    
    document.getElementById('ump-btn-pause').classList.remove('hidden');
    document.getElementById('ump-btn-resume').classList.add('hidden');
    
    // Change current paused item back to pending so it gets picked up
    const item = this.queue[this.currentIndex];
    if (item && item.status === 'paused') {
      item.status = 'pending';
    }
    
    this.processNext();
  }

  cancelFile(id) {
    const index = this.queue.findIndex(item => item.id === id);
    if (index === -1) return;

    const item = this.queue[index];
    if (item.status === 'complete' || item.status === 'canceled') return;

    if (item.status === 'uploading') {
      // Abort active upload
      if (this.activeXhr) {
        this.activeXhr.abort();
        this.activeXhr = null;
      }
      item.status = 'canceled';
      this.updateFileUI(item);
      this.currentIndex++;
      this.processNext();
    } else {
      item.status = 'canceled';
      this.updateFileUI(item);
    }
  }

  cancelAll() {
    this.status = 'canceled';
    
    if (this.activeXhr) {
      this.activeXhr.abort();
      this.activeXhr = null;
    }

    this.queue.forEach(item => {
      if (item.status === 'pending' || item.status === 'uploading') {
        item.status = 'canceled';
        this.updateFileUI(item);
      }
    });

    document.querySelector('.ump-title').textContent = '🛑 Uploads Canceled';
    document.getElementById('ump-btn-pause').classList.add('hidden');
    document.getElementById('ump-btn-resume').classList.add('hidden');
    document.getElementById('ump-btn-cancel').classList.add('hidden');
    document.getElementById('ump-btn-close').classList.remove('hidden');
  }
}
