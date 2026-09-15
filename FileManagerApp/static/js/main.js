/* main.js – handles AJAX upload with progress, drag-and-drop, and UI interactions */

document.addEventListener('DOMContentLoaded', () => {

  /* ── Upload with progress ──────────────────────────────────────────────── */
  const uploadForm     = document.getElementById('uploadForm');
  const fileInput      = document.getElementById('fileInput');
  const dropZone       = document.getElementById('dropZone');
  const dropLabel      = document.getElementById('dropLabel');
  const progressWrap   = document.getElementById('progressWrap');
  const progressBar    = document.getElementById('progressBar');
  const progressText   = document.getElementById('progressText');
  const uploadStatus   = document.getElementById('uploadStatus');

  // Drag-and-drop support on the drop zone
  if (dropZone) {
    dropZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropZone.classList.add('drag-over');
    });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
    dropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropZone.classList.remove('drag-over');
      if (e.dataTransfer.files.length) {
        fileInput.files = e.dataTransfer.files;
        updateDropLabel(e.dataTransfer.files[0].name);
      }
    });
    dropZone.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', () => {
      if (fileInput.files.length) {
        updateDropLabel(fileInput.files[0].name);
        uploadForm.dispatchEvent(new Event('submit'));
      }
    });
  }

  function updateDropLabel(name) {
    if (dropLabel) dropLabel.textContent = '📄 ' + name;
  }

  if (uploadForm) {
    uploadForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const file = fileInput.files[0];
      if (!file) {
        showStatus('Please choose a file first.', 'error');
        return;
      }

      const destFolderInput = uploadForm.querySelector('input[name="folder"]');
      const destFolder = destFolderInput ? destFolderInput.value : '';

      fetch('/api/upload_rules?folder=' + encodeURIComponent(destFolder))
        .then(res => res.json())
        .then(rules => {
          const maxFileSize = rules.max_file_size_mb ? parseFloat(rules.max_file_size_mb) * 1024 * 1024 : null;
          const blockedExts = (rules.blocked_extensions || []).map(e => e.trim().toLowerCase());
          
          if (file.name.includes('.')) {
            const ext = file.name.split('.').pop().toLowerCase();
            if (blockedExts.includes(ext)) {
              showStatus('❌ File format ".' + ext + '" is blocked by administrator.', 'error');
              return;
            }
          }
          
          if (maxFileSize && file.size > maxFileSize) {
            showStatus('❌ your file size is larger then the admin allow please contact the administrator..', 'error');
            return;
          }
          
          const queue = new FileVaultUploadQueue({
            uploadUrl: uploadForm.action,
            destFolder: destFolder,
            onComplete: () => window.location.reload()
          });
          queue.addFiles([file]);
        })
        .catch(err => {
          console.error('Error fetching upload rules:', err);
          showStatus('❌ Could not validate upload rules.', 'error');
        });
    });
  }

  function setProgress(pct) {
    progressBar.style.width = pct + '%';
    progressText.textContent = pct + '%';
  }

  function showStatus(msg, type) {
    if (!uploadStatus) return;
    uploadStatus.textContent = msg;
    uploadStatus.className = 'upload-status ' + type;
    uploadStatus.classList.remove('hidden');
  }

  /* ── Delete confirmation ───────────────────────────────────────────────── */
  document.querySelectorAll('.delete-form').forEach(form => {
    form.addEventListener('submit', (e) => {
      if (!confirm('Delete "' + form.dataset.name + '"? This cannot be undone.')) {
        e.preventDefault();
      }
    });
  });

  /* ── Folder creation modal ─────────────────────────────────────────────── */
  const newFolderBtn   = document.getElementById('newFolderBtn');
  const folderModal    = document.getElementById('folderModal');
  const closeFolderBtn = document.getElementById('closeFolderBtn');

  if (newFolderBtn && folderModal) {
    newFolderBtn.addEventListener('click', () => {
      folderModal.classList.remove('hidden');
      folderModal.querySelector('input[name="folder_name"]').focus();
    });
    if (closeFolderBtn) {
      closeFolderBtn.addEventListener('click', () => folderModal.classList.add('hidden'));
    }
    folderModal.addEventListener('click', (e) => {
      if (e.target === folderModal) folderModal.classList.add('hidden');
    });
  }

  /* ── Search / filter ───────────────────────────────────────────────────── */
  const searchInput = document.getElementById('searchInput');
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      const q = searchInput.value.toLowerCase();
      document.querySelectorAll('.file-row, .folder-row').forEach(row => {
        const name = row.dataset.name ? row.dataset.name.toLowerCase() : '';
        row.style.display = name.includes(q) ? '' : 'none';
      });
    });
  }

  /* ── Topbar Upload Dropdown ─────────────────────────────────────────────── */
  const uploadDropdownBtn = document.getElementById('uploadDropdownBtn');
  const uploadDropdownMenu = document.getElementById('uploadDropdownMenu');
  if (uploadDropdownBtn && uploadDropdownMenu) {
    uploadDropdownBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      uploadDropdownMenu.classList.toggle('show');
    });
    document.addEventListener('click', (e) => {
      if (!uploadDropdownBtn.contains(e.target) && !uploadDropdownMenu.contains(e.target)) {
        uploadDropdownMenu.classList.remove('show');
      }
    });
  }
  /* ── Double Click Navigation & Local Application Launching ────────────── */
  document.addEventListener('dblclick', (e) => {
    const row = e.target.closest('.file-row, .folder-row, .grid-card');
    if (!row) return;
    
    // Ignore double clicks on inputs, buttons, or links
    if (e.target.closest('input, button, a')) return;
    
    const checkEl = row.querySelector('.row-check') || row.querySelector('input[type="checkbox"]');
    
    // Fallback search for grid view paths if no checkEl exists
    let path = '';
    let type = '';
    
    if (checkEl) {
      path = checkEl.dataset.path;
      type = checkEl.dataset.type;
    } else {
      // In grid view, find target paths from details or buttons
      const starBtn = row.querySelector('.star-btn');
      if (starBtn) {
        // extract path from toggleStar('path', ...)
        const match = starBtn.getAttribute('onclick').match(/'([^']+)'/);
        if (match) path = match[1];
      }
      type = row.classList.contains('folder-row') ? 'folder' : 'file';
    }
    
    if (!path) return;
    
    if (type === 'folder') {
      const folderLink = row.querySelector('.folder-link') || row.querySelector('a');
      if (folderLink) {
        window.location.href = folderLink.href;
      }
    } else {
      const fd = new FormData();
      fd.append('filepath', path);
      
      const csrfMeta = document.querySelector('meta[name="csrf-token"]');
      const csrfToken = csrfMeta ? csrfMeta.getAttribute('content') : '';

      fetch('/api/open_local', { 
        method: 'POST', 
        headers: {
          'X-CSRF-Token': csrfToken
        },
        body: fd 
      })
        .then(r => r.json())
        .then(res => {
          if (res.status === 'success') {
            console.log('Local launch success:', res.msg);
          } else {
            triggerWebPreview(row, path);
          }
        })
        .catch(err => {
          console.error('Local launch error, falling back to web preview:', err);
          triggerWebPreview(row, path);
        });
    }
  });

  function triggerWebPreview(row, path) {
    const name = row.dataset.name;
    const previewLink = row.querySelector('.preview-link') || row.querySelector('.grid-thumb');
    if (previewLink) {
      previewLink.click();
    } else {
      openDetails(path);
    }
  }

});

/* ── Upload panel toggle (collapsible) ──────────────────────────────────── */
function toggleUploadPanel() {
  const body   = document.getElementById('uploadPanelBody');
  const toggle = document.getElementById('uploadPanelToggle');
  if (!body) return;
  const isOpen = body.style.display !== 'none';
  body.style.display = isOpen ? 'none' : '';
  if (toggle) toggle.textContent = isOpen ? '▼ Expand' : '▲ Collapse';
}

/* ── Upload tab switcher ────────────────────────────────────────────────── */
function switchTab(tab) {
  const panelFile   = document.getElementById('panelFile');
  const panelFolder = document.getElementById('panelFolder');
  const tabFile     = document.getElementById('tabFile');
  const tabFolder   = document.getElementById('tabFolder');
  // Make sure the panel body is open first
  const body = document.getElementById('uploadPanelBody');
  if (body && body.style.display === 'none') toggleUploadPanel();

  if (tab === 'file') {
    if (panelFile)   panelFile.style.display   = '';
    if (panelFolder) panelFolder.style.display = 'none';
    if (tabFile)     tabFile.classList.add('active');
    if (tabFolder)   tabFolder.classList.remove('active');
  } else {
    if (panelFile)   panelFile.style.display   = 'none';
    if (panelFolder) panelFolder.style.display = '';
    if (tabFile)     tabFile.classList.remove('active');
    if (tabFolder)   tabFolder.classList.add('active');
  }
}

window.handleFileClick = function(path, filename) {
  const ext = filename.split('.').pop().toLowerCase();
  
  // Browser previewable
  const browserFriendly = [
    'png','jpg','jpeg','gif','svg','webp','bmp',
    'mp4','webm','mov','mp3','wav','ogg','flac',
    'pdf','txt','md','csv','json','xml','py','js','html','css','log'
  ];
  
  if (browserFriendly.includes(ext)) {
    const encodedPath = path.split('/').map(encodeURIComponent).join('/');
    openPreview('/preview/' + encodedPath, filename);
  } else {
    const fd = new FormData();
    fd.append('filepath', path);
    
    const csrfMeta = document.querySelector('meta[name="csrf-token"]');
    const csrfToken = csrfMeta ? csrfMeta.getAttribute('content') : '';

    fetch('/api/open_local', {
      method: 'POST',
      headers: {
        'X-CSRF-Token': csrfToken
      },
      body: fd
    })
    .then(r => r.json())
    .then(res => {
      if (res.status === 'success') {
        console.log('Opened locally:', res.msg);
      } else {
        console.warn('Could not open file locally:', res.msg);
        openDetails(path);
      }
    })
    .catch(err => {
      console.error('Error opening locally:', err);
      openDetails(path);
    });
  }
};

/* ── Bulk Actions ────────────────────────────────────────────────────────── */
window.toggleSelectAll = function(cb) {
  document.querySelectorAll('.row-check').forEach(c=>c.checked=cb.checked);
  window.updateBulkBar();
};
document.addEventListener('change', e => { if(e.target.classList.contains('row-check')) window.updateBulkBar(); });
window.updateBulkBar = function() {
  const sel = document.querySelectorAll('.row-check:checked');
  const bar = document.getElementById('bulkBar');
  const count = document.getElementById('bulkCount');
  if (count) count.textContent = sel.length+' selected';
  if (bar) bar.classList.toggle('hidden', sel.length === 0);
};
window.clearSelection = function() {
  document.querySelectorAll('.row-check').forEach(c=>c.checked=false);
  const sa = document.getElementById('selectAll');
  if (sa) sa.checked=false;
  window.updateBulkBar();
};
window.bulkDownloadZip = function() {
  const sel = Array.from(document.querySelectorAll('.row-check:checked'));
  if (!sel.length) { alert('Select at least one item to download.'); return; }

  const batchPaths = document.getElementById('batchPaths');
  const form       = document.getElementById('batchDownloadForm');
  if (!batchPaths || !form) { alert('Download form not found.'); return; }

  // Populate paths and submit — form.submit() streams directly to the
  // browser download manager without loading the ZIP into memory, which is
  // essential for large files (multi-GB). fetch()+blob would fail for those.
  batchPaths.value = sel.map(c => c.dataset.path).join(',');

  // Show loading state on the button
  const btn = document.querySelector('[onclick="bulkDownloadZip()"]');
  if (btn) { btn.textContent = '⏳ Preparing ZIP…'; btn.disabled = true; }

  form.submit();

  // Re-enable button after a short delay so the user can retry if needed
  setTimeout(function() {
    if (btn) { btn.textContent = '⬇ Download ZIP'; btn.disabled = false; }
  }, 4000);
};
window.bulkDelete = function() {
  const sel = Array.from(document.querySelectorAll('.row-check:checked'));
  if(!sel.length) return;
  if(!confirm('Delete '+sel.length+' selected item(s)? They will be moved to Trash.')) return;
  
  const paths = sel.map(c => c.dataset.path).join(',');
  const token = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
  
  const fd = new FormData();
  fd.append('csrf_token', token);
  fd.append('paths', paths);
  
  // Disable button to prevent double submits
  const btn = document.querySelector('[onclick="bulkDelete()"]');
  if (btn) { btn.textContent = '⏳ Deleting…'; btn.disabled = true; }
  
  fetch('/batch_delete', {
    method: 'POST',
    body: fd
  }).then(response => {
    window.location.reload();
  }).catch(err => {
    alert('Delete failed: ' + err);
    window.location.reload();
  });
};
