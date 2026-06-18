// Secret Remover - Neon Edition
// v2: Web Worker scanning (with cancel), folder upload, no FileSaver dependency.
// Pure scanning logic lives in scan-core.js (shared with scanner-worker.js).

// [NEW] Minimal saveAs for modern browsers — replaces the FileSaver.js CDN
// dependency (one less third-party script to trust on a security tool).
if (typeof window !== 'undefined' && typeof window.saveAs === 'undefined') {
    window.saveAs = function (blob, filename) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 10000);
    };
}

class SecretRemover {
    constructor() {
        this.zip = null;
        this.findings = [];
        this.processedFiles = 0;
        this.totalFiles = 0;
        this.selectedFindings = new Set();
        this.scanMessages = [];
        this.scanLabel = '';
        this.cancelled = false;

        // [NEW] Worker state. Falls back to main-thread scanning if Workers
        // are unavailable (e.g. opening index.html via file://).
        this.worker = null;
        this.workerBroken = false;

        // Main-thread fallback still needs 'd'-flagged regexes.
        ScanCore.prepareRegexWithIndices(SECRET_PATTERNS);

        this.initializeUI();
    }

    initializeUI() {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.setupEventListeners());
        } else {
            this.setupEventListeners();
        }
    }

    setupEventListeners() {
        const dropzone = document.getElementById('dropzone');
        const fileInput = document.getElementById('fileInput');
        const folderInput = document.getElementById('folderInput');
        const folderLink = document.getElementById('folderLink');
        const downloadBtn = document.getElementById('downloadBtn');
        const resetBtn = document.getElementById('resetBtn');
        const cancelScanBtn = document.getElementById('cancelScanBtn');
        const exportJsonBtn = document.getElementById('exportJsonBtn');
        const exportCsvBtn = document.getElementById('exportCsvBtn');
        const selectAllBtn = document.getElementById('selectAllBtn');
        const deselectAllBtn = document.getElementById('deselectAllBtn');
        const deselectEntropyBtn = document.getElementById('deselectEntropyBtn');
        const rescanBtn = document.getElementById('rescanBtn');

        // Drag and drop
        dropzone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropzone.classList.add('dragover');
        });

        dropzone.addEventListener('dragleave', () => {
            dropzone.classList.remove('dragover');
        });

        dropzone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropzone.classList.remove('dragover');
            this.handleDrop(e.dataTransfer);
        });

        dropzone.addEventListener('click', () => fileInput.click());

        // Keyboard accessibility for the dropzone.
        dropzone.setAttribute('tabindex', '0');
        dropzone.setAttribute('role', 'button');
        dropzone.setAttribute('aria-label', 'Upload a ZIP file or folder to scan');
        dropzone.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                fileInput.click();
            }
        });

        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                this.handleZipFile(e.target.files[0]);
            }
        });

        // [NEW] Folder picker (no need to zip first).
        if (folderLink && folderInput) {
            folderLink.addEventListener('click', (e) => {
                e.stopPropagation();
                folderInput.click();
            });
            folderInput.addEventListener('change', (e) => {
                if (e.target.files.length > 0) {
                    const entries = Array.from(e.target.files).map(f => ({
                        path: f.webkitRelativePath || f.name,
                        file: f
                    }));
                    this.handleFolderEntries(entries);
                }
            });
        }

        downloadBtn.addEventListener('click', () => this.downloadCleanedZip());
        resetBtn.addEventListener('click', () => this.reset());
        if (cancelScanBtn) {
            // [NEW] Hard-cancel: terminates the worker mid-regex if needed.
            cancelScanBtn.addEventListener('click', () => this.cancelScan());
        }
        exportJsonBtn.addEventListener('click', () => this.exportReport('json'));
        exportCsvBtn.addEventListener('click', () => this.exportReport('csv'));
        selectAllBtn.addEventListener('click', () => this.selectAllFindings(true));
        deselectAllBtn.addEventListener('click', () => this.selectAllFindings(false));
        if (deselectEntropyBtn) {
            deselectEntropyBtn.addEventListener('click', () => this.deselectEntropyFindings());
        }
        rescanBtn.addEventListener('click', () => this.rescanWithCustomPattern());
    }

    // Non-blocking toast instead of alert() where possible.
    notify(message, isError = false) {
        let toast = document.getElementById('srToast');
        if (!toast) {
            toast = document.createElement('div');
            toast.id = 'srToast';
            toast.setAttribute('role', 'status');
            toast.setAttribute('aria-live', 'polite');
            toast.style.cssText =
                'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);' +
                'padding:12px 20px;font-family:monospace;font-size:14px;' +
                'z-index:9999;max-width:90vw;transition:opacity .3s;pointer-events:none;';
            document.body.appendChild(toast);
        }
        toast.classList.toggle('error', isError);
        toast.textContent = message;
        toast.style.opacity = '1';
        clearTimeout(this._toastTimer);
        this._toastTimer = setTimeout(() => { toast.style.opacity = '0'; }, 4000);
    }

    /* =====================================================================
       INPUT HANDLING — zip file, dropped folder, or picked folder all end
       up as a JSZip object in this.zip, then runScan() does the rest.
       ===================================================================== */

    handleDrop(dataTransfer) {
        // Folder(s) dropped? (Chrome/Edge/Firefox/Safari support webkitGetAsEntry)
        const items = dataTransfer.items;
        if (items && items.length > 0 && typeof items[0].webkitGetAsEntry === 'function') {
            const entries = [];
            let hasDirectory = false;
            for (const item of items) {
                const entry = item.webkitGetAsEntry();
                if (entry) {
                    entries.push(entry);
                    if (entry.isDirectory) hasDirectory = true;
                }
            }
            if (hasDirectory) {
                this.collectDroppedEntries(entries)
                    .then(files => this.handleFolderEntries(files))
                    .catch(err => this.notify('Could not read dropped folder: ' + err.message, true));
                return;
            }
        }

        if (dataTransfer.files.length > 0) {
            this.handleZipFile(dataTransfer.files[0]);
        }
    }

    // Recursively walk dropped FileSystemEntry trees → [{path, file}]
    async collectDroppedEntries(entries) {
        const files = [];

        const readEntry = (entry, prefix) => new Promise((resolve, reject) => {
            if (entry.isFile) {
                entry.file(f => {
                    files.push({ path: prefix + entry.name, file: f });
                    resolve();
                }, reject);
            } else if (entry.isDirectory) {
                const reader = entry.createReader();
                const readBatch = () => {
                    reader.readEntries(async (batch) => {
                        if (batch.length === 0) { resolve(); return; }
                        for (const child of batch) {
                            await readEntry(child, prefix + entry.name + '/');
                        }
                        readBatch(); // directory readers return results in batches
                    }, reject);
                };
                readBatch();
            } else {
                resolve();
            }
        });

        for (const entry of entries) {
            await readEntry(entry, '');
        }
        return files;
    }

    async handleZipFile(file) {
        if (!file.name.endsWith('.zip')) {
            this.notify('Please upload a ZIP file — or use "select a folder" below the dropzone', true);
            return;
        }

        const MAX_SIZE = 250 * 1024 * 1024; // 250 MB
        if (file.size > MAX_SIZE) {
            const ok = confirm(
                `This ZIP is ${this.formatBytes(file.size)}. Scanning very large ` +
                `archives can take a while. Continue?`
            );
            if (!ok) return;
        }

        try {
            const arrayBuffer = await file.arrayBuffer();
            this.zip = await JSZip.loadAsync(arrayBuffer);
            this.scanLabel = `${file.name} (${this.formatBytes(file.size)})`;
            await this.runScan();
        } catch (error) {
            console.error('Error:', error);
            this.notify('Error reading ZIP: ' + error.message, true);
            this.reset();
        }
    }

    // [NEW] Build an in-memory JSZip from folder files so the rest of the
    // pipeline (scan + cleaned-zip download) is identical to the ZIP path.
    async handleFolderEntries(entries) {
        if (!entries || entries.length === 0) {
            this.notify('That folder appears to be empty', true);
            return;
        }

        let totalSize = 0;
        for (const e of entries) totalSize += e.file.size;
        if (totalSize > 250 * 1024 * 1024) {
            const ok = confirm(
                `This folder is ${this.formatBytes(totalSize)} across ${entries.length} files. ` +
                `Scanning may take a while. Continue?`
            );
            if (!ok) return;
        }

        try {
            const zip = new JSZip();
            for (const { path, file } of entries) {
                // Skip obviously irrelevant trees before they enter memory.
                if (SKIP_PATTERNS.some(p => p.test(path + (path.endsWith('/') ? '' : '/'))) ||
                    SKIP_PATTERNS.some(p => p.test(path))) {
                    continue;
                }
                zip.file(path, file);
            }
            this.zip = zip;
            this.scanLabel = `folder (${entries.length} files, ${this.formatBytes(totalSize)})`;
            await this.runScan();
        } catch (error) {
            console.error('Error:', error);
            this.notify('Error reading folder: ' + error.message, true);
            this.reset();
        }
    }

    /* =====================================================================
       SCANNING — worker-first, main-thread fallback, cancellable.
       ===================================================================== */

    getCustomPatternConfig() {
        const customInput = document.getElementById('customPatternInput');
        const source = customInput ? customInput.value.trim() : '';
        if (!source) return null;

        // Validate on the main thread for instant feedback.
        let testRe;
        try {
            testRe = new RegExp(source);
        } catch (e) {
            this.notify('Invalid Custom Regex: ' + e.message, true);
            return undefined; // signals "abort scan"
        }
        if (testRe.test('')) {
            this.notify('Custom regex matches empty string — make it more specific (use + instead of *)', true);
            return undefined;
        }

        let flags = 'g';
        try { new RegExp('', 'd'); flags = 'gd'; } catch (e) { /* no 'd' support */ }

        return {
            name: 'Custom Keyword / Regex',
            source,
            flags,
            redact: '[CUSTOM_MATCH_REDACTED]',
            category: 'generic'
        };
    }

    // Lazily create the scanning worker. Returns null if unsupported/broken.
    getWorker() {
        if (this.workerBroken) return null;
        if (this.worker) return this.worker;
        try {
            this.worker = new Worker('scanner-worker.js');
            this.worker.onmessage = (e) => {
                if (this._pendingWorker) {
                    const { resolve } = this._pendingWorker;
                    this._pendingWorker = null;
                    resolve(e.data);
                }
            };
            this.worker.onerror = (e) => {
                // Worker file failed to load or crashed — fall back permanently.
                console.warn('Scanner worker error, falling back to main thread:', e.message);
                this.workerBroken = true;
                if (this._pendingWorker) {
                    const { reject } = this._pendingWorker;
                    this._pendingWorker = null;
                    reject(new Error('worker failed'));
                }
                try { this.worker.terminate(); } catch (err) {}
                this.worker = null;
            };
            return this.worker;
        } catch (e) {
            this.workerBroken = true;
            return null;
        }
    }

    workerCall(message) {
        return new Promise((resolve, reject) => {
            this._pendingWorker = { resolve, reject };
            this.worker.postMessage(message);
        });
    }

    async runScan() {
        this.showProgress();
        this.findings = [];
        this.selectedFindings = new Set();
        this.processedFiles = 0;
        this.scanMessages = [];
        this.cancelled = false;

        const customPattern = this.getCustomPatternConfig();
        if (customPattern === undefined) { this.reset(); return; } // invalid regex

        this.addScanMessage(`> Initializing Secret Scanner...`);
        this.addScanMessage(`> Loading: ${this.scanLabel}`);
        if (customPattern) {
            this.addScanMessage(`> Using Custom Pattern: ${customPattern.source}`);
        }

        // Decide scan engine
        let useWorker = !!this.getWorker();
        if (useWorker) {
            try {
                const initReply = await this.workerCall({ type: 'init', customPattern });
                if (initReply.type === 'error') {
                    this.notify(initReply.message, true);
                    this.reset();
                    return;
                }
            } catch (e) {
                useWorker = false;
            }
        }

        // Main-thread fallback needs the custom pattern injected locally.
        let localPatterns = SECRET_PATTERNS;
        if (!useWorker && customPattern) {
            const custom = {
                name: customPattern.name,
                regex: new RegExp(customPattern.source, customPattern.flags),
                redact: customPattern.redact,
                category: customPattern.category
            };
            localPatterns = [custom, ...SECRET_PATTERNS];
        }

        this.addScanMessage(`> Engine: ${useWorker ? 'background worker' : 'main thread'}`);

        try {
            const allPaths = Object.keys(this.zip.files);
            const files = allPaths.filter(path => {
                const zipEntry = this.zip.files[path];
                return !zipEntry.dir && this.shouldScanFile(path);
            });

            this.totalFiles = files.length;

            this.addScanMessage(`> Found ${allPaths.length} total files`);
            this.addScanMessage(`> Scanning ${this.totalFiles} code files...`);
            this.addScanMessage(`>`);

            document.getElementById('scanFiles').textContent = '0';
            document.getElementById('scanSecrets').textContent = '0';

            for (const path of files) {
                if (this.cancelled) return; // cancelScan() already reset the UI

                const zipEntry = this.zip.files[path];
                const content = await zipEntry.async('string');

                // Skip files that decoded as binary (NUL bytes).
                if (content.indexOf('\u0000') !== -1) {
                    this.processedFiles++;
                    this.queueScanStats();
                    continue;
                }

                let fileFindings;
                if (useWorker) {
                    try {
                        const reply = await this.workerCall({ type: 'scanFile', path, content });
                        if (this.cancelled) return;
                        fileFindings = reply.type === 'result' ? reply.findings : [];
                        if (reply.type === 'error') {
                            this.addScanMessage(`> [x] ${this.truncatePath(path)} — ${reply.message}`);
                        }
                    } catch (e) {
                        // Worker died mid-scan — switch to fallback for the rest.
                        useWorker = false;
                        if (customPattern) {
                            const custom = {
                                name: customPattern.name,
                                regex: new RegExp(customPattern.source, customPattern.flags),
                                redact: customPattern.redact,
                                category: customPattern.category
                            };
                            localPatterns = [custom, ...SECRET_PATTERNS];
                        }
                        fileFindings = ScanCore.scanContent(content, path, localPatterns, EntropyDetector);
                    }
                } else {
                    fileFindings = ScanCore.scanContent(content, path, localPatterns, EntropyDetector);
                    if (this.processedFiles % 20 === 0) {
                        await this.sleep(5); // let the UI breathe in fallback mode
                    }
                }

                if (fileFindings.length > 0) {
                    this.addScanMessage(`> [!] ${this.truncatePath(path)} → ${fileFindings.length} secret(s)`);
                }

                this.findings.push(...fileFindings);
                this.processedFiles++;
                this.queueScanStats();
            }

            if (this.cancelled) return;

            this.addScanMessage(`>`);
            this.addScanMessage(`> ═══════════════════════════════`);
            this.addScanMessage(`> SCAN COMPLETE`);
            this.addScanMessage(`> Total Secrets Found: ${this.findings.length}`);
            this.addScanMessage(`> ═══════════════════════════════`);

            this.findings.forEach((f, i) => {
                f.id = i;
                this.selectedFindings.add(i);
            });

            await this.sleep(800);
            if (this.cancelled) return;
            this.showResults();
        } catch (error) {
            console.error('Error:', error);
            this.notify('Error during scan: ' + error.message, true);
            this.reset();
        }
    }

    // [NEW] Hard-cancel the scan. terminate() stops the worker even if it is
    // stuck inside a catastrophic regex — something the main thread could
    // never recover from on its own.
    cancelScan() {
        this.cancelled = true;
        if (this.worker) {
            try { this.worker.terminate(); } catch (e) {}
            this.worker = null; // a fresh worker is created on the next scan
        }
        this._pendingWorker = null;
        this.notify('Scan cancelled');
        this.reset();
    }

    async rescanWithCustomPattern() {
        if (!this.zip) {
            this.notify('No file loaded. Please upload a ZIP or folder first.', true);
            return;
        }
        await this.runScan();
    }

    /* ===================================================================== */

    truncatePath(path) {
        if (path.length > 50) {
            return '...' + path.slice(-47);
        }
        return path;
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    addScanMessage(message) {
        this.scanMessages.push(message);
        const output = document.getElementById('scanOutput');
        if (output) {
            output.textContent = this.scanMessages.slice(-12).join('\n');
            output.scrollTop = output.scrollHeight;
        }
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    shouldScanFile(path) {
        if (this.shouldSkipFile(path)) return false;

        const fileName = path.split('/').pop();

        // Dotenv variants (.env.production, .env.staging, …)
        if (fileName === '.env' || fileName.startsWith('.env.')) {
            return true;
        }

        if (SCANNABLE_FILENAMES.some(name => fileName === name || fileName.endsWith(name))) {
            return true;
        }

        const ext = '.' + fileName.split('.').pop().toLowerCase();
        return SCANNABLE_EXTENSIONS.includes(ext);
    }

    shouldSkipFile(path) {
        return SKIP_PATTERNS.some(pattern => pattern.test(path));
    }

    // Coalesce stat/progress DOM writes into one paint per frame.
    queueScanStats() {
        if (this._statsQueued) return;
        this._statsQueued = true;
        requestAnimationFrame(() => {
            this._statsQueued = false;
            const filesEl = document.getElementById('scanFiles');
            const secretsEl = document.getElementById('scanSecrets');
            if (filesEl) filesEl.textContent = this.processedFiles;
            if (secretsEl) secretsEl.textContent = this.findings.length;
            this.updateProgress(this.processedFiles, this.totalFiles);
        });
    }

    updateProgress(current, total) {
        const fill = document.getElementById('progressFill');
        const text = document.getElementById('progressText');
        const percent = document.getElementById('progressPercent');

        const pct = total > 0 ? Math.round((current / total) * 100) : 0;
        if (fill) fill.style.width = pct + '%';
        if (text) text.textContent = `Scanning: ${current} / ${total} files`;
        if (percent) percent.textContent = pct + '%';
    }

    showProgress() {
        document.getElementById('uploadSection').classList.add('hidden');
        document.getElementById('progressSection').classList.remove('hidden');
        document.getElementById('resultsSection').classList.add('hidden');
    }

    showResults() {
        document.getElementById('progressSection').classList.add('hidden');
        document.getElementById('resultsSection').classList.remove('hidden');

        this.renderSummary();
        this.renderCategories();
        this.renderFindings();
        this.updateCounts();
    }

    renderSummary() {
        const container = document.getElementById('summaryCards');

        const uniqueCategories = new Set(this.findings.map(f => f.category)).size;
        const affectedFiles = new Set(this.findings.map(f => f.file)).size;

        container.innerHTML = `
            <div class="summary-card cyan">
                <div class="card-icon">📁</div>
                <div class="card-value">${this.processedFiles}</div>
                <div class="card-label">FILES SCANNED</div>
            </div>
            <div class="summary-card pink">
                <div class="card-icon">🔐</div>
                <div class="card-value">${this.findings.length}</div>
                <div class="card-label">SECRETS FOUND</div>
            </div>
            <div class="summary-card green">
                <div class="card-icon">📄</div>
                <div class="card-value">${affectedFiles}</div>
                <div class="card-label">FILES AFFECTED</div>
            </div>
            <div class="summary-card purple">
                <div class="card-icon">📊</div>
                <div class="card-value">${uniqueCategories}</div>
                <div class="card-label">CATEGORIES</div>
            </div>
        `;
    }

    renderCategories() {
        const container = document.getElementById('categoryCards');

        if (this.findings.length === 0) {
            container.innerHTML = '<p style="color: var(--neon-green); text-align: center; padding: 20px;">No secrets detected in your code!</p>';
            return;
        }

        const counts = {};
        for (const f of this.findings) {
            counts[f.category] = (counts[f.category] || 0) + 1;
        }

        const icons = {
            cloud: '☁️',
            vcs: '📦',
            communication: '💬',
            payment: '💳',
            payment_india: '🇮🇳',
            sms_india: '📲',
            database: '🗄️',
            privateKeys: '🔑',
            apiKeys: '🔌',
            ci_cd: '⚙️',
            ai_ml: '🤖',
            generic: '📝',
            entropy: '🎲'
        };

        let html = '';
        const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);

        for (const [cat, count] of sorted) {
            const catInfo = PATTERN_CATEGORIES[cat] || { name: cat, description: '' };
            html += `
                <div class="category-card">
                    <div class="category-icon">${icons[cat] || '📋'}</div>
                    <div class="category-info">
                        <div class="category-name">${catInfo.name}</div>
                        <div class="category-count">${count} secret${count > 1 ? 's' : ''}</div>
                    </div>
                </div>
            `;
        }

        container.innerHTML = html;
    }

    renderFindings() {
        const container = document.getElementById('findings');

        if (this.findings.length === 0) {
            container.innerHTML = '<div class="no-findings">✓ NO SECRETS DETECTED</div>';
            return;
        }

        const grouped = {};
        for (const f of this.findings) {
            if (!grouped[f.file]) grouped[f.file] = [];
            grouped[f.file].push(f);
        }

        let html = '';
        for (const [file, findings] of Object.entries(grouped)) {
            const selectedCount = findings.filter(f => this.selectedFindings.has(f.id)).length;

            html += `
                <div class="finding-file">
                    <div class="file-header">
                        <span class="file-icon">📄</span>
                        <span class="file-path">${this.escapeHtml(file)}</span>
                        <span class="file-count">${selectedCount}/${findings.length}</span>
                    </div>
            `;

            for (const finding of findings) {
                const isSelected = this.selectedFindings.has(finding.id);
                const catInfo = PATTERN_CATEGORIES[finding.category] || { name: finding.category };

                html += `
                    <div class="finding-item ${isSelected ? 'selected' : ''}" data-id="${finding.id}">
                        <label class="checkbox-wrapper">
                            <input type="checkbox" ${isSelected ? 'checked' : ''} data-id="${finding.id}">
                            <span class="custom-checkbox"></span>
                        </label>
                        <div class="finding-content">
                            <div class="finding-meta">
                                <span class="finding-type">${this.escapeHtml(finding.type)}</span>
                                <span class="finding-category">${catInfo.name}</span>
                                <span class="finding-line">Line ${finding.line}</span>
                            </div>
                            <div class="finding-preview">
                                <code>${this.escapeHtml(finding.preview)}</code>
                                <span class="arrow">→</span>
                                <code class="redacted">${this.escapeHtml(finding.redact)}</code>
                            </div>
                        </div>
                    </div>
                `;
            }

            html += '</div>';
        }

        container.innerHTML = html;

        container.querySelectorAll('input[type="checkbox"]').forEach(cb => {
            cb.addEventListener('change', (e) => {
                const id = parseInt(e.target.dataset.id);
                if (e.target.checked) {
                    this.selectedFindings.add(id);
                    e.target.closest('.finding-item').classList.add('selected');
                } else {
                    this.selectedFindings.delete(id);
                    e.target.closest('.finding-item').classList.remove('selected');
                }
                this.updateCounts();
                this.updateFileHeaders();
            });
        });
    }

    updateFileHeaders() {
        document.querySelectorAll('.finding-file').forEach(fileEl => {
            const checkboxes = fileEl.querySelectorAll('input[type="checkbox"]');
            const selected = Array.from(checkboxes).filter(cb => cb.checked).length;
            const countEl = fileEl.querySelector('.file-count');
            if (countEl) {
                countEl.textContent = `${selected}/${checkboxes.length}`;
            }
        });
    }

    updateCounts() {
        const removeCount = this.selectedFindings.size;
        const keepCount = this.findings.length - removeCount;

        document.getElementById('removeCount').textContent = removeCount;
        document.getElementById('keepCount').textContent = keepCount;

        const btnText = document.querySelector('#downloadBtn .btn-text');
        if (btnText) {
            btnText.textContent = removeCount > 0
                ? `DOWNLOAD CLEAN CODE (${removeCount} REMOVED)`
                : 'DOWNLOAD (NO CHANGES)';
        }
    }

    selectAllFindings(select) {
        if (select) {
            this.findings.forEach(f => this.selectedFindings.add(f.id));
        } else {
            this.selectedFindings.clear();
        }
        this.renderFindings();
        this.updateCounts();
    }

    // Remove every high-entropy finding from the selection at once.
    deselectEntropyFindings() {
        const entropyFindings = this.findings.filter(f => f.isEntropy || f.category === 'entropy');

        if (entropyFindings.length === 0) {
            this.notify('No high-entropy findings in this scan');
            return;
        }

        let removed = 0;
        for (const f of entropyFindings) {
            if (this.selectedFindings.has(f.id)) {
                this.selectedFindings.delete(f.id);
                removed++;
            }
        }

        this.renderFindings();
        this.updateCounts();

        this.notify(removed > 0
            ? `Deselected ${removed} high-entropy finding${removed > 1 ? 's' : ''}`
            : 'All high-entropy findings were already deselected');
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    async downloadCleanedZip() {
        if (!this.zip) return;

        try {
            const cleanedZip = new JSZip();

            for (const path of Object.keys(this.zip.files)) {
                const zipEntry = this.zip.files[path];

                if (zipEntry.dir) {
                    cleanedZip.folder(path);
                    continue;
                }

                if (this.shouldSkipFile(path)) {
                    const content = await zipEntry.async('uint8array');
                    cleanedZip.file(path, content);
                    continue;
                }

                if (this.shouldScanFile(path)) {
                    let content = await zipEntry.async('string');

                    // Apply redactions by redactStart/redactEnd (value-only
                    // spans), sorted descending so earlier indices stay valid.
                    const fileFindings = this.findings
                        .filter(f => f.file === path && this.selectedFindings.has(f.id))
                        .sort((a, b) => b.redactStart - a.redactStart);

                    for (const finding of fileFindings) {
                        content = content.substring(0, finding.redactStart) +
                            finding.redact +
                            content.substring(finding.redactEnd);
                    }

                    cleanedZip.file(path, content);
                } else {
                    const content = await zipEntry.async('uint8array');
                    cleanedZip.file(path, content);
                }
            }

            const blob = await cleanedZip.generateAsync({
                type: 'blob',
                compression: 'DEFLATE',
                compressionOptions: { level: 6 }
            });

            saveAs(blob, 'cleaned-source.zip');
            this.notify(`Cleaned ZIP downloaded — ${this.selectedFindings.size} secret(s) redacted`);
        } catch (error) {
            console.error('Error:', error);
            this.notify('Error creating ZIP: ' + error.message, true);
        }
    }

    // Guard CSV cells against spreadsheet formula injection.
    csvSafe(value) {
        const str = String(value);
        if (/^[=+\-@\t\r]/.test(str)) {
            return "'" + str;
        }
        return str;
    }

    exportReport(format) {
        if (this.findings.length === 0) {
            this.notify('No findings to export', true);
            return;
        }

        const data = this.findings.map(f => ({
            file: f.file,
            line: f.line,
            type: f.type,
            category: PATTERN_CATEGORIES[f.category]?.name || f.category,
            preview: f.preview,
            willRemove: this.selectedFindings.has(f.id),
            isEntropy: f.isEntropy || false
        }));

        let content, filename, mimeType;

        if (format === 'json') {
            content = JSON.stringify({
                generatedAt: new Date().toISOString(),
                tool: 'Secret Remover - Neon Edition',
                totalFindings: this.findings.length,
                toRemove: this.selectedFindings.size,
                filesScanned: this.processedFiles,
                findings: data
            }, null, 2);
            filename = 'secret-scan-report.json';
            mimeType = 'application/json';
        } else {
            const headers = ['File', 'Line', 'Type', 'Category', 'Preview', 'Will Remove'];
            const rows = data.map(r => [
                `"${this.csvSafe(r.file).replace(/"/g, '""')}"`,
                r.line,
                `"${this.csvSafe(r.type).replace(/"/g, '""')}"`,
                `"${this.csvSafe(r.category).replace(/"/g, '""')}"`,
                `"${this.csvSafe(r.preview).replace(/"/g, '""')}"`,
                r.willRemove
            ]);
            content = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
            filename = 'secret-scan-report.csv';
            mimeType = 'text/csv';
        }

        const blob = new Blob([content], { type: mimeType });
        saveAs(blob, filename);
    }

    reset() {
        this.zip = null;
        this.scanLabel = '';
        this.findings = [];
        this.selectedFindings = new Set();
        this.processedFiles = 0;
        this.totalFiles = 0;
        this.scanMessages = [];

        document.getElementById('uploadSection').classList.remove('hidden');
        document.getElementById('progressSection').classList.add('hidden');
        document.getElementById('resultsSection').classList.add('hidden');
        document.getElementById('fileInput').value = '';
        const folderInput = document.getElementById('folderInput');
        if (folderInput) folderInput.value = '';
        const customInput = document.getElementById('customPatternInput');
        if (customInput) customInput.value = '';
        document.getElementById('scanOutput').textContent = '';
    }
}

// Initialize
const app = new SecretRemover();
