// Secret Remover - Neon Edition

class SecretRemover {
    constructor() {
        this.zip = null;
        this.findings = [];
        this.processedFiles = 0;
        this.totalFiles = 0;
        this.selectedFindings = new Set();
        this.scanMessages = [];

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
        const downloadBtn = document.getElementById('downloadBtn');
        const resetBtn = document.getElementById('resetBtn');
        const exportJsonBtn = document.getElementById('exportJsonBtn');
        const exportCsvBtn = document.getElementById('exportCsvBtn');
        const selectAllBtn = document.getElementById('selectAllBtn');
        const deselectAllBtn = document.getElementById('deselectAllBtn');
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
            if (e.dataTransfer.files.length > 0) {
                this.handleFile(e.dataTransfer.files[0]);
            }
        });

        dropzone.addEventListener('click', () => fileInput.click());

        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                this.handleFile(e.target.files[0]);
            }
        });

        downloadBtn.addEventListener('click', () => this.downloadCleanedZip());
        resetBtn.addEventListener('click', () => this.reset());
        exportJsonBtn.addEventListener('click', () => this.exportReport('json'));
        exportCsvBtn.addEventListener('click', () => this.exportReport('csv'));
        selectAllBtn.addEventListener('click', () => this.selectAllFindings(true));
        deselectAllBtn.addEventListener('click', () => this.selectAllFindings(false));
        rescanBtn.addEventListener('click', () => this.rescanWithCustomPattern());
    }

    async handleFile(file) {
        if (!file.name.endsWith('.zip')) {
            alert('Please upload a ZIP file');
            return;
        }
        this.currentFile = file;

        this.showProgress();
        this.findings = [];
        this.selectedFindings = new Set();
        this.processedFiles = 0;
        this.scanMessages = [];

        // Custom pattern (only used during re-scan)
        const customInput = document.getElementById('customPatternInput');
        const customRegexInput = customInput ? customInput.value.trim() : '';
        let customPatternObj = null;
        if (customRegexInput) {
            try {
                // Remove existing custom pattern if any
                const existingIndex = SECRET_PATTERNS.findIndex(p => p.name === "Custom Keyword / Regex");
                if (existingIndex > -1) {
                    SECRET_PATTERNS.splice(existingIndex, 1);
                }

                // Add the new pattern
                customPatternObj = {
                    name: "Custom Keyword / Regex",
                    regex: new RegExp(customRegexInput, 'g'),
                    redact: "[CUSTOM_MATCH_REDACTED]",
                    category: "generic"
                };
                SECRET_PATTERNS.unshift(customPatternObj); // Prepend to match first
            } catch (e) {
                alert('Invalid Custom Regex: ' + e.message);
                this.reset();
                return;
            }
        }

        this.addScanMessage(`> Initializing Secret Scanner...`);
        this.addScanMessage(`> Loading: ${file.name}`);
        this.addScanMessage(`> Size: ${this.formatBytes(file.size)}`);
        if (customRegexInput) {
            this.addScanMessage(`> Using Custom Pattern: ${customRegexInput}`);
        }

        try {
            const arrayBuffer = await file.arrayBuffer();
            this.zip = await JSZip.loadAsync(arrayBuffer);

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

            // Scan all files with all patterns enabled
            for (const path of Object.keys(this.zip.files)) {
                const zipEntry = this.zip.files[path];

                if (zipEntry.dir) continue;
                if (this.shouldSkipFile(path)) continue;

                if (this.shouldScanFile(path)) {
                    const content = await zipEntry.async('string');
                    const fileFindings = this.scanFile(content, path);

                    if (fileFindings.length > 0) {
                        this.addScanMessage(`> [!] ${this.truncatePath(path)} → ${fileFindings.length} secret(s)`);
                    }

                    this.findings.push(...fileFindings);
                    this.processedFiles++;

                    this.updateProgress(this.processedFiles, this.totalFiles);
                    document.getElementById('scanFiles').textContent = this.processedFiles;
                    document.getElementById('scanSecrets').textContent = this.findings.length;

                    if (this.processedFiles % 20 === 0) {
                        await this.sleep(5);
                    }
                }
            }

            this.addScanMessage(`>`);
            this.addScanMessage(`> ═══════════════════════════════`);
            this.addScanMessage(`> SCAN COMPLETE`);
            this.addScanMessage(`> Total Secrets Found: ${this.findings.length}`);
            this.addScanMessage(`> ═══════════════════════════════`);

            // Assign IDs and select all by default
            this.findings.forEach((f, i) => {
                f.id = i;
                this.selectedFindings.add(i);
            });

            // Clean up custom pattern after scan completes
            if (customPatternObj) {
                const existingIndex = SECRET_PATTERNS.findIndex(p => p.name === "Custom Keyword / Regex");
                if (existingIndex > -1) {
                    SECRET_PATTERNS.splice(existingIndex, 1);
                }
            }

            await this.sleep(800);
            this.showResults();
        } catch (error) {
            console.error('Error:', error);
            alert('Error processing file: ' + error.message);
            this.reset();
        }
    }

    async rescanWithCustomPattern() {
        if (!this.currentFile) {
            alert('No file loaded. Please upload a ZIP first.');
            return;
        }
        await this.handleFile(this.currentFile);
    }

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

    scanFile(content, filePath) {
        const fileFindings = [];

        // Scan with all regex patterns
        for (const pattern of SECRET_PATTERNS) {
            pattern.regex.lastIndex = 0;

            let match;
            while ((match = pattern.regex.exec(content)) !== null) {
                fileFindings.push({
                    file: filePath,
                    line: this.getLineNumber(content, match.index),
                    type: pattern.name,
                    category: pattern.category,
                    fullMatch: match[0],
                    preview: this.createPreview(match[0]),
                    redact: pattern.redact,
                    index: match.index,
                    isEntropy: false
                });

                if (match.index === pattern.regex.lastIndex) {
                    pattern.regex.lastIndex++;
                }
            }
        }

        // Entropy detection
        const entropyFindings = EntropyDetector.findHighEntropyStrings(content);
        for (const ef of entropyFindings) {
            const isDuplicate = fileFindings.some(f =>
                Math.abs(f.index - ef.index) < 10 ||
                f.fullMatch.includes(ef.value) ||
                ef.match.includes(f.fullMatch)
            );

            if (!isDuplicate) {
                fileFindings.push({
                    file: filePath,
                    line: this.getLineNumber(content, ef.index),
                    type: `High Entropy (${ef.entropy} bits)`,
                    category: 'entropy',
                    fullMatch: ef.match,
                    preview: this.createPreview(ef.value),
                    redact: '[HIGH_ENTROPY_REDACTED]',
                    index: ef.index,
                    isEntropy: true,
                    entropy: ef.entropy
                });
            }
        }

        return fileFindings;
    }

    shouldScanFile(path) {
        if (this.shouldSkipFile(path)) return false;

        const fileName = path.split('/').pop();
        const ext = '.' + fileName.split('.').pop().toLowerCase();

        if (SCANNABLE_FILENAMES.some(name => fileName === name || fileName.endsWith(name))) {
            return true;
        }

        return SCANNABLE_EXTENSIONS.includes(ext);
    }

    shouldSkipFile(path) {
        return SKIP_PATTERNS.some(pattern => pattern.test(path));
    }

    getLineNumber(content, index) {
        return content.substring(0, index).split('\n').length;
    }

    createPreview(match) {
        const maxLen = 35;
        if (match.length <= maxLen) {
            const show = Math.min(6, Math.floor(match.length / 3));
            return match.substring(0, show) + '•••' + match.substring(match.length - show);
        }
        return match.substring(0, 10) + '•••' + match.substring(match.length - 10);
    }

    updateProgress(current, total) {
        const fill = document.getElementById('progressFill');
        const text = document.getElementById('progressText');
        const percent = document.getElementById('progressPercent');

        const pct = total > 0 ? Math.round((current / total) * 100) : 0;
        fill.style.width = pct + '%';
        text.textContent = `Scanning: ${current} / ${total} files`;
        percent.textContent = pct + '%';
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

        // Count by category
        const counts = {};
        for (const f of this.findings) {
            counts[f.category] = (counts[f.category] || 0) + 1;
        }

        const icons = {
            cloud: '☁️',
            vcs: '📦',
            communication: '💬',
            payment: '💳',
            database: '🗄️',
            privateKeys: '🔑',
            apiKeys: '🔌',
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

        // Group by file
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

        // Add event listeners
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

                    // Get selected findings for this file, sorted descending by index
                    const fileFindings = this.findings
                        .filter(f => f.file === path && this.selectedFindings.has(f.id))
                        .sort((a, b) => b.index - a.index);

                    // Apply redactions from end to start
                    for (const finding of fileFindings) {
                        content = content.substring(0, finding.index) +
                            finding.redact +
                            content.substring(finding.index + finding.fullMatch.length);
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
        } catch (error) {
            console.error('Error:', error);
            alert('Error creating ZIP: ' + error.message);
        }
    }

    exportReport(format) {
        if (this.findings.length === 0) {
            alert('No findings to export');
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
                `"${r.file}"`,
                r.line,
                `"${r.type}"`,
                `"${r.category}"`,
                `"${r.preview.replace(/"/g, '""')}"`,
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
        this.currentFile = null;
        this.findings = [];
        this.selectedFindings = new Set();
        this.processedFiles = 0;
        this.totalFiles = 0;
        this.scanMessages = [];

        document.getElementById('uploadSection').classList.remove('hidden');
        document.getElementById('progressSection').classList.add('hidden');
        document.getElementById('resultsSection').classList.add('hidden');
        document.getElementById('fileInput').value = '';
        const customInput = document.getElementById('customPatternInput');
        if (customInput) customInput.value = '';
        document.getElementById('scanOutput').textContent = '';
    }
}

// Initialize
const app = new SecretRemover();
