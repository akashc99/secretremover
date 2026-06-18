// scanner-worker.js — runs all regex + entropy scanning off the main thread,
// so a huge repo or a pathological custom regex can never freeze the page.
// The main thread can hard-cancel at any moment with worker.terminate().
//
// Protocol (main → worker):
//   { type: 'init', customPattern: { source, flags, name, redact, category } | null }
//   { type: 'scanFile', path, content }
// Protocol (worker → main):
//   { type: 'ready' }
//   { type: 'result', path, findings }
//   { type: 'error', path, message }

'use strict';

importScripts('patterns.js', 'scan-core.js');

// Active pattern list for this scan session (base patterns + optional custom).
let activePatterns = SECRET_PATTERNS;

ScanCore.prepareRegexWithIndices(SECRET_PATTERNS);

self.onmessage = function (e) {
    const msg = e.data;

    if (msg.type === 'init') {
        if (msg.customPattern) {
            let custom;
            try {
                custom = {
                    name: msg.customPattern.name,
                    regex: new RegExp(msg.customPattern.source, msg.customPattern.flags),
                    redact: msg.customPattern.redact,
                    category: msg.customPattern.category
                };
            } catch (err) {
                self.postMessage({ type: 'error', path: null, message: 'Invalid custom regex: ' + err.message });
                return;
            }
            // Fresh array each init so a previous scan's custom pattern
            // never leaks into the next one.
            activePatterns = [custom, ...SECRET_PATTERNS];
        } else {
            activePatterns = SECRET_PATTERNS;
        }
        self.postMessage({ type: 'ready' });
        return;
    }

    if (msg.type === 'scanFile') {
        try {
            const findings = ScanCore.scanContent(msg.content, msg.path, activePatterns, EntropyDetector);
            self.postMessage({ type: 'result', path: msg.path, findings });
        } catch (err) {
            self.postMessage({ type: 'error', path: msg.path, message: err.message });
        }
    }
};
