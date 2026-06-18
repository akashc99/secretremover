// scan-core.js — pure scanning logic shared by the page (fallback path)
// and scanner-worker.js (primary path). No DOM access in this file.
// Load order: patterns.js must be loaded first (provides SECRET_PATTERNS,
// EntropyDetector, SCANNABLE_* and SKIP_PATTERNS).

(function (global) {
    'use strict';

    // Recompile pattern regexes with the 'd' (hasIndices) flag so redaction
    // can target only capture group 1 (the secret value). No-op if already
    // done or if the engine lacks 'd' support.
    function prepareRegexWithIndices(patterns) {
        for (const pattern of patterns) {
            if (pattern.regex.hasIndices) continue;
            try {
                pattern.regex = new RegExp(pattern.regex.source, pattern.regex.flags + 'd');
            } catch (e) {
                break; // engine without 'd' — whole-match redaction fallback
            }
        }
    }

    function buildNewlineOffsets(content) {
        const offsets = [];
        let i = content.indexOf('\n');
        while (i !== -1) {
            offsets.push(i);
            i = content.indexOf('\n', i + 1);
        }
        return offsets;
    }

    function lineFromOffsets(offsets, index) {
        let lo = 0, hi = offsets.length;
        while (lo < hi) {
            const mid = (lo + hi) >> 1;
            if (offsets[mid] < index) lo = mid + 1;
            else hi = mid;
        }
        return lo + 1;
    }

    function createPreview(match) {
        const maxLen = 35;
        if (match.length <= maxLen) {
            const show = Math.min(6, Math.floor(match.length / 3));
            return match.substring(0, show) + '•••' + match.substring(match.length - show);
        }
        return match.substring(0, 10) + '•••' + match.substring(match.length - 10);
    }

    // Keep exactly one finding per overlapping region.
    // Preference: specific provider pattern > generic > entropy;
    // ties broken by longer span.
    function resolveOverlaps(findings) {
        if (findings.length < 2) return findings;

        const rank = (f) => {
            if (f.isEntropy || f.category === 'entropy') return 0;
            if (f.category === 'generic') return 1;
            return 2;
        };

        const sorted = [...findings].sort((a, b) => {
            if (a.redactStart !== b.redactStart) return a.redactStart - b.redactStart;
            const r = rank(b) - rank(a);
            if (r !== 0) return r;
            return (b.redactEnd - b.redactStart) - (a.redactEnd - a.redactStart);
        });

        const kept = [];
        for (const f of sorted) {
            const clash = kept.find(k =>
                f.redactStart < k.redactEnd && k.redactStart < f.redactEnd
            );
            if (!clash) {
                kept.push(f);
            } else if (rank(f) > rank(clash) ||
                       (rank(f) === rank(clash) &&
                        (f.redactEnd - f.redactStart) > (clash.redactEnd - clash.redactStart))) {
                kept[kept.indexOf(clash)] = f;
            }
        }

        kept.sort((a, b) => a.redactStart - b.redactStart);
        return kept;
    }

    // Scan one file's content with the given pattern list (+ entropy).
    // Returns findings without UI ids — the caller assigns those.
    function scanContent(content, filePath, patterns, entropyDetector) {
        let fileFindings = [];
        const newlineOffsets = buildNewlineOffsets(content);

        for (const pattern of patterns) {
            pattern.regex.lastIndex = 0;

            let match;
            while ((match = pattern.regex.exec(content)) !== null) {
                let redactStart = match.index;
                let redactEnd = match.index + match[0].length;
                if (match.indices && match.indices[1]) {
                    redactStart = match.indices[1][0];
                    redactEnd = match.indices[1][1];
                }

                fileFindings.push({
                    file: filePath,
                    line: lineFromOffsets(newlineOffsets, match.index),
                    type: pattern.name,
                    category: pattern.category,
                    fullMatch: match[0],
                    preview: createPreview(match[1] !== undefined ? match[1] : match[0]),
                    redact: pattern.redact,
                    index: match.index,
                    redactStart,
                    redactEnd,
                    isEntropy: false
                });

                if (match.index === pattern.regex.lastIndex) {
                    pattern.regex.lastIndex++;
                }
            }
        }

        const entropyFindings = entropyDetector.findHighEntropyStrings(content);
        for (const ef of entropyFindings) {
            const isDuplicate = fileFindings.some(f =>
                Math.abs(f.index - ef.index) < 10 ||
                f.fullMatch.includes(ef.value) ||
                ef.match.includes(f.fullMatch)
            );

            if (!isDuplicate) {
                fileFindings.push({
                    file: filePath,
                    line: lineFromOffsets(newlineOffsets, ef.index),
                    type: `High Entropy (${ef.entropy} bits)`,
                    category: 'entropy',
                    fullMatch: ef.match,
                    preview: createPreview(ef.value),
                    redact: '[HIGH_ENTROPY_REDACTED]',
                    index: ef.index,
                    redactStart: ef.index,
                    redactEnd: ef.index + ef.match.length,
                    isEntropy: true,
                    entropy: ef.entropy
                });
            }
        }

        return resolveOverlaps(fileFindings);
    }

    const ScanCore = {
        prepareRegexWithIndices,
        buildNewlineOffsets,
        lineFromOffsets,
        createPreview,
        resolveOverlaps,
        scanContent
    };

    // Browser window, Worker self, or Node (tests)
    global.ScanCore = ScanCore;
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = ScanCore;
    }
})(typeof self !== 'undefined' ? self : (typeof window !== 'undefined' ? window : globalThis));
