/**
 * PII Shield – Client-Side PII Detection Engine & UI Controller
 * Note: Redaction modes will be implemented separately in the next stage.
 * All detection runs locally in the browser; no detected PII values are ever logged.
 */

(function () {
    "use strict";

    const SAMPLE_TEXT = [
        "Customer Record #1042",
        "Name: Aarav Sharma",
        "Email: aarav.sharma@example.com",
        "Phone: +91 98765 43210",
        "IP Address: 192.168.10.45",
        "PAN: ABCPK1234F",
        "Aadhaar: 4321 8765 1098",
        "Credit Card: 4532-8910-2345-6784",
        "",
        "Secondary Contact: priya.mehta@company.org | 9123456789 | 10.0.4.21"
    ].join("\n");

    const MODE_LABELS = {
        full: "Full Mask",
        partial: "Partial Mask",
        pseudonym: "Consistent Pseudonymization"
    };

    const CATEGORY_META = {
        emails: { label: "Email Address", priority: 1 },
        cards: { label: "Credit Card", priority: 2 },
        aadhaar: { label: "Aadhaar Number", priority: 3 },
        ips: { label: "IPv4 Address", priority: 4 },
        pan: { label: "Indian PAN", priority: 5 },
        phones: { label: "Indian Phone Number", priority: 6 }
    };

    function initPIIShield() {
        // DOM References
        const rawInput = document.getElementById("raw-input");
        const fileInput = document.getElementById("file-input");
        const uploadFileBtn = document.getElementById("upload-file-btn");
        const loadSampleBtn = document.getElementById("load-sample-btn");
        const clearInputBtn = document.getElementById("clear-input-btn");
        const fileBadge = document.getElementById("file-badge");
        const charCountEl = document.getElementById("char-count");
        const lineCountEl = document.getElementById("line-count");

        const modeCards = Array.from(document.querySelectorAll(".mode-card"));
        const modeRadios = Array.from(document.querySelectorAll('input[name="redaction-mode"]'));
        const sanitizeBtn = document.getElementById("sanitize-btn");
        const detectionStatusEl = document.getElementById("detection-status");

        const statEls = {
            emails: document.getElementById("stat-emails"),
            phones: document.getElementById("stat-phones"),
            ips: document.getElementById("stat-ips"),
            pan: document.getElementById("stat-pan"),
            aadhaar: document.getElementById("stat-aadhaar"),
            cards: document.getElementById("stat-cards")
        };
        const totalDetectedBadge = document.getElementById("total-detected-badge");

        const originalPreview = document.getElementById("original-preview");
        const sanitizedPreview = document.getElementById("sanitized-preview");
        const activeModeTag = document.getElementById("active-mode-tag");
        const downloadBtn = document.getElementById("download-btn");
        const copyOutputBtn = document.getElementById("copy-output-btn");

        const activityLogEl = document.getElementById("activity-log");
        const clearLogBtn = document.getElementById("clear-log-btn");

        if (!rawInput || !sanitizeBtn || !originalPreview || !sanitizedPreview) {
            return;
        }

        // Local UI State
        let selectedMode = "full";
        let loadedFileName = "";
        let lastDetections = [];
        let currentSanitizedText = "";
        let hasSanitizedCurrentInput = false;

        function showStatus(message, variant = "info") {
            if (!detectionStatusEl) return;
            detectionStatusEl.textContent = message;
            detectionStatusEl.className = "detection-status";
            if (variant === "success") detectionStatusEl.classList.add("is-success");
            if (variant === "warning") detectionStatusEl.classList.add("is-warning");
            if (variant === "error") detectionStatusEl.classList.add("is-error");
            detectionStatusEl.hidden = false;
        }

        function hideStatus() {
            if (!detectionStatusEl) return;
            detectionStatusEl.hidden = true;
            detectionStatusEl.textContent = "";
            detectionStatusEl.className = "detection-status";
        }

        // Utilities
        function formatTime(date) {
            return date.toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit"
            });
        }

        function addLogEntry(message, category = "info") {
            const li = document.createElement("li");
            li.className = "log-item";

            const badgeMap = {
                info: { label: "INFO", cls: "log-badge-info" },
                mode: { label: "MODE", cls: "log-badge-mode" },
                success: { label: "DONE", cls: "log-badge-success" }
            };
            const badgeInfo = badgeMap[category] || badgeMap.info;

            const mainDiv = document.createElement("div");
            mainDiv.className = "log-item-main";

            const badge = document.createElement("span");
            badge.className = `log-badge ${badgeInfo.cls}`;
            badge.textContent = badgeInfo.label;

            const msgSpan = document.createElement("span");
            msgSpan.className = "log-message";
            msgSpan.textContent = message;

            const timeSpan = document.createElement("span");
            timeSpan.className = "log-time";
            timeSpan.textContent = formatTime(new Date());

            mainDiv.appendChild(badge);
            mainDiv.appendChild(msgSpan);
            li.appendChild(mainDiv);
            li.appendChild(timeSpan);

            activityLogEl.prepend(li);
        }

        function createEmptyCounts() {
            return { emails: 0, phones: 0, ips: 0, pan: 0, aadhaar: 0, cards: 0 };
        }

        function updateInputCounts() {
            const text = rawInput.value;
            const chars = text.length;
            const lines = text ? text.split(/\r\n|\r|\n/).length : 0;

            charCountEl.textContent = `${chars.toLocaleString()} character${chars === 1 ? "" : "s"}`;
            lineCountEl.textContent = `${lines.toLocaleString()} line${lines === 1 ? "" : "s"}`;
            clearInputBtn.hidden = chars === 0 && !loadedFileName;
        }

        function updateStats(counts) {
            let total = 0;
            Object.keys(statEls).forEach((key) => {
                const value = counts[key] || 0;
                statEls[key].textContent = String(value);
                total += value;
            });
            totalDetectedBadge.textContent = `${total} Total Match${total === 1 ? "" : "es"}`;
        }

        function resetPreviewAndStats() {
            lastDetections = [];
            currentSanitizedText = "";
            hasSanitizedCurrentInput = false;
            originalPreview.textContent =
                "No input provided yet. Paste text or load the sample dataset above, then click Sanitize Data.";
            originalPreview.classList.add("empty-state");

            sanitizedPreview.textContent =
                "Sanitized output will appear here once you click Sanitize Data.";
            sanitizedPreview.classList.add("empty-state");

            downloadBtn.disabled = true;
            copyOutputBtn.disabled = true;
            updateStats(createEmptyCounts());
        }

        function setRedactionMode(mode) {
            selectedMode = mode;
            modeCards.forEach((card) => {
                card.classList.toggle("is-selected", card.dataset.mode === mode);
            });
            activeModeTag.textContent = MODE_LABELS[mode] || "Full Mask";
        }

        // ==========================================================================
        // PII Detection Engine
        // ==========================================================================

        function isAlphanumericChar(ch) {
            return Boolean(ch) && /[A-Za-z0-9]/.test(ch);
        }

        function hasCleanBoundaries(text, start, end) {
            const prev = start > 0 ? text[start - 1] : "";
            const next = end < text.length ? text[end] : "";
            return !isAlphanumericChar(prev) && !isAlphanumericChar(next);
        }

        function isAdjacentToHyphenDigit(text, start, end) {
            const before = text.slice(Math.max(0, start - 2), start);
            const after = text.slice(end, Math.min(text.length, end + 2));
            return /\d-$/.test(before) || /^-\d/.test(after);
        }

        function isInsideFourDigitGroupSequence(text, start, end) {
            const before = text.slice(Math.max(0, start - 6), start);
            const after = text.slice(end, Math.min(text.length, end + 6));
            return /(?:^|\D)\d{4}[ \t-]$/.test(before) || /^[ \t-]\d{4}(?:$|\D)/.test(after);
        }

        /**
         * Validates a candidate digit string using the Luhn checksum algorithm.
         */
        function isValidLuhn(digits) {
            if (!/^\d{13,19}$/.test(digits)) {
                return false;
            }
            // Reject trivial repeated-digit sequences (e.g. 0000000000000000)
            if (/^(\d)\1+$/.test(digits)) {
                return false;
            }

            let sum = 0;
            let shouldDouble = false;

            for (let i = digits.length - 1; i >= 0; i -= 1) {
                let digit = Number(digits[i]);
                if (shouldDouble) {
                    digit *= 2;
                    if (digit > 9) {
                        digit -= 9;
                    }
                }
                sum += digit;
                shouldDouble = !shouldDouble;
            }

            return sum % 10 === 0;
        }

        function isValidEmail(email) {
            const parts = email.split("@");
            if (parts.length !== 2) return false;
            const [localPart, domainPart] = parts;
            if (!localPart || !domainPart) return false;
            if (localPart.startsWith(".") || localPart.endsWith(".") || localPart.includes("..")) {
                return false;
            }
            if (domainPart.includes("..")) return false;
            const domainLabels = domainPart.split(".");
            if (domainLabels.length < 2) return false;
            const tld = domainLabels[domainLabels.length - 1];
            if (!/^[A-Za-z]{2,}$/.test(tld)) return false;
            return domainLabels.every((label) => label.length > 0 && !label.startsWith("-") && !label.endsWith("-"));
        }

        function isValidIPv4(ip) {
            const octets = ip.split(".");
            if (octets.length !== 4) return false;
            return octets.every((octet) => {
                if (!/^\d{1,3}$/.test(octet)) return false;
                if (octet.length > 1 && octet.startsWith("0")) return false;
                const num = Number(octet);
                return num >= 0 && num <= 255;
            });
        }

        function isValidIndianPhone(candidate) {
            const digits = candidate.replace(/\D/g, "");
            let subscriberDigits = digits;
            if (digits.length === 12 && digits.startsWith("91")) {
                subscriberDigits = digits.slice(2);
            } else if (digits.length === 11 && digits.startsWith("0")) {
                subscriberDigits = digits.slice(1);
            }
            return /^[6-9]\d{9}$/.test(subscriberDigits);
        }

        function collectRegexMatches(text, regex, category, validator) {
            const matches = [];
            regex.lastIndex = 0;
            let result = regex.exec(text);

            while (result !== null) {
                const value = result[0];
                const start = result.index;
                const end = start + value.length;

                if (!validator || validator(value, start, end, text)) {
                    matches.push({
                        category,
                        label: CATEGORY_META[category].label,
                        value,
                        start,
                        end
                    });
                }

                if (value.length === 0) {
                    regex.lastIndex += 1;
                }
                result = regex.exec(text);
            }

            return matches;
        }

        function detectEmails(text) {
            const emailRegex = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
            return collectRegexMatches(text, emailRegex, "emails", (value, start, end, source) => {
                if (!hasCleanBoundaries(source, start, end)) return false;
                return isValidEmail(value);
            });
        }

        function detectCreditCards(text) {
            // Matches 13-19 continuous digits or standard grouped credit card formats (4-4-4-4, 4-6-5, etc.)
            const cardRegex = /(?:\d{4}(?:[ -]\d{4}){3}(?:[ -]\d{1,3})?|\d{4}[ -]\d{6}[ -]\d{5}|\d{13,19})/g;
            return collectRegexMatches(text, cardRegex, "cards", (value, start, end, source) => {
                if (!hasCleanBoundaries(source, start, end)) return false;
                if (isAdjacentToHyphenDigit(source, start, end)) return false;
                if (isInsideFourDigitGroupSequence(source, start, end)) return false;
                const digits = value.replace(/\D/g, "");
                return isValidLuhn(digits);
            });
        }

        function detectAadhaar(text) {
            // Matches 12-digit Indian Aadhaar in XXXX XXXX XXXX, XXXX-XXXX-XXXX, or XXXXXXXXXXXX format
            const aadhaarRegex = /[2-9]\d{3}(?: \d{4} \d{4}|-\d{4}-\d{4}|\d{8})/g;
            return collectRegexMatches(text, aadhaarRegex, "aadhaar", (value, start, end, source) => {
                if (!hasCleanBoundaries(source, start, end)) return false;
                if (isAdjacentToHyphenDigit(source, start, end)) return false;
                if (isInsideFourDigitGroupSequence(source, start, end)) return false;
                const digits = value.replace(/\D/g, "");
                return /^[2-9]\d{11}$/.test(digits);
            });
        }

        function detectIPv4(text) {
            const ipv4Regex = /(?:\d{1,3}\.){3}\d{1,3}/g;
            return collectRegexMatches(text, ipv4Regex, "ips", (value, start, end, source) => {
                const prev = start > 0 ? source[start - 1] : "";
                const next = end < source.length ? source[end] : "";
                if (prev === "." || next === ".") return false;
                if (!hasCleanBoundaries(source, start, end)) return false;
                return isValidIPv4(value);
            });
        }

        function detectPAN(text) {
            const panRegex = /[A-Z]{5}\d{4}[A-Z]/g;
            return collectRegexMatches(text, panRegex, "pan", (_value, start, end, source) => {
                return hasCleanBoundaries(source, start, end);
            });
        }

        function detectIndianPhones(text) {
            const phoneRegex = /(?:\+91[ \t-]?|91[ \t-]|0[ \t-]?)?[6-9]\d{2}[ \t-]?\d{2,3}[ \t-]?\d{4,5}/g;
            return collectRegexMatches(text, phoneRegex, "phones", (value, start, end, source) => {
                const prev = start > 0 ? source[start - 1] : "";
                const next = end < source.length ? source[end] : "";
                if (isAlphanumericChar(prev) || isAlphanumericChar(next) || prev === "+") {
                    return false;
                }
                if (isAdjacentToHyphenDigit(source, start, end)) {
                    return false;
                }
                return isValidIndianPhone(value);
            });
        }

        /**
         * Resolves duplicate and overlapping candidates deterministically by category priority,
         * longer span length, and earlier start offset, then sorts chronologically by position.
         */
        function resolveOverlaps(candidates) {
            const sorted = [...candidates].sort((a, b) => {
                const priorityDiff = CATEGORY_META[a.category].priority - CATEGORY_META[b.category].priority;
                if (priorityDiff !== 0) return priorityDiff;

                const lengthDiff = (b.end - b.start) - (a.end - a.start);
                if (lengthDiff !== 0) return lengthDiff;

                return a.start - b.start;
            });

            const accepted = [];
            for (const candidate of sorted) {
                const overlapsExisting = accepted.some(
                    (existing) => candidate.start < existing.end && existing.start < candidate.end
                );
                if (!overlapsExisting) {
                    accepted.push(candidate);
                }
            }

            return accepted.sort((a, b) => a.start - b.start);
        }

        function countDetectionsByCategory(detections) {
            const counts = createEmptyCounts();
            for (const match of detections) {
                counts[match.category] += 1;
            }
            return counts;
        }

        function detectPII(text) {
            if (!text) {
                return {
                    detections: [],
                    counts: createEmptyCounts()
                };
            }

            const candidates = [
                ...detectEmails(text),
                ...detectCreditCards(text),
                ...detectAadhaar(text),
                ...detectIPv4(text),
                ...detectPAN(text),
                ...detectIndianPhones(text)
            ];

            const detections = resolveOverlaps(candidates);
            const counts = countDetectionsByCategory(detections);

            return { detections, counts };
        }

        // ==========================================================================
        // Highlighting & Interface Updates
        // ==========================================================================

        function renderHighlightedOriginal(text, detections) {
            originalPreview.textContent = "";
            originalPreview.classList.remove("empty-state");

            const fragment = document.createDocumentFragment();
            let cursor = 0;

            for (const match of detections) {
                if (match.start > cursor) {
                    fragment.appendChild(document.createTextNode(text.slice(cursor, match.start)));
                }

                const mark = document.createElement("mark");
                mark.className = `pii-highlight pii-highlight-${match.category}`;
                mark.dataset.category = match.category;
                mark.title = `${match.label} (${match.start}–${match.end})`;
                mark.textContent = text.slice(match.start, match.end);
                fragment.appendChild(mark);

                cursor = match.end;
            }

            if (cursor < text.length) {
                fragment.appendChild(document.createTextNode(text.slice(cursor)));
            }

            originalPreview.appendChild(fragment);
        }

  // ==========================================================================
  // Redaction Modes Engine
  // ==========================================================================

  const PSEUDONYM_PREFIX = {
    emails: "EMAIL",
    phones: "PHONE",
    ips: "IP",
    pan: "PAN",
    aadhaar: "AADHAAR",
    cards: "CARD"
  };

  function normalizeValueForPseudonym(category, value) {
    if (category === "emails") {
      return value.trim().toLowerCase();
    }
    if (category === "phones") {
      const digits = value.replace(/\D/g, "");
      if (digits.length === 12 && digits.startsWith("91")) {
        return digits.slice(2);
      }
      if (digits.length === 11 && digits.startsWith("0")) {
        return digits.slice(1);
      }
      return digits;
    }
    if (category === "pan") {
      return value.trim().toUpperCase();
    }
    if (category === "aadhaar" || category === "cards") {
      return value.replace(/\D/g, "");
    }
    return value.trim();
  }

  function maskPartial(category, value) {
    if (category === "emails") {
      const atIndex = value.indexOf("@");
      if (atIndex <= 0) return "[REDACTED]";
      const localPart = value.slice(0, atIndex);
      const domainPart = value.slice(atIndex + 1);
      const visibleCount = localPart.length > 2 ? 2 : 1;
      return `${localPart.slice(0, visibleCount)}***@${domainPart}`;
    }

    if (category === "phones") {
      const digits = value.replace(/\D/g, "");
      const lastFour = digits.slice(-4);
      const maskLength = Math.max(6, digits.length - 4);
      return `${"*".repeat(maskLength)}${lastFour}`;
    }

    if (category === "ips") {
      const octets = value.split(".");
      if (octets.length !== 4) return "[REDACTED]";
      return `${octets[0]}.${octets[1]}.*.*`;
    }

    if (category === "pan") {
      if (value.length < 4) return "[REDACTED]";
      return `${value.slice(0, 2)}${"*".repeat(value.length - 3)}${value.slice(-1)}`;
    }

    if (category === "aadhaar") {
      const digits = value.replace(/\D/g, "");
      const lastFour = digits.slice(-4);
      if (value.includes("-")) return `****-****-${lastFour}`;
      if (value.includes(" ")) return `**** **** ${lastFour}`;
      return `********${lastFour}`;
    }

    if (category === "cards") {
      const digits = value.replace(/\D/g, "");
      const lastFour = digits.slice(-4);
      if (value.includes("-")) return `****-****-****-${lastFour}`;
      if (value.includes(" ")) return `**** **** **** ${lastFour}`;
      return `${"*".repeat(Math.max(8, digits.length - 4))}${lastFour}`;
    }

    return "[REDACTED]";
  }

  function redactDetections(text, detections, mode) {
    const segments = [];
    const outputParts = [];
    const pseudonymMap = new Map();
    const categoryCounters = {
      emails: 0,
      phones: 0,
      ips: 0,
      pan: 0,
      aadhaar: 0,
      cards: 0
    };

    function getPseudonymPlaceholder(category, value) {
      const normalized = normalizeValueForPseudonym(category, value);
      const key = `${category}:${normalized}`;
      if (!pseudonymMap.has(key)) {
        categoryCounters[category] += 1;
        const prefix = PSEUDONYM_PREFIX[category] || "PII";
        const suffix = String(categoryCounters[category]).padStart(2, "0");
        pseudonymMap.set(key, `${prefix}_${suffix}`);
      }
      return pseudonymMap.get(key);
    }

    let cursor = 0;

    for (const match of detections) {
      if (match.start > cursor) {
        const plain = text.slice(cursor, match.start);
        segments.push({ text: plain, isRedacted: false });
        outputParts.push(plain);
      }

      let replacement = "[REDACTED]";
      if (mode === "partial") {
        replacement = maskPartial(match.category, match.value);
      } else if (mode === "pseudonym") {
        replacement = getPseudonymPlaceholder(match.category, match.value);
      }

      segments.push({
        text: replacement,
        isRedacted: true,
        category: match.category,
        label: match.label
      });
      outputParts.push(replacement);
      cursor = match.end;
    }

    if (cursor < text.length) {
      const tail = text.slice(cursor);
      segments.push({ text: tail, isRedacted: false });
      outputParts.push(tail);
    }

    return {
      sanitizedText: outputParts.join(""),
      segments
    };
  }

  function renderSanitizedOutput(segments) {
    sanitizedPreview.textContent = "";
    sanitizedPreview.classList.remove("empty-state");

    const fragment = document.createDocumentFragment();
    for (const segment of segments) {
      if (!segment.isRedacted) {
        fragment.appendChild(document.createTextNode(segment.text));
      } else {
        const mark = document.createElement("mark");
        mark.className = "pii-redacted";
        mark.dataset.category = segment.category;
        mark.title = `Redacted ${segment.label} (${MODE_LABELS[selectedMode]})`;
        mark.textContent = segment.text;
        fragment.appendChild(mark);
      }
    }

    sanitizedPreview.appendChild(fragment);
  }

  function runDetection({ logAction = false, fromButton = false, applyRedaction = false } = {}) {
    try {
      const inputText = typeof rawInput.value === "string" ? rawInput.value : "";

      if (!inputText.trim()) {
        resetPreviewAndStats();
        if (fromButton) {
          showStatus("Please paste text or upload a .txt / .csv file before sanitizing.", "warning");
          addLogEntry("Sanitization skipped: input text area is empty.", "info");
          rawInput.focus();
        } else {
          hideStatus();
        }
        return { detections: [], counts: createEmptyCounts(), sanitizedText: "" };
      }

      const { detections, counts } = detectPII(inputText);
      lastDetections = detections;

      renderHighlightedOriginal(inputText, detections);
      updateStats(counts);

      const totalMatches = detections.length;

      if (applyRedaction) {
        const { sanitizedText, segments } = redactDetections(inputText, detections, selectedMode);
        currentSanitizedText = sanitizedText;
        hasSanitizedCurrentInput = true;
        renderSanitizedOutput(segments);

        if (downloadBtn) downloadBtn.disabled = false;
        if (copyOutputBtn) copyOutputBtn.disabled = false;

        if (totalMatches === 0) {
          showStatus("Sanitization complete: No PII detected; output matches original text.", "warning");
        } else {
          showStatus(
            `Sanitized ${totalMatches} PII entit${totalMatches === 1 ? "y" : "ies"} using ${MODE_LABELS[selectedMode]}.`,
            "success"
          );
        }

        if (logAction) {
          addLogEntry(
            `Sanitized with ${MODE_LABELS[selectedMode]}: ${totalMatches} match${totalMatches === 1 ? "" : "es"} ` +
              `(Emails: ${counts.emails}, Phones: ${counts.phones}, IPv4: ${counts.ips}, ` +
              `PAN: ${counts.pan}, Aadhaar: ${counts.aadhaar}, Cards: ${counts.cards}).`,
            "success"
          );
        }

        return { detections, counts, sanitizedText };
      }

      // Live detection preview before Sanitize is clicked
      currentSanitizedText = "";
      hasSanitizedCurrentInput = false;
      if (downloadBtn) downloadBtn.disabled = true;
      if (copyOutputBtn) copyOutputBtn.disabled = true;

      if (totalMatches === 0) {
        sanitizedPreview.textContent =
          "No PII detected yet. Click Sanitize Data to generate output.";
        showStatus("Live preview: No PII detected yet. Click Sanitize Data to sanitize.", "info");
      } else {
        sanitizedPreview.textContent =
          `Detected ${totalMatches} PII entit${totalMatches === 1 ? "y" : "ies"} in Original Text. Click Sanitize Data to apply ${MODE_LABELS[selectedMode]}.`;
        showStatus(
          `Live preview: ${totalMatches} PII match${totalMatches === 1 ? "" : "es"} found — click Sanitize Data to apply ${MODE_LABELS[selectedMode]}.`,
          "info"
        );
      }
      sanitizedPreview.classList.add("empty-state");

      return { detections, counts, sanitizedText: "" };
    } catch (error) {
      const errorMessage = error && error.message ? error.message : "Unexpected sanitization error.";
      showStatus(`JavaScript error during processing: ${errorMessage}`, "error");
      addLogEntry(`Processing error: ${errorMessage}`, "info");
      return { detections: [], counts: createEmptyCounts(), sanitizedText: "" };
    }
  }

  // ==========================================================================
  // Event Handlers
  // ==========================================================================

  function handleInputChange() {
    updateInputCounts();
    runDetection({ logAction: false, fromButton: false, applyRedaction: false });
  }

  rawInput.addEventListener("input", handleInputChange);
  rawInput.addEventListener("paste", () => {
    window.setTimeout(handleInputChange, 0);
  });

  if (uploadFileBtn && fileInput) {
    uploadFileBtn.addEventListener("click", () => {
      fileInput.click();
    });

    fileInput.addEventListener("change", (event) => {
      const file = event.target.files && event.target.files[0];
      if (!file) return;

      const validExtension = /\.(txt|csv)$/i.test(file.name);
      if (!validExtension) {
        showStatus(`Unsupported file "${file.name}". Please upload a .txt or .csv file.`, "warning");
        addLogEntry(`Skipped "${file.name}" — only .txt and .csv files are supported.`, "info");
        fileInput.value = "";
        return;
      }

      const reader = new FileReader();
      reader.onload = (loadEvent) => {
        const content = String(loadEvent.target.result || "");
        rawInput.value = content;
        loadedFileName = file.name;
        fileBadge.textContent = `Loaded: ${file.name}`;
        fileBadge.hidden = false;
        updateInputCounts();
        const { detections } = runDetection({ logAction: false, fromButton: false, applyRedaction: false });
        addLogEntry(
          `Loaded local file "${file.name}" (${content.length.toLocaleString()} chars, ${detections.length} PII match${detections.length === 1 ? "" : "es"} detected).`,
          "info"
        );
      };
      reader.onerror = () => {
        showStatus(`Could not read "${file.name}". Please try another file.`, "error");
        addLogEntry(`Could not read "${file.name}". Please try another file.`, "info");
      };
      reader.readAsText(file);
      fileInput.value = "";
    });
  }

  if (loadSampleBtn) {
    loadSampleBtn.addEventListener("click", () => {
      rawInput.value = SAMPLE_TEXT;
      loadedFileName = "";
      fileBadge.hidden = true;
      updateInputCounts();
      const { detections } = runDetection({ logAction: false, fromButton: false, applyRedaction: false });
      addLogEntry(
        `Loaded built-in sample dataset (${detections.length} PII match${detections.length === 1 ? "" : "es"} detected).`,
        "info"
      );
    });
  }

  if (clearInputBtn) {
    clearInputBtn.addEventListener("click", () => {
      rawInput.value = "";
      loadedFileName = "";
      fileBadge.hidden = true;
      updateInputCounts();
      resetPreviewAndStats();
      hideStatus();
      addLogEntry("Cleared input text and reset results.", "info");
    });
  }

  modeRadios.forEach((radio) => {
    radio.addEventListener("change", (event) => {
      if (event.target.checked) {
        setRedactionMode(event.target.value);
        addLogEntry(`Redaction mode switched to ${MODE_LABELS[selectedMode]}.`, "mode");
        if (hasSanitizedCurrentInput && rawInput.value.trim()) {
          runDetection({ logAction: true, fromButton: true, applyRedaction: true });
        } else if (rawInput.value.trim()) {
          runDetection({ logAction: false, fromButton: false, applyRedaction: false });
        }
      }
    });
  });

  sanitizeBtn.addEventListener("click", () => {
    runDetection({ logAction: true, fromButton: true, applyRedaction: true });
  });

  if (copyOutputBtn) {
    copyOutputBtn.addEventListener("click", async () => {
      if (!currentSanitizedText) return;
      try {
        await navigator.clipboard.writeText(currentSanitizedText);
        showStatus("Sanitized output copied to clipboard.", "success");
        addLogEntry("Copied sanitized output to clipboard.", "info");
      } catch {
        showStatus("Clipboard access unavailable in this browser context.", "warning");
        addLogEntry("Clipboard access unavailable in this browser context.", "info");
      }
    });
  }

  if (downloadBtn) {
    downloadBtn.addEventListener("click", () => {
      if (!currentSanitizedText) return;
      const baseName = loadedFileName ? loadedFileName.replace(/\.(txt|csv)$/i, "") : "pii-shield-output";
      const outputFileName = `${baseName}-sanitized.txt`;

      const blob = new Blob([currentSanitizedText], { type: "text/plain;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = outputFileName;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);

      addLogEntry(`Downloaded sanitized output as "${outputFileName}".`, "success");
    });
  }

  if (clearLogBtn && activityLogEl) {
    clearLogBtn.addEventListener("click", () => {
      activityLogEl.innerHTML = "";
      addLogEntry("Activity log cleared.", "info");
    });
  }

  window.addEventListener("error", (event) => {
    const msg = event && event.message ? event.message : "Unexpected script error.";
    showStatus(`Runtime error: ${msg}`, "error");
  });

  // Expose pure detection and redaction helpers for local verification
  window.PIIShieldDetector = {
    detectPII,
    redactDetections,
    isValidLuhn,
    getLastDetections: () => [...lastDetections]
  };

  // Initial Setup
  updateInputCounts();
  setRedactionMode("full");
  resetPreviewAndStats();
  hideStatus();
  addLogEntry("PII Shield workspace initialized (100% client-side).", "info");
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initPIIShield);
  } else {
    initPIIShield();
  }
})();
