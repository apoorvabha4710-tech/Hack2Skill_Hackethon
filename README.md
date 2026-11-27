# 🛡️ PII Shield – Smart Data Sanitization Tool

**Protect Sensitive Information. Share Data Safely.**

PII Shield is a browser-based data sanitization tool that automatically detects and protects Personally Identifiable Information (PII) from text and files.

It helps users identify sensitive information and replace it with secure placeholders before sharing or using their data.

## 🚀 Problem Statement

Sharing text and documents can unintentionally expose sensitive personal information such as email addresses, phone numbers, government identification numbers, and credit card details.

Manually finding and removing this information can be time-consuming and error-prone.

PII Shield aims to simplify this process through automatic PII detection and flexible data sanitization.

## ✨ Key Features

- **Automatic PII Detection:** Identifies emails, phone numbers, IP addresses, Indian PAN numbers, Aadhaar numbers, and credit card numbers.
- **Luhn Validation:** Validates credit card numbers to reduce false-positive detections.
- **Three Redaction Modes:**
  - Full Mask – Replaces sensitive information with `[REDACTED]`.
  - Partial Mask – Hides most of the sensitive information while retaining limited context.
  - Consistent Pseudonymization – Replaces recurring sensitive values with consistent placeholders.
- **Live Comparison:** Displays original and sanitized text side by side.
- **File Upload:** Supports TXT and CSV file uploads.
- **Sample Text Loader:** Provides sample data for quick testing.
- **Download Sanitized Output:** Allows users to download the protected text.
- **Detection Statistics:** Displays counts of detected PII categories.

## 🔒 Privacy First

PII Shield processes data directly in the browser.

- No external API calls.
- No backend server required.
- No database required.
- Sensitive input is not intentionally transmitted to an external server.

This client-side approach helps minimize unnecessary exposure of personal information.

## 🛠️ Technologies Used

- HTML5
- CSS3
- JavaScript
- Browser File API
- JavaScript Blob API

## 📁 Project Structure

```text
PII-Shield/
│
├── index.html
├── style.css
├── script.js
└── README.md
```

## 🌐 Live Demo

Try PII Shield here:

**[Launch PII Shield – Live Demo](PASTE_YOUR_LIVE_DEMO_URL_HERE)**

Explore the application, test the PII detection features, experiment with all three sanitization modes, and download sanitized results.
## 🧪 Testing

The application includes testing for:

- PII detection across supported categories.
- Full, Partial, and Consistent Pseudonymization modes.
- Repeated-value consistency.
- TXT and CSV file uploads.
- Sanitized TXT downloads.
- Credit card validation using the Luhn algorithm.

## ⚠️ Important Note

PII Shield is an educational project and a privacy-assistance tool. Automated detection may miss certain sensitive information or produce false positives. Always review sanitized output before sharing important documents.

## 🌱 Future Improvements

- Support for additional PII formats and countries.
- Improved detection accuracy.
- Support for additional file formats.
- More advanced privacy-preserving features.

## 👩‍💻 Project Purpose

Built as a project to explore browser-based privacy protection, data sanitization, and JavaScript-based information processing.

**PII Shield – Making Data Sharing Safer, One Scan at a Time.**