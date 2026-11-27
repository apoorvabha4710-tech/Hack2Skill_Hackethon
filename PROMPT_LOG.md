# PII Shield – AI Prompt Log

## Project
**PII Shield – Smart Data Sanitization Tool**

## AI Development Tool
Google Antigravity

## Note
This prompt log contains reconstructed summaries of the prompts used during development. They are not verbatim copies of the original prompts.

### Prompt 1: Initial Website Development
Create a responsive, professional browser-based PII Shield application using HTML, CSS and vanilla JavaScript. Include a text input area, file upload, sample text loader, three redaction mode options, detection statistics, side-by-side comparison and a download option. Use a clean, modern dashboard design with blue and lavender accents.

### Prompt 2: PII Detection Engine
Implement client-side detection for email addresses, phone numbers, IP addresses, Indian PAN numbers, Aadhaar numbers and credit card numbers. Include Luhn validation for credit card detection. Display detection counts and highlight detected entities. Do not use external APIs or servers.

### Prompt 3: Sanitize Button Functionality
Connect the Sanitize button to the existing detection logic. Ensure that the entered text is scanned, detection statistics are updated, and the original and sanitized text areas display the appropriate results. Preserve the existing design.

### Prompt 4: Redaction Modes
Implement three redaction modes:
- Full Mask: Replace detected sensitive values with `[REDACTED]`.
- Partial Mask: Hide most of the sensitive value while retaining limited context.
- Consistent Pseudonymization: Replace recurring sensitive values with consistent placeholders.

### Prompt 5: Download and File Handling
Implement TXT and CSV file uploads, sample text loading, and downloading sanitized output as a TXT file. Ensure processing remains entirely client-side.

### Prompt 6: Testing and Debugging
Review the existing HTML, CSS and JavaScript files. Fix issues affecting the Sanitize button, detection logic, redaction modes and output display. Preserve working features and avoid unnecessary redesign.

## Development Principles
- Client-side processing
- No external API dependency
- No unnecessary transmission of sensitive data
- Responsive user interface
- Maintainable HTML, CSS and JavaScript code

## Final Outcome
A browser-based tool that detects and sanitizes common Personally Identifiable Information using three redaction methods.