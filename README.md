# File Inspection Tool

## Overview
A Python-based file inspection tool that identifies a file's true type using magic numbers.
It is designed to detect file masquerading, suspicious payloads, and ambiguous formats.
The tool evaluates full and partial magic matches, assigns confidence scores and returns structured inspection results by reading raw binary headers and comparing them against known magic signatures.

### Key Features
- Magic-number based file type identification
- Offset-aware signature matching
- Full and partial magic matching
- Confidence scoring using float
- Detection of extension mismatches (file masquerading)
- JSON-driven signature database (extensible)
- Safe, minimal file I/O handling
- Structured output for automation or additional SOC tooling

### Detection Logic
1. Load magic number signatures from a JSON file
2. Read specific byte ranges from the target file
3. Compare observed bytes to expected magic values
4. Evaluate:
   - Full matches
   - Partial matches
   - Confidence score
5. Generate a structured inspection result with a risk assessment

### Signature Format
Signatures are defined in JSON and converted into structured models at runtime.

Example:
```
{
            "type_name": "Windows PE Executable",
            "category": "executable",
            "magic_value": "4D5A",
            "offset": 0,
            "match_length": 2,
            "confidence_weight": 1.0,
            "allowed_extensions": [".exe", ".dll", ".sys"],
            "description": "Standard PE (Portable Executable) header",
            "revision": 1
}
```

## Example Usage
```
python main.py samples/test.png signatures/magic_signatures.json
```
Example output:
```
=== File Inspection Report ===
File: samples/test.png
Observed Extension: .png
Risk Level: Low
Summary: File identified as PNG Image

- PNG Image
  Confidence: 1.0
  Reason: Exact magic number match
```
Or
```
python main.py samples/fake.pdf signatures/magic_signatures.json
```
Example output:
```
=== File Inspection Report ===
File: samples\fake.pdf
Observed Extension: .pdf
Risk Level: High
Summary: File masquerading detected: appears as .pdf, but identified as Windows PE Executable

- Windows PE Executable
  Confidence: 1.0
  Reason: Exact magic number match
```

Inspection results can be printed to console for manual analysis or serialized to JSON for ingestion by other tools (SIEM, SOAR, other tools).

## Security Use Cases
- Detecting disguised executables or scripts
- Identifying malicious payloads delivered as documents or images
- Supporting SOC triage
- Assisting DFIR investigations
- Validating file integrity during IR










