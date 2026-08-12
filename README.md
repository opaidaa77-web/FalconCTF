# FalconCTF

**FalconCTF v1.0.0** is an intelligent CTF analysis and triage framework designed to accelerate the initial investigation of cybersecurity challenges.

FalconCTF analyzes challenge files, detects useful indicators, follows encoded payloads, classifies the likely challenge category, recommends next actions, builds a prioritized solve plan, and generates structured analysis reports.

> FalconCTF is designed to assist CTF analysts. It does not claim to automatically solve every challenge.

---

## Key Features

- Smart file analysis
- File type detection
- MD5, SHA1 and SHA256 hashing
- Readable strings extraction
- Flag detection
- Archive analysis
- Base64 detection and decoding
- Hexadecimal detection and decoding
- Recursive encoding analysis
- Payload intelligence
- Decoded payload extraction
- Challenge classification
- Interest scoring
- Recommendation engine
- Intelligent solve planning
- Professional report generation
- Interactive mode
- Command-line interface

---

## Intelligent Analysis Pipeline

Challenge File

↓

File Type Detection

↓

Analysis Router

↓

Strings / Hashes / Archive Analysis

↓

Encoding Analyzer

↓

Recursive Decoding

↓

Payload Inspector

↓

Payload Type + Confidence + Route

↓

Challenge Classifier

↓

Interest Score

↓

Recommendation Engine

↓

Intelligent Solve Planner

↓

Professional Report

---

## Payload Intelligence

FalconCTF can inspect decoded data and recognize several useful payload types, including:

- ZIP
- GZIP
- 7-Zip
- RAR
- ELF
- PE Executables
- PNG
- JPEG
- GIF
- PDF
- Readable Text
- Flag Candidates

Example:

    Source Encoding : BASE64
    Payload Type    : ZIP Archive
    Confidence      : 100%
    Next Route      : archive_analysis
    Saved Payload   : output/challenge_decoded/decoded_payload_001_base64_d1.zip

---

## Challenge Classification

FalconCTF uses evidence from the original challenge and discovered payloads to estimate the likely challenge category.

Supported classification areas currently include:

- Archive
- Encoding / Crypto
- Forensics
- Reverse Engineering
- General Analysis

Example:

    Likely Category : Archive
    Confidence      : 75%
    Secondary       : Encoding / Crypto (70%)

---

## Intelligent Solve Planner

FalconCTF generates prioritized investigation steps.

Example:

    [1] Analyze the decoded archive payload.
    Priority : 95
    Reason   : BASE64 decoding revealed ZIP Archive with 100% confidence.

The planner recommends investigation steps without automatically performing offensive actions.

---

## Command-Line Interface

Show help:

    ./falconctf --help

Show version:

    ./falconctf --version

Analyze a challenge:

    ./falconctf analyze challenge.bin

Analyze an archive with a known password:

    ./falconctf analyze challenge.zip --password secret

Other commands:

    ./falconctf file challenge.bin
    ./falconctf strings challenge.bin
    ./falconctf flags 'flag{example}'
    ./falconctf base64 --decode ZmxhZ3tleGFtcGxlfQ==
    ./falconctf hex challenge.bin
    ./falconctf system

---

## Interactive Mode

Run FalconCTF without arguments:

    ./falconctf

Available options include:

    [1] Smart Analysis
    [2] File Analyzer
    [3] Flag Detector
    [4] Strings Extractor
    [5] Base64 Tool
    [6] Hex Analyzer
    [7] System Information
    [8] Exit

---

## Competition Demo

FalconCTF includes a demonstration challenge:

    demo/competition_challenge.txt

Run it with:

    ./falconctf analyze demo/competition_challenge.txt

The demo demonstrates this pipeline:

    Encoded TXT
        ↓
    Base64 Detection
        ↓
    Automatic Decoding
        ↓
    ZIP Payload Detection
        ↓
    Payload Export
        ↓
    Archive Analysis
        ↓
    Interesting File Detection
        ↓
    Flag Detection
        ↓
    Classification
        ↓
    Solve Plan
        ↓
    Report

Demo flag:

    FalconCTF{competition_demo_success}

---

## Reports

FalconCTF automatically generates structured reports containing:

- File information
- Hashes
- Challenge classification
- Payload intelligence
- Encoding information
- Interest score
- Flag candidates
- Interesting findings
- Recommendations
- Solve plan

Reports are generated inside:

    reports/

Decoded payloads are exported inside:

    output/

---

## Automated Testing

Run the automated test suite:

    python3 -m pytest -q

FalconCTF includes regression tests covering:

- Payload inspection
- Encoding detection
- Recursive decoding
- File signatures
- False-positive handling
- Payload extraction
- Classification
- Scoring
- Recommendations
- Solve planning
- Report generation

---

## Current Scope

FalconCTF is currently strongest in:

- Encoding challenge triage
- Archive challenge analysis
- Forensics-oriented artifacts
- Binary / Reverse Engineering triage

FalconCTF is not currently intended to replace specialized tools for:

- Web exploitation
- Binary exploitation
- Advanced cryptography
- Full automated reverse engineering

Instead, FalconCTF identifies useful evidence and helps determine the best next investigation path.

---

## Project Structure

    FalconCTF/
    ├── config/
    ├── demo/
    ├── modules/
    ├── src/
    ├── tests/
    ├── falconctf
    ├── pytest.ini
    ├── LICENSE
    └── README.md

---

## Responsible Use

FalconCTF is intended for:

- Capture The Flag competitions
- Cybersecurity education
- Security research
- Authorized laboratory environments

Only use FalconCTF on systems, files, and environments you are authorized to analyze.

---

## Version

**FalconCTF v1.0.0**
