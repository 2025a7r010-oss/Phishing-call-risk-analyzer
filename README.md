# AI-Based Phishing Call Detection and Risk Analysis System
**B.Tech CSE Cyber Security Mini-Project**

---

## 1. Project Overview

The **AI-Based Phishing Call Detection and Risk Analysis System** is an intelligent cybersecurity application designed to analyze phone-call conversations, identify potential phishing and social-engineering tactics, and explain security risks.

The application analyzes recorded phone-call conversations to identify potential phishing and social-engineering indicators. It combines speech transcription with explainable text analysis to help users understand suspicious communication and make safer decisions.

It requires **zero paid cloud APIs**, **zero API keys**, and executes entirely on local hardware using open-source libraries.

---

## 2. Implemented Technologies

| Component | Technology | Rationale & Purpose |
| :--- | :--- | :--- |
| **Backend Logic** | Python 3.11 | Core evaluation pipeline, regex pattern matching, and scoring logic. |
| **Web Interface** | Streamlit | Professional, interactive dashboard with responsive navigation. |
| **Speech-to-Text** | `faster-whisper` (`tiny.en`) | Offline speech recognition running locally on CPU with 8-bit quantization. |
| **Audio Processing** | `imageio-ffmpeg` & `pydub` | Automatic local audio decoding supporting WAV, MP3, and M4A. |
| **Pattern Matching** | Python `re` (Regular Expressions) | Deterministic, transparent, and explainable indicator extraction. |
| **Automated Testing** | `pytest` | Test suite covering boundaries, deduplication, negations, and audio decoding. |

---

## 3. Application Structure & Navigation

The application is structured into four focused pages:

1. **Dashboard:** Overview of system capabilities, core feature cards (Audio-to-Text Transcription, Phishing Indicator Detection, Explainable Risk Assessment, Security Recommendations), a three-step workflow (`Upload Recording → Generate Transcript → Analyze Risk`), and prominent navigation action buttons.
2. **Analyze Call:** Upload recorded call audio (`.wav`, `.mp3`, `.m4a`), view file metadata and audio player, transcribe via local Whisper, review the transcript, and evaluate phishing risks.
3. **Transcript Analysis:** Manually enter or paste call conversation text, with optional reference test examples, and clear input controls.
4. **Analysis Results:** Dedicated security assessment report displaying calculated risk score (0–100), calibrated risk level with glowing badges, compact Risk Level Guide, explainable score breakdown, indicator evidence, timestamp, analysis method, and tailored safety advice.

---

## 4. Risk Level Guide & Scoring Logic

The risk score is calculated dynamically in code from the detected indicators using a transparent heuristic formula:

$$\text{Final Score} = \min(100, \min(70, \text{Base Indicator Score}) + \text{Compound Synergy Bonus})$$

### Risk Level Scale
- 🟢 **Low Risk (0 – 30 pts):** Standard, non-threatening communication or legitimate bank advisories.
- 🟡 **Medium Risk (31 – 70 pts):** Suspicious calls displaying single-vector pressure (e.g. expiring rewards with OTP inquiry).
- 🔴 **High Risk (71 – 100 pts):** Coordinated multi-vector attacks combining impersonation, threats, fund diversion, and credential extraction.

> *Heuristic Note:* The score is a heuristic risk assessment based on observed language patterns, not a statistical certainty of fraud.

### Indicator Categories & Caps
- **Credential Harvesting (OTP / PIN / CVV / Passwords):** Max 28 pts
- **Payment Diversion & Safe Account Transfers:** Max 24 pts
- **Account Freeze / Legal Threats:** Max 22 pts
- **Remote Access (AnyDesk / Screen Share):** Max 26 pts
- **Urgency & Psychological Pressure:** Max 18 pts
- **Authority Impersonation (Bank / Police / Cyber Cell):** Max 16 pts
- **Isolation & Secrecy Demands:** Max 16 pts
- **Suspicious Web Links & SMS Redirection:** Max 16 pts

### Compound Tactic Synergies
- **High-Pressure Credential Extraction (Urgency + OTP):** +16 pts
- **Coercive Authority Impersonation (Authority + Threats):** +14 pts
- **Extortion / Penalty Payment (Threats + Payment):** +16 pts
- **Tech Support Takeover (Authority + Remote Access):** +18 pts
- **Victim Isolation (Secrecy + Urgency):** +12 pts

---

## 5. Project Directory Structure

```text
phishing_call_detector/
├── .streamlit/
│   └── config.toml         # Server config: binds to 0.0.0.0:8501 for local network access
├── app.py                  # Main Streamlit web application & 5-section navigation
├── analyzer.py             # Rule-based text analysis, scoring, and explanations
├── transcriber.py          # Offline faster-whisper speech-to-text engine
├── speech_to_text.py       # Compatibility bridge importing transcriber.py
├── demo_data.py            # Reference call conversations for testing & evaluation
├── generate_samples.py     # Script to generate speech WAV audio files via Windows SAPI TTS
├── requirements.txt        # Verified project dependencies
├── README.md               # Complete project documentation
├── verify_pipeline.py      # Console diagnostic script (Windows UTF-8 compatible)
├── sample_audio/           # Test audio files in WAV, MP3, and M4A formats
│   ├── high_risk_bank_fraud.wav
│   ├── high_risk_bank_fraud.mp3
│   ├── high_risk_bank_fraud.m4a
│   ├── high_risk_remote_support.wav
│   ├── medium_risk_kyc_alert.wav
│   └── low_risk_appointment.wav
└── tests/
    └── test_pipeline.py    # Automated test suite (12 test cases)
```

---

## 6. Installation & Execution Guide

### Step 1: Open Terminal in the Project Directory
```powershell
cd "c:\Users\HP\Documents\ak skills\phishing_call_detector"
```
*(Or in `c:\Users\HP\Downloads\Project\phishing_call_detector`)*

### Step 2: Install Python Dependencies
```powershell
pip install -r requirements.txt
```

### Step 3: Launch the Application
Run the standard Streamlit command:
```powershell
streamlit run app.py
```

Because `.streamlit/config.toml` is pre-configured with `address = "0.0.0.0"` and `port = 8501`, the application will automatically bind to all network interfaces and display both local and network URLs:
- **Local URL:** `http://localhost:8501` (or `http://127.0.0.1:8501`)
- **Network URL:** `http://192.168.31.94:8501`

---

## 7. Local Network IP Access (Demonstration on Another Device)

To demonstrate the application to your teacher or classmates on another device (such as a smartphone, tablet, or another laptop) connected to the same Wi-Fi:

### 1. How to Find Your Laptop's IPv4 Address
1. Open PowerShell or Command Prompt on your laptop.
2. Run:
   ```powershell
   ipconfig
   ```
3. Look for the active **Wireless LAN adapter Wi-Fi** section.
4. Locate the **IPv4 Address** line (for example: `192.168.31.94`).

### 2. URL Format for the Teacher's Device
Open any web browser (Chrome, Safari, Edge) on the other device and enter:
```text
http://<YOUR-LAPTOP-IP>:8501
```
For example:
```text
http://192.168.31.94:8501
```

### 3. Essential Network Prerequisites
- **Same Wi-Fi Network:** The teacher's device and your laptop must be connected to the exact same Wi-Fi router or mobile hotspot. If one device is on mobile data (4G/5G) and the other is on Wi-Fi, they will not be able to communicate.
- **Client Isolation:** Some university or public guest Wi-Fi networks block device-to-device communication (AP Isolation). If this occurs, creating a quick mobile hotspot from your phone and connecting both your laptop and the other device to it guarantees connectivity.

### 4. Windows Firewall Access (If Required)
If the second device cannot load the page, Windows Defender Firewall may be blocking incoming connections on port 8501. To allow it, run this PowerShell command as Administrator:
```powershell
New-NetFirewallRule -DisplayName "Streamlit Cyber Security App" -Direction Inbound -LocalPort 8501 -Protocol TCP -Action Allow
```
*(Alternatively, when Windows displays the "Windows Defender Firewall has blocked some features of this app" popup upon running Streamlit, check "Private networks" and click "Allow access".)*

### 5. Private Local Network vs. Public Internet
- **Private Local Network:** This configuration (`0.0.0.0:8501`) makes the application accessible *only* to devices connected to your local Wi-Fi router. It is **not** exposed to the public internet and does not require port forwarding.
- **Permanent Public URL:** Deploying a permanent public link accessible from anywhere in the world requires cloud hosting (e.g., Streamlit Community Cloud, AWS, or Hugging Face Spaces) and is distinct from local classroom demonstration.

---

## 8. Automated Testing & Reliability

The project includes an automated test suite verifying 12 key criteria:
```powershell
pytest tests/test_pipeline.py -v
```

| # | Test Dimension | Verification Method | Status |
| :-: | :--- | :--- | :---: |
| 1 | **Normal Conversation** | Verified routine clinic appointment produces 0 score / Low Risk | ✅ Passed |
| 2 | **Sensitive Info Request** | Verified urgent OTP call produces 62 score / Medium Risk | ✅ Passed |
| 3 | **Multi-Vector Scam** | Verified coercion attack produces 100 score / High Risk | ✅ Passed |
| 4 | **Empty Transcripts** | Verified empty string and whitespace return 0 / Low Risk safely | ✅ Passed |
| 5 | **Deduplication & Caps** | Verified repeated urgency phrases do not exceed category caps | ✅ Passed |
| 6 | **Invalid Audio Handling** | Verified missing, 0-byte, and unsupported files fail gracefully | ✅ Passed |
| 7 | **Score Boundaries** | Verified scores strictly stay within [0, 100] across all cases | ✅ Passed |
| 8 | **Reference Conversations** | Verified all test examples match their expected risk tiers | ✅ Passed |
| 9 | **Safe Negation Filter** | Verified "never ask for OTP" is recognized as defensive advice | ✅ Passed |
| 10 | **Speech-to-Text Pipeline**| Verified local Whisper transcription on `.wav`, `.mp3`, and `.m4a` | ✅ Passed |
| 11 | **Isolated Keywords** | Verified words like "bank", "OTP", "KYC" alone do not trigger phishing | ✅ Passed |
| 12 | **Schema & Diagnostics** | Verified runtime health checks and session state data schema | ✅ Passed |

---

## 9. System Limitations

- **Analyzes Pre-Recorded / Input Data Only:** Evaluates intentionally uploaded audio recordings or manually pasted transcripts; it does not intercept or monitor incoming phone calls.
- **Speech Recognition Constraints:** Transcription accuracy depends on audio quality, speaker accent, and ambient background noise.
- **Heuristic Risk Estimation:** Risk scores are rule-based heuristic estimates intended for user awareness, not statistical proof that a caller is fraudulent.
- **Scam Evolution:** Highly novel attack patterns using non-standard wording may not match defined rules, while benign calls with unusual phrasing may occasionally generate false alarms.
