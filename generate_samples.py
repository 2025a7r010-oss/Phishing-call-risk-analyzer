"""
AI-Based Phishing Call Detection and Analysis System
Utility: generate_samples.py

Generates realistic phone call audio WAV files using Windows SAPI TTS
for classroom demonstration and automated pipeline tests.
"""

import os
import subprocess
import sys
from pathlib import Path


SAMPLES = [
    {
        "filename": "high_risk_bank_fraud.wav",
        "title": "High Risk - Bank Fraud Impersonation Call",
        "description": "Caller claims to be from Bank Fraud Department, threatens account block within 15 mins, and demands OTP.",
        "text": "Hello, this is officer Rahul calling from the bank fraud department. We have detected suspicious activity on your debit card. Your account will be blocked immediately within fifteen minutes. To cancel the block, you must share your OTP sent to your phone right now. Do not delay, verify your OTP immediately."
    },
    {
        "filename": "high_risk_remote_support.wav",
        "title": "High Risk - Fake Technical Support & Remote Access",
        "description": "Caller claims your system is infected and demands you install AnyDesk for screen sharing.",
        "text": "Good afternoon, I am speaking from cyber security technical support team. A severe virus has compromised your online banking account. You need to install AnyDesk immediately and grant remote access to our executive. Stay on the line and do not hang up, open AnyDesk right now."
    },
    {
        "filename": "medium_risk_kyc_alert.wav",
        "title": "Medium Risk - KYC Update Notice",
        "description": "Caller notifies that KYC has expired and urges completing it immediately, without asking for OTP.",
        "text": "Dear customer, this is an official verification call from customer support. Your KYC and Aadhaar verification has expired. Your account verification is pending. Please complete your KYC immediately to avoid any service disruption on your account."
    },
    {
        "filename": "low_risk_appointment.wav",
        "title": "Low Risk - Doctor Appointment Reminder",
        "description": "Standard legitimate reminder call with explicit safety advice.",
        "text": "Hello, this is a reminder call from City Health Clinic regarding your regular health checkup scheduled for tomorrow at ten in the morning. Please arrive ten minutes early. Please note, our clinic will never ask for your password or OTP. Have a wonderful day."
    }
]


def generate_all_samples():
    output_dir = Path(__file__).resolve().parent / "sample_audio"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Generating sample audio files in: {output_dir}")

    # Build a powershell script
    ps_lines = [
        "Add-Type -AssemblyName System.Speech",
        "$synth = New-Object System.Speech.Synthesis.SpeechSynthesizer"
    ]

    for sample in SAMPLES:
        target_path = (output_dir / sample["filename"]).resolve()
        safe_path = str(target_path).replace("'", "''")
        safe_text = sample["text"].replace("'", "''")
        ps_lines.append(f"$synth.SetOutputToWaveFile('{safe_path}')")
        ps_lines.append(f"$synth.Speak('{safe_text}')")
        ps_lines.append(f"Write-Host 'Generated: {sample['filename']}'")

    ps_lines.append("$synth.Dispose()")
    ps_lines.append("Write-Host 'All samples successfully synthesized.'")

    ps_script_path = output_dir / "_synth_script.ps1"
    with open(ps_script_path, "w", encoding="utf-8") as f:
        f.write("\n".join(ps_lines))

    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ps_script_path)],
            capture_output=True,
            text=True
        )
        print("PowerShell Output:")
        print(proc.stdout)
        if proc.stderr:
            print("PowerShell Stderr:", proc.stderr)
    finally:
        if ps_script_path.exists():
            ps_script_path.unlink()

    # Verify generated files
    for sample in SAMPLES:
        p = output_dir / sample["filename"]
        if p.exists() and p.stat().st_size > 0:
            print(f"  [OK] {sample['filename']} ({p.stat().st_size} bytes)")
        else:
            print(f"  [FAILED] {sample['filename']}")


if __name__ == "__main__":
    generate_all_samples()
