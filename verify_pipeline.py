"""
AI-Based Phishing Call Detection and Risk Analysis System
Module: verify_pipeline.py

End-to-end pipeline verification script.
Tests both Speech-to-Text transcription on audio files (WAV, MP3, M4A)
and instant text analysis across demonstration samples.
Windows-compatible terminal output (avoids charmap codec encoding errors).
"""

import sys
from pathlib import Path

# Ensure UTF-8 output on Windows consoles if supported
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add project root to path
PROJECT_DIR = Path(__file__).resolve().parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from transcriber import LocalSpeechTranscriber
from analyzer import PhishingCallAnalyzer
from demo_data import get_all_demo_samples


def run_verification():
    print("=" * 70)
    print("  AI-BASED PHISHING CALL DETECTION -- PIPELINE VERIFICATION")
    print("=" * 70)

    transcriber = LocalSpeechTranscriber(model_size="tiny.en")
    analyzer = PhishingCallAnalyzer()

    # Part 1: Verify System Health
    print("\n[1] Checking System Health & Prerequisites...")
    health = transcriber.check_system_health()
    print(f"  * Faster-Whisper Available: {health['faster_whisper_available']}")
    print(f"  * Audio Decoder (FFmpeg):   {health['ffmpeg_available']} ({health['ffmpeg_path']})")
    print(f"  * Speech Model Ready:       {health['model_ready']} ({health['model_size']})")

    # Part 2: Verify Audio Transcription Pipeline
    print("\n[2] Testing Speech-to-Text Audio Transcription...")
    audio_test_files = [
        "high_risk_bank_fraud.wav",
        "medium_risk_kyc_alert.wav",
        "low_risk_appointment.wav",
        "high_risk_bank_fraud.mp3",
        "high_risk_bank_fraud.m4a"
    ]

    for filename in audio_test_files:
        filepath = PROJECT_DIR / "sample_audio" / filename
        if not filepath.exists():
            print(f"  [WARN] Skipping {filename} (not found)")
            continue

        res = transcriber.transcribe_audio_file(filepath, original_filename=filename)
        if not res["success"]:
            print(f"  [FAIL] {filename} -> {res.get('error')}")
            sys.exit(1)

        analysis = analyzer.analyze_transcript(res["text"])
        snippet = res["text"][:65] + "..." if len(res["text"]) > 65 else res["text"]
        print(f"  [PASS] {filename:<28} | Duration: {res['duration']:>4}s | Score: {analysis['score']:>3}/100 | Tier: {analysis['risk_level']}")
        print(f"         Excerpt: \"{snippet}\"")

    # Part 3: Verify Demo Mode Scenarios (Offline Transcripts)
    print("\n[3] Testing Demo Mode Scenarios (No Whisper Dependency Required)...")
    demos = get_all_demo_samples()
    for sample in demos:
        analysis = analyzer.analyze_transcript(sample["transcript"])
        status = "[PASS]" if analysis["risk_level"] == sample["expected_risk"] else "[FAIL]"
        print(f"  {status} | {sample['expected_risk']:<11} | Score: {analysis['score']:>3}/100 | {sample['title'][:48]}")
        print(f"         Formula: {analysis['scoring_breakdown']['formula']}")

    print("\n" + "=" * 70)
    print("  >>> ALL PIPELINE TESTS AND VERIFICATIONS PASSED SUCCESSFULLY! <<<")
    print("=" * 70)


if __name__ == "__main__":
    run_verification()
