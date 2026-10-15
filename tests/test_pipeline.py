"""
AI-Based Phishing Call Detection and Risk Analysis System
Module: tests/test_pipeline.py

Comprehensive Test Suite Verifying:
1. Normal harmless conversation (Low Risk: 0–30)
2. Conversation requesting sensitive information / OTP (Medium Risk: 31–70)
3. Multi-vector scam combining impersonation, threats, secrecy, urgent payment (High Risk: 71–100)
4. Empty and whitespace transcripts
5. Repeated indicators and category score capping
6. Invalid, empty, or unsupported audio handling
7. Risk score boundary calibrations (0–100 range and tier thresholds)
8. Reference call evaluation without audio/Whisper dependencies
9. Single-word false positive prevention (innocuous 'bank', 'otp', 'kyc')
10. Speech-to-text audio transcription across WAV, MP3, and M4A
11. Isolated keywords alone do not trigger phishing
12. System health diagnostics and session result data schema integrity
"""

import os
import sys
import tempfile
from pathlib import Path
import pytest

# Ensure project root is in sys.path
PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from analyzer import PhishingCallAnalyzer
from transcriber import LocalSpeechTranscriber
from demo_data import DEMO_SAMPLES, get_all_demo_samples


@pytest.fixture
def analyzer():
    return PhishingCallAnalyzer()


@pytest.fixture
def transcriber():
    return LocalSpeechTranscriber(model_size="tiny.en")


# ==============================================================================
# TEST 1: NORMAL HARMLESS CONVERSATION
# ==============================================================================
def test_normal_harmless_conversation(analyzer):
    """A routine, polite healthcare or business call should be classified as Low Risk (0–30)."""
    transcript = (
        "Hello Mr. Sharma, this is an automated reminder from City Care Clinic regarding "
        "your regular dental checkup scheduled for tomorrow at four thirty PM with Dr. Verma. "
        "Please arrive ten minutes early. If you need to reschedule, call reception during work hours."
    )
    res = analyzer.analyze_transcript(transcript)
    assert 0 <= res["score"] <= 30, f"Expected Low Risk (0-30), got score: {res['score']}"
    assert res["risk_level"] == "Low Risk"
    assert len(res["detected_indicators"]) == 0


# ==============================================================================
# TEST 2: CONVERSATION REQUESTING SENSITIVE INFORMATION / OTP
# ==============================================================================
def test_sensitive_info_request_medium_risk(analyzer):
    """A call requesting OTP verification with time urgency should trigger Medium Risk (31–70)."""
    transcript = (
        "Dear customer, this is an official verification call from customer support. "
        "Your account verification is pending and will expire within two hours. "
        "We have sent an authentication code to your mobile number. Please share your OTP sent to "
        "your phone right now so we can complete verification before the deadline."
    )
    res = analyzer.analyze_transcript(transcript)
    assert 31 <= res["score"] <= 70, f"Expected Medium Risk (31-70), got score: {res['score']}"
    assert res["risk_level"] == "Medium Risk"
    assert any("credential_harvesting" in c["id"] for c in res["detected_categories"])
    assert any("OTP" in rec for rec in res["recommendations"])


# ==============================================================================
# TEST 3: MULTI-VECTOR COERCION SCAM (HIGH RISK)
# ==============================================================================
def test_multi_vector_high_risk_scam(analyzer):
    """
    A call combining authority impersonation, account blocking threats, secrecy,
    safe account payment demand, and OTP extraction must score High Risk (71–100).
    """
    transcript = (
        "Attention, this is Senior Inspector Sharma calling from the Reserve Bank cyber security "
        "division and bank fraud department. Your bank account has been flagged for illegal activity "
        "and will be blocked immediately within fifteen minutes. A police case and court notice are "
        "being issued right now. You must not tell anyone or discuss this with family, this call is strictly "
        "confidential. To prevent immediate arrest, you must transfer your funds to our government safe "
        "account immediately right now and provide your ATM PIN and the OTP sent to your phone. "
        "Stay on the line and do not hang up the call."
    )
    res = analyzer.analyze_transcript(transcript)
    assert 71 <= res["score"] <= 100, f"Expected High Risk (71-100), got score: {res['score']}"
    assert res["risk_level"] == "High Risk"
    assert len(res["combinations_detected"]) >= 2
    assert any("safe account" in rec.lower() or "transfer" in rec.lower() for rec in res["recommendations"])


# ==============================================================================
# TEST 4: EMPTY AND WHITESPACE TRANSCRIPTS
# ==============================================================================
def test_empty_transcripts_and_whitespace(analyzer):
    """Empty strings, None, or whitespace must not crash and should return score 0 / Low Risk."""
    for empty_val in ["", "   ", "\n\t  \n"]:
        res = analyzer.analyze_transcript(empty_val)
        assert res["score"] == 0
        assert res["risk_level"] == "Low Risk"
        assert "empty" in res["summary"].lower() or "no transcript" in res["summary"].lower()


# ==============================================================================
# TEST 5: REPEATED INDICATORS & SCORE CAPPING
# ==============================================================================
def test_repeated_indicators_and_score_capping(analyzer):
    """Repeating the same urgency phrase must not inflate the score beyond the category cap."""
    single_urgency = "Please act immediately right now."
    repeated_urgency = "Act immediately right now! Right now! Immediately! Urgent! Do not delay! Right now! Urgent!"

    res_single = analyzer.analyze_transcript(single_urgency)
    res_repeat = analyzer.analyze_transcript(repeated_urgency)

    # Urgency alone has a category cap of 18, so it must stay in Low Risk (<= 30)
    assert res_repeat["score"] <= 30, f"Urgency alone inflated score to {res_repeat['score']}"
    assert res_repeat["risk_level"] == "Low Risk"


# ==============================================================================
# TEST 6: INVALID AND UNSUPPORTED AUDIO
# ==============================================================================
def test_invalid_and_unsupported_audio(transcriber):
    """Transcriber must handle nonexistent, empty, and unsupported files with clean errors."""
    # 1. Non-existent file
    res1 = transcriber.transcribe_audio_file("non_existent_audio_file_999.wav")
    assert res1["success"] is False
    assert "not found" in res1["error"].lower()

    # 2. 0-byte file
    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
        empty_path = tmp.name
    try:
        res2 = transcriber.transcribe_audio_file(empty_path)
        assert res2["success"] is False
        assert "empty" in res2["error"].lower() or "0 bytes" in res2["error"].lower()
    finally:
        if os.path.exists(empty_path):
            os.remove(empty_path)

    # 3. Unsupported file extension
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
        txt_path = tmp.name
        tmp.write(b"plain text audio")
    try:
        res3 = transcriber.transcribe_audio_file(txt_path)
        assert res3["success"] is False
        assert "unsupported" in res3["error"].lower()
    finally:
        if os.path.exists(txt_path):
            os.remove(txt_path)


# ==============================================================================
# TEST 7: RISK SCORE BOUNDARIES & TIER LIMITS
# ==============================================================================
def test_risk_score_boundaries(analyzer):
    """Score must always be strictly between 0 and 100 inclusive, and tiers must match specifications."""
    # Low: 0–30, Medium: 31–70, High: 71–100
    res_empty = analyzer.analyze_transcript("")
    assert res_empty["score"] == 0
    assert res_empty["risk_level"] == "Low Risk"

    # Extreme attack containing every single malicious indicator
    mega_scam = (
        "Calling from bank fraud department and cyber security police. Your account will be blocked "
        "immediately within fifteen minutes. A police case and arrest warrant are issued. "
        "Do not tell anyone, keep this strictly confidential. Install AnyDesk right now and grant "
        "remote access. Transfer your balance to our safe account immediately. Share your OTP and ATM PIN "
        "sent to your mobile number. Click on bit.ly link sent via SMS."
    )
    res_mega = analyzer.analyze_transcript(mega_scam)
    assert res_mega["score"] <= 100
    assert res_mega["score"] >= 71
    assert res_mega["risk_level"] == "High Risk"


# ==============================================================================
# TEST 8: REFERENCE CONVERSATIONS RELIABILITY
# ==============================================================================
def test_demo_mode_without_audio_dependency(analyzer):
    """All reference transcripts in demo_data.py must run directly in analyzer without Whisper."""
    samples = get_all_demo_samples()
    assert len(samples) >= 3

    for sample in samples:
        res = analyzer.analyze_transcript(sample["transcript"])
        assert 0 <= res["score"] <= 100
        assert res["risk_level"] == sample["expected_risk"], (
            f"Sample '{sample['title']}' expected {sample['expected_risk']}, got {res['risk_level']} (Score: {res['score']})"
        )


# ==============================================================================
# TEST 9: INNOCUOUS WORDS & SAFE DEFENSIVE NEGATION
# ==============================================================================
def test_innocuous_words_and_safe_negation(analyzer):
    """
    Conversations discussing banking or OTP innocuously or providing security warnings
    must NOT be classified as phishing calls.
    """
    # 1. Casual conversational bank mention
    casual_chat = "Hey mom, I stopped by the bank to deposit my scholarship check, see you at dinner."
    res1 = analyzer.analyze_transcript(casual_chat)
    assert res1["score"] <= 30
    assert res1["risk_level"] == "Low Risk"

    # 2. Legitimate bank reminder advising NEVER to share OTP
    bank_advisory = (
        "Hello, this is a reminder from Apex Bank regarding your monthly statement. "
        "Apex Bank reminds you that our officers will never ask for your OTP, CVV, or PIN. "
        "Please do not share your credentials with anyone."
    )
    res2 = analyzer.analyze_transcript(bank_advisory)
    assert res2["score"] <= 30
    assert res2["risk_level"] == "Low Risk"
    assert len(res2["safe_indicators_detected"]) > 0


# ==============================================================================
# TEST 10: SPEECH-TO-TEXT TRANSCRIPTION ON AUDIO SAMPLES (WAV, MP3, M4A)
# ==============================================================================
def test_speech_to_text_audio_pipeline(transcriber):
    """Verifies that faster-whisper successfully transcribes WAV, MP3, and M4A files."""
    sample_dir = PROJECT_DIR / "sample_audio"

    for ext in ["wav", "mp3", "m4a"]:
        sample_path = sample_dir / f"high_risk_bank_fraud.{ext}"
        if sample_path.exists():
            res = transcriber.transcribe_audio_file(sample_path)
            assert res["success"] is True
            assert len(res["text"]) > 20
            assert "otp" in res["text"].lower() or "bank" in res["text"].lower()


# ==============================================================================
# TEST 11: ISOLATED KEYWORDS ALONE DO NOT TRIGGER PHISHING
# ==============================================================================
def test_isolated_keywords_alone_do_not_trigger_phishing(analyzer):
    """Isolated keywords like 'bank', 'OTP', or 'KYC' on their own must not trigger phishing."""
    cases = [
        "The local bank is closed on Sundays.",
        "We learned about OTP authentication in our cyber security class today.",
        "Please carry your KYC identification documents for campus registration."
    ]
    for text in cases:
        res = analyzer.analyze_transcript(text)
        assert res["score"] <= 30, f"Keyword alone inflated score to {res['score']} for: '{text}'"
        assert res["risk_level"] == "Low Risk"


# ==============================================================================
# TEST 12: SYSTEM HEALTH DIAGNOSTICS & RESULT SCHEMA INTEGRITY
# ==============================================================================
def test_system_health_and_result_schema(transcriber, analyzer):
    """Verifies genuine runtime health checks and ensures result dictionary has all required keys."""
    health = transcriber.check_system_health()
    assert "faster_whisper_available" in health
    assert "ffmpeg_available" in health
    assert "model_ready" in health

    # Verify result dictionary schema
    sample_text = "This is a call from tech support asking you to install AnyDesk right now."
    res = analyzer.analyze_transcript(sample_text)
    required_keys = [
        "score", "risk_level", "summary", "scoring_breakdown", "key_reasons",
        "detected_categories", "detected_indicators", "combinations_detected",
        "safe_indicators_detected", "recommendations", "educational_disclaimer"
    ]
    for key in required_keys:
        assert key in res, f"Missing required result key: {key}"
