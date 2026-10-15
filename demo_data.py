"""
AI-Based Phishing Call Detection and Risk Analysis System
Module: demo_data.py

Reference Call Conversations for Testing and Evaluation.
Provides realistic phone-call dialogue transcripts representing:
- Low Risk (Routine healthcare reminder, benign bank advisory with safe negation)
- Medium Risk (Expiring reward points & OTP inquiry)
- High Risk (Multi-vector legal coercion & impersonation scam)
"""

from typing import List, Dict, Any


DEMO_SAMPLES: List[Dict[str, Any]] = [
    {
        "id": "sample_low_risk_clinic",
        "title": "Example 1: Routine Appointment Confirmation",
        "expected_risk": "Low Risk",
        "expected_score_range": "0 – 30",
        "scenario": "Legitimate Healthcare Reminder",
        "description": (
            "A standard, routine confirmation call from a local healthcare clinic. "
            "Contains no pressure, no requests for credentials, and no payment instructions."
        ),
        "transcript": (
            "Hello Mr. Sharma, this is an automated reminder from City Care Clinic regarding "
            "your regular dental checkup scheduled for tomorrow afternoon at four thirty PM with "
            "Dr. Verma. Please remember to arrive ten minutes early and bring your previous prescription. "
            "If you need to reschedule, please call our clinic desk during regular working hours. "
            "Thank you and have a wonderful day."
        ),
        "audio_filename": "low_risk_appointment.wav"
    },
    {
        "id": "sample_medium_risk_otp",
        "title": "Example 2: Expiring Reward Points & OTP Request",
        "expected_risk": "Medium Risk",
        "expected_score_range": "31 – 70",
        "scenario": "Urgent Reward Points Expiration & Credential Inquiry",
        "description": (
            "A suspicious call where the caller creates artificial urgency regarding expiring reward points "
            "and asks the user to disclose an authentication code (OTP) over the phone right now."
        ),
        "transcript": (
            "Hello, this is calling regarding your reward points account. "
            "Your accumulated bonus points worth four thousand rupees will expire today within two hours. "
            "To renew your points before they expire, please share the OTP sent to your phone right now. "
            "Please tell me the code immediately so I can process the renewal for you."
        ),
        "audio_filename": "medium_risk_kyc_alert.wav"
    },
    {
        "id": "sample_high_risk_multi_vector",
        "title": "Example 3: Multi-Vector Legal Coercion & Impersonation",
        "expected_risk": "High Risk",
        "expected_score_range": "71 – 100",
        "scenario": "Law Enforcement Impersonation + Secrecy + Account Block + Safe Account Transfer + OTP",
        "description": (
            "A critical social-engineering attack combining authority impersonation (Reserve Bank / Cyber Cell), "
            "threat of arrest and account freezing, isolation/secrecy orders, urgent fund diversion to a "
            "'safe account', and requests for OTP/ATM PIN."
        ),
        "transcript": (
            "Attention, this is Senior Inspector Sharma calling from the Reserve Bank cyber security "
            "division and bank fraud department. Your bank account has been flagged for illegal activity "
            "and will be blocked immediately within fifteen minutes. A police case and court notice are "
            "being issued right now. You must not tell anyone or discuss this with family, this call is strictly "
            "confidential. To prevent immediate arrest, you must transfer your funds to our government safe "
            "account immediately right now and provide your ATM PIN and the OTP sent to your phone. "
            "Stay on the line and do not hang up the call."
        ),
        "audio_filename": "high_risk_bank_fraud.wav"
    },
    {
        "id": "sample_low_risk_bank_safe",
        "title": "Example 4: Official Bank Security Advisory (Safe Context)",
        "expected_risk": "Low Risk",
        "expected_score_range": "0 – 30",
        "scenario": "Legitimate Bank Reminder with Defensive Advice",
        "description": (
            "Demonstrates context-awareness: Although the caller mentions banking and the word 'OTP', "
            "they explicitly advise the customer NEVER to share passwords or OTPs. The system recognizes "
            "this safe context and correctly classifies it as Low Risk."
        ),
        "transcript": (
            "Hello, this is a customer service reminder from Apex Bank regarding your monthly statement. "
            "Your account statement for this month is ready to view in your official net banking portal. "
            "Apex Bank reminds you that our officers will never ask for your OTP, CVV, or login password. "
            "Please do not share your confidential credentials with anyone over the phone. Have a great day."
        ),
        "audio_filename": None
    }
]


def get_all_demo_samples() -> List[Dict[str, Any]]:
    """Returns the list of all reference call profiles."""
    return DEMO_SAMPLES


def get_all_example_samples() -> List[Dict[str, Any]]:
    """Alias returning the list of all reference call profiles."""
    return DEMO_SAMPLES


def get_demo_sample_by_id(sample_id: str) -> Dict[str, Any]:
    """Retrieves a specific reference call profile by ID."""
    for sample in DEMO_SAMPLES:
        if sample["id"] == sample_id:
            return sample
    return DEMO_SAMPLES[0]
