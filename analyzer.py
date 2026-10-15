"""
AI-Based Phishing Call Detection and Risk Analysis System
Module: analyzer.py

Transparent, Rule-Based Phishing & Social Engineering Analyzer.
Performs text preprocessing, pattern matching across 10 social-engineering categories,
detects coordinated tactic combinations (synergies), applies score capping to prevent
inflation, and produces an explainable 0–100 risk score and tailored safety recommendations.

Risk Level Scale:
  - Low Risk:    0 – 30
  - Medium Risk: 31 – 70
  - High Risk:   71 – 100
"""

import re
from typing import Dict, List, Any


class PhishingCallAnalyzer:
    """
    Context-aware, rule-based analyzer for social engineering and vishing detection.
    Evaluates call transcripts, checks for legitimate security advice / negations,
    identifies dangerous tactic combinations, and outputs an explainable risk evaluation.
    """

    def __init__(self):
        # 1. Social-Engineering Indicator Categories
        # Each category has regex patterns, associated points, and a maximum score cap
        # to prevent a single repeated phrase from inflating the entire score.
        self.category_definitions = {
            "credential_harvesting": {
                "name": "Credential & Sensitive Data Harvesting",
                "severity": "Critical",
                "max_score": 28,
                "description": "Caller asks for one-time passwords (OTP), PINs, CVV, or passwords.",
                "patterns": [
                    (r"\b(?:share|tell|give|read|send|enter|provide|verify)\b[^\n.!?]{0,40}\b(?:otp|one[- ]time[- ]password|cvv|atm pin|secret pin|login password|mpin)\b", 22, "Direct request to disclose OTP / PIN / Password"),
                    (r"\b(?:otp|code|pin)\b[^\n.!?]{0,35}\b(?:sent to your (?:phone|mobile|number)|received just now|on your screen)\b", 16, "Inquiry about temporary authentication code sent to device"),
                    (r"\b(?:confirm|provide|read out)\b[^\n.!?]{0,30}\b(?:16[- ]digit card number|cvv number|expiry date)\b", 18, "Request for complete payment card details"),
                ],
                "safe_negation_patterns": [
                    r"\b(?:never|do not|don't)\b[^\n.!?]{0,45}\b(?:share|give|tell|disclose)\b[^\n.!?]{0,45}\b(?:otp|pin|password|cvv|credentials)\b",
                    r"\b(?:never|will never)\b[^\n.!?]{0,45}\b(?:ask for|request|demand)\b[^\n.!?]{0,45}\b(?:otp|password|pin|cvv)\b",
                    r"\b(?:bank|we|officers?|clinic|service)\b[^\n.!?]{0,45}\b(?:never|will never)\b[^\n.!?]{0,45}\b(?:ask|request)\b"
                ]
            },
            "financial_diversion": {
                "name": "Payment Diversion & Money Transfer Demands",
                "severity": "High",
                "max_score": 24,
                "description": "Caller instructs recipient to transfer funds or make urgent payments.",
                "patterns": [
                    (r"\b(?:transfer|send|deposit|pay)\b[^\n.!?]{0,40}\b(?:money|funds|penalty fee|security deposit|refundable fee|balance)\b", 18, "Instruction to send money or transfer balance"),
                    (r"\b(?:transfer to|send to)\b[^\n.!?]{0,35}\b(?:safe account|virtual account|temp(?:orary)? account|upi id|government safe account)\b", 22, "Request to redirect funds to an external 'safe' or temporary account"),
                    (r"\b(?:gift card|crypto|bitcoin|western union|voucher)\b[^\n.!?]{0,30}\b(?:payment|fee|transfer)\b", 20, "Unconventional and non-traceable payment method requested"),
                ],
                "safe_negation_patterns": []
            },
            "threats_intimidation": {
                "name": "Threats & Account Block Consequences",
                "severity": "High",
                "max_score": 22,
                "description": "Caller threatens account suspension, card block, legal action, or arrest.",
                "patterns": [
                    (r"\b(?:account|card|sim|connection|service)\b[^\n.!?]{0,35}\b(?:blocked|suspended|deactivated|terminated|frozen|cancelled|closed)\b", 15, "Threat of immediate account deactivation or freeze"),
                    (r"\b(?:blocked|suspended|terminated|frozen)\b[^\n.!?]{0,35}\b(?:within|today|immediately|permanently)\b", 14, "Imminent penalty consequence"),
                    (r"\b(?:police case|legal action|court notice|arrest warrant|cyber cell complaint|heavy penalty|fine of)\b", 18, "Threat of law enforcement, legal proceedings, or arrest"),
                ],
                "safe_negation_patterns": [
                    r"\b(?:to prevent|to protect against)\b[^\n.!?]{0,25}\b(?:fraud|suspension)\b"
                ]
            },
            "authority_impersonation": {
                "name": "Authority & Trust Impersonation",
                "severity": "Medium",
                "max_score": 16,
                "description": "Caller claims to represent a financial institution, regulatory body, or law enforcement.",
                "patterns": [
                    (r"\b(?:calling from|this is|speaking from|i am from)\b[^\n.!?]{0,45}\b(?:bank fraud department|head office|security division|reserve bank|rbi|cyber\s*security|technical support|tech support|card department)\b", 14, "Claims to represent bank fraud, cyber security, or tech support"),
                    (r"\b(?:i am|this is)\b[^\n.!?]{0,35}\b(?:officer|inspector|executive|manager|agent)\b[^\n.!?]{0,35}\b(?:from (?:the )?(?:bank|police|customs|tax department|cyber cell|reserve bank|support team))\b", 14, "Official title and agency impersonation"),
                    (r"\b(?:official verification call|authorized verification)\b", 8, "Vague claims of official authority"),
                ],
                "safe_negation_patterns": []
            },
            "urgency_coercion": {
                "name": "Urgency & Psychological Pressure",
                "severity": "High",
                "max_score": 18,
                "description": "Caller creates artificial panic or severe time pressure to force quick compliance.",
                "patterns": [
                    (r"\b(?:within\s+(?:\d+|five|ten|fifteen|thirty)\s+(?:minutes|mins|hours)|right now|immediately|urgent(?:ly)?|without delay)\b", 12, "Immediate deadline or extreme urgency demand"),
                    (r"\b(?:act now|before it is too late|last chance|final warning|limited time)\b", 10, "Pressure language demanding instant compliance"),
                    (r"\b(?:do not delay|time is running out|immediate action required)\b", 10, "Time-critical coercion phrase"),
                ],
                "safe_negation_patterns": []
            },
            "remote_access": {
                "name": "Remote Access & Software Installation",
                "severity": "Critical",
                "max_score": 26,
                "description": "Caller requests installation of remote control tools or screen sharing.",
                "patterns": [
                    (r"\b(?:install|download|open)\b[^\n.!?]{0,40}\b(?:anydesk|teamviewer|quicksupport|rustdesk|zoho assist|airdroid)\b", 24, "Request to install known remote desktop management tool"),
                    (r"\b(?:grant|give|enable)\b[^\n.!?]{0,35}\b(?:remote access|screen share|screen sharing|device control)\b", 22, "Direct request for device screen share or remote takeover"),
                    (r"\b(?:download|install)\b[^\n.!?]{0,35}\b(?:apk|support app|verification app|security patch)\b", 18, "Instruction to install external or unverified application"),
                ],
                "safe_negation_patterns": []
            },
            "isolation_tactics": {
                "name": "Isolation & Secrecy Tactics",
                "severity": "High",
                "max_score": 16,
                "description": "Caller instructs victim not to disconnect or talk to anyone, isolating them from outside advice.",
                "patterns": [
                    (r"\b(?:do not|don't)\b[^\n.!?]{0,30}\b(?:tell anyone|discuss with family|inform anyone|talk to the branch)\b", 15, "Coercing victim into keeping conversation strictly secret"),
                    (r"\b(?:stay on the line|do not (?:disconnect|hang up|cut the call)|keep the call active)\b", 12, "Refusing to let recipient hang up to verify caller independently"),
                    (r"\b(?:strictly confidential|secret investigation|do not share this conversation)\b", 12, "Insisting on secrecy under false authority pretext"),
                ],
                "safe_negation_patterns": []
            },
            "suspicious_links_sms": {
                "name": "Suspicious Links & Channel Redirection",
                "severity": "Medium",
                "max_score": 16,
                "description": "Caller directs victim to click unverified web links or short URLs.",
                "patterns": [
                    (r"\b(?:click on|open)\b[^\n.!?]{0,35}\b(?:link sent via sms|link in whatsapp|telegram link|form link)\b", 14, "Instruction to click external link sent via messaging"),
                    (r"\b(?:visit|go to)\b[^\n.!?]{0,35}\b(?:bit\.ly|tinyurl|tiny\.cc|goo\.gl|http|forms\.gle)\b", 14, "Direction to shortener or unverified external web URL"),
                ],
                "safe_negation_patterns": []
            },
            "kyc_verification_pressure": {
                "name": "KYC & Identity Verification Pretext",
                "severity": "Medium",
                "max_score": 16,
                "description": "Caller uses routine KYC compliance as a pretext for urgent intervention.",
                "patterns": [
                    (r"\b(?:kyc|pan card|aadhaar|identity verification)\b[^\n.!?]{0,40}\b(?:is pending|has expired|not updated|incomplete|suspended)\b", 12, "Pretext that identity verification or KYC has expired"),
                    (r"\b(?:update|complete|re-verify)\b[^\n.!?]{0,30}\b(?:your kyc|aadhaar details|pan details)\b[^\n.!?]{0,30}\b(?:immediately|over the call|right now)\b", 14, "Demand to perform immediate KYC update over the phone"),
                ],
                "safe_negation_patterns": []
            },
            "fake_rewards_offers": {
                "name": "Fake Rewards, Lottery & Refund Pretext",
                "severity": "Medium",
                "max_score": 15,
                "description": "Caller lures victim with prizes, lotteries, or unexpected refunds.",
                "patterns": [
                    (r"\b(?:congratulations|selected)\b[^\n.!?]{0,35}\b(?:won a lottery|cashback prize|reward of|gift voucher|lucky draw)\b", 14, "Claims victim has won an unverified prize or lottery"),
                    (r"\b(?:claim|receive)\b[^\n.!?]{0,35}\b(?:your refund|overpaid amount|cashback)\b[^\n.!?]{0,35}\b(?:click|provide details|transfer)\b", 14, "Baiting with financial refund or reward claim"),
                ],
                "safe_negation_patterns": []
            }
        }

        # 2. Coordinated Scam Combinations (Synergies)
        # Real-world social-engineering attacks combine multiple pressure tactics.
        # When known dangerous combinations occur together, a synergy boost is applied.
        self.compound_synergies = [
            {
                "id": "syn_urgency_otp",
                "categories": ["urgency_coercion", "credential_harvesting"],
                "boost": 16,
                "label": "High-Pressure Credential Extraction",
                "explanation": "Critical combo: Caller pairs extreme time urgency with an immediate request for OTP / PIN."
            },
            {
                "id": "syn_authority_threat",
                "categories": ["authority_impersonation", "threats_intimidation"],
                "boost": 14,
                "label": "Coercive Authority Impersonation",
                "explanation": "Dangerous combo: Caller poses as an official authority (Bank / Police / RBI) while threatening penalties or account closure."
            },
            {
                "id": "syn_threat_payment",
                "categories": ["threats_intimidation", "financial_diversion"],
                "boost": 16,
                "label": "Extortion / Penalty Payment Demand",
                "explanation": "Dangerous combo: Caller couples an account or legal threat with an order to transfer money or pay fees."
            },
            {
                "id": "syn_authority_remote",
                "categories": ["authority_impersonation", "remote_access"],
                "boost": 18,
                "label": "Tech Support / Remote Takeover Vishing",
                "explanation": "Critical combo: Caller claims official technical / security authority and demands remote tool installation (e.g., AnyDesk)."
            },
            {
                "id": "syn_kyc_threat",
                "categories": ["kyc_verification_pressure", "threats_intimidation"],
                "boost": 12,
                "label": "Urgent KYC Expiration Extortion",
                "explanation": "Scam pattern: Exploiting routine KYC compliance pretexts to threaten immediate service deactivation."
            },
            {
                "id": "syn_isolation_pressure",
                "categories": ["isolation_tactics", "urgency_coercion"],
                "boost": 12,
                "label": "Victim Isolation & Panic Tactics",
                "explanation": "Psychological coercion: Forcing victim to keep the conversation confidential while rushing compliance."
            }
        ]

    def _preprocess_text(self, text: str) -> str:
        """
        Simple, readable text preprocessing:
        - Converts text to lowercase for consistent pattern matching.
        - Normalizes multiple spaces and newlines into single spaces.
        - Preserves sentence boundaries for regex context limits.
        """
        if not text:
            return ""
        # Convert to lowercase
        lowered = text.lower()
        # Normalize whitespace
        normalized = re.sub(r"\s+", " ", lowered).strip()
        return normalized

    def _check_safe_negations(self, text: str, safe_patterns: List[str]) -> bool:
        """
        Checks if the transcript contains defensive security advice
        (e.g., 'we will never ask for your OTP', 'do not share your password').
        Prevents benign calls from being wrongly penalized.
        """
        for pattern in safe_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def analyze_transcript(self, raw_transcript: str) -> Dict[str, Any]:
        """
        Performs rule-based, transparent phishing and social-engineering risk analysis.

        Risk Scale:
          - Low Risk:    0 – 30
          - Medium Risk: 31 – 70
          - High Risk:   71 – 100

        Returns a structured dictionary with scores, indicators, explanations, and safety advice.
        """
        # Step 1: Preprocessing & Empty Check
        if not raw_transcript or not raw_transcript.strip():
            return {
                "score": 0,
                "risk_level": "Low Risk",
                "summary": "No transcript content provided for analysis.",
                "scoring_breakdown": {
                    "base_score": 0,
                    "synergy_bonus": 0,
                    "formula": "Base Score (0) + Combination Bonus (0) = 0",
                    "explanation": "The transcript is empty; therefore the risk score is 0."
                },
                "key_reasons": ["Transcript is empty or no spoken dialogue was detected."],
                "detected_categories": [],
                "detected_indicators": [],
                "combinations_detected": [],
                "safe_indicators_detected": [],
                "recommendations": ["Ensure clear audio recording before re-submitting for analysis."],
                "educational_disclaimer": self._disclaimer()
            }

        cleaned_text = self._preprocess_text(raw_transcript)

        total_base_score = 0
        detected_categories: List[Dict[str, Any]] = []
        all_detected_indicators: List[Dict[str, Any]] = []
        active_category_ids = set()
        safe_indicators_detected: List[str] = []

        # Step 2: Evaluate Each Indicator Category
        for cat_id, cat_info in self.category_definitions.items():
            cat_matches = []
            raw_cat_score = 0

            # Check for defensive security context (negation)
            is_negated = False
            if cat_info.get("safe_negation_patterns"):
                if self._check_safe_negations(cleaned_text, cat_info["safe_negation_patterns"]):
                    is_negated = True
                    safe_indicators_detected.append(
                        f"Legitimate security advice detected regarding {cat_info['name']} "
                        f"(caller specifically advised NOT to disclose sensitive details)."
                    )

            # Match category regex patterns against preprocessed text
            for pattern, weight, explanation in cat_info["patterns"]:
                for match in re.finditer(pattern, cleaned_text, re.IGNORECASE):
                    matched_snippet = match.group(0).strip()

                    # Deduplication: Avoid double-counting the exact same match in this category
                    if not any(m["snippet"] == matched_snippet for m in cat_matches):
                        cat_matches.append({
                            "snippet": matched_snippet,
                            "explanation": explanation,
                            "weight": weight
                        })
                        raw_cat_score += weight

            # If legitimate negation was detected, strongly attenuate the category score
            if is_negated and raw_cat_score > 0:
                raw_cat_score = max(0, int(raw_cat_score * 0.20))

            # Score Capping: Cap category score to avoid over-counting repeated indicators
            capped_cat_score = min(cat_info["max_score"], raw_cat_score)

            if cat_matches:
                active_category_ids.add(cat_id)
                cat_summary = {
                    "id": cat_id,
                    "name": cat_info["name"],
                    "severity": cat_info["severity"],
                    "description": cat_info["description"],
                    "score_contribution": capped_cat_score,
                    "matches": cat_matches
                }
                detected_categories.append(cat_summary)
                total_base_score += capped_cat_score

                for m in cat_matches:
                    all_detected_indicators.append({
                        "category_name": cat_info["name"],
                        "severity": cat_info["severity"],
                        "matched_phrase": m["snippet"],
                        "explanation": m["explanation"],
                        "contribution": m["weight"]
                    })

        # Step 3: Evaluate Coordinated Scam Combinations (Synergies)
        synergy_score = 0
        combinations_detected = []
        for syn in self.compound_synergies:
            req_cats = syn["categories"]
            # Check if all required categories were triggered
            if all(c in active_category_ids for c in req_cats):
                synergy_score += syn["boost"]
                combinations_detected.append({
                    "label": syn["label"],
                    "boost": syn["boost"],
                    "explanation": syn["explanation"],
                    "categories": [self.category_definitions[c]["name"] for c in req_cats]
                })

        # Step 4: Calculate Final Calibrated Risk Score (0 to 100)
        # Cap base indicator score at 70 so isolated indicators alone cannot trigger High Risk
        capped_base = min(70, total_base_score)
        total_raw = capped_base + synergy_score
        final_score = int(min(100, max(0, round(total_raw))))

        # Step 5: Classify Risk Level
        # Low Risk:    0 – 30
        # Medium Risk: 31 – 70
        # High Risk:   71 – 100
        if final_score >= 71:
            risk_level = "High Risk"
            summary = (
                "High probability of social engineering / phishing call detected. "
                "Multiple dangerous indicators and coordinated coercion tactics were observed."
            )
        elif final_score >= 31:
            risk_level = "Medium Risk"
            summary = (
                "Suspicious indicators detected. The caller employs urgency or asks for verification details. "
                "Independent verification through official channels is strongly advised."
            )
        else:
            risk_level = "Low Risk"
            summary = (
                "Few or no significant social-engineering indicators detected. "
                "The conversation exhibits standard, low-suspicion communication."
            )

        # Step 6: Formulate Transparent Explanations
        key_reasons = []
        if combinations_detected:
            for syn in combinations_detected:
                key_reasons.append(
                    f"Coordinated Scam Pattern: {syn['label']} (+{syn['boost']} pts) — {syn['explanation']}"
                )

        for cat in detected_categories:
            sample_snippets = [f'"{m["snippet"]}"' for m in cat["matches"][:2]]
            sample_str = ", ".join(sample_snippets)
            key_reasons.append(
                f"{cat['name']} [{cat['severity']}]: Found suspicious phrases such as {sample_str} "
                f"(contributed +{cat['score_contribution']} pts)."
            )

        if not key_reasons:
            key_reasons.append(
                "No suspicious pressure phrases, credential requests, or diversion demands were identified in this transcript."
            )

        # Plain-language scoring explanation
        scoring_breakdown = {
            "base_score": capped_base,
            "synergy_bonus": synergy_score,
            "formula": f"Base Indicator Score ({capped_base}) + Coordinated Tactic Bonus ({synergy_score}) = {final_score}/100",
            "explanation": (
                f"Calculated from {len(detected_categories)} indicator category/categories "
                f"(base: {capped_base} pts) plus {len(combinations_detected)} multi-vector tactic bonus ({synergy_score} pts), "
                f"resulting in a calibrated score of {final_score}/100."
            )
        }

        # Step 7: Tailored Safety Recommendations
        recommendations = self._generate_recommendations(active_category_ids, risk_level)

        return {
            "score": final_score,
            "risk_level": risk_level,
            "summary": summary,
            "scoring_breakdown": scoring_breakdown,
            "key_reasons": key_reasons,
            "detected_categories": detected_categories,
            "detected_indicators": all_detected_indicators,
            "combinations_detected": combinations_detected,
            "safe_indicators_detected": safe_indicators_detected,
            "recommendations": recommendations,
            "educational_disclaimer": self._disclaimer()
        }

    def _generate_recommendations(self, active_categories: set, risk_level: str) -> List[str]:
        """
        Generates tailored safety advice based strictly on detected risk vectors.
        """
        recs = []
        if "credential_harvesting" in active_categories:
            recs.append("NEVER share OTP, CVV, ATM PIN, or passwords over the phone. Legitimate bank staff will never request them.")
        if "remote_access" in active_categories:
            recs.append("Do NOT install remote desktop applications (such as AnyDesk, TeamViewer, or QuickSupport) or grant screen control.")
        if "financial_diversion" in active_categories:
            recs.append("Do NOT transfer money to any 'safe account' or make urgent UPI payments requested during a phone call.")
        if "threats_intimidation" in active_categories or "urgency_coercion" in active_categories:
            recs.append("Scammers use urgency and fear to force quick mistakes. Disconnect the call and calm down before taking any action.")
        if "authority_impersonation" in active_categories or "kyc_verification_pressure" in active_categories:
            recs.append("Independently verify caller identity using the official phone number printed on your bank card or official website.")
        if "suspicious_links_sms" in active_categories:
            recs.append("Do NOT open links or short URLs sent via SMS or messaging apps during an active phone call.")
        if "isolation_tactics" in active_categories:
            recs.append("If a caller demands you keep the conversation secret or forbids you from speaking to family, it is almost certainly a scam.")

        # Baseline safety recommendation
        if not recs:
            recs.append("Always maintain vigilance. Never disclose sensitive financial credentials to unverified callers.")
        else:
            recs.append("If you suspect fraud, report the incident immediately to your bank and the national cyber crime reporting portal.")

        return recs

    def _disclaimer(self) -> str:
        """Educational viva disclaimer required by project guidelines."""
        return (
            "Heuristic Evaluation Disclaimer: This system provides an estimated risk score based on rule-based pattern "
            "analysis of spoken language. It does not definitively prove fraud or innocence. High scores indicate "
            "concerning social-engineering tactics requiring extreme caution, while low scores do not guarantee legitimacy."
        )
