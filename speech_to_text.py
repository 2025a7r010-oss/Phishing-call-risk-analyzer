"""
AI-Based Phishing Call Detection and Risk Analysis System
Module: speech_to_text.py

Compatibility alias module for transcriber.py.
Imports and exposes LocalSpeechTranscriber so legacy scripts remain functional.
"""

from transcriber import LocalSpeechTranscriber

__all__ = ["LocalSpeechTranscriber"]
