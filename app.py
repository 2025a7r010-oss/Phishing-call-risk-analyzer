"""
AI-Based Phishing Call Detection and Risk Analysis System
Module: app.py

A modern, cybersecurity-themed web application for analyzing recorded phone-call
audio and conversation transcripts to detect potential phishing and social-engineering tactics.
B.Tech CSE Cyber Security Mini-Project.
"""

import os
import sys
from pathlib import Path
import json
from datetime import datetime

# Ensure project root is available in sys.path
PROJECT_DIR = Path(__file__).resolve().parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

import streamlit as st
from analyzer import PhishingCallAnalyzer
from transcriber import LocalSpeechTranscriber

# Safe reference transcript import with fallback
try:
    from demo_data import get_all_example_samples
except ImportError:
    try:
        from demo_data import get_all_demo_samples as get_all_example_samples
    except ImportError:
        def get_all_example_samples():
            return []


# -----------------------------------------------------------------------------
# 1. PAGE CONFIGURATION & STYLING
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="AI-Based Phishing Call Detection and Risk Analysis System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Dark navy/blue gradient theme with cyan, purple, and teal accents
st.markdown("""
<style>
    /* Google Fonts */
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    /* Global page styling */
    .stApp {
        background: radial-gradient(ellipse at 20% 0%, #171E38 0%, #0B0F19 45%, #080C14 100%) fixed;
        color: #F1F5F9;
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    /* Headings and typography */
    h1, h2, h3, h4, h5, h6 {
        font-family: 'Plus Jakarta Sans', sans-serif !important;
        letter-spacing: -0.02em;
        color: #FFFFFF !important;
    }

    p, span, label, li {
        color: #CBD5E1;
    }

    /* Gradient Titles */
    .hero-title {
        background: linear-gradient(110deg, #38BDF8 0%, #818CF8 45%, #C084FC 90%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-size: 2.35rem;
        font-weight: 800;
        letter-spacing: -0.025em;
        line-height: 1.25;
        margin-bottom: 0.4rem;
    }

    .hero-subtitle {
        font-size: 1.05rem;
        color: #94A3B8;
        line-height: 1.6;
        margin-bottom: 1.8rem;
        max-width: 900px;
    }

    .section-title {
        font-size: 1.35rem;
        font-weight: 700;
        color: #38BDF8 !important;
        margin-top: 1.2rem;
        margin-bottom: 0.8rem;
        display: flex;
        align-items: center;
        gap: 8px;
    }

    /* Cyber Glass Cards */
    .cyber-card {
        background: linear-gradient(145deg, rgba(23, 31, 54, 0.75) 0%, rgba(13, 19, 36, 0.85) 100%);
        backdrop-filter: blur(14px);
        -webkit-backdrop-filter: blur(14px);
        border: 1px solid rgba(56, 189, 248, 0.18);
        border-radius: 14px;
        padding: 1.4rem;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5), inset 0 1px 1px rgba(255, 255, 255, 0.08);
        margin-bottom: 1.2rem;
        transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
    }
    .cyber-card:hover {
        border-color: rgba(56, 189, 248, 0.4);
        box-shadow: 0 14px 30px -5px rgba(6, 182, 212, 0.15), inset 0 1px 1px rgba(255, 255, 255, 0.12);
        transform: translateY(-2px);
    }

    /* Feature Cards */
    .feature-card {
        background: linear-gradient(145deg, rgba(23, 31, 54, 0.8) 0%, rgba(13, 19, 36, 0.9) 100%);
        border: 1px solid rgba(99, 102, 241, 0.2);
        border-radius: 14px;
        padding: 1.4rem;
        height: 100%;
        box-shadow: 0 8px 20px -4px rgba(0, 0, 0, 0.4);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .feature-card:hover {
        border-color: rgba(168, 85, 247, 0.45);
        transform: translateY(-3px);
        box-shadow: 0 12px 28px -4px rgba(168, 85, 247, 0.2);
    }
    .feature-card h4 {
        font-size: 1.12rem;
        font-weight: 700;
        color: #F8FAFC !important;
        margin-top: 0.6rem;
        margin-bottom: 0.4rem;
    }
    .feature-card p {
        font-size: 0.9rem;
        color: #94A3B8;
        line-height: 1.55;
        margin-bottom: 0;
    }

    /* Badges & Icons */
    .icon-badge-cyan {
        background: rgba(6, 182, 212, 0.15);
        color: #22D3EE;
        border: 1px solid rgba(6, 182, 212, 0.35);
        padding: 8px 12px;
        border-radius: 10px;
        display: inline-block;
        font-size: 1.4rem;
        box-shadow: 0 0 12px rgba(6, 182, 212, 0.2);
    }
    .icon-badge-purple {
        background: rgba(168, 85, 247, 0.15);
        color: #C084FC;
        border: 1px solid rgba(168, 85, 247, 0.35);
        padding: 8px 12px;
        border-radius: 10px;
        display: inline-block;
        font-size: 1.4rem;
        box-shadow: 0 0 12px rgba(168, 85, 247, 0.2);
    }
    .icon-badge-teal {
        background: rgba(20, 184, 166, 0.15);
        color: #2DD4BF;
        border: 1px solid rgba(20, 184, 166, 0.35);
        padding: 8px 12px;
        border-radius: 10px;
        display: inline-block;
        font-size: 1.4rem;
        box-shadow: 0 0 12px rgba(20, 184, 166, 0.2);
    }
    .icon-badge-blue {
        background: rgba(59, 130, 246, 0.15);
        color: #60A5FA;
        border: 1px solid rgba(59, 130, 246, 0.35);
        padding: 8px 12px;
        border-radius: 10px;
        display: inline-block;
        font-size: 1.4rem;
        box-shadow: 0 0 12px rgba(59, 130, 246, 0.2);
    }

    /* Workflow Cards */
    .workflow-card {
        background: linear-gradient(145deg, rgba(23, 31, 54, 0.6) 0%, rgba(13, 19, 36, 0.7) 100%);
        border: 1px solid rgba(56, 189, 248, 0.2);
        border-radius: 12px;
        padding: 1.2rem;
        text-align: center;
        height: 100%;
        box-shadow: 0 4px 14px rgba(0, 0, 0, 0.3);
    }
    .workflow-step {
        display: inline-block;
        width: 32px;
        height: 32px;
        line-height: 32px;
        background: linear-gradient(135deg, #06B6D4 0%, #3B82F6 100%);
        color: #FFFFFF;
        font-weight: 800;
        border-radius: 50%;
        margin-bottom: 0.5rem;
        box-shadow: 0 0 12px rgba(6, 182, 212, 0.4);
    }

    /* Metric Result Cards */
    .metric-result-card {
        background: linear-gradient(145deg, rgba(23, 31, 54, 0.85) 0%, rgba(13, 19, 36, 0.95) 100%);
        border: 1px solid rgba(56, 189, 248, 0.25);
        border-radius: 14px;
        padding: 1.3rem;
        text-align: center;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
    }
    .score-glow-low {
        font-size: 2.85rem;
        font-weight: 800;
        color: #34D399;
        text-shadow: 0 0 20px rgba(52, 211, 153, 0.45);
        line-height: 1.1;
    }
    .score-glow-med {
        font-size: 2.85rem;
        font-weight: 800;
        color: #FBBF24;
        text-shadow: 0 0 20px rgba(251, 191, 36, 0.45);
        line-height: 1.1;
    }
    .score-glow-high {
        font-size: 2.85rem;
        font-weight: 800;
        color: #F87171;
        text-shadow: 0 0 22px rgba(248, 113, 113, 0.55);
        line-height: 1.1;
    }

    .risk-badge-low {
        background: rgba(16, 185, 129, 0.16);
        color: #34D399;
        border: 1px solid rgba(52, 211, 153, 0.45);
        padding: 6px 14px;
        border-radius: 9999px;
        font-weight: 700;
        display: inline-block;
        box-shadow: 0 0 12px rgba(16, 185, 129, 0.25);
    }
    .risk-badge-med {
        background: rgba(245, 158, 11, 0.16);
        color: #FBBF24;
        border: 1px solid rgba(251, 191, 36, 0.45);
        padding: 6px 14px;
        border-radius: 9999px;
        font-weight: 700;
        display: inline-block;
        box-shadow: 0 0 12px rgba(245, 158, 11, 0.25);
    }
    .risk-badge-high {
        background: rgba(239, 68, 68, 0.18);
        color: #F87171;
        border: 1px solid rgba(248, 113, 113, 0.5);
        padding: 6px 14px;
        border-radius: 9999px;
        font-weight: 700;
        display: inline-block;
        box-shadow: 0 0 14px rgba(239, 68, 68, 0.35);
    }

    /* Indicator Cards */
    .indicator-card-dark {
        background: linear-gradient(145deg, rgba(23, 31, 54, 0.75) 0%, rgba(13, 19, 36, 0.85) 100%);
        border: 1px solid rgba(56, 189, 248, 0.25);
        border-left: 4px solid #38BDF8;
        border-radius: 0 10px 10px 0;
        padding: 1.1rem 1.3rem;
        margin-bottom: 0.9rem;
        box-shadow: 0 4px 14px rgba(0, 0, 0, 0.3);
    }
    .evidence-quote-dark {
        background: rgba(10, 15, 29, 0.9);
        border: 1px solid rgba(56, 189, 248, 0.25);
        border-radius: 8px;
        padding: 8px 14px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.9rem;
        color: #38BDF8;
        margin: 0.4rem 0;
    }

    /* Safe Reassuring Banner */
    .safe-banner-dark {
        background: linear-gradient(145deg, rgba(6, 78, 59, 0.35) 0%, rgba(4, 47, 46, 0.4) 100%);
        border: 1px solid rgba(52, 211, 153, 0.4);
        border-left: 5px solid #10B981;
        padding: 14px 18px;
        border-radius: 0 10px 10px 0;
        color: #D1FAE5;
        margin: 1rem 0;
    }

    /* Disclaimer Card */
    .disclaimer-card-dark {
        background: rgba(15, 23, 42, 0.6);
        border-left: 4px solid #64748B;
        padding: 12px 16px;
        border-radius: 0 8px 8px 0;
        font-size: 0.86rem;
        color: #94A3B8;
        margin-top: 1.6rem;
    }

    /* Streamlit Sidebar Customization */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #090D17 0%, #0F172A 100%) !important;
        border-right: 1px solid rgba(56, 189, 248, 0.15) !important;
    }
    section[data-testid="stSidebar"] .stRadio label {
        color: #E2E8F0 !important;
        font-size: 0.95rem !important;
    }

    /* Primary and Secondary Buttons */
    div.stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #06B6D4 0%, #3B82F6 50%, #8B5CF6 100%) !important;
        color: #FFFFFF !important;
        border: none !important;
        border-radius: 10px !important;
        padding: 0.65rem 1.4rem !important;
        font-weight: 700 !important;
        font-size: 1.02rem !important;
        letter-spacing: 0.01em !important;
        box-shadow: 0 4px 16px rgba(6, 182, 212, 0.35) !important;
        transition: all 0.25s ease !important;
    }
    div.stButton > button[kind="primary"]:hover {
        box-shadow: 0 6px 22px rgba(139, 92, 246, 0.55) !important;
        transform: translateY(-2px) !important;
    }

    div.stButton > button[kind="secondary"] {
        background: rgba(23, 31, 54, 0.75) !important;
        color: #E2E8F0 !important;
        border: 1px solid rgba(56, 189, 248, 0.3) !important;
        border-radius: 10px !important;
        font-weight: 600 !important;
        transition: all 0.2s ease !important;
    }
    div.stButton > button[kind="secondary"]:hover {
        background: rgba(30, 41, 59, 0.95) !important;
        border-color: #38BDF8 !important;
        color: #38BDF8 !important;
        transform: translateY(-1px) !important;
    }

    /* Streamlit Text Area Styling */
    .stTextArea textarea {
        background-color: rgba(13, 19, 36, 0.85) !important;
        color: #F8FAFC !important;
        border: 1px solid rgba(56, 189, 248, 0.25) !important;
        border-radius: 10px !important;
        font-size: 0.95rem !important;
    }
    .stTextArea textarea:focus {
        border-color: #38BDF8 !important;
        box-shadow: 0 0 12px rgba(56, 189, 248, 0.3) !important;
    }

    /* Streamlit Selectbox Styling */
    div[data-baseweb="select"] {
        background-color: rgba(13, 19, 36, 0.85) !important;
        border-radius: 10px !important;
    }

    /* Streamlit File Upload Dropzone */
    section[data-testid="stFileUploadDropzone"] {
        background-color: rgba(13, 19, 36, 0.7) !important;
        border: 1px dashed rgba(56, 189, 248, 0.4) !important;
        border-radius: 12px !important;
    }

    /* Expander Styling */
    div[data-testid="stExpander"] {
        border: 1px solid rgba(56, 189, 248, 0.2) !important;
        border-radius: 10px !important;
        background: rgba(13, 19, 36, 0.6) !important;
    }
</style>
""", unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# 2. STATE MANAGEMENT & COMPONENT INITIALIZATION
# -----------------------------------------------------------------------------
if "nav_page" not in st.session_state:
    st.session_state.nav_page = "Dashboard"

if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None

if "analysis_transcript" not in st.session_state:
    st.session_state.analysis_transcript = ""

if "analysis_source" not in st.session_state:
    st.session_state.analysis_source = ""

if "analysis_timestamp" not in st.session_state:
    st.session_state.analysis_timestamp = ""

if "analysis_method" not in st.session_state:
    st.session_state.analysis_method = ""

if "audio_transcribed_text" not in st.session_state:
    st.session_state.audio_transcribed_text = ""

if "analysis_history" not in st.session_state:
    st.session_state.analysis_history = []


@st.cache_resource(show_spinner=False)
def load_transcriber():
    """Initializes and caches the local Whisper speech transcriber."""
    return LocalSpeechTranscriber(model_size="tiny.en")


@st.cache_resource(show_spinner=False)
def load_analyzer():
    """Initializes and caches the rule-based phishing analyzer."""
    return PhishingCallAnalyzer()


transcriber = load_transcriber()
analyzer = load_analyzer()


# -----------------------------------------------------------------------------
# 3. SIDEBAR NAVIGATION (FOUR PAGES ONLY)
# -----------------------------------------------------------------------------
with st.sidebar:
    st.markdown("""
    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 0.2rem;">
        <span style="font-size: 1.8rem;">🛡️</span>
        <strong style="font-size: 1.15rem; color: #38BDF8;">Phishing Detector</strong>
    </div>
    <div style="font-size: 0.82rem; color: #94A3B8; margin-bottom: 0.8rem;">
        Cybersecurity Risk Analysis
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    # The 4 strictly requested pages
    nav_options = [
        "Dashboard",
        "Analyze Call",
        "Transcript Analysis",
        "Analysis Results"
    ]

    current_idx = nav_options.index(st.session_state.nav_page) if st.session_state.nav_page in nav_options else 0
    selected_page = st.radio(
        "Navigation",
        options=nav_options,
        index=current_idx,
        label_visibility="collapsed"
    )

    if selected_page != st.session_state.nav_page:
        st.session_state.nav_page = selected_page
        st.rerun()

    st.markdown("---")



    st.markdown("---")



# -----------------------------------------------------------------------------
# 4. VIEW: DASHBOARD
# -----------------------------------------------------------------------------
if st.session_state.nav_page == "Dashboard":
    st.markdown("""
    <div style="display: flex; align-items: center; gap: 14px; margin-bottom: 0.2rem;">
        <span style="font-size: 2.4rem;">🛡️</span>
        <div class="hero-title">AI-Based Phishing Call Detection and Risk Analysis System</div>
    </div>
    <div class="hero-subtitle">
        An intelligent cybersecurity tool for analyzing phone-call conversations, 
        detecting potential phishing and social-engineering tactics, and explaining security risks.
    </div>
    """, unsafe_allow_html=True)

    # Introduction Card with subtle cyber gradient
    st.markdown("""
    <div class="cyber-card">
        
        <p style="color: #CBD5E1; font-size: 0.98rem; line-height: 1.6; margin-bottom: 0;">
            This application analyzes recorded phone-call conversations to identify potential phishing and 
            social-engineering indicators. It combines speech transcription with explainable text analysis 
            to help users understand suspicious communication and make safer decisions.
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Prominent Action Buttons
    col_a1, col_a2 = st.columns(2)
    with col_a1:
        if st.button("🚀 Start Audio Analysis", type="primary", use_container_width=True):
            st.session_state.nav_page = "Analyze Call"
            st.rerun()
    with col_a2:
        if st.button("📝 Analyze Text Transcript", type="secondary", use_container_width=True):
            st.session_state.nav_page = "Transcript Analysis"
            st.rerun()

    # Core Feature Cards (2x2 Grid with vibrant cyan/purple/teal badges)
    st.markdown('<div class="section-title">⚡ Core Capabilities</div>', unsafe_allow_html=True)

    col_f1, col_f2 = st.columns(2)
    with col_f1:
        st.markdown("""
        <div class="feature-card">
            <span class="icon-badge-cyan">🎙️</span>
            <h4>Audio-to-Text Transcription</h4>
            <p>
                Transcribes uploaded phone-call recordings (WAV, MP3, M4A) locally using Whisper speech recognition. 
                Executes on local hardware without sending audio data to external cloud APIs.
            </p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)

        st.markdown("""
        <div class="feature-card">
            <span class="icon-badge-teal">📊</span>
            <h4>Explainable Risk Assessment</h4>
            <p>
                Calculates a calibrated 0–100 integer risk score categorized into Low, Medium, and High Risk tiers. 
                Provides a transparent mathematical breakdown showing base indicators and multi-vector combinations.
            </p>
        </div>
        """, unsafe_allow_html=True)

    with col_f2:
        st.markdown("""
        <div class="feature-card">
            <span class="icon-badge-purple">🔍</span>
            <h4>Phishing Indicator Detection</h4>
            <p>
                Identifies suspicious patterns across 10 social-engineering categories, including credential theft (OTP/PIN), 
                artificial urgency, account threats, authority impersonation, and remote software requests.
            </p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)

        st.markdown("""
        <div class="feature-card">
            <span class="icon-badge-blue">🛡️</span>
            <h4>Security Recommendations</h4>
            <p>
                Generates practical, tailored security precautions based directly on the specific threat vectors detected 
                in the conversation to protect personal credentials and financial safety.
            </p>
        </div>
        """, unsafe_allow_html=True)

    # Three-Step Workflow
    st.markdown('<div class="section-title">🔄 Analysis Workflow</div>', unsafe_allow_html=True)

    col_w1, col_w2, col_w3 = st.columns(3)
    with col_w1:
        st.markdown("""
        <div class="workflow-card">
            <span class="workflow-step">1</span>
            <h5 style="color: #F8FAFC; margin: 0.3rem 0;">Upload Recording</h5>
            <p style="color: #94A3B8; font-size: 0.88rem; margin: 0;">
                Select a recorded phone call (WAV, MP3, M4A) or paste conversation text.
            </p>
        </div>
        """, unsafe_allow_html=True)
    with col_w2:
        st.markdown("""
        <div class="workflow-card">
            <span class="workflow-step">2</span>
            <h5 style="color: #F8FAFC; margin: 0.3rem 0;">Generate Transcript</h5>
            <p style="color: #94A3B8; font-size: 0.88rem; margin: 0;">
                Local Whisper speech engine transcribes spoken dialogue into readable text.
            </p>
        </div>
        """, unsafe_allow_html=True)
    with col_w3:
        st.markdown("""
        <div class="workflow-card">
            <span class="workflow-step">3</span>
            <h5 style="color: #F8FAFC; margin: 0.3rem 0;">Analyze Risk</h5>
            <p style="color: #94A3B8; font-size: 0.88rem; margin: 0;">
                Heuristic engine calculates risk score, extracts evidence, and presents safety advice.
            </p>
        </div>
        """, unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# 5. VIEW: ANALYZE CALL (AUDIO)
# -----------------------------------------------------------------------------
elif st.session_state.nav_page == "Analyze Call":
    st.markdown("""
    <div style="display: flex; align-items: center; gap: 14px; margin-bottom: 0.2rem;">
        <span style="font-size: 2.4rem;">🎙️</span>
        <div class="hero-title">Audio Call Analysis</div>
    </div>
    <div class="hero-subtitle">
        Upload a recorded phone-call audio file for automated speech transcription and phishing risk evaluation.
    </div>
    """, unsafe_allow_html=True)

    col_u1, col_u2 = st.columns([3, 2])

    with col_u1:
        uploaded_file = st.file_uploader(
            "Select an audio recording from your device",
            type=["wav", "mp3", "m4a"],
            help="Supported audio formats: WAV, MP3, and M4A."
        )

    with col_u2:
        st.markdown("""
        <div class="cyber-card" style="margin-bottom: 0;">
            <h5 style="margin-bottom: 0.4rem; color: #38BDF8 !important;">Audio File Guidelines</h5>
            <ul style="font-size: 0.88rem; color: #CBD5E1; margin-bottom: 0; padding-left: 1.2rem; line-height: 1.6;">
                <li>Supported formats: <strong>WAV, MP3, M4A</strong>.</li>
                <li>Clear audio produces higher speech recognition accuracy.</li>
                <li>Speech transcription runs locally on your laptop CPU.</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    if uploaded_file is not None:
        file_size_kb = round(uploaded_file.size / 1024, 1)

        # File metadata card
        st.markdown(f"""
        <div class="cyber-card" style="padding: 0.9rem 1.3rem; margin-top: 1rem;">
            <span style="color: #38BDF8; font-weight: 700;">Uploaded File:</span> <code>{uploaded_file.name}</code> &nbsp;|&nbsp; 
            <span style="color: #A855F7; font-weight: 700;">Size:</span> {file_size_kb} KB &nbsp;|&nbsp; 
            <span style="color: #2DD4BF; font-weight: 700;">Format:</span> {Path(uploaded_file.name).suffix.upper().replace('.', '')}
        </div>
        """, unsafe_allow_html=True)

        st.audio(uploaded_file, format=f"audio/{Path(uploaded_file.name).suffix.replace('.', '')}")

        # Step 1: Transcribe button
        if st.button("🚀 Transcribe Call Audio", type="primary", use_container_width=True):
            with st.spinner("Transcribing audio locally using Whisper speech recognition..."):
                transcribe_result = transcriber.transcribe_audio_file(uploaded_file, original_filename=uploaded_file.name)

            if not transcribe_result["success"]:
                st.error(f"Transcription Error: {transcribe_result['error']}")
            else:
                transcript_text = transcribe_result.get("text", "").strip()
                if not transcript_text:
                    st.warning("Audio was processed, but no spoken dialogue was detected in the file.")
                else:
                    duration_s = transcribe_result.get("duration", 0.0)
                    st.success(f"Transcription completed ({duration_s}s audio processed).")
                    st.session_state.audio_transcribed_text = transcript_text
                    st.session_state.analysis_source = f"Uploaded Audio: {uploaded_file.name}"

        # Step 2: Review and Analyze Transcript
        if st.session_state.audio_transcribed_text:
            st.markdown('<div class="section-title">Review Generated Transcript</div>', unsafe_allow_html=True)
            st.caption("You can review or adjust words in the transcript below before evaluating risk:")

            reviewed_text = st.text_area(
                "Generated Transcript Text:",
                value=st.session_state.audio_transcribed_text,
                height=150,
                key="audio_review_text"
            )

            col_sub1, col_sub2 = st.columns([1, 2])
            with col_sub1:
                if st.button("📊 Analyze Transcript", type="primary", use_container_width=True):
                    if not reviewed_text.strip():
                        st.warning("Transcript is empty. Please enter conversation text.")
                    else:
                        with st.spinner("Evaluating transcript for social-engineering indicators..."):
                            analysis = analyzer.analyze_transcript(reviewed_text)

                        st.session_state.analysis_result = analysis
                        st.session_state.analysis_transcript = reviewed_text
                        st.session_state.analysis_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        st.session_state.analysis_method = "Speech-to-Text Transcription (Whisper) + Rule-Based Heuristic Analysis"
                        st.session_state.nav_page = "Analysis Results"
                        st.rerun()


# -----------------------------------------------------------------------------
# 6. VIEW: TRANSCRIPT ANALYSIS
# -----------------------------------------------------------------------------
elif st.session_state.nav_page == "Transcript Analysis":
    st.markdown("""
    <div style="display: flex; align-items: center; gap: 14px; margin-bottom: 0.2rem;">
        <span style="font-size: 2.4rem;">📝</span>
        <div class="hero-title">Transcript Analysis</div>
    </div>
    <div class="hero-subtitle">
        Enter or paste a recorded phone-call conversation to analyze for potential social-engineering indicators and risk patterns.
    </div>
    """, unsafe_allow_html=True)

    # Optional test example selector
    example_samples = get_all_example_samples()
    example_options = ["None (Custom Input)"] + [s["title"] for s in example_samples]

    selected_example = st.selectbox(
        "Load a test example conversation (Optional test examples):",
        options=example_options,
        index=0,
        help="Select a test example scenario to populate the input box, or select None to enter your own text."
    )

    # Populate text area if test example is selected
    if selected_example != "None (Custom Input)":
        for s in example_samples:
            if s["title"] == selected_example:
                default_text = s["transcript"]
                break
    else:
        default_text = st.session_state.custom_text_buffer

    transcript_input = st.text_area(
        "Call Conversation Transcript:",
        value=default_text,
        height=170,
        placeholder="Type or paste conversation dialogue here...",
        key="main_transcript_input"
    )

    st.session_state.custom_text_buffer = transcript_input

    # Action buttons: Analyze and Clear
    col_t1, col_t2, col_t3 = st.columns([1, 1, 2])

    with col_t1:
        analyze_clicked = st.button("🔍 Analyze Call Transcript", type="primary", use_container_width=True)

    with col_t2:
        clear_clicked = st.button("🗑️ Clear Transcript", type="secondary", use_container_width=True)

    if clear_clicked:
        st.session_state.custom_text_buffer = ""
        st.session_state.main_transcript_input = ""
        st.rerun()

    if analyze_clicked:
        cleaned_input = transcript_input.strip()
        if not cleaned_input:
            st.warning("Please enter conversation text before starting the analysis.")
        else:
            with st.spinner("Analyzing conversation for social-engineering indicators..."):
                analysis = analyzer.analyze_transcript(cleaned_input)

            source_name = selected_example if selected_example != "None (Custom Input)" else "Manual Transcript Input"
            st.session_state.analysis_result = analysis
            st.session_state.analysis_transcript = cleaned_input
            st.session_state.analysis_source = source_name
            st.session_state.analysis_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            st.session_state.analysis_method = "Manual Transcript Input + Rule-Based Heuristic Analysis"
            st.session_state.nav_page = "Analysis Results"
            st.rerun()


# -----------------------------------------------------------------------------
# 7. VIEW: ANALYSIS RESULTS
# -----------------------------------------------------------------------------
elif st.session_state.nav_page == "Analysis Results":
    st.markdown("""
    <div style="display: flex; align-items: center; gap: 14px; margin-bottom: 0.2rem;">
        <span style="font-size: 2.4rem;">📊</span>
        <div class="hero-title">Analysis Results</div>
    </div>
    <div class="hero-subtitle">
        Detailed risk assessment, detected indicators, supporting transcript evidence, and tailored safety recommendations.
    </div>
    """, unsafe_allow_html=True)

    if st.session_state.analysis_result is None:
        st.markdown("""
        <div class="cyber-card" style="text-align: center; padding: 2.8rem 1rem;">
            <div style="font-size: 2.5rem; margin-bottom: 0.5rem;">🔍</div>
            <h4 style="color: #38BDF8 !important; margin-bottom: 0.4rem;">No Call Has Been Analyzed Yet</h4>
            <p style="color: #94A3B8; max-width: 540px; margin: 0 auto 1.5rem auto; line-height: 1.6;">
                Upload a recorded audio file under "Analyze Call" or enter a conversation transcript 
                under "Transcript Analysis" to evaluate phishing and social-engineering indicators.
            </p>
        </div>
        """, unsafe_allow_html=True)

        col_empty1, col_empty2 = st.columns(2)
        with col_empty1:
            if st.button("🎙️ Upload Audio Recording", type="primary", use_container_width=True):
                st.session_state.nav_page = "Analyze Call"
                st.rerun()
        with col_empty2:
            if st.button("📝 Enter Call Transcript", type="secondary", use_container_width=True):
                st.session_state.nav_page = "Transcript Analysis"
                st.rerun()

    else:
        analysis = st.session_state.analysis_result
        transcript_text = st.session_state.analysis_transcript
        source_name = st.session_state.analysis_source
        timestamp_val = st.session_state.analysis_timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        method_val = st.session_state.analysis_method or "Rule-Based Heuristic Analysis"

        # Metadata banner
        st.markdown(f"""
        <div class="cyber-card" style="padding: 0.9rem 1.3rem; font-size: 0.92rem;">
            <span style="color: #38BDF8; font-weight: 700;">Subject:</span> <code>{source_name}</code> &nbsp;|&nbsp; 
            <span style="color: #C084FC; font-weight: 700;">Timestamp:</span> {timestamp_val} &nbsp;|&nbsp; 
            <span style="color: #2DD4BF; font-weight: 700;">Method:</span> {method_val}
        </div>
        """, unsafe_allow_html=True)

        # Transcript expander
        with st.expander("📄 Review Call Conversation Transcript", expanded=False):
            st.write(transcript_text if transcript_text else "*(Empty transcript)*")
            st.caption(f"Word Count: {len(transcript_text.split())} words")

        score = analysis["score"]
        risk_level = analysis["risk_level"]
        breakdown = analysis.get("scoring_breakdown", {})

        # 1. Overview Metric Cards & Compact Risk Level Guide
        col_m1, col_m2, col_m3 = st.columns([1, 1, 2])

        with col_m1:
            st.markdown('<div class="metric-result-card">', unsafe_allow_html=True)
            st.markdown("<strong style='color:#94A3B8;'>Phishing Risk Score</strong>", unsafe_allow_html=True)
            if risk_level == "High Risk":
                st.markdown(f'<div class="score-glow-high">{score} <span style="font-size:1.1rem; color:#94A3B8;">/ 100</span></div>', unsafe_allow_html=True)
            elif risk_level == "Medium Risk":
                st.markdown(f'<div class="score-glow-med">{score} <span style="font-size:1.1rem; color:#94A3B8;">/ 100</span></div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="score-glow-low">{score} <span style="font-size:1.1rem; color:#94A3B8;">/ 100</span></div>', unsafe_allow_html=True)
            st.progress(score / 100.0)
            st.markdown('</div>', unsafe_allow_html=True)

        with col_m2:
            st.markdown('<div class="metric-result-card">', unsafe_allow_html=True)
            st.markdown("<strong style='color:#94A3B8;'>Risk Classification</strong>", unsafe_allow_html=True)
            st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
            if risk_level == "High Risk":
                st.markdown('<span class="risk-badge-high">🔴 HIGH RISK</span>', unsafe_allow_html=True)
                st.caption("Multiple Coercive Tactics Detected")
            elif risk_level == "Medium Risk":
                st.markdown('<span class="risk-badge-med">🟡 MEDIUM RISK</span>', unsafe_allow_html=True)
                st.caption("Suspicious Verification Indicators")
            else:
                st.markdown('<span class="risk-badge-low">🟢 LOW RISK</span>', unsafe_allow_html=True)
                st.caption("Standard Low-Suspicion Dialogue")
            st.markdown('</div>', unsafe_allow_html=True)

        with col_m3:
            # Compact Risk Level Guide placed beside score
            st.markdown("""
            <div class="cyber-card" style="margin-bottom: 0; padding: 1.1rem 1.3rem;">
                <strong style="color: #38BDF8;">Risk Level Guide</strong>
                <ul style="font-size: 0.86rem; color: #CBD5E1; margin: 0.4rem 0 0.5rem 0; padding-left: 1.1rem; line-height: 1.6;">
                    <li>🟢 <strong style="color:#34D399;">Low Risk (0–30):</strong> Standard conversation or legitimate security reminders.</li>
                    <li>🟡 <strong style="color:#FBBF24;">Medium Risk (31–70):</strong> Suspicious indicators such as unverified credential requests or urgency.</li>
                    <li>🔴 <strong style="color:#F87171;">High Risk (71–100):</strong> Multi-vector attack combining impersonation, threats, or fund diversion.</li>
                </ul>
                <div style="font-size: 0.78rem; color: #94A3B8; font-style: italic;">
                    Note: The risk score is a heuristic assessment based on observed language patterns, not a definitive probability of fraud.
                </div>
            </div>
            """, unsafe_allow_html=True)

        # Executive Assessment box
        st.markdown(f"""
        <div class="cyber-card" style="margin-top: 1.2rem;">
            <strong style="color: #38BDF8; font-size: 1.05rem;">Executive Assessment</strong>
            <p style="color: #E2E8F0; margin: 0.4rem 0 0 0; font-size: 0.95rem; line-height: 1.6;">
                {analysis['summary']}
            </p>
        </div>
        """, unsafe_allow_html=True)

        # 2. Score Explanation
        st.markdown('<div class="section-title">💡 Why This Score Was Calculated</div>', unsafe_allow_html=True)
        st.markdown(f"**Scoring Formula:** `{breakdown.get('formula', f'Score: {score}/100')}`")
        st.info(f"**Explanation:** {breakdown.get('explanation', '')}")

        # 3. Coordinated Scam Combinations Detected
        if analysis["combinations_detected"]:
            st.markdown('<div class="section-title">⚡ Coordinated Scam Combinations Detected</div>', unsafe_allow_html=True)
            for syn in analysis["combinations_detected"]:
                st.error(f"⚠️ **{syn['label']}** (+{syn['boost']} pts): {syn['explanation']}")

        # 4. Detected Indicators & Supporting Evidence
        st.markdown('<div class="section-title">🔎 Detected Suspicious Indicators</div>', unsafe_allow_html=True)

        if analysis["detected_categories"]:
            for cat in analysis["detected_categories"]:
                st.markdown(f"""
                <div class="indicator-card-dark">
                    <div style="font-weight: 700; color: #F8FAFC; font-size: 1.05rem;">
                        📌 {cat['name']} <span style="color:#C084FC;">(Severity: {cat['severity']}, Contribution: +{cat['score_contribution']} pts)</span>
                    </div>
                    <div style="font-size: 0.9rem; color: #CBD5E1; margin: 0.3rem 0;">
                        <strong>Why It Was Flagged:</strong> {cat['description']}
                    </div>
                    <div style="font-size: 0.88rem; color: #38BDF8; font-weight: 600;">Transcript Evidence:</div>
                """, unsafe_allow_html=True)

                for m in cat["matches"]:
                    st.markdown(f'<div class="evidence-quote-dark">"{m["snippet"]}" — <em style="color:#CBD5E1;">{m["explanation"]}</em> <span style="color:#2DD4BF;">(+{m["weight"]} pts)</span></div>', unsafe_allow_html=True)

                st.markdown("</div>", unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="safe-banner-dark">
                <strong style="font-size: 1.05rem;">✅ No Significant Suspicious Indicators Detected</strong><br>
                The conversation does not display credential demands, artificial urgency, legal threats, 
                or unauthorized fund diversion instructions.
            </div>
            """, unsafe_allow_html=True)

        # 5. Defensive / Safe Context
        if analysis["safe_indicators_detected"]:
            st.markdown('<div class="section-title">🛡️ Defensive Context Recognized</div>', unsafe_allow_html=True)
            for note in analysis["safe_indicators_detected"]:
                st.info(f"🛡️ {note}")

        # 6. Recommended Actions
        st.markdown('<div class="section-title">🛡️ Recommended Security Actions</div>', unsafe_allow_html=True)
        for rec in analysis["recommendations"]:
            st.markdown(f"👉 **{rec}**")

        # 7. Academic Disclaimer
        st.markdown(f"""
        <div class="disclaimer-card-dark">
            <strong>System Notice:</strong> {analysis["educational_disclaimer"]}
        </div>
        """, unsafe_allow_html=True)

        # 8. Download Structured Report
        st.markdown("---")
        report_data = {
            "title": "AI-Based Phishing Call Detection and Risk Analysis System",
            "source": source_name,
            "timestamp": timestamp_val,
            "method": method_val,
            "transcript": transcript_text,
            "score": score,
            "risk_level": risk_level,
            "scoring_formula": breakdown.get("formula", ""),
            "detected_categories": [c["name"] for c in analysis["detected_categories"]],
            "recommendations": analysis["recommendations"]
        }

        st.download_button(
            label="📥 Download Analysis Report (JSON)",
            data=json.dumps(report_data, indent=2),
            file_name="phishing_analysis_report.json",
            mime="application/json"
        )
