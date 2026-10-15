"""
AI-Based Phishing Call Detection and Risk Analysis System
Module: transcriber.py

Speech-to-Text Transcription Module.
Uses OpenAI Whisper locally via faster-whisper to transcribe recorded
phone-call audio files (WAV, MP3, M4A) without requiring internet or paid APIs.
Includes robust FFmpeg path resolution and beginner-friendly error handling.
"""

import os
import shutil
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional

# Attempt automatic FFmpeg configuration using imageio_ffmpeg if available
_ffmpeg_binary_path = None
try:
    import imageio_ffmpeg
    _binary = imageio_ffmpeg.get_ffmpeg_exe()
    if _binary and os.path.exists(_binary):
        _ffmpeg_binary_path = _binary
        _binary_dir = os.path.dirname(_binary)
        # Prepend to PATH so external processes can find it
        if _binary_dir not in os.environ.get("PATH", ""):
            os.environ["PATH"] = _binary_dir + os.pathsep + os.environ.get("PATH", "")
except Exception:
    _ffmpeg_binary_path = None


class LocalSpeechTranscriber:
    """
    Handles speech-to-text audio processing using faster-whisper.
    Runs entirely on local hardware (CPU/GPU) without cloud services.
    """

    _cached_model = None
    _cached_model_size = None

    def __init__(self, model_size: str = "tiny.en", device: str = "cpu", compute_type: str = "int8"):
        """
        Initialize the transcriber.
        :param model_size: Whisper model size ('tiny.en' is lightweight, fast, and ideal for student laptops).
        :param device: 'cpu' for standard laptops, 'cuda' if NVIDIA GPU is available.
        :param compute_type: 'int8' quantization enables low memory usage and fast CPU inference.
        """
        self.model_size = model_size
        self.device = device
        self.compute_type = compute_type
        self.ffmpeg_path = self._resolve_ffmpeg()

    @classmethod
    def _resolve_ffmpeg(cls) -> Optional[str]:
        """
        Locates the FFmpeg executable from system PATH or the bundled imageio_ffmpeg package.
        """
        # 1. First check system PATH
        system_ffmpeg = shutil.which("ffmpeg")
        if system_ffmpeg:
            return system_ffmpeg

        # 2. Check cached imageio-ffmpeg binary
        if _ffmpeg_binary_path and os.path.exists(_ffmpeg_binary_path):
            return _ffmpeg_binary_path

        # 3. Dynamic lookup via imageio_ffmpeg
        try:
            import imageio_ffmpeg
            exe = imageio_ffmpeg.get_ffmpeg_exe()
            if exe and os.path.exists(exe):
                return exe
        except Exception:
            pass

        return None

    def get_whisper_model(self):
        """
        Loads the faster-whisper model.
        Caches the model instance so it does not reload on every call.
        """
        if LocalSpeechTranscriber._cached_model is None or LocalSpeechTranscriber._cached_model_size != self.model_size:
            from faster_whisper import WhisperModel
            LocalSpeechTranscriber._cached_model = WhisperModel(
                self.model_size,
                device=self.device,
                compute_type=self.compute_type
            )
            LocalSpeechTranscriber._cached_model_size = self.model_size
        return LocalSpeechTranscriber._cached_model

    def check_system_health(self) -> Dict[str, Any]:
        """
        Verifies system readiness: checks package installations and audio decoder availability.
        Used by the Streamlit UI to show clear diagnostic status.
        """
        faster_whisper_ok = False
        try:
            import faster_whisper
            faster_whisper_ok = True
        except ImportError:
            faster_whisper_ok = False

        ffmpeg_ok = bool(self.ffmpeg_path)

        model_ok = False
        try:
            # Check if model can be retrieved
            _ = self.get_whisper_model()
            model_ok = True
        except Exception:
            model_ok = False

        return {
            "faster_whisper_available": faster_whisper_ok,
            "ffmpeg_available": ffmpeg_ok,
            "ffmpeg_path": self.ffmpeg_path or "Not found in PATH (PyAV direct fallback enabled)",
            "model_ready": model_ok,
            "model_size": self.model_size
        }

    def transcribe_audio_file(self, audio_source: Any, original_filename: Optional[str] = None) -> Dict[str, Any]:
        """
        Transcribes an uploaded audio file or local audio path into plain text.
        Supports: WAV, MP3, M4A, OGG, FLAC.

        :param audio_source: Either a filepath string, Path object, or a Streamlit UploadedFile object.
        :param original_filename: Original name of uploaded file for format validation.
        :return: Dict containing 'success', 'text', 'duration', 'error', and 'warning'.
        """
        supported_formats = {".wav", ".mp3", ".m4a", ".ogg", ".flac"}
        temp_file_created = False
        temp_file_path = None

        try:
            # Step 1: Resolve file path and validate filename
            if hasattr(audio_source, "read"):
                # Handle Streamlit UploadedFile object
                fname = original_filename or getattr(audio_source, "name", "uploaded_audio.wav")
                ext = Path(fname).suffix.lower()

                if ext not in supported_formats:
                    return {
                        "success": False,
                        "text": "",
                        "error": f"Unsupported audio file format '{ext}'. Please upload WAV, MP3, or M4A."
                    }

                # Save to a temporary file on disk so Whisper can process it
                with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
                    tmp.write(audio_source.read())
                    temp_file_path = tmp.name
                    temp_file_created = True

                # Reset file buffer pointer
                if hasattr(audio_source, "seek"):
                    audio_source.seek(0)

                target_path = Path(temp_file_path)

            else:
                # Handle string / Path input
                target_path = Path(audio_source)
                if not target_path.exists():
                    return {
                        "success": False,
                        "text": "",
                        "error": f"Audio file not found at: {target_path}"
                    }

                ext = target_path.suffix.lower()
                if ext not in supported_formats:
                    return {
                        "success": False,
                        "text": "",
                        "error": f"Unsupported audio file format '{ext}'. Please provide a WAV, MP3, or M4A file."
                    }

            # Step 2: Validate file size (detect 0-byte corrupted uploads)
            file_size_bytes = os.path.getsize(target_path)
            if file_size_bytes == 0:
                return {
                    "success": False,
                    "text": "",
                    "error": "The uploaded audio file is empty (0 bytes). Please upload a valid recording."
                }

            # Step 3: Load Whisper model
            try:
                model = self.get_whisper_model()
            except Exception as e:
                return {
                    "success": False,
                    "text": "",
                    "error": f"Failed to initialize Whisper model '{self.model_size}': {str(e)}"
                }

            # Step 4: Transcribe using faster-whisper
            # beam_size=5 ensures high transcription accuracy on noisy phone audio
            segments, info = model.transcribe(
                str(target_path),
                beam_size=5,
                language="en",
                condition_on_previous_text=False
            )

            # Collect transcribed text segments
            transcript_pieces = []
            for segment in segments:
                text_part = segment.text.strip()
                if text_part:
                    transcript_pieces.append(text_part)

            final_transcript = " ".join(transcript_pieces).strip()

            warning_msg = None
            if not final_transcript:
                warning_msg = "Transcription succeeded, but no audible speech was detected in the audio file."

            return {
                "success": True,
                "text": final_transcript,
                "duration": round(info.duration, 2) if hasattr(info, "duration") else 0.0,
                "warning": warning_msg
            }

        except Exception as e:
            err_str = str(e)
            user_friendly_err = f"Transcription error: {err_str}"
            if "ffmpeg" in err_str.lower():
                user_friendly_err = (
                    "Audio decoding error. FFmpeg was not detected or failed to decode this audio format. "
                    "You can install imageio-ffmpeg (`pip install imageio-ffmpeg`) or use Demo Mode to test transcripts immediately."
                )
            return {
                "success": False,
                "text": "",
                "error": user_friendly_err
            }

        finally:
            # Clean up temporary file
            if temp_file_created and temp_file_path and os.path.exists(temp_file_path):
                try:
                    os.remove(temp_file_path)
                except Exception:
                    pass
