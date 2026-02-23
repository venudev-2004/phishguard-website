from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple


@dataclass
class PhishingModel:
    """
    Minimal phishing model wrapper.

    In a real project this would load a trained ML model from disk.
    For now we implement a simple heuristic-based detector so the app
    runs without extra dependencies.
    """

    def __post_init__(self) -> None:
        # Placeholder for loading a real model if you add one later.
        self.loaded = True

    def predict(self, url: str) -> Tuple[bool, float | None]:
        """
        Predict whether a URL is phishing.

        Returns:
            (is_phishing, score) where score is a confidence between 0 and 1.
        """
        if not url:
            return False, None

        lowered = url.lower()

        # Very simple heuristic rules
        suspicious_keywords = [
            "login",
            "verify",
            "update",
            "secure",
            "bank",
            "account",
            "paypal",
            "gift",
            "prize",
        ]

        score = 0.0

        if any(word in lowered for word in suspicious_keywords):
            score += 0.4

        # Many subdomains / path segments increase suspicion
        dot_count = lowered.count(".")
        if dot_count >= 4:
            score += 0.2

        if "@" in lowered or "-" in lowered:
            score += 0.1

        # Cap score between 0 and 1
        score = max(0.0, min(score, 1.0))

        is_phishing = score >= 0.5
        return is_phishing, score

    def predict_email(self, text: str) -> Tuple[bool, float | None]:
        """
        Predict whether an email body / content is phishing.

        This is a heuristic placeholder – replace with a real
        NLP / ML model when available.
        """
        if not text:
            return False, None

        lowered = text.lower()

        red_flags = [
            "verify your account",
            "verify your identity",
            "update your account",
            "confirm your password",
            "login to your",
            "unusual activity",
            "unauthorized login",
            "click the link below",
            "click here to avoid",
            "your account will be closed",
            "urgent action required",
        ]

        score = 0.0

        if any(flag in lowered for flag in red_flags):
            score += 0.5

        # Excessive use of exclamation marks or all caps can be suspicious
        if lowered.count("!") >= 3:
            score += 0.2

        if any(word.isupper() and len(word) >= 4 for word in lowered.split()):
            score += 0.1

        score = max(0.0, min(score, 1.0))
        is_phishing = score >= 0.5
        return is_phishing, score

