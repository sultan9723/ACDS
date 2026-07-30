import re
from typing import Dict, Any, List, Optional
import joblib
import os
import logging

from .models import Email

logger = logging.getLogger(__name__)

PHISHING_KEYWORDS = [
    "urgent action required",
    "verify your account",
    "suspicious activity",
    "invoice",
    "urgent",
    "payment",
    "verify",
    "account",
    "prize",
    "winner",
]

SUSPICIOUS_URL_PATTERNS = [
    r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
]

class DetectionAgent:
    def __init__(self, use_ml: bool = False, model_path: str = "ml/models/phishing_model.pkl"):
        self.ml_requested = use_ml
        self.use_ml = use_ml
        self.model = None
        self.vectorizer = None

        if self.use_ml:
            try:
                # Load pre-trained model and vectorizer
                self.model = joblib.load(model_path)
                # Assuming vectorizer is saved alongside or a path is provided
                self.vectorizer = joblib.load(model_path.replace(".pkl", "_vectorizer.pkl")) 
                logger.info(f"ML model loaded from {model_path}")
            except FileNotFoundError:
                logger.warning(f"ML model or vectorizer not found at {model_path}. Falling back to rule-based detection.")
                self.use_ml = False
            except Exception as e:
                logger.error(f"Error loading ML model: {e}. Falling back to rule-based detection.")
                self.use_ml = False
        
        logger.info(f"DetectionAgent initialized. ML enabled: {self.use_ml}")

    def detect_phishing(self, email: Email) -> Dict[str, Any]:
        if self.use_ml and self.model and self.vectorizer:
            return self._ml_detect_phishing(email)
        else:
            return self._rule_based_detect_phishing(email)

    def _ml_detect_phishing(self, email: Email) -> Dict[str, Any]:
        """ML-based phishing detection."""
        try:
            email_text = email.subject + " " + email.body
            email_vector = self.vectorizer.transform([email_text])
            prediction = self.model.predict(email_vector)[0]
            # Assuming the model can provide probability estimates
            confidence_score = self.model.predict_proba(email_vector)[0][prediction]

            is_phishing = bool(prediction)
            # For ML, matched indicators could be top features, but for MVP, this is simplified
            matched_indicators = ["ML Model Prediction"] if is_phishing else []

            logger.info(f"ML Detection for {email.id}: is_phishing={is_phishing}, confidence={confidence_score:.2f}")
            return {
                "is_phishing": is_phishing,
                "confidence_score": float(confidence_score),
                "matched_indicators": matched_indicators,
                "detection_agent_id": "ML_Phishing_Detection_Agent",
            }
        except Exception as e:
            logger.error(f"Error during ML detection for email {email.id}: {e}. Falling back to rule-based.")
            return self._rule_based_detect_phishing(email)


    def _rule_based_detect_phishing(self, email: Email) -> Dict[str, Any]:
        """Rule-based phishing detection (deterministic fallback)."""
        is_phishing = False
        confidence_score = 0.0
        matched_indicators: List[str] = []

        # Rule 1: Keywords in subject or body
        email_content = (email.subject + " " + email.body).lower()
        
        for keyword in PHISHING_KEYWORDS:
            if keyword in email_content:
                is_phishing = True
                confidence_score += 0.3
                matched_indicators.append(f"Keyword '{keyword}' found")

        # Rule 2: Suspicious sender (simple check, e.g., common free email domains combined with digits/unusual patterns)
        # This is a very basic example; real-world would involve reputation lookups, DMARC/SPF/DKIM checks
        if "paypal" in email.sender and "support" not in email.sender: # Example
            is_phishing = True
            confidence_score += 0.4
            matched_indicators.append(f"Suspicious sender domain: {email.sender}")

        # Rule 3: Presence of external links (simplified)
        # This checks for http/https links in the body. Real phishing checks would involve URL analysis.
        for pattern in SUSPICIOUS_URL_PATTERNS:
            for url in re.findall(pattern, email.body):
                is_phishing = True
                confidence_score += 0.3
                matched_indicators.append(f"Suspicious URL found: {url}")

        # Normalize confidence score to max 1.0
        confidence_score = min(confidence_score, 1.0)
        
        if not is_phishing: # If no rules triggered, it's not phishing
            confidence_score = 0.0 # No confidence in non-phishing for rule-based

        logger.info(f"Rule-based Detection for {email.id}: is_phishing={is_phishing}, confidence={confidence_score:.2f}, indicators={matched_indicators}")
        return {
            "is_phishing": is_phishing,
            "confidence_score": float(confidence_score),
            "matched_indicators": matched_indicators,
            "detection_agent_id": (
                "RuleBased_ML_Placeholder_Agent"
                if self.ml_requested
                else "RuleBased_Agent"
            ),
        }

_detection_agent_instance: Optional[DetectionAgent] = None

def get_detection_agent(use_ml: bool = False, model_path: str = "ml/models/phishing_model.pkl") -> DetectionAgent:
    global _detection_agent_instance
    if _detection_agent_instance is None:
        _detection_agent_instance = DetectionAgent(use_ml, model_path)
    return _detection_agent_instance
