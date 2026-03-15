# utils/ml_ids_engine.py
# ─────────────────────────────────────────────────────────────────────────────
# Singleton ML prediction engine.
# Loads ids_model.pkl, scaler.pkl, label_encoder.pkl produced by train_model.py
# and exposes a simple predict() classmethod.
# ─────────────────────────────────────────────────────────────────────────────

import os
import logging
import numpy as np

logger = logging.getLogger(__name__)

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODEL_PATH         = os.path.join(_ROOT, "ids_model.pkl")
SCALER_PATH        = os.path.join(_ROOT, "scaler.pkl")
ENCODER_PATH       = os.path.join(_ROOT, "label_encoder.pkl")
ANOMALY_MODEL_PATH = os.path.join(_ROOT, "anomaly_model.pkl")


class MLIDSEngine:
    _model   = None
    _scaler  = None
    _encoder = None
    _anomaly_model = None
    _ready   = False
    _feature_count = None

    @classmethod
    def _load(cls):
        if cls._ready:
            return True
        try:
            import joblib
            if not all(os.path.exists(p) for p in (MODEL_PATH, SCALER_PATH, ENCODER_PATH)):
                logger.warning(
                    "ML model files not found. Run train_model.py first. "
                    "ML predictions will be disabled."
                )
                return False

            cls._model   = joblib.load(MODEL_PATH)
            cls._scaler  = joblib.load(SCALER_PATH)
            cls._encoder = joblib.load(ENCODER_PATH)
            if os.path.exists(ANOMALY_MODEL_PATH):
                cls._anomaly_model = joblib.load(ANOMALY_MODEL_PATH)
            else:
                cls._anomaly_model = None

            # Cache expected feature count (from scaler)
            cls._feature_count = cls._scaler.n_features_in_
            cls._ready = True
            logger.info(
                f"ML-IDS engine loaded — {len(cls._encoder.classes_)} classes, "
                f"{cls._feature_count} features"
            )
            return True
        except Exception as e:
            logger.exception("Failed to load ML model: %s", e)
            return False

    @classmethod
    def predict(cls, features: dict) -> tuple:
        """
        Predict attack class from a feature dictionary.

        Parameters
        ----------
        features : dict
            Keys must be the same numerical features used during training.
            Missing features are filled with 0.

        Returns
        -------
        (label: str, confidence: float)
            label      – class name, e.g. "BENIGN", "PortScan", "DoS Hulk"
            confidence – probability of predicted class (0–1)
        """
        if not cls._load():
            return ("UNKNOWN", 0.0)

        try:
            # Build a zero-padded vector of the right length
            vec = np.zeros((1, cls._feature_count), dtype=np.float32)

            # Fill in whatever features we have (by position in scaler)
            feature_names = getattr(cls._scaler, "feature_names_in_", None)
            if feature_names is not None:
                for i, name in enumerate(feature_names):
                    val = features.get(name, 0)
                    try:
                        vec[0, i] = float(val)
                    except Exception:
                        pass
            else:
                # Fallback: fill by order of provided values
                for i, val in enumerate(features.values()):
                    if i >= cls._feature_count:
                        break
                    try:
                        vec[0, i] = float(val)
                    except Exception:
                        pass

            # Replace any NaN / inf
            vec = np.nan_to_num(vec, nan=0.0, posinf=0.0, neginf=0.0)

            # Scale and predict
            vec_scaled = cls._scaler.transform(vec)
            pred_idx   = cls._model.predict(vec_scaled)[0]
            proba      = cls._model.predict_proba(vec_scaled)[0]
            confidence = float(proba[pred_idx])
            label      = cls._encoder.inverse_transform([pred_idx])[0]

            return (str(label), confidence)

        except Exception as e:
            logger.debug("ML predict error: %s", e)
            return ("UNKNOWN", 0.0)

    @classmethod
    def predict_anomaly(cls, features: dict) -> tuple:
        """
        Predict if the flow is an anomaly (zero-day attack) based on statistical deviation.
        Returns:
            (is_anomaly: bool, score: float)
            score < 0 means anomaly, closer to -1 is worse.
        """
        if not cls._load() or not cls._anomaly_model:
            return (False, 1.0)

        try:
            vec = np.zeros((1, cls._feature_count), dtype=np.float32)
            feature_names = getattr(cls._scaler, "feature_names_in_", None)
            if feature_names is not None:
                for i, name in enumerate(feature_names):
                    val = features.get(name, 0)
                    try:
                        vec[0, i] = float(val)
                    except Exception:
                        pass
            else:
                for i, val in enumerate(features.values()):
                    if i >= cls._feature_count:
                        break
                    try:
                        vec[0, i] = float(val)
                    except Exception:
                        pass

            vec = np.nan_to_num(vec, nan=0.0, posinf=0.0, neginf=0.0)
            vec_scaled = cls._scaler.transform(vec)
            
            # Isolation forest predict: 1 is normal, -1 is anomaly.
            pred = cls._anomaly_model.predict(vec_scaled)[0]
            score = cls._anomaly_model.score_samples(vec_scaled)[0]
            
            is_anomaly = bool(pred == -1)
            return (is_anomaly, float(score))

        except Exception as e:
            logger.debug("Anomaly predict error: %s", e)
            return (False, 1.0)

    @classmethod
    def is_ready(cls) -> bool:
        return cls._ready or cls._load()
