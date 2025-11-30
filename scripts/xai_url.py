import os
import sys
import shap
import joblib
import pandas as pd
import numpy as np

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, os.pardir))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from scripts.url_features import extract_url_features


# Load the trained URL model

model_path = os.path.join(project_root, 'models', 'url_model.joblib')

try:
    model = joblib.load(model_path)
    print("[OK] Model loaded successfully.")
except Exception as e:
    print(f"[ERROR] Error loading model: {e}")
    model = None


# Initialize SHAP explainer safely

explainer = None
if model is not None:
    try:
        background = pd.DataFrame(
            [extract_url_features("https://example.com")]
        )
        explainer = shap.Explainer(model.predict_proba, background)
        print("[OK] SHAP KernelExplainer initialized successfully.")
    except Exception as e:
        print(f"[ERROR] Error initializing SHAP explainer: {e}")
        explainer = None



# Main explanation function

def explain_url(url):
    """Return top 8 most influential features for a given URL."""
    if model is None or explainer is None:
        return [("Model or SHAP not available", 0)]

    feats = pd.DataFrame([extract_url_features(url)])
    try:
        shap_values = explainer(feats)
        if shap_values.values.ndim == 3:
            values = shap_values.values[0, :, 1]
        else:
            values = shap_values.values[0]

        importance = sorted(
            zip(feats.columns, values),
            key=lambda x: -abs(x[1])
        )[:8]

        return importance

    except Exception as e:
        print(f"[ERROR] Error during SHAP explanation: {e}")
        return [("SHAP explanation error", 0)]
