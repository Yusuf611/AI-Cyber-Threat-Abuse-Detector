import numpy as np

def top_text_tokens(tfidf, model, text, top_n=8):
    """
    Return top influential tokens in a text sample based on model weights.
    Works best with linear models like Logistic Regression.
    """
    try:
        
        X = tfidf.transform([text])
        features = tfidf.get_feature_names_out()

        
        if hasattr(model, "coef_"):
            weights = model.coef_[0]
        else:
            return [("Model does not support feature importance", 0)]

        
        scores = X.toarray()[0] * weights

        
        idx = np.argsort(scores)[::-1][:top_n]
        results = [(features[i], float(scores[i])) for i in idx if scores[i] != 0]

        return results if results else [("No influential words found", 0)]

    except Exception as e:
        print(f"[ERROR] Error in text explainability: {e}")
        return [("Explainability error", 0)]
