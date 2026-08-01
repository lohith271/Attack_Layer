import numpy as np
from app.ml.ensemble import get_ensemble_prediction
from app.security.adversarial_guard import AdversarialGuard
from app.ml.model_manager import get_model

def predict_decision(embedding) -> dict:
    """
    Predict security decision using the robust multi-model ensemble
    and adversarial defense layers. Includes One-Class SVM anomaly detection.
    """
    # 1. Run ensemble prediction
    ensemble_res = get_ensemble_prediction(embedding)
    
    # 2. Run adversarial guard checks
    adv_res = AdversarialGuard.assess_adversarial_risk(ensemble_res["model_predictions"])
    
    prediction = ensemble_res["prediction"]
    confidence = ensemble_res["confidence"]
    
    # 3. Run One-Class SVM Anomaly Check (OOD)
    one_class_anomaly = False
    oc_svm = get_model("one_class_svm")
    if oc_svm is not None:
        try:
            X = np.array(embedding, dtype=np.float32).reshape(1, -1)
            # 1 = benign, -1 = anomaly/OOD
            oc_pred = oc_svm.predict(X)[0]
            if oc_pred == -1:
                one_class_anomaly = True
                print("One-Class SVM: Out-of-Distribution / Anomaly Detected!")
        except Exception as e:
            print(f"Error predicting with One-Class SVM: {e}")
            
    # If One-Class SVM flags an anomaly, override prediction to Attack (1) with high confidence
    if one_class_anomaly:
        prediction = 1
        confidence = 0.99
    
    # If adversarial guard flags a critical disagreement or anomaly, 
    # override or flag it. For example, if critical model disagreement, 
    # we force review state by adjusting confidence/prediction, or flagging it.
    elif adv_res["adversarial_detected"]:
        # If there's a risk of adversarial attack/disagreement, flag low trust
        print(f"Adversarial Guard Triggered: {adv_res['reasons']}")
        # Keep prediction but force a quarantine/review confidence level if it was an attack prediction,
        # or flag it for review.
        if prediction == 1:
            # Boost confidence to BLOCK if highly likely, or lower to force QUARANTINE/REVIEW
            # Let's adjust to ensure human review is triggered
            confidence = min(confidence, 0.85)  # Forces Quarantine / Review
            
    # Return output format expected by the system
    return {
        "prediction": prediction,
        "confidence": confidence,
        "ensemble_info": ensemble_res,
        "adversarial_info": adv_res,
        "one_class_anomaly": one_class_anomaly
    }