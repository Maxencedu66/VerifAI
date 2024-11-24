import os
import pickle
import numpy as np
# Ajouter le chemin du dossier parent
import sys
import os
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(parent_dir)
from pe_extractor_ember import PEFeatureExtractor
import argparse

def predict_sample(model, file_data, feature_version=2):
    """
    Predict a PE file with a trained XGBoost model.

    Args:
        model: Trained model (XGBoost).
        file_data (bytes): Binary data of the PE file.
        feature_version (int): Version of the feature extractor to use.

    Returns:
        float: Probability that the file is malware.
    """
    # Extraire les caractéristiques
    extractor = PEFeatureExtractor(feature_version)
    features = np.array(extractor.feature_vector(file_data), dtype=np.float32).reshape(1, -1)

    # Vérifier le type de modèle et effectuer une prédiction
    if hasattr(model, "predict_proba"):  # Pour XGBoost sklearn API
        return model.predict_proba(features)[0][1]  # Probabilité de la classe MALWARE
    else:
        raise ValueError("Unsupported model type. Model must support predict_proba.")

def classify_exe(file_to_test, model_path, threshold=0.5):
    """
    Classify a PE file as SAFE or MALWARE using a XGBoost model.

    Args:
        file_to_test (str): Path to the .exe file to test.
        model_path (str): Path to the trained XGBoost model.
        threshold (float): Threshold for classification.

    Returns:
        None
    """
    # Charger le modèle préentraîné
    try:
        with open(model_path, "rb") as f:
            xgb_model = pickle.load(f)
    except Exception as e:
        print(f"Erreur lors du chargement du modèle : {e}")
        return

    # Charger le fichier exécutable
    try:
        with open(file_to_test, "rb") as f:
            file_data = f.read()
    except Exception as e:
        print(f"Erreur lors de l'ouverture du fichier : {e}")
        return

    # Prédire avec le modèle
    try:
        prediction_prob = predict_sample(xgb_model, file_data)
    except Exception as e:
        print(f"Erreur lors de la prédiction : {e}")
        return

    # Interpréter la probabilité
    classification = "MALWARE" if prediction_prob >= threshold else "SAFE"
    confidence = prediction_prob if classification == "MALWARE" else 1 - prediction_prob

    # Afficher le résultat
    print(f"Prediction: {prediction_prob:.4f}")
    print(f"Confidence: {confidence * 100:.2f}%")
    print(f"Classification: {file_to_test} is {classification}.")


if __name__ == "__main__":
    # Configurer l'analyse des arguments de la ligne de commande
    parser = argparse.ArgumentParser(description="Classify an executable file as SAFE or MALWARE using a trained XGBoost model.")
    parser.add_argument("exe_file", help="Path to the executable file to test (e.g., Skype-8.132.0.201.exe)")
    parser.add_argument("--model_path", type=str, default="../modeles_ML/xgboost_model.pkl", help="Path to the trained XGBoost model (default: ../modeles_ML/xgboost_model.pkl)")
    parser.add_argument("--threshold", type=float, default=0.5, help="Threshold for classification (default: 0.5)")

    # Lire les arguments
    args = parser.parse_args()

    # Appeler la fonction de classification
    classify_exe(args.exe_file, args.model_path, threshold=args.threshold)
