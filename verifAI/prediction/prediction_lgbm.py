
import lightgbm as lgb
import os
import argparse

# Ajouter le chemin du dossier parent
import sys
import os
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(parent_dir)
from pe_extractor_ember import PEFeatureExtractor
from fonctions import predict_sample

# Fonction pour analyser le fichier via la ligne de commande
def classify_exe(file_to_test, threshold=0.5):
    """
    Classe un fichier exécutable comme SAFE ou MALWARE en utilisant le modèle EMBER.
    Affiche la probabilité et le degré de confiance pour chaque prédiction.

    Args:
        file_to_test (str): Chemin vers le fichier .exe à tester.
        threshold (float): Seuil pour séparer les classes SAFE et MALWARE.
    """
    # Chemin du modèle préentraîné
    folder_path = "../modeles_ML"
    model_path = os.path.join(folder_path, "lgb_model.plk")

    # Charger le modèle préentraîné
    try:
        lgbm_model = lgb.Booster(model_file=model_path)
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
        prediction = predict_sample(lgbm_model, file_data)
    except Exception as e:
        print(f"Erreur lors de la prédiction : {e}")
        return

    # Interpréter la probabilité
    if 0 <= prediction <= 1:
        confidence = prediction if prediction >= threshold else 1 - prediction
        classification = "MALWARE" if prediction >= threshold else "SAFE"
        print(f"Prediction: {prediction:.4f}")
        print(f"Confidence: {confidence * 100:.2f}%")
        print(f"Classification: {file_to_test} is {classification}.")
    else:
        print(f"Prediction: {prediction}")
        print(f"{file_to_test} could not be classified.")

# Main function
if __name__ == "__main__":
    # Créer un parser pour récupérer l'argument du fichier en ligne de commande
    parser = argparse.ArgumentParser(description="Classify an executable file as SAFE or MALWARE using EMBER.")
    parser.add_argument("exe_file", help="Path to the executable file to test (e.g., Skype-8.132.0.201.exe)")
    parser.add_argument("--threshold", type=float, default=0.5, help="Threshold for classification (default: 0.5)")

    # Parse les arguments
    args = parser.parse_args()

    # Appeler la fonction de classification avec le fichier spécifié
    classify_exe(args.exe_file, threshold=args.threshold)
