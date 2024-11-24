import lightgbm as lgb
import os
import argparse
import warnings

# Ajouter le chemin du dossier parent
import sys
import os
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(parent_dir)
from pe_extractor_ember import PEFeatureExtractor
from fonctions import predict_sample

# Désactiver les warnings de LightGBM
warnings.filterwarnings(action="ignore", category=UserWarning, module="lightgbm")

# Fonction pour analyser un fichier
def classify_exe(file_to_test, lgbm_model, threshold=0.5):
    """
    Classe un fichier exécutable comme SAFE ou MALWARE en utilisant le modèle EMBER.
    Affiche la probabilité et le degré de confiance pour chaque prédiction.

    Args:
        file_to_test (str): Chemin vers le fichier .exe à tester.
        lgbm_model: Modèle LightGBM préentraîné.
        threshold (float): Seuil pour séparer les classes SAFE et MALWARE.
    """
    try:
        # Charger le fichier exécutable
        with open(file_to_test, "rb") as f:
            file_data = f.read()

        # Prédire avec le modèle
        prediction = predict_sample(lgbm_model, file_data)

        # Interpréter la probabilité
        if 0 <= prediction <= 1:
            confidence = prediction if prediction >= threshold else 1 - prediction
            classification = "MALWARE" if prediction >= threshold else "SAFE"
            print(f"File: {file_to_test}")
            print(f"Prediction: {prediction:.4f}")
            print(f"Confidence: {confidence * 100:.2f}%")
            print(f"Classification: {classification}\n")
        else:
            print(f"File: {file_to_test} could not be classified. Prediction: {prediction}\n")

    except Exception as e:
        print(f"Erreur lors de l'analyse de {file_to_test} : {e}")

# Fonction principale
def classify_all_executables(folder_path, threshold=0.5):
    """
    Parcourt tous les fichiers .exe dans un dossier et les classe comme SAFE ou MALWARE.

    Args:
        folder_path (str): Chemin du dossier contenant les fichiers .exe.
        threshold (float): Seuil pour séparer les classes SAFE et MALWARE.
    """
    model_path = os.path.join(folder_path, "../modeles_ML/lgb_model.txt")

    # Charger le modèle préentraîné
    try:
        lgbm_model = lgb.Booster(model_file=model_path)
    except Exception as e:
        print(f"Erreur lors du chargement du modèle : {e}")
        return

    # Parcourir tous les fichiers .exe dans le dossier
    exe_folder = os.path.join(folder_path, "executable")
    if not os.path.exists(exe_folder):
        print(f"Le dossier {exe_folder} n'existe pas.")
        return

    exe_files = [f for f in os.listdir(exe_folder) ]
    if not exe_files:
        print("Aucun fichier .exe trouvé dans le dossier.")
        return

    print(f"Nombre de fichiers .exe trouvés : {len(exe_files)}\n")
    for exe_file in exe_files:
        file_path = os.path.join(exe_folder, exe_file)
        classify_exe(file_path, lgbm_model, threshold)

# Main function
if __name__ == "__main__":
    # Créer un parser pour récupérer les arguments en ligne de commande
    parser = argparse.ArgumentParser(description="Classify all .exe files in a folder as SAFE or MALWARE using EMBER.")
    parser.add_argument("--folder_path", type=str, default="../modeles_ML/lgb_model.plk", help="Path to the folder containing the model and executables (default: current folder)")
    parser.add_argument("--threshold", type=float, default=0.5, help="Threshold for classification (default: 0.5)")

    # Parse les arguments
    args = parser.parse_args()

    # Appeler la fonction de classification pour tous les fichiers .exe
    classify_all_executables(args.folder_path, threshold=args.threshold)