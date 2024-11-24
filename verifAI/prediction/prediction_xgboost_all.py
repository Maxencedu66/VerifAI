import os
import pickle
import numpy as np
import time
import argparse
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
# Ajouter le chemin du dossier parent
import sys
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(parent_dir)
from pe_extractor_ember import PEFeatureExtractor


def predict_sample(model, file_data, feature_version=2):
    extractor = PEFeatureExtractor(feature_version)
    features = np.array(extractor.feature_vector(file_data), dtype=np.float32).reshape(1, -1)
    if hasattr(model, "predict_proba"):  # Pour XGBoost sklearn API
        return model.predict_proba(features)[0][1]  # Probabilité de la classe MALWARE
    else:
        raise ValueError("Unsupported model type. Model must support predict_proba.")


def classify_exe(file_to_test, model, threshold=0.5):
    try:
        with open(file_to_test, "rb") as f:
            file_data = f.read()
    except Exception as e:
        print(f"Erreur lors de l'ouverture du fichier {file_to_test}: {e}")
        return None

    try:
        prediction_prob = predict_sample(model, file_data)
    except Exception as e:
        print(f"Erreur lors de la prédiction pour {file_to_test}: {e}")
        return None

    classification = "MALWARE" if prediction_prob >= threshold else "SAFE"
    confidence = prediction_prob if classification == "MALWARE" else 1 - prediction_prob

    return {
        "filename": file_to_test,
        "probability": prediction_prob,
        "confidence": confidence * 100,
        "classification": classification
    }


def classify_all_files(folder_path, model_path, threshold=0.5, output_file="results.txt"):
    try:
        with open(model_path, "rb") as f:
            model = pickle.load(f)
    except Exception as e:
        print(f"Erreur lors du chargement du modèle : {e}")
        return

    print(f"Scanning folder: {folder_path}")

    total_files = 0
    correct_predictions = 0
    total_time = []
    results = []
    file_sizes = []
    y_true = []
    y_pred = []

    for root, _, files in os.walk(folder_path):
        for file in files:
            clean_file = file.replace(" ", "_")
            if file != clean_file:
                old_path = os.path.join(root, file)
                new_path = os.path.join(root, clean_file)
                os.rename(old_path, new_path)
                print(f"Renamed: {old_path} -> {new_path}")

            file_path = os.path.join(root, clean_file)
            file_size = os.path.getsize(file_path)
            file_sizes.append(file_size)

            start_time = time.time()
            result = classify_exe(file_path, model, threshold)
            end_time = time.time()

            if result:
                results.append(result)
                processing_time = end_time - start_time
                total_time.append(processing_time)

                is_virus = not file.lower().endswith(".exe")
                correct_prediction = (result["classification"] == "MALWARE" and is_virus) or \
                                     (result["classification"] == "SAFE" and not is_virus)
                if correct_prediction:
                    correct_predictions += 1

                y_true.append("MALWARE" if is_virus else "SAFE")
                y_pred.append(result["classification"])

                total_files += 1

                print(f"File: {result['filename']}")
                print(f"  Prediction: {result['probability']:.4f}")
                print(f"  Confidence: {result['confidence']:.2f}%")
                print(f"  Classification: {result['classification']}")
                print(f"  Processing time: {processing_time:.4f} seconds\n")
            else:
                print(f"Erreur lors de l'analyse du fichier {file_path}.\n")

    avg_time = np.mean(total_time) if total_time else 0
    max_time = np.max(total_time) if total_time else 0
    min_time = np.min(total_time) if total_time else 0
    accuracy = correct_predictions / total_files if total_files else 0
    max_size = max(file_sizes) if file_sizes else 0
    min_size = min(file_sizes) if file_sizes else 0
    avg_size = np.mean(file_sizes) if file_sizes else 0

    with open(output_file, "w") as f:
        f.write(f"Total files analyzed: {total_files}\n")
        f.write(f"Average processing time: {avg_time:.4f} seconds\n")
        f.write(f"Maximum processing time: {max_time:.4f} seconds\n")
        f.write(f"Minimum processing time: {min_time:.4f} seconds\n")
        f.write(f"Maximum file size: {max_size} bytes\n")
        f.write(f"Minimum file size: {min_size} bytes\n")
        f.write(f"Average file size: {avg_size:.2f} bytes\n")
        f.write(f"Accuracy: {accuracy:.2%}\n\n")
        f.write("Detailed Results:\n")
        for result in results:
            f.write(f"{result['filename']}: {result['classification']} ({result['confidence']:.2f}%)\n")

    print(f"Results saved to {output_file}")

    cm = confusion_matrix(y_true, y_pred, labels=["SAFE", "MALWARE"])
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["SAFE", "MALWARE"])
    disp.plot(cmap="Blues")
    plt.title("Confusion Matrix")
    plt.savefig("confusion_matrix.png")
    print("Confusion matrix saved as 'confusion_matrix.png'.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Classify all files in a folder as SAFE or MALWARE using a trained XGBoost model.")
    parser.add_argument("--folder_path", type=str, default="../executables_tests", help="Path to the folder containing files (default: ../executables_tests/)")
    parser.add_argument("--model_path", type=str, default="../modeles_ML/xgboost_model.pkl", help="Path to the trained model (default: ../modeles_ML/xgboost_model.pkl)")
    parser.add_argument("--threshold", type=float, default=0.5, help="Threshold for classification (default: 0.5)")
    parser.add_argument("--output_file", type=str, default="results.txt", help="Path to the output file for saving results.")

    args = parser.parse_args()

    classify_all_files(args.folder_path, args.model_path, threshold=args.threshold, output_file=args.output_file)
