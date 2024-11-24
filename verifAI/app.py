import os
import shutil
import numpy as np
from flask import Flask, request, render_template, flash, redirect, url_for
from flask_session import Session
from fonctions import clean_filename, classify_exe, load_model

# Flask app creation
app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["UPLOAD_FOLDER"] = "uploads"  # Dossier pour stocker les fichiers uploadés
app.secret_key = "supersecretkey"  # Nécessaire pour flash
Session(app)

# Charger le modèle XGBoost
MODEL_PATH = "./modeles_ML/xgboost_model.pkl"

try:
    model = load_model(MODEL_PATH)
    if model is None:
        raise RuntimeError("Le modèle n'a pas pu être chargé. Vérifiez le chemin ou le fichier.")
except Exception as e:
    raise RuntimeError(f"Erreur critique lors du chargement du modèle : {e}")

# Route principale
@app.route("/")
def home():
    return render_template("home.html", title="VirusLeBoss")


# Route pour gérer l'upload de fichier et analyse
@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        flash("Pas de fichier sélectionné", "error")
        return redirect(url_for("home"))

    file = request.files["file"]
    if file.filename == "":
        flash("Veuillez sélectionner un fichier", "error")
        return redirect(url_for("home"))

    # Nettoyer le nom du fichier
    original_filename = file.filename
    cleaned_filename = clean_filename(original_filename)

    # Sauvegarder le fichier nettoyé
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], cleaned_filename)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    file.save(file_path)

    # Analyse du fichier
    try:
        result = classify_exe(file_path, MODEL_PATH)  # Appeler `classify_exe` avec `MODEL_PATH`
        flash(f"Fichier analysé : {original_filename}", "info")
        if result["classification"] == "SAFE":
            flash(f"Classification : {result['classification']} - Confiance : {result['confidence']:.2f}%", "success")
        else:
            flash(f"Classification : {result['classification']} - Confiance : {result['confidence']:.2f}%", "error")
    except Exception as e:
        flash(f"Erreur lors de l'analyse du fichier : {e}", "error")
    finally:
        # Nettoyage : Supprimer le fichier uploadé après l'analyse
        if os.path.exists(file_path):
            os.remove(file_path)

    return redirect(url_for("home"))


# Main
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5454)
