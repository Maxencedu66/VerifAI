#!/usr/bin/python

import re
import lief
import hashlib
import numpy as np
import pickle
import os
import json
from sklearn.feature_extraction import FeatureHasher
import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import GridSearchCV
from sklearn.model_selection import TimeSeriesSplit
from sklearn.metrics import (roc_auc_score, make_scorer)
from pe_extractor_ember import PEFeatureExtractor





def load_model(model_path):
    """
    Charger un modèle sauvegardé avec pickle.

    Args:
        model_path (str): Chemin vers le fichier du modèle sauvegardé.

    Returns:
        model: Modèle chargé ou None en cas d'échec.
    """
    try:
        with open(model_path, "rb") as f:
            model = pickle.load(f)
        print(f"Model successfully loaded from {model_path}")
        return model
    except Exception as e:
        print(f"Erreur lors du chargement du modèle : {e}")
        return None

# Nettoyage des noms de fichiers
def clean_filename(filename):
    """
    Nettoyer le nom du fichier en supprimant ou remplaçant les caractères spéciaux.

    Args:
        filename (str): Nom du fichier d'origine.

    Returns:
        str: Nom de fichier nettoyé.
    """
    return filename.replace(" ", "_").replace("(", "").replace(")", "").replace("&", "").replace("'", "")




# Fonction pour prédire si un fichier est un malware
def classify_exe(file_path, model_path, threshold=0.5):
    """
    Prédit si un fichier exécutable est SAFE ou MALWARE en utilisant un modèle XGBoost chargé dynamiquement.

    Args:
        file_path (str): Chemin vers le fichier à analyser.
        model_path (str): Chemin vers le fichier du modèle sauvegardé.
        threshold (float): Seuil pour la classification.

    Returns:
        dict: Résultat de l'analyse contenant la prédiction, la classification, et la confiance.
    """
    # Charger le modèle
    model = load_model(model_path)
    if model is None:
        raise RuntimeError(f"Le modèle n'a pas pu être chargé depuis {model_path}. Analyse annulée.")

    # Charger le fichier exécutable
    try:
        with open(file_path, "rb") as f:
            file_data = f.read()
    except Exception as e:
        raise RuntimeError(f"Erreur lors de l'ouverture du fichier : {e}")

    # Extraire les caractéristiques et effectuer la prédiction
    try:
        extractor = PEFeatureExtractor()
        features = np.array(extractor.feature_vector(file_data), dtype=np.float32).reshape(1, -1)
        prediction = model.predict_proba(features)[0][1]  # Probabilité que le fichier soit MALWARE
    except Exception as e:
        raise RuntimeError(f"Erreur lors de la prédiction : {e}")

    # Interpréter la prédiction
    classification = "MALWARE" if prediction >= threshold else "SAFE"
    confidence = prediction if classification == "MALWARE" else 1 - prediction

    return {
        "prediction": prediction,
        "classification": classification,
        "confidence": confidence * 100,
    }






## Permet de predire avec le modèle de Ember prédéfinie
def predict_sample(lgbm_model, file_data, feature_version=2):
    """
    Predict a PE file with an LightGBM model
    """
    extractor = PEFeatureExtractor(feature_version)
    features = np.array(extractor.feature_vector(file_data), dtype=np.float32)
    return lgbm_model.predict([features])[0]


