# Description : ce script permet de lancer une application Web Flask pour prédire si un fichier exécutable est un malware ou non. 
# Il utilise un modèle RandomForest entraîné sur des données PE extraites. 
# L'application permet aux utilisateurs de télécharger un fichier .exe, d'extraire les informations PE et de prédire s'il s'agit d'un malware ou non.
# 
# python install -r requirements.txt
# python app.py

import pefile
import hashlib
import os
import pandas as pd
import random
import string
from flask import Flask, request, render_template, flash, redirect, session, url_for
from flask_session import Session
import pickle
from scipy.stats import entropy
import numpy as np

# flask app creation
app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["UPLOAD_FOLDER"] = "uploads"  # Dossier pour stocker les fichiers uploadés
Session(app)

# Charger le modèle entraîné
model_path = "modele_ML/rf_model.pkl"  # Le chemin vers le modèle .pkl
with open(model_path, 'rb') as file:
    model = pickle.load(file)

def get_file_hash(file_path, hash_algo='sha256'):
    hash_func = hashlib.new(hash_algo)
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)
    return hash_func.hexdigest()




def calculate_section_entropies(pe):
    """
    Calcule les entropies des sections dans le fichier PE.
    """
    sections_entropies = []
    for section in pe.sections:
        try:
            # Récupérer les données de la section
            data = section.get_data()
            if len(data) > 0:
                # Calculer la fréquence des octets (0-255)
                byte_frequencies = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
                # Normaliser les fréquences
                probabilities = byte_frequencies / len(data)
                # Calculer l'entropie de Shannon
                sections_entropies.append(entropy(probabilities, base=2))
        except Exception as e:
            print(f"Erreur dans le calcul de l'entropie pour une section : {e}")
            continue

    return sections_entropies


def extract_resources(pe):
    """Extraire les ressources PE avec leurs entropies et tailles."""
    resources = []

    def parse_directory(directory):
        if hasattr(directory, 'entries'):
            for entry in directory.entries:
                if hasattr(entry, 'directory'):
                    # Si l'entrée a un sous-répertoire, continuer la récursion
                    parse_directory(entry.directory)
                elif hasattr(entry, 'data') and hasattr(entry.data, 'struct'):
                    # Si l'entrée est une ressource avec des données
                    try:
                        data_rva = entry.data.struct.OffsetToData
                        size = entry.data.struct.Size
                        resource_data = pe.get_data(data_rva, size)
                        if resource_data:
                            # Calculer l'entropie
                            byte_frequencies = np.bincount(np.frombuffer(resource_data, dtype=np.uint8), minlength=256)
                            probabilities = byte_frequencies / len(resource_data)
                            resource_entropy = entropy(probabilities, base=2)
                            resources.append({"size": len(resource_data), "entropy": resource_entropy})
                    except Exception as e:
                        print(f"Erreur lors de l'extraction des données de ressource : {e}")
                        continue

    # Commencer avec la racine des ressources
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') and pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            parse_directory(entry.directory)

    return resources

def extract_version_info(pe):
    """
    Extraire et calculer la taille des informations de version (VersionInformationSize).
    """
    version_info_size = 0

    try:
        # Vérifier si le fichier contient des informations de ressources
        if hasattr(pe, 'FileInfo'):
            for fileinfo in pe.FileInfo:
                # Parcourir les StringTables
                if hasattr(fileinfo, 'StringTable'):
                    for st in fileinfo.StringTable:
                        if hasattr(st, 'entries'):
                            version_info_size += len(st.entries)  # Compter les entrées

                # Parcourir les VarFileInfo
                if hasattr(fileinfo, 'Var'):
                    for var in fileinfo.Var:
                        if hasattr(var, 'entry'):
                            version_info_size += len(var.entry.keys())  # Compter les clés

        # Ajouter 1 si VS_VERSIONINFO existe (niveau global)
        if hasattr(pe, 'VS_VERSIONINFO'):
            version_info_size += 1

    except Exception as e:
        print(f"Erreur lors de l'extraction des informations de version : {e}")

    return version_info_size


def extract_pe_info(file_path):
    """Extraire les informations PE et les statistiques des ressources."""
    pe = pefile.PE(file_path)
    version_information_size = extract_version_info(pe)
   
    
    # Extraction des ressources
    resources = extract_resources(pe)
    resources_sizes = [res["size"] for res in resources]
    resources_entropies = [res["entropy"] for res in resources]

    # Calcul des statistiques des ressources
    resources_mean_size = sum(resources_sizes) / len(resources_sizes) if resources_sizes else 0
    resources_min_size = min(resources_sizes) if resources_sizes else 0
    resources_max_size = max(resources_sizes) if resources_sizes else 0
    resources_mean_entropy = sum(resources_entropies) / len(resources_entropies) if resources_entropies else 0
    resources_min_entropy = min(resources_entropies) if resources_entropies else 0
    resources_max_entropy = max(resources_entropies) if resources_entropies else 0

    # Calcul des entropies des sections
    sections_entropies = calculate_section_entropies(pe)

    # Ajouter les informations PE et statistiques
    pe_info = {
        "Name": os.path.basename(file_path),
        "Machine": pe.FILE_HEADER.Machine,
        "SizeOfOptionalHeader": pe.FILE_HEADER.SizeOfOptionalHeader,
        "Characteristics": pe.FILE_HEADER.Characteristics,
        "MajorLinkerVersion": pe.OPTIONAL_HEADER.MajorLinkerVersion,
        "MinorLinkerVersion": pe.OPTIONAL_HEADER.MinorLinkerVersion,
        "SizeOfCode": pe.OPTIONAL_HEADER.SizeOfCode,
        "SizeOfInitializedData": pe.OPTIONAL_HEADER.SizeOfInitializedData,
        "SizeOfUninitializedData": pe.OPTIONAL_HEADER.SizeOfUninitializedData,
        "AddressOfEntryPoint": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        "BaseOfCode": pe.OPTIONAL_HEADER.BaseOfCode,
        "BaseOfData": pe.OPTIONAL_HEADER.BaseOfData if hasattr(pe.OPTIONAL_HEADER, 'BaseOfData') else 0,
        "ImageBase": pe.OPTIONAL_HEADER.ImageBase,
        "SectionAlignment": pe.OPTIONAL_HEADER.SectionAlignment,
        "FileAlignment": pe.OPTIONAL_HEADER.FileAlignment,
        "MajorOperatingSystemVersion": pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
        "MinorOperatingSystemVersion": pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
        "MajorImageVersion": pe.OPTIONAL_HEADER.MajorImageVersion,
        "MinorImageVersion": pe.OPTIONAL_HEADER.MinorImageVersion,
        "MajorSubsystemVersion": pe.OPTIONAL_HEADER.MajorSubsystemVersion,
        "MinorSubsystemVersion": pe.OPTIONAL_HEADER.MinorSubsystemVersion,
        "SizeOfImage": pe.OPTIONAL_HEADER.SizeOfImage,
        "SizeOfHeaders": pe.OPTIONAL_HEADER.SizeOfHeaders,
        "CheckSum": pe.OPTIONAL_HEADER.CheckSum,
        "Subsystem": pe.OPTIONAL_HEADER.Subsystem,
        "DllCharacteristics": pe.OPTIONAL_HEADER.DllCharacteristics,
        "SizeOfStackReserve": pe.OPTIONAL_HEADER.SizeOfStackReserve,
        "SizeOfStackCommit": pe.OPTIONAL_HEADER.SizeOfStackCommit,
        "SizeOfHeapReserve": pe.OPTIONAL_HEADER.SizeOfHeapReserve,
        "SizeOfHeapCommit": pe.OPTIONAL_HEADER.SizeOfHeapCommit,
        "LoaderFlags": pe.OPTIONAL_HEADER.LoaderFlags,
        "NumberOfRvaAndSizes": pe.OPTIONAL_HEADER.NumberOfRvaAndSizes,
        "SectionsNb": pe.FILE_HEADER.NumberOfSections,
        "SectionsMeanEntropy": sum(sections_entropies) / len(sections_entropies) if sections_entropies else 0,
        "SectionsMinEntropy": min(sections_entropies) if sections_entropies else 0,
        "SectionsMaxEntropy": max(sections_entropies) if sections_entropies else 0,
        "SectionsMeanRawsize": sum([section.SizeOfRawData for section in pe.sections]) / len(pe.sections) if pe.sections else 0,
        "SectionsMinRawsize": min([section.SizeOfRawData for section in pe.sections]) if pe.sections else 0,
        "SectionMaxRawsize": max([section.SizeOfRawData for section in pe.sections]) if pe.sections else 0,
        "SectionsMeanVirtualsize": sum([section.Misc_VirtualSize for section in pe.sections]) / len(pe.sections) if pe.sections else 0,
        "SectionsMinVirtualsize": min([section.Misc_VirtualSize for section in pe.sections]) if pe.sections else 0,
        "SectionMaxVirtualsize": max([section.Misc_VirtualSize for section in pe.sections]) if pe.sections else 0,
        "ImportsNbDLL": len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0,
        "ImportsNb": sum([len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT]) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0,
        "ImportsNbOrdinal": sum([1 for entry in pe.DIRECTORY_ENTRY_IMPORT for imp in entry.imports if imp.name is None]) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0,
        "ExportNb": len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0,
        "ResourcesNb": len(resources),
        "ResourcesMeanEntropy": resources_mean_entropy,
        "ResourcesMinEntropy": resources_min_entropy,
        "ResourcesMaxEntropy": resources_max_entropy,
        "ResourcesMeanSize": resources_mean_size,
        "ResourcesMinSize": resources_min_size,
        "ResourcesMaxSize": resources_max_size,
        "LoadConfigurationSize": pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG') else 0,
        "VersionInformationSize": 0,
    }

    # Sauvegarder les informations PE dans un CSV
    output_csv = "pe_data.csv"
    pe_info_list = [pe_info]
    if os.path.exists(output_csv):
        df = pd.read_csv(output_csv)
        df = pd.concat([df, pd.DataFrame(pe_info_list)], ignore_index=True).drop_duplicates()
    else:
        df = pd.DataFrame(pe_info_list)
    df.to_csv(output_csv, index=False)

    return pe_info  # Renvoie pe_info pour utilisation dans la route




# Route principale
@app.route("/")
def home():
    return render_template("home.html", title="VirusAI")

# Route pour gérer l'upload de fichier et extraction des informations PE
@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        flash("Pas de fichier sélectionné")
        return redirect(url_for("home"))
    
    file = request.files["file"]
    if file.filename == "" or not file.filename.endswith(".exe"):
        flash("Veuillez uploader un fichier .exe")
        return redirect(url_for("home"))
    
    # Sauvegarder le fichier
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    file.save(file_path)
    
    # Extraire et enregistrer les informations PE
    try:
        pe_info = extract_pe_info(file_path)

        # Convertir les caractéristiques en DataFrame pour la prédiction
        feature_df = pd.DataFrame([pe_info])

        # Supprimer les colonnes inutiles pour le modèle
        columns_to_drop = ["Name"]
        feature_df = feature_df.drop(columns=[col for col in columns_to_drop if col in feature_df.columns])

        # Faire une prédiction avec le modèle chargé
        prediction = model.predict(feature_df)

        # Vérifier si le fichier est un malware ou non
        if prediction == 0:
            flash("Le fichier est un virus.")
        else:
            flash("Le fichier est sain.")
    except Exception as e:
        flash(f"Erreur lors de l'analyse du fichier: {e}")
    
    return redirect(url_for("home"))


# main
if __name__ == "__main__":
    app.run(debug=1, host="0.0.0.0", port="5454")
