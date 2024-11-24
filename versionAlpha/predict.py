# Description: Ce script permet de charger un modèle entraîné et de l'utiliser pour prédire si des fichiers exe sont sains ou malveillants.
# La sortie inclut une matrice de confusion et un résumé des résultats.
# python predict.py

import pandas as pd
import pickle
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
import matplotlib.pyplot as plt


# Charger le modèle entraîné
model_path = "modele_ML/rf_model.pkl"  # Remplacer par le chemin vers votre modèle .pkl
with open(model_path, 'rb') as file:
    model = pickle.load(file)

# Charger les données du CSV
data_csv = "modele_ML/extraction.csv"  # Remplacer par le chemin vers votre CSV
data = pd.read_csv(data_csv, header=0)  # `header=0` pour spécifier que la première ligne est l'en-tête

# Nommer les colonnes pour correspondre aux données
data.columns = [
    "Name", "md5", "Machine", "SizeOfOptionalHeader", "Characteristics",
    "MajorLinkerVersion", "MinorLinkerVersion", "SizeOfCode", "SizeOfInitializedData",
    "SizeOfUninitializedData", "AddressOfEntryPoint", "BaseOfCode", "BaseOfData",
    "ImageBase", "SectionAlignment", "FileAlignment", "MajorOperatingSystemVersion",
    "MinorOperatingSystemVersion", "MajorImageVersion", "MinorImageVersion",
    "MajorSubsystemVersion", "MinorSubsystemVersion", "SizeOfImage", "SizeOfHeaders",
    "CheckSum", "Subsystem", "DllCharacteristics", "SizeOfStackReserve", "SizeOfStackCommit",
    "SizeOfHeapReserve", "SizeOfHeapCommit", "LoaderFlags", "NumberOfRvaAndSizes",
    "SectionsNb", "SectionsMeanEntropy", "SectionsMinEntropy", "SectionsMaxEntropy",
    "SectionsMeanRawsize", "SectionsMinRawsize", "SectionMaxRawsize", "SectionsMeanVirtualsize",
    "SectionsMinVirtualsize", "SectionMaxVirtualsize", "ImportsNbDLL", "ImportsNb",
    "ImportsNbOrdinal", "ExportNb", "ResourcesNb", "ResourcesMeanEntropy", "ResourcesMinEntropy",
    "ResourcesMaxEntropy", "ResourcesMeanSize", "ResourcesMinSize", "ResourcesMaxSize",
    "LoadConfigurationSize", "VersionInformationSize", "legitimate"
]


#drop columns Name, MD5 and legitimate
features = data.drop(columns=["Name", "md5", "legitimate"])

# Convertir les données en numérique et gérer les valeurs manquantes
features = features.apply(pd.to_numeric, errors='coerce').fillna(0)

# Faire les prédictions
predictions = model.predict(features)

# Générer les étiquettes réelles basées sur les noms de fichiers (hypothèse VS_ pour Virus)
true_labels = data["Name"].apply(lambda x: 0 if x.startswith("VS_") else 1)  # 0 = Virus, 1 = Sain

# Calculer la matrice de confusion
cm = confusion_matrix(true_labels, predictions)

# Afficher la matrice de confusion
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Virus", "Sain"])
disp.plot(cmap=plt.cm.Blues)
plt.title("Matrice de Confusion")
plt.show()

# Résumé des résultats
correct = (true_labels == predictions).sum()
incorrect = (true_labels != predictions).sum()
print(f"\nNombre de prédictions correctes : {correct}")
print(f"Nombre de prédictions incorrectes : {incorrect}")
print(f"Précision : {correct / (correct + incorrect) * 100:.2f}%")
