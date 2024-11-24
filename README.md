# VerifAI - Système de Détection Statique de Virus par Machine Learning

## Description du Projet

**VerifAI** est une solution de détection statique de virus basée sur le machine learning. Ce système analyse les fichiers exécutables pour déterminer s’ils sont malveillants ou sûrs, sans nécessiter de signatures traditionnelles. Il utilise le **dataset EMBER** et un modèle entraîné avec **XGBoost**, tout en intégrant des extractions de caractéristiques statiques via la bibliothèque **LIEF 0.9** et Python 3.6.

> **Note :** En raison des exigences de compatibilité (LIEF 0.9 et Python 3.6), l'application est exécutée dans un environnement Docker. Elle n'est pas compatible avec les architectures ARM, comme celles des Mac récents équipés de puces Apple Silicon (M1/M2).

---

## Objectifs

1. **Détection proactive** : Identifier les fichiers malveillants, y compris ceux non répertoriés dans les bases de signatures.
2. **Performance élevée** : Fournir une analyse rapide et précise grâce à un pipeline optimisé.
3. **Interface conviviale** : Offrir une interface web pour permettre aux utilisateurs de soumettre leurs fichiers.
4. **Fiabilité** : Évaluer la précision du modèle à travers des métriques robustes.

---

## Fonctionnalités

### Détection Statique de Virus
- **Analyse par Machine Learning** : Utilisation d'un modèle XGBoost entraîné sur des caractéristiques extraites des exécutables.
- **Prise en charge des fichiers .exe et autres** : Les fichiers sans extension .exe sont considérés comme suspects (malwares).

### Application Web Intégrée
- **Flask Backend** : Permet aux utilisateurs de télécharger des fichiers et de recevoir une évaluation instantanée.
- **Résultats détaillés** : Score de confiance et classification pour chaque fichier soumis.
- **Gestion des noms de fichiers** : Nettoyage des caractères spéciaux pour éviter les erreurs d'analyse.

### Évaluation et Statistiques
- **Temps d'analyse** : Temps moyen, maximum et minimum pour analyser les fichiers.
- **Statistiques sur les fichiers** : Taille moyenne, taille minimale et taille maximale des fichiers analysés.
- **Matrice de confusion** : Visualisation des performances du modèle.
- **Rapport détaillé** : Résultats enregistrés dans un fichier texte avec les statistiques globales et les prédictions.

---

## Pré-requis

1. **Docker** : Pour exécuter l’application dans un environnement compatible.
2. **Python 3.6** : Utilisé dans le conteneur Docker.
3. **Compatibilité avec les systèmes x86_64** : Non compatible avec les puces ARM des Mac récents.

---

## Notebook Kaggle

Un notebook détaillé, utilisé pour l'entraînement des modèles et la comparaison des performances entre **RandomForest** et **XGBoost**, est disponible sur Kaggle. Ce notebook présente les étapes suivantes :
- Préparation des données avec le dataset **EMBER**.
- Entraînement des modèles **RandomForest** et **XGBoost**.
- Comparaison des performances à l'aide de métriques et de visualisations.
- Exportation du modèle le plus performant pour intégration dans l'application **VerifAI**.

Accédez au notebook ici : [Notebook Kaggle - VerifAI](https://www.kaggle.com/code/maxencebouchadel/verifai-entrainement-des-mod-les)

---

## Instructions pour l’Installation et l’Utilisation

## 1. Construire et Lancer le Conteneur Docker
```bash
docker build -t verifai .
docker run -it -p 5454:5454 verifai
```
### 2. Lancer l’Application
Dans le conteneur Docker, exécutez :
```bash
python app.py
```
L’application sera disponible à l’adresse `http://localhost:5454`.

---

## Version Alpha

Le projet contient une première version expérimentale dans le dossier `VersionAlpha`. Cette version utilise un extracteur de caractéristiques développé manuellement et n’est pas compatible avec le dataset EMBER. Les résultats obtenus étaient insatisfaisants, car le modèle détectait de nombreux faux positifs en raison d’un dataset contenant trop peu de features.

### Points Clés :
- **Problèmes** :
  - Non compatible avec les fichiers `.exe` actuels.
  - Détection excessive de fichiers sains comme malveillants.
- **Exécution** : Lancer `app.py` depuis le dossier `VersionAlpha` pour tester cette version.

---

