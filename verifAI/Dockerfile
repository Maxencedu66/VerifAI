# Utiliser une version compatible de Python
FROM python:3.6-slim

# Installer les dépendances système
RUN apt-get update && apt-get install -y \
    wget \
    git \
    nano \
    python3-setuptools \
    libgomp1 \
    && apt-get clean


# Définir le répertoire de travail
WORKDIR /app

# Copier les fichiers du projet
COPY . /app

# Installer les dépendances Python
RUN pip install -r requirements.txt

# Commande par défaut
CMD ["bash"]
