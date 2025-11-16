# Générateur & Analyseur de mots de passe PyQt6

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![PyQt6](https://img.shields.io/badge/PyQt6-6.6.0+-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

Application Python pour générer des mots de passe sécurisés et analyser leurs faiblesses via une interface graphique PyQt6.

## Fonctionnalités
- Génération de mots de passe avec options :
  - Longueur personnalisable
  - Minuscules, majuscules, chiffres, symboles
  - Exclusion de caractères ambigus
  - Motifs personnalisés
- Analyse d’entropie réaliste :
  - Estimation naïve et ajustée
  - Détection de motifs clavier, séquences alphabétiques, répétitions
  - Détection de mots du dictionnaire (anglais/français) et listes compromises
  - Détection de dates et séquences numériques
  - Détection de mots prononçables
- Affichage clair de la force du mot de passe et des faiblesses détectées
- Copier un mot de passe généré dans le presse-papier
- Tester l’entropie d’un mot de passe saisi manuellement

## Installation
Voir [INSTALL.md](INSTALL.md)

## Usage
1. Lancer `main.py`
2. Dans la section **Options génération**, définir les paramètres souhaités
3. Cliquer sur **Générer** pour obtenir un mot de passe
4. Voir l’entropie et les faiblesses détectées
5. Copier le mot de passe ou tester un mot personnalisé dans la zone dédiée

## Licence
MIT License - voir [LICENSE.md](LICENSE.md)
